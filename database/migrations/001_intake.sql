-- AI Operations Intake: audit store
-- Everything lives in the private schema "intake", which the Supabase public REST API doesn't expose.
-- Writes happen only through SECURITY DEFINER functions. History is append-only and enforced by trigger.

create extension if not exists pgcrypto with schema extensions;

create schema if not exists intake;
revoke all on schema intake from public, anon, authenticated;

create sequence if not exists intake.reference_seq;

create table intake.intake_records (
  id                  uuid primary key default gen_random_uuid(),
  reference           text not null unique default (
                        'OPS-' || to_char(now() at time zone 'utc', 'YYYY') || '-' ||
                        lpad(nextval('intake.reference_seq')::text, 6, '0')),
  origin_execution_id text not null unique,
  channel             text not null check (channel in ('form', 'api', 'test')),
  requester_email     text check (requester_email is null or char_length(requester_email) <= 254),
  request_text        text not null check (char_length(request_text) between 1 and 4000),
  brief               text check (brief is null or char_length(brief) <= 500),
  category            text,
  urgency             text check (urgency in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
  urgency_score       numeric(4,3) check (urgency_score between 0 and 1),
  confidence_score    numeric(4,3) check (confidence_score between 0 and 1),
  ai_model            text,
  sensitive_flags     jsonb not null default '[]'::jsonb check (jsonb_typeof(sensitive_flags) = 'array'),
  injection_flags     jsonb not null default '[]'::jsonb check (jsonb_typeof(injection_flags) = 'array'),
  route               text not null check (route in ('INCIDENT_DESK', 'OPERATIONS_QUEUE', 'HUMAN_REVIEW')),
  rule_applied        text not null,
  sla_minutes         integer not null check (sla_minutes > 0),
  deadline            timestamptz not null,
  status              text not null check (status in ('OPEN_INCIDENT', 'QUEUED', 'PENDING_REVIEW', 'APPROVED', 'REJECTED')),
  review_token_hash   text,
  token_expires_at    timestamptz,
  token_used_at       timestamptz,
  reviewer_id         text,
  review_decision     text check (review_decision in ('APPROVED', 'REJECTED')),
  review_notes        text check (review_notes is null or char_length(review_notes) <= 1000),
  reviewed_at         timestamptz,
  escalated_at        timestamptz,
  is_test             boolean not null default false,
  decision_history    jsonb not null default '[]'::jsonb check (jsonb_typeof(decision_history) = 'array'),
  created_at          timestamptz not null default now()
);

create index intake_pending_deadline_idx
  on intake.intake_records (deadline)
  where status = 'PENDING_REVIEW' and escalated_at is null;

alter table intake.intake_records enable row level security;
-- No policies and no table grants: only the table owner can touch rows, which here means the
-- SECURITY DEFINER functions below. n8n_intake reads through intake.get_record().

-- ---------------------------------------------------------------------------
-- Append-only guard
-- ---------------------------------------------------------------------------
create or replace function intake.guard_records()
returns trigger
language plpgsql
set search_path = ''
as $$
declare
  old_len integer;
begin
  if tg_op = 'DELETE' then
    raise exception 'intake_records is append-only: DELETE is not allowed';
  end if;

  if new.id is distinct from old.id
     or new.reference is distinct from old.reference
     or new.origin_execution_id is distinct from old.origin_execution_id
     or new.channel is distinct from old.channel
     or new.request_text is distinct from old.request_text
     or new.requester_email is distinct from old.requester_email
     or new.is_test is distinct from old.is_test
     or new.created_at is distinct from old.created_at
     or new.review_token_hash is distinct from old.review_token_hash then
    raise exception 'intake_records: immutable column changed';
  end if;

  old_len := jsonb_array_length(old.decision_history);
  if jsonb_array_length(new.decision_history) < old_len
     or (select coalesce(jsonb_agg(e order by i), '[]'::jsonb)
           from jsonb_array_elements(new.decision_history) with ordinality as t(e, i)
          where i <= old_len) is distinct from old.decision_history then
    raise exception 'intake_records: decision_history is append-only';
  end if;

  if old.review_decision is not null and new.review_decision is distinct from old.review_decision then
    raise exception 'intake_records: review decision is final';
  end if;
  if old.token_used_at is not null and new.token_used_at is distinct from old.token_used_at then
    raise exception 'intake_records: review token already consumed';
  end if;

  return new;
end;
$$;

create trigger intake_records_guard
  before update or delete on intake.intake_records
  for each row execute function intake.guard_records();

create or replace function intake.block_truncate()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  raise exception 'intake_records is append-only: TRUNCATE is not allowed';
end;
$$;

create trigger intake_records_no_truncate
  before truncate on intake.intake_records
  for each statement execute function intake.block_truncate();

-- ---------------------------------------------------------------------------
-- Public view of a record (never exposes the token hash)
-- ---------------------------------------------------------------------------
create or replace function intake.record_json(r intake.intake_records)
returns jsonb
language sql
immutable
set search_path = ''
as $$
  select to_jsonb(r) - 'review_token_hash';
$$;

-- ---------------------------------------------------------------------------
-- intake_create: the single insert path. Idempotent on origin_execution_id.
-- Input: jsonb from the n8n Governance Rules node. The DB sets deadline and token.
-- Returns the record, plus the raw review_token once (HUMAN_REVIEW only).
-- ---------------------------------------------------------------------------
create or replace function intake.intake_create(p jsonb)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_route   text := p->>'route';
  v_sla     integer := (p->>'sla_minutes')::integer;
  v_token   text;
  v_hash    text;
  v_status  text;
  v_history jsonb := coalesce(p->'decision_history', '[]'::jsonb);
  r         intake.intake_records;
begin
  if jsonb_typeof(v_history) <> 'array' then
    raise exception 'decision_history must be an array';
  end if;

  select * into r from intake.intake_records where origin_execution_id = p->>'origin_execution_id';
  if found then
    -- Retry of the same execution: return the existing record, never a duplicate.
    return jsonb_build_object('ok', true, 'result', 'already_exists', 'record', intake.record_json(r));
  end if;

  v_status := case v_route
                when 'INCIDENT_DESK'    then 'OPEN_INCIDENT'
                when 'OPERATIONS_QUEUE' then 'QUEUED'
                when 'HUMAN_REVIEW'     then 'PENDING_REVIEW'
              end;

  if v_route = 'HUMAN_REVIEW' then
    v_token := encode(extensions.gen_random_bytes(32), 'hex');
    v_hash  := encode(extensions.digest(v_token, 'sha256'), 'hex');
  end if;

  insert into intake.intake_records (
    origin_execution_id, channel, requester_email, request_text, brief, category, urgency,
    urgency_score, confidence_score, ai_model, sensitive_flags, injection_flags, route,
    rule_applied, sla_minutes, deadline, status, review_token_hash, token_expires_at,
    is_test, decision_history)
  values (
    p->>'origin_execution_id',
    p->>'channel',
    nullif(p->>'requester_email', ''),
    p->>'request_text',
    left(p->>'brief', 500),
    p->>'category',
    p->>'urgency',
    (p->>'urgency_score')::numeric,
    (p->>'confidence_score')::numeric,
    p->>'ai_model',
    coalesce(p->'sensitive_flags', '[]'::jsonb),
    coalesce(p->'injection_flags', '[]'::jsonb),
    v_route,
    p->>'rule_applied',
    v_sla,
    now() + make_interval(mins => v_sla),
    v_status,
    v_hash,
    case when v_hash is not null then now() + interval '72 hours' end,
    coalesce((p->>'is_test')::boolean, false),
    v_history || jsonb_build_array(jsonb_build_object(
      'step', 'RECORDED', 'status', v_status, 'sla_minutes', v_sla, 'at', now())))
  returning * into r;

  return jsonb_build_object('ok', true, 'result', 'created', 'record', intake.record_json(r),
                            'review_token', v_token);
end;
$$;

-- ---------------------------------------------------------------------------
-- review_decide: atomic, idempotent approval checkpoint keyed by origin_execution_id.
-- ---------------------------------------------------------------------------
create or replace function intake.review_decide(
  p_exec text, p_token text, p_decision text, p_reviewer text, p_notes text default null)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_hash text := encode(extensions.digest(coalesce(p_token, ''), 'sha256'), 'hex');
  r      intake.intake_records;
begin
  if p_decision not in ('APPROVED', 'REJECTED') then
    return jsonb_build_object('ok', false, 'result', 'invalid_decision');
  end if;

  -- The single atomic transition. The row lock makes double clicks race-safe.
  update intake.intake_records
     set status           = p_decision,
         review_decision  = p_decision,
         reviewer_id      = left(p_reviewer, 254),
         review_notes     = left(p_notes, 1000),
         reviewed_at      = now(),
         token_used_at    = now(),
         decision_history = decision_history || jsonb_build_array(jsonb_build_object(
                              'step', p_decision, 'by', left(p_reviewer, 254),
                              'notes', left(p_notes, 1000), 'at', now()))
   where origin_execution_id = p_exec
     and status = 'PENDING_REVIEW'
     and token_used_at is null
     and review_token_hash = v_hash
     and token_expires_at > now()
  returning * into r;

  if found then
    return jsonb_build_object('ok', true, 'result', 'decided', 'record', intake.record_json(r));
  end if;

  -- Not decided: explain why without leaking anything to a bad token.
  select * into r from intake.intake_records where origin_execution_id = p_exec;
  if not found or r.review_token_hash is distinct from v_hash then
    return jsonb_build_object('ok', false, 'result', 'invalid_link');
  end if;

  if r.token_used_at is not null then
    update intake.intake_records
       set decision_history = decision_history || jsonb_build_array(jsonb_build_object(
             'step', 'DUPLICATE_DECISION_IGNORED', 'attempted', p_decision,
             'by', left(p_reviewer, 254), 'at', now()))
     where id = r.id
    returning * into r;
    return jsonb_build_object('ok', false, 'result', 'already_decided',
                              'decision', r.review_decision, 'record', intake.record_json(r));
  end if;

  update intake.intake_records
     set decision_history = decision_history || jsonb_build_array(jsonb_build_object(
           'step', 'EXPIRED_LINK_ATTEMPT', 'attempted', p_decision,
           'by', left(p_reviewer, 254), 'at', now()))
   where id = r.id;
  return jsonb_build_object('ok', false, 'result', 'expired');
end;
$$;

-- ---------------------------------------------------------------------------
-- review_preview: what the confirm page may show (validates the link, changes nothing).
-- ---------------------------------------------------------------------------
create or replace function intake.review_preview(p_exec text, p_token text)
returns jsonb
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  r intake.intake_records;
begin
  select * into r from intake.intake_records
   where origin_execution_id = p_exec
     and review_token_hash = encode(extensions.digest(coalesce(p_token, ''), 'sha256'), 'hex');
  if not found then
    return jsonb_build_object('ok', false, 'result', 'invalid_link');
  end if;
  return jsonb_build_object(
    'ok', true,
    'result', case when r.token_used_at is not null then 'already_decided'
                   when r.token_expires_at <= now() then 'expired'
                   else 'open' end,
    'reference', r.reference, 'brief', r.brief, 'category', r.category, 'urgency', r.urgency,
    'confidence_score', r.confidence_score, 'rule_applied', r.rule_applied,
    'deadline', r.deadline, 'review_decision', r.review_decision);
end;
$$;

-- ---------------------------------------------------------------------------
-- append_event: whitelisted operational events (notifications, downstream dispatch).
-- ---------------------------------------------------------------------------
create or replace function intake.append_event(p_exec text, p_event jsonb)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  r intake.intake_records;
begin
  if p_event->>'step' not in ('NOTIFIED', 'NOTIFICATION_FAILED', 'NOTIFICATION_SUPPRESSED_TEST',
                              'DOWNSTREAM_DISPATCHED', 'ESCALATION_NOTIFIED') then
    raise exception 'append_event: step % is not allowed', p_event->>'step';
  end if;
  update intake.intake_records
     set decision_history = decision_history || jsonb_build_array(
           p_event || jsonb_build_object('at', now()))
   where origin_execution_id = p_exec
  returning * into r;
  if not found then
    return jsonb_build_object('ok', false, 'result', 'not_found');
  end if;
  return jsonb_build_object('ok', true, 'result', 'appended', 'reference', r.reference);
end;
$$;

-- ---------------------------------------------------------------------------
-- sla_escalate_breached: SLA watchdog ("no silent limbo"). Each record escalates once.
-- ---------------------------------------------------------------------------
create or replace function intake.sla_escalate_breached()
returns setof jsonb
language plpgsql
security definer
set search_path = ''
as $$
begin
  return query
  update intake.intake_records
     set escalated_at     = now(),
         decision_history = decision_history || jsonb_build_array(jsonb_build_object(
                              'step', 'SLA_BREACHED_ESCALATED', 'deadline', deadline,
                              'minutes_overdue', floor(extract(epoch from now() - deadline) / 60),
                              'at', now()))
   where status = 'PENDING_REVIEW'
     and escalated_at is null
     and deadline < now()
  returning intake.record_json(intake_records.*);
end;
$$;

-- ---------------------------------------------------------------------------
-- get_record: read one record by execution id (used by the acceptance gate).
-- ---------------------------------------------------------------------------
create or replace function intake.get_record(p_exec text)
returns jsonb
language sql
stable
security definer
set search_path = ''
as $$
  select jsonb_build_object(
    'row_count', (select count(*) from intake.intake_records where origin_execution_id = p_exec),
    'record', (select intake.record_json(r) from intake.intake_records r
                where origin_execution_id = p_exec));
$$;

-- ---------------------------------------------------------------------------
-- Least-privilege role for n8n. Created WITHOUT a password: set one in the Supabase SQL editor:
--   alter role n8n_intake with password '<strong password>';
-- ---------------------------------------------------------------------------
do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'n8n_intake') then
    create role n8n_intake login noinherit;
  end if;
end;
$$;

revoke all on all functions in schema intake from public, anon, authenticated;
alter default privileges in schema intake revoke execute on functions from public;

grant usage on schema intake to n8n_intake;
grant execute on function
  intake.intake_create(jsonb),
  intake.review_decide(text, text, text, text, text),
  intake.review_preview(text, text),
  intake.append_event(text, jsonb),
  intake.sla_escalate_breached(),
  intake.get_record(text)
to n8n_intake;
