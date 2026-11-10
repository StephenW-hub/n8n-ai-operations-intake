-- ============================================================
-- Single-file fresh install: migrations 001 + 002 + 003, in order.
-- Run once as the database owner on a new Postgres (Supabase, RDS, Azure or self-hosted).
-- Then: set the n8n_intake password, insert your routes (see routes_example.sql),
-- and optionally run seed_demo.sql.
-- ============================================================

-- >>> migrations/001_intake.sql
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

-- >>> migrations/002_governance_v2.sql
-- Governance Engine v2
-- * Renames to the Master Spec vocabulary: intake_audit_logs, sla_deadline, intent, concise_brief
-- * Adds department, the tiered-model fields (review_brief / review_model / models_used),
--   attachment metadata (never file bytes), is_demo and resolved_at
-- * Tightens the guard: the classification and routing decision is immutable once written.
--   Only the review lifecycle, escalation and appended history may change.
-- * Adds the executive_reports archive and the deterministic KPI and friction functions behind
--   the monthly COO report
-- plpgsql stores function bodies as text, so every function that names the table is recreated.

alter table intake.intake_records rename to intake_audit_logs;
alter table intake.intake_audit_logs rename column deadline to sla_deadline;
alter table intake.intake_audit_logs rename column category to intent;
alter table intake.intake_audit_logs rename column brief    to concise_brief;
alter index intake.intake_pending_deadline_idx rename to intake_audit_logs_pending_sla_idx;
alter trigger intake_records_guard       on intake.intake_audit_logs rename to intake_audit_logs_guard;
alter trigger intake_records_no_truncate on intake.intake_audit_logs rename to intake_audit_logs_no_truncate;

alter table intake.intake_audit_logs
  add column department      text check (department is null or department in
                               ('Finance', 'IT', 'Operations', 'HR', 'Campus/Facilities',
                                'Customer Service', 'Other')),
  add column review_brief    text check (review_brief is null or char_length(review_brief) <= 6000),
  add column review_model    text,
  add column models_used     jsonb not null default '[]'::jsonb check (jsonb_typeof(models_used) = 'array'),
  add column attachment_meta jsonb check (attachment_meta is null or jsonb_typeof(attachment_meta) = 'object'),
  add column is_demo         boolean not null default false,
  add column resolved_at     timestamptz;

create index intake_audit_logs_created_idx on intake.intake_audit_logs (created_at)
  where not is_test;

-- ---------------------------------------------------------------------------
-- Guard v2. Every column is immutable except the review lifecycle, escalation and history.
-- ---------------------------------------------------------------------------
create or replace function intake.guard_records()
returns trigger
language plpgsql
set search_path = ''
as $$
declare
  mutable constant text[] := array['status', 'reviewer_id', 'review_decision', 'review_notes',
                                   'reviewed_at', 'resolved_at', 'token_used_at', 'escalated_at',
                                   'decision_history'];
  old_len integer;
begin
  if tg_op = 'DELETE' then
    raise exception 'intake_audit_logs is append-only: DELETE is not allowed';
  end if;

  if (to_jsonb(new) - mutable) is distinct from (to_jsonb(old) - mutable) then
    raise exception 'intake_audit_logs: the classification and routing record is immutable';
  end if;

  old_len := jsonb_array_length(old.decision_history);
  if jsonb_array_length(new.decision_history) < old_len
     or (select coalesce(jsonb_agg(e order by i), '[]'::jsonb)
           from jsonb_array_elements(new.decision_history) with ordinality as t(e, i)
          where i <= old_len) is distinct from old.decision_history then
    raise exception 'intake_audit_logs: decision_history is append-only';
  end if;

  if new.status is distinct from old.status
     and not (old.status = 'PENDING_REVIEW' and new.status in ('APPROVED', 'REJECTED')) then
    raise exception 'intake_audit_logs: illegal status transition % -> %', old.status, new.status;
  end if;
  if old.review_decision is not null and new.review_decision is distinct from old.review_decision then
    raise exception 'intake_audit_logs: review decision is final';
  end if;
  if old.token_used_at is not null and new.token_used_at is distinct from old.token_used_at then
    raise exception 'intake_audit_logs: review token already consumed';
  end if;
  if old.escalated_at is not null and new.escalated_at is distinct from old.escalated_at then
    raise exception 'intake_audit_logs: escalation timestamp is final';
  end if;

  return new;
end;
$$;

create or replace function intake.block_truncate()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  raise exception '% is append-only: TRUNCATE is not allowed', tg_table_name;
end;
$$;

create or replace function intake.record_json(r intake.intake_audit_logs)
returns jsonb
language sql
immutable
set search_path = ''
as $$
  select to_jsonb(r) - 'review_token_hash';
$$;

-- ---------------------------------------------------------------------------
-- intake_create v2
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
  r         intake.intake_audit_logs;
begin
  if jsonb_typeof(v_history) <> 'array' then
    raise exception 'decision_history must be an array';
  end if;

  select * into r from intake.intake_audit_logs where origin_execution_id = p->>'origin_execution_id';
  if found then
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

  insert into intake.intake_audit_logs (
    origin_execution_id, channel, requester_email, department, request_text, concise_brief,
    intent, urgency, urgency_score, confidence_score, ai_model, models_used, review_brief,
    review_model, attachment_meta, sensitive_flags, injection_flags, route, rule_applied,
    sla_minutes, sla_deadline, status, review_token_hash, token_expires_at, is_test, is_demo,
    decision_history)
  values (
    p->>'origin_execution_id',
    p->>'channel',
    nullif(p->>'requester_email', ''),
    nullif(p->>'department', ''),
    p->>'request_text',
    left(p->>'concise_brief', 500),
    p->>'intent',
    p->>'urgency',
    (p->>'urgency_score')::numeric,
    (p->>'confidence_score')::numeric,
    p->>'ai_model',
    coalesce(p->'models_used', '[]'::jsonb),
    left(p->>'review_brief', 6000),
    p->>'review_model',
    case when jsonb_typeof(p->'attachment_meta') = 'object' then p->'attachment_meta' end,
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
    coalesce((p->>'is_demo')::boolean, false),
    v_history || jsonb_build_array(jsonb_build_object(
      'step', 'RECORDED', 'status', v_status, 'sla_minutes', v_sla, 'at', now())))
  returning * into r;

  return jsonb_build_object('ok', true, 'result', 'created', 'record', intake.record_json(r),
                            'review_token', v_token);
end;
$$;

-- ---------------------------------------------------------------------------
-- review_decide v2 (also sets resolved_at)
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
  r      intake.intake_audit_logs;
begin
  if p_decision not in ('APPROVED', 'REJECTED') then
    return jsonb_build_object('ok', false, 'result', 'invalid_decision');
  end if;

  update intake.intake_audit_logs
     set status           = p_decision,
         review_decision  = p_decision,
         reviewer_id      = left(p_reviewer, 254),
         review_notes     = left(p_notes, 1000),
         reviewed_at      = now(),
         resolved_at      = now(),
         token_used_at    = now(),
         decision_history = decision_history || jsonb_build_array(jsonb_build_object(
                              'step', p_decision, 'by', left(p_reviewer, 254),
                              'notes', left(p_notes, 1000),
                              'within_sla', now() <= sla_deadline, 'at', now()))
   where origin_execution_id = p_exec
     and status = 'PENDING_REVIEW'
     and token_used_at is null
     and review_token_hash = v_hash
     and token_expires_at > now()
  returning * into r;

  if found then
    return jsonb_build_object('ok', true, 'result', 'decided', 'record', intake.record_json(r));
  end if;

  select * into r from intake.intake_audit_logs where origin_execution_id = p_exec;
  if not found or r.review_token_hash is distinct from v_hash then
    return jsonb_build_object('ok', false, 'result', 'invalid_link');
  end if;

  if r.token_used_at is not null then
    update intake.intake_audit_logs
       set decision_history = decision_history || jsonb_build_array(jsonb_build_object(
             'step', 'DUPLICATE_DECISION_IGNORED', 'attempted', p_decision,
             'by', left(p_reviewer, 254), 'at', now()))
     where id = r.id
    returning * into r;
    return jsonb_build_object('ok', false, 'result', 'already_decided',
                              'decision', r.review_decision, 'record', intake.record_json(r));
  end if;

  update intake.intake_audit_logs
     set decision_history = decision_history || jsonb_build_array(jsonb_build_object(
           'step', 'EXPIRED_LINK_ATTEMPT', 'attempted', p_decision,
           'by', left(p_reviewer, 254), 'at', now()))
   where id = r.id;
  return jsonb_build_object('ok', false, 'result', 'expired');
end;
$$;

-- ---------------------------------------------------------------------------
-- review_preview v2
-- ---------------------------------------------------------------------------
create or replace function intake.review_preview(p_exec text, p_token text)
returns jsonb
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  r intake.intake_audit_logs;
begin
  select * into r from intake.intake_audit_logs
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
    'reference', r.reference, 'department', r.department, 'concise_brief', r.concise_brief,
    'review_brief', r.review_brief, 'intent', r.intent, 'urgency', r.urgency,
    'confidence_score', r.confidence_score, 'rule_applied', r.rule_applied,
    'sensitive_flags', r.sensitive_flags, 'injection_flags', r.injection_flags,
    'sla_deadline', r.sla_deadline, 'review_decision', r.review_decision);
end;
$$;

-- ---------------------------------------------------------------------------
-- append_event v2 (more whitelisted operational events)
-- ---------------------------------------------------------------------------
create or replace function intake.append_event(p_exec text, p_event jsonb)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  r intake.intake_audit_logs;
begin
  if p_event->>'step' not in ('NOTIFIED', 'NOTIFICATION_FAILED', 'NOTIFICATION_SUPPRESSED_TEST',
                              'NOTIFICATION_NO_ROUTE', 'DOWNSTREAM_DISPATCHED',
                              'ESCALATION_NOTIFIED') then
    raise exception 'append_event: step % is not allowed', p_event->>'step';
  end if;
  update intake.intake_audit_logs
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
-- sla_escalate_breached v2
-- ---------------------------------------------------------------------------
create or replace function intake.sla_escalate_breached()
returns setof jsonb
language plpgsql
security definer
set search_path = ''
as $$
begin
  return query
  update intake.intake_audit_logs
     set escalated_at     = now(),
         decision_history = decision_history || jsonb_build_array(jsonb_build_object(
                              'step', 'SLA_BREACHED_ESCALATED', 'sla_deadline', sla_deadline,
                              'minutes_overdue', floor(extract(epoch from now() - sla_deadline) / 60),
                              'at', now()))
   where status = 'PENDING_REVIEW'
     and escalated_at is null
     and sla_deadline < now()
  returning intake.record_json(intake_audit_logs.*);
end;
$$;

create or replace function intake.get_record(p_exec text)
returns jsonb
language sql
stable
security definer
set search_path = ''
as $$
  select jsonb_build_object(
    'row_count', (select count(*) from intake.intake_audit_logs where origin_execution_id = p_exec),
    'record', (select intake.record_json(r) from intake.intake_audit_logs r
                where origin_execution_id = p_exec));
$$;

-- ---------------------------------------------------------------------------
-- Executive report archive (append-only)
-- ---------------------------------------------------------------------------
create table intake.executive_reports (
  id                  uuid primary key default gen_random_uuid(),
  period_start        date not null,
  period_end          date not null,
  origin_execution_id text not null unique,
  run_kind            text not null check (run_kind in ('scheduled', 'manual')),
  include_demo        boolean not null default false,
  kpis                jsonb not null,
  friction            jsonb not null,
  recommendations     jsonb,
  ai_model            text,
  html                text,
  delivered_to        jsonb not null default '[]'::jsonb,
  created_at          timestamptz not null default now(),
  check (period_end > period_start)
);
create unique index executive_reports_one_scheduled_per_month
  on intake.executive_reports (period_start) where run_kind = 'scheduled';
alter table intake.executive_reports enable row level security;

create or replace function intake.block_mutation()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  raise exception '% is append-only: % is not allowed', tg_table_name, tg_op;
end;
$$;

create trigger executive_reports_immutable
  before update or delete on intake.executive_reports
  for each row execute function intake.block_mutation();
create trigger executive_reports_no_truncate
  before truncate on intake.executive_reports
  for each statement execute function intake.block_truncate();

-- ---------------------------------------------------------------------------
-- report_kpis: deterministic KPIs for one calendar month (p_month = any day in that month).
-- Test rows are always excluded. Demo rows are included only when asked.
-- ---------------------------------------------------------------------------
create or replace function intake.report_kpis(
  p_month date, p_minutes_saved integer default 12, p_hourly_rate numeric default 25,
  p_include_demo boolean default false)
returns jsonb
language sql
stable
security definer
set search_path = ''
as $$
  with bounds as (
    select date_trunc('month', p_month)::date                        as m_start,
           (date_trunc('month', p_month) + interval '1 month')::date as m_end,
           (date_trunc('month', p_month) - interval '1 month')::date as p_start
  ),
  cur as (
    select l.* from intake.intake_audit_logs l, bounds b
     where l.created_at >= b.m_start and l.created_at < b.m_end
       and not l.is_test and (p_include_demo or not l.is_demo)
  ),
  prev as (
    select count(*) as n from intake.intake_audit_logs l, bounds b
     where l.created_at >= b.p_start and l.created_at < b.m_start
       and not l.is_test and (p_include_demo or not l.is_demo)
  ),
  hr as (
    -- Human Review items whose SLA outcome is known: decided, or deadline already passed
    select count(*) filter (where reviewed_at is not null or sla_deadline < now()) as measurable,
           count(*) filter (where reviewed_at is not null and reviewed_at <= sla_deadline) as in_sla
      from cur where route = 'HUMAN_REVIEW'
  ),
  agg as (
    select count(*)                                                    as total,
           count(*) filter (where route = 'INCIDENT_DESK')             as incident_desk,
           count(*) filter (where route = 'OPERATIONS_QUEUE')          as operations_queue,
           count(*) filter (where route = 'HUMAN_REVIEW')              as human_review,
           count(*) filter (where route <> 'HUMAN_REVIEW')             as auto_routed,
           count(*) filter (where jsonb_array_length(sensitive_flags) > 0) as sensitive_catches,
           count(*) filter (where jsonb_array_length(injection_flags) > 0) as injection_blocks,
           count(*) filter (where rule_applied = 'LOW_CONFIDENCE')     as low_confidence_holds,
           count(*) filter (where rule_applied = 'AI_UNAVAILABLE')     as ai_unavailable,
           count(*) filter (where escalated_at is not null)            as sla_escalations,
           count(*) filter (where review_decision = 'APPROVED')        as approved,
           count(*) filter (where review_decision = 'REJECTED')        as rejected,
           count(*) filter (where status = 'PENDING_REVIEW')           as still_pending,
           round(avg(confidence_score), 3)                             as avg_confidence
      from cur
  )
  select jsonb_build_object(
    'period_start', b.m_start, 'period_end', b.m_end, 'include_demo', p_include_demo,
    'total_requests', a.total,
    'prior_month_requests', p.n,
    'mom_delta_pct', case when p.n > 0 then round((a.total - p.n) * 100.0 / p.n, 1) end,
    'routing', jsonb_build_object('INCIDENT_DESK', a.incident_desk,
                                  'OPERATIONS_QUEUE', a.operations_queue,
                                  'HUMAN_REVIEW', a.human_review),
    'auto_routed', a.auto_routed,
    'sla_compliance_pct', case when h.measurable > 0 then round(h.in_sla * 100.0 / h.measurable, 1) end,
    'sla_measurable_reviews', h.measurable,
    'sla_escalations', a.sla_escalations,
    'sensitive_catches', a.sensitive_catches,
    'injection_blocks', a.injection_blocks,
    'low_confidence_holds', a.low_confidence_holds,
    'ai_unavailable', a.ai_unavailable,
    'approved', a.approved, 'rejected', a.rejected, 'still_pending', a.still_pending,
    'avg_confidence', a.avg_confidence,
    'admin_hours_saved', round(a.auto_routed * p_minutes_saved / 60.0, 1),
    'labor_value_avoided_usd', round(a.auto_routed * p_minutes_saved / 60.0 * p_hourly_rate, 2),
    'by_department', coalesce((select jsonb_object_agg(coalesce(department, 'Unspecified'), n)
                                 from (select department, count(*) n from cur group by department) d),
                              '{}'::jsonb),
    'assumptions', jsonb_build_object(
      'minutes_saved_per_auto_routed_request', p_minutes_saved,
      'hourly_rate_usd', p_hourly_rate,
      'sla_compliance_definition',
        'Share of Human Review items decided on or before their SLA deadline, among items that were decided or whose deadline has passed.',
      'hours_saved_definition',
        'Requests routed automatically (Incident Desk + Operations Queue) x minutes of manual triage avoided.'))
  from agg a, prev p, hr h, bounds b;
$$;

-- ---------------------------------------------------------------------------
-- report_friction: aggregated friction patterns (no raw request text ever leaves the DB here)
-- ---------------------------------------------------------------------------
create or replace function intake.report_friction(p_month date, p_include_demo boolean default false)
returns jsonb
language sql
stable
security definer
set search_path = ''
as $$
  with cur as (
    select * from intake.intake_audit_logs
     where created_at >= date_trunc('month', p_month)
       and created_at <  date_trunc('month', p_month) + interval '1 month'
       and not is_test and (p_include_demo or not is_demo)
  ),
  dept as (
    select coalesce(department, 'Unspecified') as department,
           count(*) as total,
           count(*) filter (where rule_applied = 'LOW_CONFIDENCE') as low_confidence,
           count(*) filter (where escalated_at is not null)        as sla_breaches,
           count(*) filter (where route = 'INCIDENT_DESK')         as incidents,
           count(*) filter (where jsonb_array_length(sensitive_flags) > 0) as sensitive
      from cur group by 1
  ),
  clusters as (
    select coalesce(department, 'Unspecified') as department, coalesce(intent, 'unknown') as intent,
           count(*) as incidents
      from cur where route = 'INCIDENT_DESK' group by 1, 2
  ),
  lowconf as (
    select coalesce(intent, 'unknown') as intent, count(*) as n, round(avg(confidence_score), 3) as avg_conf
      from cur where rule_applied = 'LOW_CONFIDENCE' group by 1
  )
  select jsonb_build_object(
    'top_friction_departments', coalesce((
      select jsonb_agg(to_jsonb(d) order by d.low_confidence + d.sla_breaches desc, d.total desc)
        from (select * from dept order by low_confidence + sla_breaches desc, total desc limit 5) d), '[]'::jsonb),
    'incident_clusters', coalesce((
      select jsonb_agg(to_jsonb(c) order by c.incidents desc)
        from (select * from clusters order by incidents desc limit 5) c), '[]'::jsonb),
    'low_confidence_intents', coalesce((
      select jsonb_agg(to_jsonb(l) order by l.n desc)
        from (select * from lowconf order by n desc limit 5) l), '[]'::jsonb));
$$;

-- ---------------------------------------------------------------------------
-- report_archive: idempotent snapshot insert
-- ---------------------------------------------------------------------------
create or replace function intake.report_archive(p jsonb)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  r intake.executive_reports;
begin
  select * into r from intake.executive_reports where origin_execution_id = p->>'origin_execution_id';
  if found then
    return jsonb_build_object('ok', true, 'result', 'already_exists', 'id', r.id);
  end if;
  begin
    insert into intake.executive_reports (period_start, period_end, origin_execution_id, run_kind,
      include_demo, kpis, friction, recommendations, ai_model, html, delivered_to)
    values ((p->>'period_start')::date, (p->>'period_end')::date, p->>'origin_execution_id',
      p->>'run_kind', coalesce((p->>'include_demo')::boolean, false), p->'kpis', p->'friction',
      p->'recommendations', p->>'ai_model', p->>'html', coalesce(p->'delivered_to', '[]'::jsonb))
    returning * into r;
  exception when unique_violation then
    return jsonb_build_object('ok', false, 'result', 'duplicate_scheduled_report');
  end;
  return jsonb_build_object('ok', true, 'result', 'archived', 'id', r.id);
end;
$$;

-- report_already_sent: lets the scheduled run skip a month it already delivered
create or replace function intake.report_already_sent(p_month date)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (select 1 from intake.executive_reports
                  where run_kind = 'scheduled' and period_start = date_trunc('month', p_month)::date);
$$;

revoke all on all functions in schema intake from public, anon, authenticated;
grant execute on function
  intake.intake_create(jsonb),
  intake.review_decide(text, text, text, text, text),
  intake.review_preview(text, text),
  intake.append_event(text, jsonb),
  intake.sla_escalate_breached(),
  intake.get_record(text),
  intake.report_kpis(date, integer, numeric, boolean),
  intake.report_friction(date, boolean),
  intake.report_archive(jsonb),
  intake.report_already_sent(date)
to n8n_intake;

-- >>> migrations/003_integrations.sql
-- Integrations: channel-agnostic notification routing.
-- Workflows never hard-code a channel. They send a neutral message with an event_type to the
-- 05 Notification Dispatcher. The dispatcher looks up routes here and fans out to Gmail, Outlook,
-- SMTP, Slack, Teams or a signed webhook into Jira, ServiceNow, Zendesk, Zapier, Make and others.
-- A client is re-pointed by editing rows. Nobody edits a workflow.
--
-- target formats:
--   gmail / outlook / smtp : an email address, or '$requester' (the request's own requester_email)
--   slack                  : channel name or id, e.g. '#ops-incidents'
--   teams                  : '<teamId>/<channelId>'
--   webhook                : https URL (POST, JSON body, X-Intake-Signature: sha256=<hmac>)

create table intake.notification_routes (
  id          uuid primary key default gen_random_uuid(),
  event_type  text not null check (event_type in (
                'INCIDENT_ALERT', 'QUEUE_NOTICE', 'REVIEW_REQUEST', 'REVIEW_DECIDED',
                'DOWNSTREAM_DISPATCH', 'SLA_ESCALATION', 'COO_REPORT', 'ERROR_ALERT')),
  channel     text not null check (channel in ('gmail', 'outlook', 'smtp', 'slack', 'teams', 'webhook')),
  target      text not null check (char_length(target) between 1 and 500),
  enabled     boolean not null default true,
  is_demo     boolean not null default false,
  notes       text,
  created_at  timestamptz not null default now(),
  unique (event_type, channel, target),
  check (channel <> 'webhook' or target like 'https://%')
);
alter table intake.notification_routes enable row level security;
-- Routes are admin-managed in SQL. n8n gets read access only, through get_routes().

create or replace function intake.get_routes(p_event_type text)
returns jsonb
language sql
stable
security definer
set search_path = ''
as $$
  select coalesce(jsonb_agg(jsonb_build_object(
           'route_id', id, 'event_type', event_type, 'channel', channel, 'target', target)
           order by channel, target), '[]'::jsonb)
    from intake.notification_routes
   where event_type = p_event_type and enabled;
$$;

revoke all on function intake.get_routes(text) from public, anon, authenticated;
grant execute on function intake.get_routes(text) to n8n_intake;
