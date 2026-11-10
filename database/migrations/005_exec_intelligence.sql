-- Executive Intelligence, ROI & Visual Dashboard engine
-- * Spec field names: inbound_channel, route_destination, human_reviewed_at, human_final_decision
-- * Six operational dimensions: channel, time, branch, route (TTR), risk category, human judgment
--   (override drift), plus sentiment/frustration and AI cost for real ROI
-- * Resolution lifecycle (resolved_at = work completed), monotonic sla_breached, sla_sweep()
-- * Settings and requester directory tables (clients edit rows, not workflows)
-- * PII-free BI views and a read-only bi_reader role
-- * report_snapshot(): one chart-ready JSON snapshot for the email, the live dashboard and the archive
--
-- Transparency: append-only rules bind the application roles (n8n_intake, bi_reader). This owner-run
-- migration disables the row guard briefly, only to rename the channel value 'form' to 'web_form'.

-- ---------------------------------------------------------------------------
-- 1. Renames and value backfill (guard briefly disabled; owner migration only)
-- ---------------------------------------------------------------------------
alter table intake.intake_audit_logs disable trigger intake_audit_logs_guard;

alter table intake.intake_audit_logs rename column channel         to inbound_channel;
alter table intake.intake_audit_logs rename column route           to route_destination;
alter table intake.intake_audit_logs rename column reviewed_at     to human_reviewed_at;
alter table intake.intake_audit_logs rename column review_decision to human_final_decision;

alter table intake.intake_audit_logs drop constraint intake_records_channel_check;
update intake.intake_audit_logs set inbound_channel = 'web_form' where inbound_channel = 'form';
alter table intake.intake_audit_logs add constraint intake_audit_logs_inbound_channel_check
  check (inbound_channel in ('web_form', 'api', 'email', 'whatsapp', 'test'));

alter table intake.intake_audit_logs drop constraint intake_records_review_decision_check;
alter table intake.intake_audit_logs add constraint intake_audit_logs_human_final_decision_check
  check (human_final_decision in ('APPROVED', 'REJECTED', 'OVERRIDDEN'));

alter table intake.intake_audit_logs drop constraint intake_records_status_check;
alter table intake.intake_audit_logs add constraint intake_audit_logs_status_check
  check (status in ('OPEN_INCIDENT', 'QUEUED', 'PENDING_REVIEW', 'APPROVED', 'OVERRIDDEN', 'REJECTED', 'RESOLVED'));

alter table intake.intake_audit_logs rename constraint intake_records_route_check to intake_audit_logs_route_destination_check;

-- ---------------------------------------------------------------------------
-- 2. New dimensions and lifecycle columns
-- ---------------------------------------------------------------------------
alter table intake.intake_audit_logs
  add column submitting_branch          text check (submitting_branch is null or char_length(submitting_branch) between 1 and 80),
  add column requester_phone            text check (requester_phone is null or char_length(requester_phone) <= 32),
  add column ai_predicted_route         text check (ai_predicted_route in ('INCIDENT_DESK', 'OPERATIONS_QUEUE', 'HUMAN_REVIEW')),
  add column post_review_route          text check (post_review_route in ('INCIDENT_DESK', 'OPERATIONS_QUEUE')),
  add column human_final_route          text check (human_final_route in ('INCIDENT_DESK', 'OPERATIONS_QUEUE')),
  add column contains_sensitive_data    boolean generated always as (jsonb_array_length(sensitive_flags) > 0) stored,
  add column sensitive_data_category    text not null default 'NONE'
                                          check (sensitive_data_category in ('PII', 'FINANCIAL', 'LEGAL', 'MEDICAL', 'NONE')),
  add column sentiment_frustration_score numeric(4,3) check (sentiment_frustration_score between 0 and 1),
  add column sla_breached               boolean not null default false,
  add column resolve_token_hash         text,
  add column resolution_source          text check (resolution_source in ('team_link', 'ticketing_callback', 'review_reject')),
  add column resolution_notes           text check (resolution_notes is null or char_length(resolution_notes) <= 1000),
  add column ai_input_tokens            integer check (ai_input_tokens >= 0),
  add column ai_output_tokens           integer check (ai_output_tokens >= 0),
  add column ai_cost_usd                numeric(10,6) check (ai_cost_usd >= 0),
  add column ai_cost_estimated          boolean not null default false;

alter table intake.intake_audit_logs enable trigger intake_audit_logs_guard;

create index intake_audit_logs_open_sla_idx on intake.intake_audit_logs (sla_deadline)
  where resolved_at is null and not sla_breached;

-- ---------------------------------------------------------------------------
-- 3. Settings and requester directory
-- ---------------------------------------------------------------------------
create table intake.settings (
  key        text primary key,
  value      text not null,
  notes      text,
  updated_at timestamptz not null default now()
);
alter table intake.settings enable row level security;
insert into intake.settings (key, value, notes) values
  ('report_timezone',                 'Africa/Nairobi', 'IANA zone for day-of-week, hour and month boundaries'),
  ('minutes_saved_per_auto_routed',   '12',   'Manual triage minutes avoided per auto-routed request'),
  ('hourly_rate_usd',                 '25',   'Fully loaded admin labour cost per hour'),
  ('ambiguity_threshold',             '0.85', 'Confidence below this counts as ambiguous (keep in sync with the Rules node CONFIG)'),
  ('price_in_per_mtok:claude-sonnet-5-5',  '2',  'USD per million input tokens'),
  ('price_out_per_mtok:claude-sonnet-5-5', '10', 'USD per million output tokens'),
  ('price_in_per_mtok:claude-opus-5-5',    '4',  'USD per million input tokens'),
  ('price_out_per_mtok:claude-opus-5-5',   '20', 'USD per million output tokens')
on conflict (key) do nothing;

create or replace function intake.get_settings()
returns jsonb
language sql
stable
security definer
set search_path = ''
as $$
  select coalesce(jsonb_object_agg(key, value), '{}'::jsonb) from intake.settings;
$$;

create table intake.requester_directory (
  contact     text primary key check (contact = lower(contact)),   -- email (lower-case) or E.164 phone
  branch      text not null,
  department  text check (department is null or department in
                ('Finance', 'IT', 'Operations', 'HR', 'Campus/Facilities', 'Customer Service', 'Other')),
  created_at  timestamptz not null default now()
);
alter table intake.requester_directory enable row level security;

create or replace function intake.lookup_requester(p_contact text)
returns jsonb
language sql
stable
security definer
set search_path = ''
as $$
  select coalesce(
    (select jsonb_build_object('found', true, 'branch', branch, 'department', department)
       from intake.requester_directory where contact = lower(trim(p_contact))),
    jsonb_build_object('found', false, 'branch', 'Unspecified', 'department', null));
$$;

-- ---------------------------------------------------------------------------
-- 4. Guard v5
-- ---------------------------------------------------------------------------
create or replace function intake.guard_records()
returns trigger
language plpgsql
set search_path = ''
as $$
declare
  mutable constant text[] := array['status', 'reviewer_id', 'human_final_decision', 'human_final_route',
                                   'review_notes', 'human_reviewed_at', 'resolved_at', 'resolution_source',
                                   'resolution_notes', 'token_used_at', 'escalated_at', 'sla_breached',
                                   'decision_history',
                                   'contains_sensitive_data'];  -- generated, derived from immutable flags
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
     and not (old.status = 'PENDING_REVIEW' and new.status in ('APPROVED', 'OVERRIDDEN', 'REJECTED'))
     and not (old.status in ('OPEN_INCIDENT', 'QUEUED', 'APPROVED', 'OVERRIDDEN') and new.status = 'RESOLVED') then
    raise exception 'intake_audit_logs: illegal status transition % -> %', old.status, new.status;
  end if;
  if old.human_final_decision is not null and new.human_final_decision is distinct from old.human_final_decision then
    raise exception 'intake_audit_logs: human decision is final';
  end if;
  if old.human_final_route is not null and new.human_final_route is distinct from old.human_final_route then
    raise exception 'intake_audit_logs: final route is final';
  end if;
  if old.resolved_at is not null and new.resolved_at is distinct from old.resolved_at then
    raise exception 'intake_audit_logs: resolution is final';
  end if;
  if old.sla_breached and not new.sla_breached then
    raise exception 'intake_audit_logs: an SLA breach cannot be cleared';
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

create or replace function intake.record_json(r intake.intake_audit_logs)
returns jsonb
language sql
immutable
set search_path = ''
as $$
  select to_jsonb(r) - 'review_token_hash' - 'view_token_hash' - 'resolve_token_hash';
$$;

-- ---------------------------------------------------------------------------
-- 5. intake_create v5
-- ---------------------------------------------------------------------------
create or replace function intake.intake_create(p jsonb)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_route   text := coalesce(p->>'route_destination', p->>'route');
  v_sla     integer := (p->>'sla_minutes')::integer;
  v_token   text;
  v_hash    text;
  v_view    text := encode(extensions.gen_random_bytes(32), 'hex');
  v_resolve text := encode(extensions.gen_random_bytes(32), 'hex');
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
    origin_execution_id, inbound_channel, requester_email, requester_phone, submitting_branch,
    department, request_text, concise_brief, intent, urgency, urgency_score, confidence_score,
    sentiment_frustration_score, ai_model, models_used, ai_input_tokens, ai_output_tokens,
    ai_cost_usd, ai_cost_estimated, review_brief, review_model, attachment_meta, sensitive_flags,
    sensitive_data_category, injection_flags, ai_predicted_route, route_destination,
    post_review_route, rule_applied, sla_minutes, sla_deadline, status, review_token_hash,
    token_expires_at, view_token_hash, resolve_token_hash, is_test, is_demo, decision_history)
  values (
    p->>'origin_execution_id',
    coalesce(p->>'inbound_channel', p->>'channel'),
    nullif(lower(p->>'requester_email'), ''),
    nullif(p->>'requester_phone', ''),
    coalesce(nullif(p->>'submitting_branch', ''), 'Unspecified'),
    nullif(p->>'department', ''),
    p->>'request_text',
    left(p->>'concise_brief', 500),
    p->>'intent',
    p->>'urgency',
    (p->>'urgency_score')::numeric,
    (p->>'confidence_score')::numeric,
    (p->>'sentiment_frustration_score')::numeric,
    p->>'ai_model',
    coalesce(p->'models_used', '[]'::jsonb),
    (p->>'ai_input_tokens')::integer,
    (p->>'ai_output_tokens')::integer,
    (p->>'ai_cost_usd')::numeric,
    coalesce((p->>'ai_cost_estimated')::boolean, false),
    left(p->>'review_brief', 6000),
    p->>'review_model',
    case when jsonb_typeof(p->'attachment_meta') = 'object' then p->'attachment_meta' end,
    coalesce(p->'sensitive_flags', '[]'::jsonb),
    coalesce(nullif(p->>'sensitive_data_category', ''), 'NONE'),
    coalesce(p->'injection_flags', '[]'::jsonb),
    nullif(p->>'ai_predicted_route', ''),
    v_route,
    case when v_route = 'HUMAN_REVIEW'
         then coalesce(nullif(p->>'post_review_route', ''),
                       case when p->>'urgency' = 'CRITICAL' then 'INCIDENT_DESK' else 'OPERATIONS_QUEUE' end) end,
    p->>'rule_applied',
    v_sla,
    now() + make_interval(mins => v_sla),
    v_status,
    v_hash,
    case when v_hash is not null then now() + interval '72 hours' end,
    encode(extensions.digest(v_view, 'sha256'), 'hex'),
    encode(extensions.digest(v_resolve, 'sha256'), 'hex'),
    coalesce((p->>'is_test')::boolean, false),
    coalesce((p->>'is_demo')::boolean, false),
    v_history || jsonb_build_array(jsonb_build_object(
      'step', 'RECORDED', 'status', v_status, 'sla_minutes', v_sla, 'at', now())))
  returning * into r;

  return jsonb_build_object('ok', true, 'result', 'created', 'record', intake.record_json(r),
                            'review_token', v_token, 'view_token', v_view, 'resolve_token', v_resolve);
end;
$$;

-- ---------------------------------------------------------------------------
-- 6. review_decide v5: APPROVED / REJECTED / OVERRIDDEN (approve, but to a different destination)
-- ---------------------------------------------------------------------------
drop function intake.review_decide(text, text, text, text, text);

create or replace function intake.review_decide(
  p_exec text, p_token text, p_decision text, p_reviewer text,
  p_notes text default null, p_final_route text default null)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_hash  text := encode(extensions.digest(coalesce(p_token, ''), 'sha256'), 'hex');
  v_final text;
  r       intake.intake_audit_logs;
begin
  if p_decision not in ('APPROVED', 'REJECTED', 'OVERRIDDEN') then
    return jsonb_build_object('ok', false, 'result', 'invalid_decision');
  end if;

  select * into r from intake.intake_audit_logs
   where origin_execution_id = p_exec and review_token_hash = v_hash;
  if not found then
    return jsonb_build_object('ok', false, 'result', 'invalid_link');
  end if;

  v_final := case p_decision
               when 'APPROVED'   then r.post_review_route
               when 'OVERRIDDEN' then p_final_route
             end;
  if p_decision = 'OVERRIDDEN' and (
       p_final_route not in ('INCIDENT_DESK', 'OPERATIONS_QUEUE')
       or p_final_route is not distinct from r.post_review_route
       or coalesce(trim(p_notes), '') = '') then
    return jsonb_build_object('ok', false, 'result', 'invalid_override',
      'detail', 'An override needs a different destination than ' || coalesce(r.post_review_route, '?') || ' and a reason.');
  end if;

  update intake.intake_audit_logs
     set status               = p_decision,
         human_final_decision = p_decision,
         human_final_route    = v_final,
         reviewer_id          = left(p_reviewer, 254),
         review_notes         = left(p_notes, 1000),
         human_reviewed_at    = now(),
         token_used_at        = now(),
         sla_breached         = sla_breached or now() > sla_deadline,
         resolved_at          = case when p_decision = 'REJECTED' then now() end,
         resolution_source    = case when p_decision = 'REJECTED' then 'review_reject' end,
         decision_history     = decision_history || jsonb_build_array(jsonb_build_object(
                                  'step', p_decision, 'by', left(p_reviewer, 254),
                                  'notes', left(p_notes, 1000), 'final_route', v_final,
                                  'ai_predicted_route', ai_predicted_route,
                                  'within_sla', now() <= sla_deadline, 'at', now()))
   where id = r.id
     and status = 'PENDING_REVIEW'
     and token_used_at is null
     and token_expires_at > now()
  returning * into r;

  if found then
    return jsonb_build_object('ok', true, 'result', 'decided', 'record', intake.record_json(r));
  end if;

  select * into r from intake.intake_audit_logs where origin_execution_id = p_exec;
  if r.token_used_at is not null then
    update intake.intake_audit_logs
       set decision_history = decision_history || jsonb_build_array(jsonb_build_object(
             'step', 'DUPLICATE_DECISION_IGNORED', 'attempted', p_decision,
             'by', left(p_reviewer, 254), 'at', now()))
     where id = r.id
    returning * into r;
    return jsonb_build_object('ok', false, 'result', 'already_decided',
                              'decision', r.human_final_decision, 'record', intake.record_json(r));
  end if;

  update intake.intake_audit_logs
     set decision_history = decision_history || jsonb_build_array(jsonb_build_object(
           'step', 'EXPIRED_LINK_ATTEMPT', 'attempted', p_decision,
           'by', left(p_reviewer, 254), 'at', now()))
   where id = r.id;
  return jsonb_build_object('ok', false, 'result', 'expired');
end;
$$;

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
    'reference', r.reference, 'inbound_channel', r.inbound_channel,
    'submitting_branch', r.submitting_branch, 'department', r.department,
    'concise_brief', r.concise_brief, 'review_brief', r.review_brief, 'intent', r.intent,
    'urgency', r.urgency, 'confidence_score', r.confidence_score,
    'sentiment_frustration_score', r.sentiment_frustration_score,
    'rule_applied', r.rule_applied, 'sensitive_data_category', r.sensitive_data_category,
    'sensitive_flags', r.sensitive_flags, 'injection_flags', r.injection_flags,
    'ai_predicted_route', r.ai_predicted_route, 'post_review_route', r.post_review_route,
    'sla_deadline', r.sla_deadline, 'human_final_decision', r.human_final_decision);
end;
$$;

-- ---------------------------------------------------------------------------
-- 7. Resolution: team "Mark resolved" link, or a verified ticketing callback
-- ---------------------------------------------------------------------------
create or replace function intake.resolve_preview(p_exec text, p_token text)
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
     and resolve_token_hash = encode(extensions.digest(coalesce(p_token, ''), 'sha256'), 'hex');
  if not found then
    return jsonb_build_object('ok', false, 'result', 'invalid_link');
  end if;
  return jsonb_build_object('ok', true,
    'result', case when r.resolved_at is not null then 'already_resolved'
                   when r.status in ('OPEN_INCIDENT', 'QUEUED', 'APPROVED', 'OVERRIDDEN') then 'open'
                   else 'not_resolvable' end,
    'reference', r.reference, 'concise_brief', r.concise_brief, 'status', r.status,
    'destination', coalesce(r.human_final_route, r.route_destination), 'sla_deadline', r.sla_deadline);
end;
$$;

create or replace function intake.resolve_record(
  p_exec text, p_source text, p_actor text, p_notes text, p_ticket_id text default null)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  r intake.intake_audit_logs;
begin
  update intake.intake_audit_logs
     set status            = 'RESOLVED',
         resolved_at       = now(),
         resolution_source = p_source,
         resolution_notes  = left(p_notes, 1000),
         -- Review items: the SLA covered the review step, so late work after approval is not a breach
         sla_breached      = sla_breached or (route_destination <> 'HUMAN_REVIEW' and now() > sla_deadline),
         decision_history  = decision_history || jsonb_build_array(jsonb_build_object(
                               'step', 'RESOLVED', 'source', p_source, 'by', left(p_actor, 254),
                               'ticket_id', p_ticket_id, 'notes', left(p_notes, 1000),
                               'within_sla', now() <= sla_deadline, 'at', now()))
   where origin_execution_id = p_exec
     and resolved_at is null
     and status in ('OPEN_INCIDENT', 'QUEUED', 'APPROVED', 'OVERRIDDEN')
  returning * into r;
  if found then
    return jsonb_build_object('ok', true, 'result', 'resolved', 'record', intake.record_json(r));
  end if;

  select * into r from intake.intake_audit_logs where origin_execution_id = p_exec;
  if not found then
    return jsonb_build_object('ok', false, 'result', 'not_found');
  end if;
  if r.resolved_at is not null then
    update intake.intake_audit_logs
       set decision_history = decision_history || jsonb_build_array(jsonb_build_object(
             'step', 'DUPLICATE_RESOLVE_IGNORED', 'source', p_source, 'by', left(p_actor, 254), 'at', now()))
     where id = r.id;
    return jsonb_build_object('ok', false, 'result', 'already_resolved');
  end if;
  return jsonb_build_object('ok', false, 'result', 'not_resolvable', 'status', r.status);
end;
$$;
revoke all on function intake.resolve_record(text, text, text, text, text) from public;

create or replace function intake.resolve_with_token(p_exec text, p_token text, p_actor text, p_notes text default null)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
begin
  if not exists (select 1 from intake.intake_audit_logs
                  where origin_execution_id = p_exec
                    and resolve_token_hash = encode(extensions.digest(coalesce(p_token, ''), 'sha256'), 'hex')) then
    return jsonb_build_object('ok', false, 'result', 'invalid_link');
  end if;
  return intake.resolve_record(p_exec, 'team_link', p_actor, p_notes);
end;
$$;

-- Called by n8n ONLY after verifying the ticketing tool's HMAC signature. Defence in depth: the
-- ticket id must match a TICKET_CREATED event already recorded for this request.
create or replace function intake.resolve_by_system(p_exec text, p_system text, p_ticket_id text, p_notes text default null)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
begin
  if (intake.get_ticket_ref(p_exec, p_system)->>'id') is distinct from p_ticket_id then
    return jsonb_build_object('ok', false, 'result', 'unknown_ticket');
  end if;
  return intake.resolve_record(p_exec, 'ticketing_callback', p_system, p_notes, p_ticket_id);
end;
$$;

-- ---------------------------------------------------------------------------
-- 8. sla_sweep: mark every unresolved overdue item, escalate review + incident breaches once
-- ---------------------------------------------------------------------------
drop function intake.sla_escalate_breached();

create or replace function intake.sla_sweep()
returns setof jsonb
language plpgsql
security definer
set search_path = ''
as $$
begin
  update intake.intake_audit_logs
     set sla_breached     = true,
         decision_history = decision_history || jsonb_build_array(jsonb_build_object(
                              'step', 'SLA_BREACHED', 'sla_deadline', sla_deadline,
                              'minutes_overdue', floor(extract(epoch from now() - sla_deadline) / 60),
                              'at', now()))
   where not sla_breached
     and sla_deadline < now()
     and (   (route_destination = 'HUMAN_REVIEW' and status = 'PENDING_REVIEW')
          or (route_destination <> 'HUMAN_REVIEW' and resolved_at is null
              and status in ('OPEN_INCIDENT', 'QUEUED')));

  return query
  update intake.intake_audit_logs
     set escalated_at     = now(),
         decision_history = decision_history || jsonb_build_array(jsonb_build_object(
                              'step', 'SLA_BREACHED_ESCALATED', 'sla_deadline', sla_deadline,
                              'minutes_overdue', floor(extract(epoch from now() - sla_deadline) / 60),
                              'at', now()))
   where escalated_at is null
     and sla_deadline < now()
     and (   (route_destination = 'HUMAN_REVIEW'  and status = 'PENDING_REVIEW')
          or (route_destination = 'INCIDENT_DESK' and status = 'OPEN_INCIDENT'))
  returning intake.record_json(intake_audit_logs.*);
end;
$$;

-- ---------------------------------------------------------------------------
-- 9. record_view v5 (PII-free) and append_event v5
-- ---------------------------------------------------------------------------
create or replace function intake.record_view(p_exec text, p_token text)
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
     and view_token_hash is not null
     and view_token_hash = encode(extensions.digest(coalesce(p_token, ''), 'sha256'), 'hex');
  if not found then
    return jsonb_build_object('ok', false, 'result', 'invalid_link');
  end if;
  return jsonb_build_object(
    'ok', true, 'result', 'ok',
    'reference', r.reference, 'created_at', r.created_at, 'inbound_channel', r.inbound_channel,
    'submitting_branch', r.submitting_branch, 'department', r.department,
    'concise_brief', r.concise_brief, 'intent', r.intent, 'urgency', r.urgency,
    'confidence_score', r.confidence_score, 'sentiment_frustration_score', r.sentiment_frustration_score,
    'models_used', r.models_used, 'contains_sensitive_data', r.contains_sensitive_data,
    'sensitive_data_category', r.sensitive_data_category,
    'injection_flag_count', jsonb_array_length(r.injection_flags),
    'ai_predicted_route', r.ai_predicted_route, 'route_destination', r.route_destination,
    'rule_applied', r.rule_applied, 'post_review_route', r.post_review_route,
    'sla_minutes', r.sla_minutes, 'sla_deadline', r.sla_deadline, 'sla_breached', r.sla_breached,
    'status', r.status, 'human_final_decision', r.human_final_decision,
    'human_final_route', r.human_final_route, 'reviewer_id', r.reviewer_id,
    'human_reviewed_at', r.human_reviewed_at, 'resolved_at', r.resolved_at,
    'resolution_source', r.resolution_source, 'escalated_at', r.escalated_at,
    'attachment', case when r.attachment_meta is not null then jsonb_build_object(
                    'provider', r.attachment_meta->>'provider', 'url', r.attachment_meta->>'url',
                    'stored_name', r.attachment_meta->>'stored_name', 'sha256', r.attachment_meta->>'sha256',
                    'storage_status', r.attachment_meta->>'storage_status') end,
    'is_test', r.is_test,
    'decision_history', r.decision_history);
end;
$$;

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
                              'ESCALATION_NOTIFIED', 'TICKET_CREATED', 'TICKET_UPDATED',
                              'TICKET_SYNC_FAILED', 'TICKET_SYNC_SKIPPED',
                              'TICKET_SYNC_SUPPRESSED_TEST', 'REQUESTER_ACKNOWLEDGED') then
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
-- 10. BI views (PII-free; test rows excluded; data_scope = live | demo)
-- ---------------------------------------------------------------------------
create view intake.vw_intake_facts as
with s as (
  select coalesce(max(value) filter (where key = 'report_timezone'), 'UTC')                   as tz,
         coalesce(max(value) filter (where key = 'ambiguity_threshold'), '0.85')::numeric     as amb
    from intake.settings
),
f as (
  select l.*, (l.created_at at time zone s.tz) as local_ts, s.amb,
         -- SLA outcome known: review decided (review items) or work resolved (others)
         case when l.route_destination = 'HUMAN_REVIEW' then l.human_reviewed_at else l.resolved_at end as sla_closed_at
    from intake.intake_audit_logs l cross join s
   where not l.is_test
)
select
  reference,
  date_trunc('month', local_ts)::date                                   as period_month,
  case when is_demo then 'demo' else 'live' end                         as data_scope,
  local_ts                                                              as created_at_local,
  extract(isodow from local_ts)::int                                    as day_of_week,
  trim(to_char(local_ts, 'Dy'))                                         as day_name,
  extract(hour from local_ts)::int                                      as hour_of_day,
  inbound_channel,
  coalesce(submitting_branch, 'Unspecified')                            as submitting_branch,
  coalesce(department, 'Unspecified')                                   as department,
  intent,
  urgency,
  confidence_score,
  (confidence_score < amb)                                              as is_ambiguous,
  contains_sensitive_data,
  sensitive_data_category,
  (jsonb_array_length(injection_flags) > 0)                             as injection_flagged,
  sentiment_frustration_score,
  ai_predicted_route,
  route_destination,
  (route_destination <> 'HUMAN_REVIEW')                                 as auto_routed,
  rule_applied,
  post_review_route,
  status,
  human_final_decision,
  human_final_route,
  (human_final_decision = 'OVERRIDDEN')                                 as is_override,
  round((extract(epoch from human_reviewed_at - created_at) / 60)::numeric, 1) as approval_latency_min,
  sla_minutes,
  sla_deadline,
  (sla_closed_at is not null or sla_deadline < now())                  as sla_outcome_known,
  (sla_breached or (sla_closed_at is null and status not in ('REJECTED', 'RESOLVED') and sla_deadline < now()))
                                                                        as sla_breached_effective,
  round(greatest(0, extract(epoch from coalesce(sla_closed_at, now()) - sla_deadline) / 60)::numeric, 1)
                                                                        as sla_overrun_min,
  resolved_at,
  round((extract(epoch from resolved_at - created_at) / 60)::numeric, 1) as ttr_minutes,
  ai_cost_usd,
  ai_cost_estimated
from f;

-- A: channel friction and peak-load heatmap
create view intake.vw_dash_channel_heatmap as
select period_month, data_scope, inbound_channel, day_of_week, day_name, hour_of_day,
       count(*)                                                        as volume,
       round(avg(is_ambiguous::int) * 100, 1)                          as ambiguity_rate_pct,
       round(avg(sla_breached_effective::int) * 100, 1)                as sla_breach_rate_pct,
       round(avg(sentiment_frustration_score), 3)                      as frustration_index
  from intake.vw_intake_facts
 group by period_month, data_scope, inbound_channel, day_of_week, day_name, hour_of_day;

-- B: departmental TTR and branch bottlenecks
create view intake.vw_dash_branch_ttr as
select period_month, data_scope, submitting_branch, route_destination,
       count(*)                                                        as requests,
       count(resolved_at)                                              as resolved,
       round(avg(ttr_minutes), 1)                                      as mean_ttr_min,
       round(percentile_cont(0.95) within group (order by ttr_minutes)::numeric, 1) as p95_ttr_min,
       count(*) filter (where sla_breached_effective)                  as sla_breaches,
       round(avg(sla_breached_effective::int) * 100, 1)                as sla_breach_rate_pct,
       round(sum(sla_overrun_min) / 60, 1)                             as overrun_hours
  from intake.vw_intake_facts
 group by period_month, data_scope, submitting_branch, route_destination;

-- C: human review override and rubric drift
create view intake.vw_dash_override_drift as
select period_month, data_scope, rule_applied, ai_predicted_route, post_review_route,
       human_final_decision, human_final_route,
       count(*)                                                        as decisions,
       count(*) filter (where ai_predicted_route = human_final_route) as ai_agreed,
       round(avg(confidence_score), 3)                                 as avg_confidence,
       round(avg(approval_latency_min), 1)                             as mean_approval_latency_min,
       round(percentile_cont(0.95) within group (order by approval_latency_min)::numeric, 1) as p95_approval_latency_min
  from intake.vw_intake_facts
 where route_destination = 'HUMAN_REVIEW' and human_final_decision is not null
 group by period_month, data_scope, rule_applied, ai_predicted_route, post_review_route,
          human_final_decision, human_final_route;

-- Governance risk shield
create view intake.vw_dash_risk_shield as
select period_month, data_scope, sensitive_data_category,
       count(*)                                                        as requests,
       count(*) filter (where injection_flagged)                       as injection_blocks,
       count(*) filter (where rule_applied = 'LOW_CONFIDENCE')         as low_confidence_holds,
       count(*) filter (where human_final_decision = 'APPROVED')       as approved,
       count(*) filter (where human_final_decision = 'OVERRIDDEN')     as overridden,
       count(*) filter (where human_final_decision = 'REJECTED')       as rejected,
       count(*) filter (where status = 'PENDING_REVIEW')               as pending
  from intake.vw_intake_facts
 group by period_month, data_scope, sensitive_data_category;

-- Executive scorecards (one row per month and scope)
create view intake.vw_executive_live_dashboard as
with s as (
  select coalesce(max(value) filter (where key = 'minutes_saved_per_auto_routed'), '12')::numeric as mins,
         coalesce(max(value) filter (where key = 'hourly_rate_usd'), '25')::numeric             as rate
    from intake.settings
),
m as (
  select period_month, data_scope,
         count(*)                                                              as total_requests,
         count(*) filter (where auto_routed)                                   as auto_routed,
         count(*) filter (where route_destination = 'INCIDENT_DESK')           as incident_desk,
         count(*) filter (where route_destination = 'OPERATIONS_QUEUE')        as operations_queue,
         count(*) filter (where route_destination = 'HUMAN_REVIEW')            as human_review,
         count(*) filter (where sla_outcome_known)                             as sla_measurable,
         count(*) filter (where sla_outcome_known and not sla_breached_effective) as sla_met,
         count(*) filter (where sla_breached_effective)                        as sla_breaches,
         round(avg(is_ambiguous::int) * 100, 1)                                as ambiguity_rate_pct,
         round(avg(sentiment_frustration_score), 3)                            as avg_frustration,
         count(*) filter (where contains_sensitive_data)                       as sensitive_catches,
         count(*) filter (where injection_flagged)                             as injection_blocks,
         count(*) filter (where rule_applied = 'LOW_CONFIDENCE')               as low_confidence_holds,
         count(*) filter (where human_final_decision is not null)              as decisions,
         count(*) filter (where is_override)                                   as overrides,
         round(avg(ttr_minutes), 1)                                            as mean_ttr_min,
         round(percentile_cont(0.95) within group (order by ttr_minutes)::numeric, 1) as p95_ttr_min,
         round(avg(approval_latency_min), 1)                                   as mean_approval_latency_min,
         round(coalesce(sum(ai_cost_usd), 0), 2)                               as ai_cost_usd,
         bool_or(ai_cost_estimated)                                            as ai_cost_includes_estimates
    from intake.vw_intake_facts
   group by period_month, data_scope
)
select m.period_month, m.data_scope, m.total_requests,
       lag(m.total_requests) over w                                            as prior_month_requests,
       round((m.total_requests - lag(m.total_requests) over w) * 100.0
             / nullif(lag(m.total_requests) over w, 0), 1)                     as mom_delta_pct,
       m.auto_routed, m.incident_desk, m.operations_queue, m.human_review,
       round(m.auto_routed * s.mins / 60, 1)                                   as admin_hours_saved,
       round(m.auto_routed * s.mins / 60 * s.rate, 2)                          as labor_value_usd,
       m.ai_cost_usd, m.ai_cost_includes_estimates,
       round(m.auto_routed * s.mins / 60 * s.rate / nullif(m.ai_cost_usd, 0), 1) as roi_multiple,
       round(m.sla_met * 100.0 / nullif(m.sla_measurable, 0), 1)               as sla_compliance_pct,
       m.sla_breaches, m.ambiguity_rate_pct, m.avg_frustration, m.sensitive_catches,
       m.injection_blocks, m.low_confidence_holds, m.decisions, m.overrides,
       round(m.overrides * 100.0 / nullif(m.decisions, 0), 1)                  as override_rate_pct,
       m.mean_ttr_min, m.p95_ttr_min, m.mean_approval_latency_min
  from m cross join s
window w as (partition by m.data_scope order by m.period_month);

-- ---------------------------------------------------------------------------
-- 11. report_snapshot: one chart-ready JSON for email, live dashboard and archive
-- ---------------------------------------------------------------------------
drop function intake.report_kpis(date, integer, numeric, boolean);
drop function intake.report_friction(date, boolean);

create or replace function intake.report_snapshot(p_month date, p_scope text default 'live')
returns jsonb
language sql
stable
security definer
set search_path = ''
as $$
  with p as (select date_trunc('month', p_month)::date as m, p_scope as sc),
  facts as (select f.* from intake.vw_intake_facts f, p where f.period_month = p.m and f.data_scope = p.sc),
  settings as (select intake.get_settings() as j)
  select jsonb_build_object(
    'period_start', (select m from p),
    'period_end',   (select (m + interval '1 month')::date from p),
    'scope',        p_scope,
    'scorecards', coalesce((select to_jsonb(d) - 'period_month' - 'data_scope'
                              from intake.vw_executive_live_dashboard d, p
                             where d.period_month = p.m and d.data_scope = p.sc),
                           jsonb_build_object('total_requests', 0)),
    'trend', coalesce((select jsonb_agg(jsonb_build_object(
                         'period_month', d.period_month, 'total_requests', d.total_requests,
                         'sla_compliance_pct', d.sla_compliance_pct, 'admin_hours_saved', d.admin_hours_saved,
                         'roi_multiple', d.roi_multiple) order by d.period_month)
                         from intake.vw_executive_live_dashboard d, p
                        where d.data_scope = p.sc and d.period_month <= p.m
                          and d.period_month > (p.m - interval '6 months')), '[]'::jsonb),
    'routing', coalesce((select jsonb_agg(jsonb_build_object('route', route_destination, 'requests', n,
                           'sla_breaches', b) order by n desc)
                           from (select route_destination, count(*) n,
                                        count(*) filter (where sla_breached_effective) b
                                   from facts group by 1) x), '[]'::jsonb),
    'by_channel', coalesce((select jsonb_agg(jsonb_build_object('channel', inbound_channel, 'volume', n,
                              'ambiguity_rate_pct', a, 'sla_breach_rate_pct', b, 'frustration_index', fr) order by n desc)
                              from (select inbound_channel, count(*) n,
                                           round(avg(is_ambiguous::int) * 100, 1) a,
                                           round(avg(sla_breached_effective::int) * 100, 1) b,
                                           round(avg(sentiment_frustration_score), 3) fr
                                      from facts group by 1) x), '[]'::jsonb),
    'heatmap', coalesce((select jsonb_agg(jsonb_build_object('channel', h.inbound_channel, 'dow', h.day_of_week,
                           'day', h.day_name, 'hour', h.hour_of_day, 'volume', h.volume,
                           'ambiguity_rate_pct', h.ambiguity_rate_pct, 'sla_breach_rate_pct', h.sla_breach_rate_pct,
                           'frustration_index', h.frustration_index) order by h.day_of_week, h.hour_of_day)
                           from intake.vw_dash_channel_heatmap h, p
                          where h.period_month = p.m and h.data_scope = p.sc), '[]'::jsonb),
    'heatmap_total', coalesce((select jsonb_agg(jsonb_build_object('dow', dow, 'hour', hr, 'volume', n)
                                 order by dow, hr)
                                 from (select day_of_week dow, hour_of_day hr, count(*) n
                                         from facts group by 1, 2) x), '[]'::jsonb),
    'branch_ttr', coalesce((select jsonb_agg(jsonb_build_object('branch', b.submitting_branch,
                              'route', b.route_destination, 'requests', b.requests, 'resolved', b.resolved,
                              'mean_ttr_min', b.mean_ttr_min, 'p95_ttr_min', b.p95_ttr_min,
                              'sla_breaches', b.sla_breaches, 'sla_breach_rate_pct', b.sla_breach_rate_pct,
                              'overrun_hours', b.overrun_hours) order by b.p95_ttr_min desc nulls last)
                              from intake.vw_dash_branch_ttr b, p
                             where b.period_month = p.m and b.data_scope = p.sc), '[]'::jsonb),
    'override_drift', jsonb_build_object(
       'by_rule', coalesce((select jsonb_agg(jsonb_build_object('rule', rule_applied, 'decisions', n,
                    'approved_unchanged', a, 'overridden', o, 'rejected', rj,
                    'approve_unchanged_rate_pct', round(a * 100.0 / nullif(n, 0), 1),
                    'override_rate_pct', round(o * 100.0 / nullif(n, 0), 1),
                    'avg_confidence', c, 'min_conf_approved_unchanged', mn) order by n desc)
                    from (select rule_applied, count(*) n,
                                 count(*) filter (where human_final_decision = 'APPROVED') a,
                                 count(*) filter (where human_final_decision = 'OVERRIDDEN') o,
                                 count(*) filter (where human_final_decision = 'REJECTED') rj,
                                 round(avg(confidence_score), 3) c,
                                 min(confidence_score) filter (where human_final_decision = 'APPROVED') mn
                            from facts where route_destination = 'HUMAN_REVIEW' and human_final_decision is not null
                           group by 1) x), '[]'::jsonb),
       'matrix', coalesce((select jsonb_agg(to_jsonb(o) - 'period_month' - 'data_scope' order by o.decisions desc)
                             from intake.vw_dash_override_drift o, p
                            where o.period_month = p.m and o.data_scope = p.sc), '[]'::jsonb),
       'ai_route_agreement_pct', (select round(avg((ai_predicted_route = human_final_route)::int) * 100, 1)
                                    from facts where human_final_route is not null),
       'approval_latency', (select jsonb_build_object(
                              'mean_min', round(avg(approval_latency_min), 1),
                              'p95_min', round(percentile_cont(0.95) within group (order by approval_latency_min)::numeric, 1))
                              from facts where approval_latency_min is not null)),
    'risk_shield', coalesce((select jsonb_agg(to_jsonb(r) - 'period_month' - 'data_scope' order by r.requests desc)
                               from intake.vw_dash_risk_shield r, p
                              where r.period_month = p.m and r.data_scope = p.sc), '[]'::jsonb),
    -- Deterministic pre-ranking of where hours are being lost, so the AI diagnoses, never invents
    'bleed_candidates', coalesce((select jsonb_agg(c order by (c->>'hours_lost')::numeric desc)
       from (select c from (
               select jsonb_build_object('dimension', 'branch_route', 'key', submitting_branch || ' / ' || route_destination,
                        'sla_breaches', count(*) filter (where sla_breached_effective),
                        'p95_ttr_min', round(percentile_cont(0.95) within group (order by ttr_minutes)::numeric, 1),
                        'hours_lost', round(sum(sla_overrun_min) / 60, 1)) c
                 from facts group by submitting_branch, route_destination
               union all
               select jsonb_build_object('dimension', 'channel_ambiguity', 'key', inbound_channel,
                        'ambiguous_requests', count(*) filter (where is_ambiguous),
                        'hours_lost', round(count(*) filter (where is_ambiguous)
                                            * ((select j->>'minutes_saved_per_auto_routed' from settings)::numeric) / 60, 1))
                 from facts group by inbound_channel
               union all
               select jsonb_build_object('dimension', 'review_hold', 'key', rule_applied,
                        'held', count(*),
                        'approved_unchanged', count(*) filter (where human_final_decision = 'APPROVED'),
                        'hours_lost', round(coalesce(sum(approval_latency_min) filter (where human_final_decision = 'APPROVED'), 0) / 60, 1))
                 from facts where route_destination = 'HUMAN_REVIEW' group by rule_applied
             ) u
             where (c->>'hours_lost')::numeric > 0
             order by (c->>'hours_lost')::numeric desc
             limit 6) t), '[]'::jsonb),
    'assumptions', (select jsonb_build_object(
       'report_timezone', j->>'report_timezone',
       'minutes_saved_per_auto_routed', (j->>'minutes_saved_per_auto_routed')::numeric,
       'hourly_rate_usd', (j->>'hourly_rate_usd')::numeric,
       'ambiguity_threshold', (j->>'ambiguity_threshold')::numeric,
       'definitions', jsonb_build_object(
         'admin_hours_saved', 'Auto-routed requests (Incident Desk + Operations Queue) x manual triage minutes avoided.',
         'roi_multiple', 'Labour value avoided / AI spend for the month.',
         'sla_compliance_pct', 'Items whose SLA outcome is known that met it. Review items: decided by the deadline. Others: resolved by the deadline.',
         'ttr', 'resolved_at - created_at (work completed, via team link or ticketing callback).',
         'override', 'Reviewer approved the work but sent it to a different destination than the rules proposed.',
         'hours_lost', 'Sum of SLA overrun, ambiguity rework, and review wait on items later approved unchanged.'))
       from settings)
  );
$$;

-- ---------------------------------------------------------------------------
-- 12. executive_reports v5
-- ---------------------------------------------------------------------------
alter table intake.executive_reports rename column kpis to snapshot;
alter table intake.executive_reports rename column recommendations to synthesis;
alter table intake.executive_reports drop column friction;
alter table intake.executive_reports drop column include_demo;
alter table intake.executive_reports
  add column data_scope        text not null default 'live' check (data_scope in ('live', 'demo')),
  add column roi_headline      text,
  add column bleed_diagnostics jsonb,
  add column rule_calibration  jsonb,
  add column synthesis_status  text check (synthesis_status in ('ok', 'failed_sanity_check', 'unavailable'));

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
      data_scope, snapshot, synthesis, synthesis_status, roi_headline, bleed_diagnostics,
      rule_calibration, ai_model, html, delivered_to)
    values ((p->>'period_start')::date, (p->>'period_end')::date, p->>'origin_execution_id',
      p->>'run_kind', coalesce(p->>'data_scope', 'live'), p->'snapshot', p->'synthesis',
      p->>'synthesis_status', p->>'roi_headline', p->'bleed_diagnostics', p->'rule_calibration',
      p->>'ai_model', p->>'html', coalesce(p->'delivered_to', '[]'::jsonb))
    returning * into r;
  exception when unique_violation then
    return jsonb_build_object('ok', false, 'result', 'duplicate_scheduled_report');
  end;
  return jsonb_build_object('ok', true, 'result', 'archived', 'id', r.id);
end;
$$;

-- ---------------------------------------------------------------------------
-- 13. Privileges
-- ---------------------------------------------------------------------------
revoke all on all functions in schema intake from public, anon, authenticated;
grant execute on function
  intake.intake_create(jsonb),
  intake.review_decide(text, text, text, text, text, text),
  intake.review_preview(text, text),
  intake.resolve_preview(text, text),
  intake.resolve_with_token(text, text, text, text),
  intake.resolve_by_system(text, text, text, text),
  intake.sla_sweep(),
  intake.record_view(text, text),
  intake.append_event(text, jsonb),
  intake.lookup_requester(text),
  intake.get_settings(),
  intake.report_snapshot(date, text),
  intake.report_archive(jsonb)
to n8n_intake;
-- resolve_record is internal (called by the two resolve_* functions), so n8n_intake gets no direct grant.

-- Read-only BI role: the six PII-free views only, no tables or functions. Set a password before use:
--   alter role bi_reader with password '<strong password>';
do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'bi_reader') then
    create role bi_reader login noinherit;
  end if;
end;
$$;
grant usage on schema intake to bi_reader;
grant select on
  intake.vw_intake_facts,
  intake.vw_dash_channel_heatmap,
  intake.vw_dash_branch_ttr,
  intake.vw_dash_override_drift,
  intake.vw_dash_risk_shield,
  intake.vw_executive_live_dashboard
to bi_reader;
