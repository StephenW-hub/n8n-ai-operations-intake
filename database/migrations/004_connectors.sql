-- Connectors: rich chat cards (adds Google Chat), CRM/ticketing sync, document storage, and a
-- token-gated read-only audit view behind every "View Audit Record" button.
-- Like 003, every connector is config rows. Clients are onboarded by inserting rows, not by
-- editing workflows.

-- ---------------------------------------------------------------------------
-- Notifications: add Google Chat. Teams and Google Chat targets are https webhook URLs.
-- ---------------------------------------------------------------------------
alter table intake.notification_routes drop constraint notification_routes_channel_check;
alter table intake.notification_routes drop constraint notification_routes_check;
alter table intake.notification_routes
  add constraint notification_routes_channel_check
    check (channel in ('gmail', 'outlook', 'smtp', 'slack', 'teams', 'google_chat', 'webhook')),
  add constraint notification_routes_url_target_check
    check (channel not in ('webhook', 'teams', 'google_chat') or target like 'https://%');

-- ---------------------------------------------------------------------------
-- CRM / ticketing routes
--   config examples:
--     jira       {"project_key":"OPS","issue_type":"Task","deadline_field":"duedate"}
--     zendesk    {"group_id":null,"tags":["ops-intake"]}
--     hubspot    {"pipeline":"0","stage":"1","deadline_property":null}
--     salesforce {"record_type_id":null,"origin":"Ops Intake","deadline_field":null}
--     webhook    {"url":"https://..."}   (ServiceNow, Freshdesk, Monday, ClickUp, Zapier, Make)
-- ---------------------------------------------------------------------------
create table intake.ticket_routes (
  id          uuid primary key default gen_random_uuid(),
  event_type  text not null check (event_type in ('TICKET_CREATE', 'TICKET_UPDATE')),
  system      text not null check (system in ('jira', 'zendesk', 'hubspot', 'salesforce', 'webhook')),
  config      jsonb not null default '{}'::jsonb check (jsonb_typeof(config) = 'object'),
  enabled     boolean not null default true,
  is_demo     boolean not null default false,
  notes       text,
  created_at  timestamptz not null default now(),
  check (system <> 'webhook' or config->>'url' like 'https://%')
);
create unique index ticket_routes_one_per_system on intake.ticket_routes (event_type, system) where enabled;
alter table intake.ticket_routes enable row level security;

create or replace function intake.get_ticket_routes(p_event_type text)
returns jsonb
language sql
stable
security definer
set search_path = ''
as $$
  select coalesce(jsonb_agg(jsonb_build_object(
           'route_id', id, 'event_type', event_type, 'system', system, 'config', config)
           order by system), '[]'::jsonb)
    from intake.ticket_routes
   where event_type = p_event_type and enabled;
$$;

-- Latest ticket linked to a record for a system (read from the append-only history)
create or replace function intake.get_ticket_ref(p_exec text, p_system text)
returns jsonb
language sql
stable
security definer
set search_path = ''
as $$
  select coalesce((
    select jsonb_build_object('found', true, 'id', e->>'ticket_id', 'url', e->>'ticket_url')
      from intake.intake_audit_logs l,
           jsonb_array_elements(l.decision_history) with ordinality as t(e, i)
     where l.origin_execution_id = p_exec
       and e->>'step' = 'TICKET_CREATED'
       and e->>'system' = p_system
     order by i desc
     limit 1), jsonb_build_object('found', false));
$$;

-- ---------------------------------------------------------------------------
-- Document storage target (exactly one active)
--   config examples:
--     gdrive     {"folder_id":"..."}
--     sharepoint {"site_id":"...","drive_id":"...","folder_id":"..."}
--     onedrive   {"folder_id":"..."}
--     s3         {"bucket":"...","prefix":"ops-intake/","region":"eu-west-1"}
--   optional:   {"scan_url":"https://..."}  external malware-scan API (off unless set)
-- ---------------------------------------------------------------------------
create table intake.storage_targets (
  id          uuid primary key default gen_random_uuid(),
  provider    text not null check (provider in ('gdrive', 'sharepoint', 'onedrive', 's3')),
  config      jsonb not null default '{}'::jsonb check (jsonb_typeof(config) = 'object'),
  enabled     boolean not null default true,
  is_demo     boolean not null default false,
  notes       text,
  created_at  timestamptz not null default now()
);
create unique index storage_targets_one_active on intake.storage_targets ((true)) where enabled;
alter table intake.storage_targets enable row level security;

create or replace function intake.get_storage_target()
returns jsonb
language sql
stable
security definer
set search_path = ''
as $$
  select coalesce((select jsonb_build_object('configured', true, 'target_id', id,
                                             'provider', provider, 'config', config)
                     from intake.storage_targets where enabled limit 1),
                  jsonb_build_object('configured', false));
$$;

-- ---------------------------------------------------------------------------
-- Read-only audit view, gated by a per-record view token (only its hash is stored)
-- ---------------------------------------------------------------------------
alter table intake.intake_audit_logs add column view_token_hash text;

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
  v_view    text := encode(extensions.gen_random_bytes(32), 'hex');
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
    sla_minutes, sla_deadline, status, review_token_hash, token_expires_at, view_token_hash,
    is_test, is_demo, decision_history)
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
    encode(extensions.digest(v_view, 'sha256'), 'hex'),
    coalesce((p->>'is_test')::boolean, false),
    coalesce((p->>'is_demo')::boolean, false),
    v_history || jsonb_build_array(jsonb_build_object(
      'step', 'RECORDED', 'status', v_status, 'sla_minutes', v_sla, 'at', now())))
  returning * into r;

  return jsonb_build_object('ok', true, 'result', 'created', 'record', intake.record_json(r),
                            'review_token', v_token, 'view_token', v_view);
end;
$$;

-- record_json now also hides the view token hash
create or replace function intake.record_json(r intake.intake_audit_logs)
returns jsonb
language sql
immutable
set search_path = ''
as $$
  select to_jsonb(r) - 'review_token_hash' - 'view_token_hash';
$$;

-- What the public "View Audit Record" page may show. It never includes the raw request text, the
-- requester email, the Opus review brief (reviewers only) or any token hash.
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
    'reference', r.reference, 'created_at', r.created_at, 'channel', r.channel,
    'department', r.department, 'concise_brief', r.concise_brief, 'intent', r.intent,
    'urgency', r.urgency, 'confidence_score', r.confidence_score, 'models_used', r.models_used,
    'sensitive_flag_count', jsonb_array_length(r.sensitive_flags),
    'injection_flag_count', jsonb_array_length(r.injection_flags),
    'route', r.route, 'rule_applied', r.rule_applied, 'sla_minutes', r.sla_minutes,
    'sla_deadline', r.sla_deadline, 'status', r.status, 'review_decision', r.review_decision,
    'reviewer_id', r.reviewer_id, 'reviewed_at', r.reviewed_at, 'escalated_at', r.escalated_at,
    'attachment', case when r.attachment_meta is not null then jsonb_build_object(
                    'provider', r.attachment_meta->>'provider', 'url', r.attachment_meta->>'url',
                    'stored_name', r.attachment_meta->>'stored_name', 'sha256', r.attachment_meta->>'sha256',
                    'storage_status', r.attachment_meta->>'storage_status') end,
    'is_test', r.is_test,
    'decision_history', r.decision_history);
end;
$$;

-- ---------------------------------------------------------------------------
-- append_event v4: ticket sync events
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
                              'ESCALATION_NOTIFIED', 'TICKET_CREATED', 'TICKET_UPDATED',
                              'TICKET_SYNC_FAILED', 'TICKET_SYNC_SKIPPED',
                              'TICKET_SYNC_SUPPRESSED_TEST') then
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

revoke all on all functions in schema intake from public, anon, authenticated;
grant execute on function
  intake.get_ticket_routes(text),
  intake.get_ticket_ref(text, text),
  intake.get_storage_target(),
  intake.record_view(text, text)
to n8n_intake;
