-- 014: extra single-purpose links for SLA escalations.
-- Tokens are stored only as hashes, so an escalation cannot reuse the original review or resolve
-- link, and rotating those would break links already sent. A request may therefore also hold
-- additional, expiring link tokens. They are minted ONLY inside internal_dispatch_take, i.e. after
-- the database's own HMAC-signed SLA ping has been verified, and returned once in plain text.

create table if not exists intake.link_tokens (
  id                  bigint generated always as identity primary key,
  origin_execution_id text        not null,
  purpose             text        not null check (purpose in ('review', 'resolve')),
  token_hash          text        not null unique,
  reason              text        not null,
  created_at          timestamptz not null default now(),
  expires_at          timestamptz not null
);
create index if not exists link_tokens_exec_idx on intake.link_tokens (origin_execution_id, purpose);
alter table intake.link_tokens enable row level security;
revoke all on intake.link_tokens from public, anon, authenticated;

-- True when p_token matches the record's primary hash or an unexpired extra link of that purpose.
create or replace function intake.token_ok(p_exec text, p_purpose text, p_token text, p_primary_hash text)
returns boolean
language sql
stable
set search_path = ''
as $$
  select coalesce(length(p_token), 0) >= 32 and (
         p_primary_hash = encode(extensions.digest(p_token, 'sha256'), 'hex')
      or exists (select 1 from intake.link_tokens lt
                  where lt.origin_execution_id = p_exec
                    and lt.purpose = p_purpose
                    and lt.token_hash = encode(extensions.digest(p_token, 'sha256'), 'hex')
                    and lt.expires_at > now()));
$$;
revoke all on function intake.token_ok(text, text, text, text) from public;

-- review_preview v3: accepts extra review links.
create or replace function intake.review_preview(p_exec text, p_token text)
returns jsonb
language plpgsql
stable security definer
set search_path = ''
as $function$
declare
  r intake.intake_audit_logs;
begin
  select * into r from intake.intake_audit_logs
   where origin_execution_id = p_exec
     and intake.token_ok(p_exec, 'review', p_token, review_token_hash);
  if not found then
    return jsonb_build_object('ok', false, 'result', 'invalid_link');
  end if;
  return jsonb_build_object(
    'ok', true,
    'result', case when r.token_used_at is not null then 'already_decided'
                   when r.token_expires_at <= now() then 'expired'
                   else 'open' end,
    'reference', r.reference, 'created_at', r.created_at, 'inbound_channel', r.inbound_channel,
    'submitting_branch', r.submitting_branch, 'department', r.department,
    'requester_email', r.requester_email, 'request_text', r.request_text,
    'concise_brief', r.concise_brief, 'review_brief', r.review_brief, 'intent', r.intent,
    'urgency', r.urgency, 'confidence_score', r.confidence_score,
    'sentiment_frustration_score', r.sentiment_frustration_score,
    'rule_applied', r.rule_applied, 'sensitive_data_category', r.sensitive_data_category,
    'sensitive_flags', r.sensitive_flags, 'injection_flags', r.injection_flags,
    'ai_predicted_route', r.ai_predicted_route, 'post_review_route', r.post_review_route,
    'sla_deadline', r.sla_deadline, 'token_expires_at', r.token_expires_at,
    'human_final_decision', r.human_final_decision, 'is_test', r.is_test,
    'escalated_at', r.escalated_at,
    'attachment', case when r.attachment_meta is not null then jsonb_build_object(
                    'url', r.attachment_meta->>'url', 'stored_name', r.attachment_meta->>'stored_name',
                    'storage_status', r.attachment_meta->>'storage_status') end);
end;
$function$;

-- review_decide v2: accepts extra review links; otherwise unchanged.
create or replace function intake.review_decide(p_exec text, p_token text, p_decision text, p_reviewer text,
                                                p_notes text default null, p_final_route text default null)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $function$
declare
  v_final text;
  r       intake.intake_audit_logs;
begin
  if p_decision not in ('APPROVED', 'REJECTED', 'OVERRIDDEN') then
    return jsonb_build_object('ok', false, 'result', 'invalid_decision');
  end if;

  select * into r from intake.intake_audit_logs
   where origin_execution_id = p_exec
     and intake.token_ok(p_exec, 'review', p_token, review_token_hash);
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
$function$;

-- resolve_preview v2 / resolve_with_token v2: accept extra resolve links.
create or replace function intake.resolve_preview(p_exec text, p_token text)
returns jsonb
language plpgsql
stable security definer
set search_path = ''
as $function$
declare
  r intake.intake_audit_logs;
begin
  select * into r from intake.intake_audit_logs
   where origin_execution_id = p_exec
     and intake.token_ok(p_exec, 'resolve', p_token, resolve_token_hash);
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
$function$;

create or replace function intake.resolve_with_token(p_exec text, p_token text, p_actor text, p_notes text default null)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $function$
begin
  if not exists (select 1 from intake.intake_audit_logs
                  where origin_execution_id = p_exec
                    and intake.token_ok(p_exec, 'resolve', p_token, resolve_token_hash)) then
    return jsonb_build_object('ok', false, 'result', 'invalid_link');
  end if;
  return intake.resolve_record(p_exec, 'team_link', p_actor, p_notes);
end;
$function$;

-- issue_resolve_link v2: an escalation review link may also request it.
create or replace function intake.issue_resolve_link(p_exec text, p_review_token text)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_token text := encode(extensions.gen_random_bytes(32), 'hex');
  r intake.intake_audit_logs;
begin
  perform set_config('intake.resolve_link', 'on', true);
  update intake.intake_audit_logs
     set resolve_token_hash = encode(extensions.digest(v_token, 'sha256'), 'hex'),
         decision_history   = decision_history || jsonb_build_array(jsonb_build_object(
                                'step', 'RESOLVE_LINK_ISSUED', 'at', now()))
   where origin_execution_id = p_exec
     and intake.token_ok(p_exec, 'review', p_review_token, review_token_hash)
     and status in ('APPROVED', 'OVERRIDDEN')
     and resolved_at is null
     and not (decision_history @> '[{"step": "RESOLVE_LINK_ISSUED"}]'::jsonb)
  returning * into r;
  perform set_config('intake.resolve_link', 'off', true);
  if r.id is null then  -- not FOUND: the PERFORM above resets it
    return jsonb_build_object('ok', false, 'result', 'not_eligible');
  end if;
  return jsonb_build_object('ok', true, 'resolve_token', v_token,
                            'record', intake.record_json(r));
end;
$$;

-- internal_dispatch_take v2: for SLA escalations, mint one extra link per record
-- (review link for held requests, resolve link for incidents) and return it once.
create or replace function intake.internal_dispatch_take(p_dispatch_id bigint, p_ts text, p_sig text)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $function$
declare
  v_ts      bigint;
  v_exp     text;
  d         intake.internal_dispatch;
  rec       jsonb;
  v_out     jsonb := '[]'::jsonb;
  v_tok     text;
  v_purpose text;
begin
  begin
    v_ts := p_ts::bigint;
  exception when others then
    return jsonb_build_object('ok', false, 'error', 'bad_timestamp');
  end;
  if abs(extract(epoch from now()) - v_ts) > 300 then
    return jsonb_build_object('ok', false, 'error', 'stale_timestamp');
  end if;
  v_exp := intake.hmac_hex('intake_internal_hook', p_ts || '.' || p_dispatch_id);
  if v_exp is null then
    return jsonb_build_object('ok', false, 'error', 'not_configured');
  end if;
  if p_sig is null or lower(p_sig) <> v_exp then
    return jsonb_build_object('ok', false, 'error', 'bad_signature');
  end if;

  select * into d from intake.internal_dispatch where id = p_dispatch_id for update;
  if not found then
    return jsonb_build_object('ok', false, 'error', 'not_found');
  end if;
  if d.status = 'TAKEN' then
    return jsonb_build_object('ok', true, 'result', 'already_taken');
  end if;
  update intake.internal_dispatch set status = 'TAKEN', taken_at = now() where id = d.id;

  if d.hook <> 'sla_escalation' then
    return jsonb_build_object('ok', true, 'result', 'taken', 'hook', d.hook, 'payload', d.payload);
  end if;

  for rec in select value from jsonb_array_elements(coalesce(d.payload->'records', '[]'::jsonb)) loop
    v_tok := encode(extensions.gen_random_bytes(32), 'hex');
    v_purpose := case when rec->>'route_destination' = 'HUMAN_REVIEW' then 'review' else 'resolve' end;
    insert into intake.link_tokens (origin_execution_id, purpose, token_hash, reason, expires_at)
    values (rec->>'origin_execution_id', v_purpose, encode(extensions.digest(v_tok, 'sha256'), 'hex'),
            'sla_escalation',
            case when v_purpose = 'review'
                 then coalesce((rec->>'token_expires_at')::timestamptz, now() + interval '3 days')
                 else now() + interval '7 days' end);
    v_out := v_out || jsonb_build_array(rec || jsonb_build_object('link_purpose', v_purpose, 'link_token', v_tok));
  end loop;

  return jsonb_build_object('ok', true, 'result', 'taken', 'hook', d.hook,
                            'payload', jsonb_build_object('records', v_out));
end;
$function$;
