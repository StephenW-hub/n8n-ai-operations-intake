-- 011: abuse throttle, right to erasure, WCAG contrast guard, in-database SLA scheduling,
--      language and voice fields (plan v8: G1, G2, G3, G6, Module 10a, Module 10b columns).
--
-- * G2  throttle_check(): per-sender and global caps, honeypot, hashed sender (no PII), logged.
-- * G3  erase_subject(): redacts a data subject's PII in place; the governance skeleton stays.
-- * 10a contrast_ratio() + org_settings_apply() wrapper: brand colours must give 4.5:1 with white text.
-- * G1  pg_cron runs the SLA sweep inside the DB every 5 minutes. n8n is called (pg_net) only when
--       there is something to notify, with a signed ping that carries an ID, never record data.
-- * G6  confirmation_language; 10b inbound_channel 'voice' + transcription_confidence + voice settings.

-- ---------------------------------------------------------------------------
-- 0. Extensions and secrets
-- ---------------------------------------------------------------------------
create extension if not exists pg_cron with schema pg_catalog;
create extension if not exists pg_net with schema extensions;

do $$
begin
  if not exists (select 1 from vault.secrets where name = 'intake_throttle_pepper') then
    perform vault.create_secret(encode(extensions.gen_random_bytes(32), 'hex'), 'intake_throttle_pepper',
                                'Pepper for hashing sender identities in throttle and erasure logs');
  end if;
  if not exists (select 1 from vault.secrets where name = 'intake_internal_hook') then
    perform vault.create_secret(encode(extensions.gen_random_bytes(32), 'hex'), 'intake_internal_hook',
                                'Signs DB-to-n8n dispatch pings');
  end if;
end $$;

-- ---------------------------------------------------------------------------
-- 1. New columns
-- ---------------------------------------------------------------------------
alter table intake.organization_settings
  add column throttle_sender_per_hour integer not null default 5   check (throttle_sender_per_hour between 1 and 100),
  add column throttle_sender_per_day  integer not null default 20  check (throttle_sender_per_day between 1 and 1000),
  add column throttle_global_per_hour integer not null default 60  check (throttle_global_per_hour between 1 and 10000),
  add column voice_enabled            boolean not null default false,
  add column stt_provider             text    not null default 'elevenlabs' check (stt_provider in ('elevenlabs')),
  add column tts_provider             text    not null default 'elevenlabs' check (tts_provider in ('elevenlabs', 'none')),
  add column n8n_webhook_base         text check (n8n_webhook_base is null or n8n_webhook_base ~ '^https://[^\s"''<>]+[^/]$');

alter table intake.organization_settings alter column accent_hex set default '#047857';

alter table intake.intake_audit_logs
  add column confirmation_language    text check (confirmation_language is null
                                                  or confirmation_language ~ '^[a-z]{2,3}(-[A-Za-z]{2,4})?$'),
  add column transcription_confidence numeric(4,3) check (transcription_confidence between 0 and 1);

alter table intake.intake_audit_logs drop constraint intake_audit_logs_inbound_channel_check;
alter table intake.intake_audit_logs add constraint intake_audit_logs_inbound_channel_check
  check (inbound_channel in ('web_form', 'api', 'email', 'whatsapp', 'voice', 'test'));

-- ---------------------------------------------------------------------------
-- 2. WCAG contrast guard (Module 10a)
-- ---------------------------------------------------------------------------
create or replace function intake.relative_luminance(p_hex text)
returns numeric
language sql
immutable
set search_path = ''
as $$
  select 0.2126 * c[1] + 0.7152 * c[2] + 0.0722 * c[3]
    from (select array_agg(case when v <= 0.03928 then v / 12.92
                                else power((v + 0.055) / 1.055, 2.4) end order by i) as c
            from (select i, ('x' || substr(p_hex, 2 * i, 2))::bit(8)::integer / 255.0 as v
                    from generate_series(1, 3) as i) s) t;
$$;

create or replace function intake.contrast_ratio(p_a text, p_b text)
returns numeric
language sql
immutable
set search_path = ''
as $$
  select round((greatest(la, lb) + 0.05) / (least(la, lb) + 0.05), 2)
    from (select intake.relative_luminance(p_a) as la, intake.relative_luminance(p_b) as lb) s;
$$;

-- The v7 validator becomes the core; the public entry point adds the contrast check.
alter function intake.org_settings_apply(jsonb, text) rename to org_settings_apply_core;
revoke all on function intake.org_settings_apply_core(jsonb, text) from public, anon, authenticated, n8n_intake;

create or replace function intake.org_settings_apply(p jsonb, p_actor text)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_err   jsonb := '{}'::jsonb;
  v_res   jsonb;
  v_ratio numeric;
  k       text;
begin
  -- Only colours being changed are checked, so an old colour never blocks unrelated edits.
  foreach k in array array['primary_hex', 'accent_hex'] loop
    if p is not null and jsonb_typeof(p) = 'object' and coalesce(p->>k, '') ~ '^#[0-9a-fA-F]{6}$' then
      v_ratio := intake.contrast_ratio(p->>k, '#ffffff');
      if v_ratio < 4.5 then
        v_err := v_err || jsonb_build_object(k, format(
          'White text on this colour is hard to read (contrast %s:1; it needs at least 4.5:1). Choose a darker shade.',
          v_ratio));
      end if;
    end if;
  end loop;

  if v_err = '{}'::jsonb then
    return intake.org_settings_apply_core(p, p_actor);
  end if;

  -- Contrast failed: still report every other problem in one go, but apply nothing.
  begin
    v_res := intake.org_settings_apply_core(p, p_actor);
    raise exception 'org_settings_contrast_rollback';
  exception when raise_exception then
    if sqlerrm <> 'org_settings_contrast_rollback' then raise; end if;
  end;
  if v_res->>'ok' = 'false' then
    v_err := (v_res->'errors') || v_err;
  end if;
  return jsonb_build_object('ok', false, 'errors', v_err);
end;
$$;

-- Throttle and voice settings: their own validator, same pattern as org_privacy_apply.
create or replace function intake.org_ops_apply(p jsonb, p_actor text)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  allowed constant text[] := array['throttle_sender_per_hour', 'throttle_sender_per_day',
                                   'throttle_global_per_hour', 'voice_enabled', 'stt_provider', 'tts_provider'];
  cur    intake.organization_settings;
  v_err  jsonb := '{}'::jsonb;
  v_new  jsonb;
  v_num  numeric;
  k      text;
  diff   jsonb;
begin
  if p is null or jsonb_typeof(p) <> 'object' then
    return jsonb_build_object('ok', false, 'errors', jsonb_build_object('_', 'Expected a JSON object.'));
  end if;
  select * into cur from intake.organization_settings where id = 1 for update;

  -- Accept form strings: "true"/"false" and numbers as text
  v_new := (select coalesce(jsonb_object_agg(key,
             case when key = 'voice_enabled' and lower(value #>> '{}') in ('true', 'false')
                  then to_jsonb(lower(value #>> '{}')::boolean)
                  else value end), '{}'::jsonb)
              from jsonb_each(p));

  for k in select jsonb_object_keys(v_new) loop
    if not (k = any(allowed)) then
      v_err := v_err || jsonb_build_object(k, 'This setting cannot be changed here.');
    end if;
  end loop;

  foreach k in array array['throttle_sender_per_hour', 'throttle_sender_per_day', 'throttle_global_per_hour'] loop
    if v_new ? k then
      begin
        v_num := (v_new->>k)::numeric;
        if v_num is null or v_num <> trunc(v_num)
           or v_num < 1
           or v_num > (case k when 'throttle_sender_per_hour' then 100
                              when 'throttle_sender_per_day'  then 1000 else 10000 end) then
          raise exception 'x';
        end if;
      exception when others then
        v_err := v_err || jsonb_build_object(k, case k
          when 'throttle_sender_per_hour' then 'Enter a whole number from 1 to 100.'
          when 'throttle_sender_per_day'  then 'Enter a whole number from 1 to 1000.'
          else 'Enter a whole number from 1 to 10000.' end);
      end;
    end if;
  end loop;
  if v_new ? 'voice_enabled' and jsonb_typeof(v_new->'voice_enabled') <> 'boolean' then
    v_err := v_err || '{"voice_enabled":"Choose yes or no."}';
  end if;
  if v_new ? 'stt_provider' and v_new->>'stt_provider' not in ('elevenlabs') then
    v_err := v_err || '{"stt_provider":"Choose elevenlabs."}';
  end if;
  if v_new ? 'tts_provider' and v_new->>'tts_provider' not in ('elevenlabs', 'none') then
    v_err := v_err || '{"tts_provider":"Choose elevenlabs or none."}';
  end if;
  if v_err = '{}'::jsonb
     and coalesce((v_new->>'throttle_sender_per_day')::integer, cur.throttle_sender_per_day)
       < coalesce((v_new->>'throttle_sender_per_hour')::integer, cur.throttle_sender_per_hour) then
    v_err := v_err || '{"throttle_sender_per_day":"The daily limit cannot be lower than the hourly limit."}';
  end if;
  if v_err <> '{}'::jsonb then
    return jsonb_build_object('ok', false, 'errors', v_err);
  end if;

  select coalesce(jsonb_object_agg(key, jsonb_build_object('from', to_jsonb(cur)->key, 'to', v_new->key)), '{}'::jsonb)
    into diff from unnest(allowed) key
   where v_new ? key and (to_jsonb(cur)->>key) is distinct from (v_new->>key);
  if diff = '{}'::jsonb then
    return jsonb_build_object('ok', true, 'result', 'unchanged', 'version', cur.version);
  end if;

  update intake.organization_settings
     set throttle_sender_per_hour = coalesce((v_new->>'throttle_sender_per_hour')::integer, throttle_sender_per_hour),
         throttle_sender_per_day  = coalesce((v_new->>'throttle_sender_per_day')::integer,  throttle_sender_per_day),
         throttle_global_per_hour = coalesce((v_new->>'throttle_global_per_hour')::integer, throttle_global_per_hour),
         voice_enabled            = coalesce((v_new->>'voice_enabled')::boolean, voice_enabled),
         stt_provider             = coalesce(v_new->>'stt_provider', stt_provider),
         tts_provider             = coalesce(v_new->>'tts_provider', tts_provider),
         version = version + 1, updated_at = now(), updated_by = left(coalesce(p_actor, 'unknown'), 254)
   where id = 1
  returning * into cur;
  return jsonb_build_object('ok', true, 'result', 'applied', 'version', cur.version, 'changes', diff);
end;
$$;

-- Deployments still on the shipped accent (#059669, 3.8:1) move to the accessible shade (#047857, 5.5:1).
update intake.organization_settings
   set accent_hex = '#047857', version = version + 1, updated_at = now(),
       updated_by = 'migration 011 (WCAG contrast)'
 where id = 1 and accent_hex = '#059669';

-- ---------------------------------------------------------------------------
-- 3. Abuse throttle (G2)
-- ---------------------------------------------------------------------------
create table intake.throttle_log (
  id           bigint generated always as identity primary key,
  at           timestamptz not null default now(),
  channel      text not null check (char_length(channel) <= 20),
  sender_hash  text not null check (sender_hash ~ '^[0-9a-f]{64}$'),
  allowed      boolean not null,
  reason       text not null check (reason in ('OK', 'TEST_CHANNEL', 'HONEYPOT', 'SENDER_HOURLY',
                                                'SENDER_DAILY', 'GLOBAL_HOURLY'))
);
create index throttle_log_sender_at on intake.throttle_log (sender_hash, at desc);
create index throttle_log_at on intake.throttle_log (at desc);
alter table intake.throttle_log enable row level security;

create or replace function intake.sender_hash(p_sender text)
returns text
language sql
stable
security definer
set search_path = ''
as $$
  select intake.hmac_hex('intake_throttle_pepper', coalesce(nullif(lower(trim(p_sender)), ''), 'anonymous'));
$$;
revoke all on function intake.sender_hash(text) from public, anon, authenticated;

create or replace function intake.throttle_check(p_channel text, p_sender text, p_honeypot text default null)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  cfg    intake.organization_settings;
  v_hash text := intake.sender_hash(p_sender);
  v_hour integer;
  v_day  integer;
  v_glob integer;
  v_why  text := 'OK';
begin
  if v_hash is null then
    raise exception 'throttle_check: secret intake_throttle_pepper is missing from Vault';
  end if;
  select * into cfg from intake.organization_settings where id = 1;

  if p_channel = 'test' then
    v_why := 'TEST_CHANNEL';
  elsif nullif(trim(coalesce(p_honeypot, '')), '') is not null then
    v_why := 'HONEYPOT';
  else
    select count(*) filter (where at > now() - interval '1 hour'),
           count(*)
      into v_hour, v_day
      from intake.throttle_log
     where sender_hash = v_hash and allowed and at > now() - interval '1 day';
    select count(*) into v_glob from intake.throttle_log
     where allowed and channel <> 'test' and at > now() - interval '1 hour';

    if v_hour >= cfg.throttle_sender_per_hour then v_why := 'SENDER_HOURLY';
    elsif v_day >= cfg.throttle_sender_per_day then v_why := 'SENDER_DAILY';
    elsif v_glob >= cfg.throttle_global_per_hour then v_why := 'GLOBAL_HOURLY';
    end if;
  end if;

  insert into intake.throttle_log (channel, sender_hash, allowed, reason)
  values (left(coalesce(p_channel, 'unknown'), 20), v_hash, v_why in ('OK', 'TEST_CHANNEL'), v_why);

  return jsonb_build_object(
    'allowed', v_why in ('OK', 'TEST_CHANNEL'),
    'reason',  v_why,
    'message', case v_why
      when 'SENDER_HOURLY' then 'You have sent several requests in the last hour. Please wait an hour and try again, or reply to your last confirmation.'
      when 'SENDER_DAILY'  then 'You have reached today''s limit for new requests. Please try again tomorrow, or reply to your last confirmation.'
      when 'GLOBAL_HOURLY' then 'We are receiving a lot of requests right now. Please try again in a few minutes.'
      when 'HONEYPOT'      then 'Your request could not be accepted.'
      else null end);
end;
$$;

-- ---------------------------------------------------------------------------
-- 4. Right to erasure (G3)
-- ---------------------------------------------------------------------------
create table intake.erasure_log (
  id            bigint generated always as identity primary key,
  erased_at     timestamptz not null default now(),
  actor         text not null check (char_length(actor) between 1 and 254),
  subject_hash  text not null check (subject_hash ~ '^[0-9a-f]{64}$'),
  record_count  integer not null check (record_count >= 0),
  record_refs   jsonb not null default '[]'::jsonb check (jsonb_typeof(record_refs) = 'array')
);
alter table intake.erasure_log enable row level security;
create trigger erasure_log_immutable before update or delete on intake.erasure_log
  for each row execute function intake.block_mutation();
create trigger erasure_log_no_truncate before truncate on intake.erasure_log
  for each statement execute function intake.block_truncate();

-- Guard v6: identical to v5, plus a narrow erasure path that may only redact PII columns.
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
  pii constant text[] := array['requester_email', 'requester_phone', 'request_text', 'concise_brief',
                               'review_brief', 'review_notes', 'resolution_notes', 'attachment_meta',
                               'decision_history',
                               'contains_sensitive_data'];  -- generated: not yet computed in BEFORE triggers
  old_len integer;
begin
  if tg_op = 'DELETE' then
    raise exception 'intake_audit_logs is append-only: DELETE is not allowed';
  end if;

  -- Erasure path (set only inside intake.erase_subject): PII columns may be redacted, nothing else moves.
  if current_setting('intake.erasure', true) = 'on' then
    if (to_jsonb(new) - pii) is distinct from (to_jsonb(old) - pii) then
      raise exception 'intake_audit_logs: erasure may only redact personal data';
    end if;
    if jsonb_array_length(new.decision_history) <> jsonb_array_length(old.decision_history) then
      raise exception 'intake_audit_logs: erasure cannot add or remove history entries';
    end if;
    return new;
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

-- Redacts every record for one email or phone. Returns the attachment metadata first, so workflow 07
-- can delete the stored files. p_confirm must be the word ERASE (guards against a mis-click).
create or replace function intake.erase_subject(p_contact text, p_actor text, p_confirm text)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_contact text := lower(trim(coalesce(p_contact, '')));
  v_refs    jsonb;
  v_files   jsonb;
  v_count   integer;
begin
  if p_confirm is distinct from 'ERASE' then
    return jsonb_build_object('ok', false, 'errors', jsonb_build_object('confirm', 'Type ERASE to confirm.'));
  end if;
  if char_length(v_contact) not between 3 and 254 then
    return jsonb_build_object('ok', false, 'errors', jsonb_build_object('contact', 'Enter the person''s email or phone number.'));
  end if;
  if char_length(trim(coalesce(p_actor, ''))) = 0 then
    return jsonb_build_object('ok', false, 'errors', jsonb_build_object('actor', 'Your name or email is required for the audit log.'));
  end if;

  select coalesce(jsonb_agg(reference order by created_at), '[]'::jsonb),
         coalesce(jsonb_agg(attachment_meta) filter (where attachment_meta is not null
                                                       and not coalesce((attachment_meta->>'erased')::boolean, false)),
                  '[]'::jsonb),
         count(*)
    into v_refs, v_files, v_count
    from intake.intake_audit_logs
   where lower(requester_email) = v_contact or requester_phone = trim(p_contact);

  perform set_config('intake.erasure', 'on', true);
  update intake.intake_audit_logs
     set requester_email  = null,
         requester_phone  = null,
         request_text     = '[ERASED]',
         concise_brief    = case when concise_brief    is not null then '[ERASED]' end,
         review_brief     = case when review_brief     is not null then '[ERASED]' end,
         review_notes     = case when review_notes     is not null then '[ERASED]' end,
         resolution_notes = case when resolution_notes is not null then '[ERASED]' end,
         attachment_meta  = case when attachment_meta  is not null then '{"erased": true}'::jsonb end,
         decision_history = (select coalesce(jsonb_agg(case when e ? 'notes' and e->>'notes' is not null
                                                             then e || '{"notes": "[ERASED]"}'::jsonb else e end
                                                        order by i), '[]'::jsonb)
                               from jsonb_array_elements(decision_history) with ordinality as t(e, i))
   where lower(requester_email) = v_contact or requester_phone = trim(p_contact);
  perform set_config('intake.erasure', 'off', true);

  delete from intake.requester_directory where contact = v_contact;
  delete from intake.throttle_log where sender_hash = intake.sender_hash(v_contact);

  insert into intake.erasure_log (actor, subject_hash, record_count, record_refs)
  values (left(trim(p_actor), 254), intake.sender_hash(v_contact), v_count, v_refs);

  return jsonb_build_object('ok', true, 'erased_records', v_count, 'references', v_refs,
                            'attachments_to_delete', v_files);
end;
$$;

-- ---------------------------------------------------------------------------
-- 5. intake_create v6: + confirmation_language, transcription_confidence (otherwise identical to v5)
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
    token_expires_at, view_token_hash, resolve_token_hash, is_test, is_demo, decision_history,
    confirmation_language, transcription_confidence)
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
      'step', 'RECORDED', 'status', v_status, 'sla_minutes', v_sla, 'at', now())),
    case when p->>'confirmation_language' ~ '^[a-z]{2,3}(-[A-Za-z]{2,4})?$' then p->>'confirmation_language' end,
    (nullif(p->>'transcription_confidence', ''))::numeric)
  returning * into r;

  return jsonb_build_object('ok', true, 'result', 'created', 'record', intake.record_json(r),
                            'review_token', v_token, 'view_token', v_view, 'resolve_token', v_resolve);
end;
$$;

-- ---------------------------------------------------------------------------
-- 6. In-database SLA scheduling (G1)
-- ---------------------------------------------------------------------------
create table intake.internal_dispatch (
  id            bigint generated always as identity primary key,
  hook          text not null check (hook in ('sla_escalation')),
  payload       jsonb not null,
  created_at    timestamptz not null default now(),
  status        text not null default 'PENDING' check (status in ('PENDING', 'TAKEN', 'FAILED')),
  attempts      integer not null default 0,
  last_sent_at  timestamptz,
  taken_at      timestamptz
);
create index internal_dispatch_pending on intake.internal_dispatch (created_at) where status = 'PENDING';
alter table intake.internal_dispatch enable row level security;

-- Owner-only onboarding: where the DB pings n8n (e.g. https://acme.app.n8n.cloud/webhook)
create or replace function intake.internal_hook_set(p_base text)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
begin
  if p_base is not null and p_base !~ '^https://[^\s"''<>]+[^/]$' then
    return jsonb_build_object('ok', false, 'errors', jsonb_build_object('n8n_webhook_base',
      'Use the https:// webhook base without a trailing slash, e.g. https://acme.app.n8n.cloud/webhook'));
  end if;
  update intake.organization_settings
     set n8n_webhook_base = p_base, version = version + 1, updated_at = now(),
         updated_by = 'owner (internal_hook_set)'
   where id = 1;
  return jsonb_build_object('ok', true, 'n8n_webhook_base', p_base);
end;
$$;

-- Runs every 5 minutes from pg_cron. Sweeps, queues escalations, (re)sends signed pings.
create or replace function intake.cron_sla_tick()
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_base   text := (select n8n_webhook_base from intake.organization_settings where id = 1);
  v_new    integer := 0;
  v_sent   integer := 0;
  v_failed integer := 0;
  v_ts     text;
  d        intake.internal_dispatch;
begin
  insert into intake.internal_dispatch (hook, payload)
  select 'sla_escalation', jsonb_build_object('records', jsonb_agg(x))
    from intake.sla_sweep() as x
  having count(*) > 0;
  get diagnostics v_new = row_count;

  update intake.internal_dispatch
     set status = 'FAILED'
   where status = 'PENDING' and attempts >= 6
     and last_sent_at < now() - interval '3 minutes';
  get diagnostics v_failed = row_count;

  if v_base is not null then
    for d in select * from intake.internal_dispatch
              where status = 'PENDING' and attempts < 6
                and (last_sent_at is null or last_sent_at < now() - interval '3 minutes')
              order by id
              for update skip locked loop
      v_ts := extract(epoch from now())::bigint::text;
      perform net.http_post(
        url     := v_base || '/sla-notifier',
        body    := jsonb_build_object('dispatch_id', d.id, 'hook', d.hook),
        headers := jsonb_build_object(
                     'Content-Type', 'application/json',
                     'X-Timestamp',  v_ts,
                     'X-Signature',  intake.hmac_hex('intake_internal_hook', v_ts || '.' || d.id)),
        timeout_milliseconds := 10000);
      update intake.internal_dispatch set attempts = attempts + 1, last_sent_at = now() where id = d.id;
      v_sent := v_sent + 1;
    end loop;
  end if;

  return jsonb_build_object('queued', v_new, 'sent', v_sent, 'failed', v_failed,
                            'webhook_configured', v_base is not null);
end;
$$;

-- n8n calls this with the headers it received. Verifies the signature inside the DB and hands over
-- the payload exactly once.
create or replace function intake.internal_dispatch_take(p_dispatch_id bigint, p_ts text, p_sig text)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_ts  bigint;
  v_exp text;
  d     intake.internal_dispatch;
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
  return jsonb_build_object('ok', true, 'result', 'taken', 'hook', d.hook, 'payload', d.payload);
end;
$$;

create or replace function intake.cron_housekeeping()
returns void
language sql
security definer
set search_path = ''
as $$
  delete from intake.throttle_log where at < now() - interval '30 days';
  delete from intake.internal_dispatch where status in ('TAKEN', 'FAILED') and created_at < now() - interval '30 days';
$$;

do $$
begin
  perform cron.unschedule(jobname) from cron.job where jobname in ('intake-sla-tick', 'intake-housekeeping');
  perform cron.schedule('intake-sla-tick',     '*/5 * * * *', 'select intake.cron_sla_tick()');
  perform cron.schedule('intake-housekeeping', '17 3 * * *',  'select intake.cron_housekeeping()');
end $$;

-- ---------------------------------------------------------------------------
-- 7. Org settings rollback v3: also restores throttle and voice settings when the snapshot has them
-- ---------------------------------------------------------------------------
create or replace function intake.org_settings_rollback(p_version integer, p_actor text)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_snap jsonb;
  v_res  jsonb;
  v_ops  jsonb;
begin
  select snapshot into v_snap from intake.organization_settings_history where version = p_version;
  if v_snap is null then
    return jsonb_build_object('ok', false, 'errors', jsonb_build_object('version', 'No such version.'));
  end if;
  v_res := intake.org_settings_apply(
    (select jsonb_object_agg(key, value) from jsonb_each(v_snap)
      where key in ('org_name', 'logo_url', 'primary_hex', 'accent_hex', 'coo_email',
                    'escalation_lead_email', 'currency_code', 'fx_usd_to_local', 'hourly_admin_cost',
                    'mins_saved_per_ticket', 'confidence_threshold', 'incident_sla_mins', 'ops_sla_mins',
                    'review_sla_mins', 'critical_review_sla_mins', 'report_timezone', 'active_branches')),
    coalesce(p_actor, 'unknown') || ' (rollback to v' || p_version || ')');
  if v_res->>'ok' = 'false' then
    return v_res;
  end if;
  v_ops := (select jsonb_object_agg(key, value) from jsonb_each(v_snap)
             where key in ('throttle_sender_per_hour', 'throttle_sender_per_day', 'throttle_global_per_hour',
                           'voice_enabled', 'stt_provider', 'tts_provider'));
  if v_ops is not null then
    perform intake.org_ops_apply(v_ops, coalesce(p_actor, 'unknown') || ' (rollback to v' || p_version || ')');
  end if;
  return v_res;
end;
$$;

-- ---------------------------------------------------------------------------
-- 8. Privileges
-- ---------------------------------------------------------------------------
revoke all on all functions in schema intake from public, anon, authenticated;
grant execute on function
  intake.org_settings_apply(jsonb, text),
  intake.org_ops_apply(jsonb, text),
  intake.throttle_check(text, text, text),
  intake.erase_subject(text, text, text),
  intake.internal_dispatch_take(bigint, text, text),
  intake.contrast_ratio(text, text),
  intake.relative_luminance(text)
to n8n_intake;
-- Not granted (owner, cron or internal only): org_settings_apply_core, internal_hook_set, cron_sla_tick,
-- cron_housekeeping, sender_hash.
