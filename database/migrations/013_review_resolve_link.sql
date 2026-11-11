-- 013: after an approval or override, issue a fresh "mark as resolved" link.
-- Tokens are stored only as SHA-256 hashes, so the original resolve link of a held
-- request cannot be rebuilt. The caller must present the (already used) review token;
-- the resolve token is rotated once (it was never shared for held requests) and returned.
--
-- guard_records v7: a narrow path, gated by the session flag intake.resolve_link that only
-- issue_resolve_link sets, may change resolve_token_hash and append exactly one history entry.

create or replace function intake.guard_records()
returns trigger
language plpgsql
set search_path = ''
as $function$
declare
  mutable constant text[] := array['status', 'reviewer_id', 'human_final_decision', 'human_final_route',
                                   'review_notes', 'human_reviewed_at', 'resolved_at', 'resolution_source',
                                   'resolution_notes', 'token_used_at', 'escalated_at', 'sla_breached',
                                   'decision_history',
                                   'contains_sensitive_data'];
  pii constant text[] := array['requester_email', 'requester_phone', 'request_text', 'concise_brief',
                               'review_brief', 'review_notes', 'resolution_notes', 'attachment_meta',
                               'decision_history',
                               'contains_sensitive_data'];
  old_len integer;
begin
  if tg_op = 'DELETE' then
    raise exception 'intake_audit_logs is append-only: DELETE is not allowed';
  end if;

  if current_setting('intake.erasure', true) = 'on' then
    if (to_jsonb(new) - pii) is distinct from (to_jsonb(old) - pii) then
      raise exception 'intake_audit_logs: erasure may only redact personal data';
    end if;
    if jsonb_array_length(new.decision_history) <> jsonb_array_length(old.decision_history) then
      raise exception 'intake_audit_logs: erasure cannot add or remove history entries';
    end if;
    return new;
  end if;

  if current_setting('intake.resolve_link', true) = 'on' then
    if (to_jsonb(new) - array['resolve_token_hash', 'decision_history', 'contains_sensitive_data'])
       is distinct from (to_jsonb(old) - array['resolve_token_hash', 'decision_history', 'contains_sensitive_data']) then
      raise exception 'intake_audit_logs: issuing a resolve link may only change the resolve token';
    end if;
    if jsonb_array_length(new.decision_history) <> jsonb_array_length(old.decision_history) + 1
       or new.decision_history - (jsonb_array_length(new.decision_history) - 1) is distinct from old.decision_history then
      raise exception 'intake_audit_logs: issuing a resolve link appends exactly one history entry';
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
$function$;

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
     and review_token_hash = encode(extensions.digest(coalesce(p_review_token, ''), 'sha256'), 'hex')
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

revoke all on function intake.issue_resolve_link(text, text) from public;
grant execute on function intake.issue_resolve_link(text, text) to n8n_intake;

-- review_preview v2: the reviewer (holder of a valid review token) also sees the original
-- request text, the requester's email and the attachment link. They need these to decide,
-- above all when the AI brief is unavailable.
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
     and review_token_hash = encode(extensions.digest(coalesce(p_token, ''), 'sha256'), 'hex');
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
    'attachment', case when r.attachment_meta is not null then jsonb_build_object(
                    'url', r.attachment_meta->>'url', 'stored_name', r.attachment_meta->>'stored_name',
                    'storage_status', r.attachment_meta->>'storage_status') end);
end;
$function$;
