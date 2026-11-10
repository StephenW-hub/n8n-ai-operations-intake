-- Fix 1: telemetry_assert_safe used a forbidden-word pattern on keys, which wrongly blocked the
-- legitimate prompt key "review_brief". Keys are now checked against an exact allow-list (stricter):
-- any key not in the list blocks the payload, so a new field can only be sent after it is added here
-- AND to the MSA telemetry clause (legal/master_services_agreement.md lists the same fields).
-- Block messages never echo the offending key or value.

create or replace function intake.telemetry_assert_safe(p jsonb)
returns void
language plpgsql
immutable
set search_path = ''
as $$
declare
  r record;
  allowed_keys constant text[] := array[
    'client_id', 'region', 'kind', 'sent_at', 'app_version', 'org_config_version', 'prompt_versions',
    'classifier', 'review_brief', 'consultant', 'consecutive_failures', 'active_user_seats',
    'requests_24h', 'pending_review', 'open_overdue', 'period', 'monthly_volume', 'sla_compliance_pct',
    'override_rate_pct', 'ambiguity_rate_pct', 'admin_hours_saved', 'confidence_drift_pct',
    'error_logs', 'workflow_code', 'node_type', 'error_class', 'count',
    'patch_id', 'status', 'cases_passed', 'cases_total'];
  safe_string constant text :=
    '^(' ||
      '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' ||                -- uuid
      '|[a-z]{2}-[a-z]+(-[0-9])?' ||                                                     -- region
      '|heartbeat|monthly_pulse|error|patch_result' ||                                   -- kind
      '|[0-9]{4}-[0-9]{2}' ||                                                            -- period
      '|[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z' ||                                          -- timestamp
      '|[0-9]+\.[0-9]+\.[0-9]+' ||                                                       -- app version
      '|0[0-9]|1[01]' ||                                                                 -- workflow code
      '|(n8n-nodes-base|@n8n/n8n-nodes-langchain)\.[A-Za-z0-9]{1,60}' ||                 -- node type
      '|AUTH|API_KEY_INVALID|RATE_LIMIT|TIMEOUT|WEBHOOK_TIMEOUT|DB_UNAVAILABLE|VALIDATION|UPSTREAM_5XX|UNKNOWN' ||
      '|RECEIVED|PENDING_CLIENT|APPLIED|APPLIED_PENDING_GATE|DECLINED|ROLLED_BACK|REJECTED' ||
    ')$';
begin
  for r in
    with recursive walk(k, v) as (
      select null::text, p
      union all
      select coalesce(e.key, walk.k), coalesce(e.value, a.value)
        from walk
        left join lateral jsonb_each(case when jsonb_typeof(walk.v) = 'object' then walk.v end) e on true
        left join lateral jsonb_array_elements(case when jsonb_typeof(walk.v) = 'array' then walk.v end) a on true
       where jsonb_typeof(walk.v) in ('object', 'array') and coalesce(e.value, a.value) is not null
    )
    select k, v from walk
  loop
    if r.k is not null and not (r.k = any(allowed_keys)) then
      raise exception 'telemetry blocked: a key is not on the telemetry allow-list';
    end if;
    if jsonb_typeof(r.v) = 'string' and (r.v #>> '{}') !~ safe_string then
      raise exception 'telemetry blocked: a value is not an allowed telemetry token';
    end if;
  end loop;
end;
$$;

-- Fix 2: patch_receive now rejects out-of-bounds settings on receipt (same bounds as
-- org_settings_apply), so a client admin is never asked to approve a patch that cannot apply.
create or replace function intake.patch_receive(p jsonb)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  allowed_settings constant text[] := array['confidence_threshold', 'incident_sla_mins', 'ops_sla_mins',
                                            'review_sla_mins', 'critical_review_sla_mins', 'mins_saved_per_ticket'];
  o        intake.organization_settings;
  v_id     uuid;
  k        text;
  pr       jsonb;
  v_safe   boolean := true;
  v_token  text;
  v_bad    text := null;
begin
  select * into o from intake.organization_settings where id = 1;
  begin
    v_id := (p->>'patch_id')::uuid;
  exception when others then
    return jsonb_build_object('ok', false, 'result', 'rejected', 'reason', 'bad_patch_id');
  end;
  if exists (select 1 from intake.config_patches where patch_id = v_id) then
    return jsonb_build_object('ok', true, 'result', 'duplicate', 'status',
                              (select status from intake.config_patches where patch_id = v_id));
  end if;

  -- Allow-list: only these top-level keys, settings keys and prompt keys
  for k in select jsonb_object_keys(p) loop
    if k not in ('patch_id', 'client_id', 'settings', 'prompts', 'reason', 'issued_at') then v_bad := 'key ' || k; end if;
  end loop;
  if v_bad is null and p ? 'settings' then
    if jsonb_typeof(p->'settings') <> 'object' then v_bad := 'settings must be an object'; end if;
    if v_bad is null then
      for k in select jsonb_object_keys(p->'settings') loop
        if not (k = any(allowed_settings)) then v_bad := 'setting ' || k;
        elsif jsonb_typeof(p->'settings'->k) <> 'number' then v_bad := 'setting ' || k || ' must be a number';
        elsif k = 'confidence_threshold' and (p->'settings'->>k)::numeric not between 0.50 and 0.99 then
          v_bad := 'setting ' || k || ' out of bounds (0.50-0.99)';
        elsif k = 'mins_saved_per_ticket' and (p->'settings'->>k)::numeric not between 0 and 240 then
          v_bad := 'setting ' || k || ' out of bounds (0-240)';
        elsif k like '%sla_mins' and (p->'settings'->>k)::numeric not between 5 and 2880 then
          v_bad := 'setting ' || k || ' out of bounds (5-2880)';
        end if;
      end loop;
    end if;
  end if;
  if v_bad is null and p ? 'prompts' then
    if jsonb_typeof(p->'prompts') <> 'array' then
      v_bad := 'prompts must be an array';
    elsif jsonb_array_length(p->'prompts') > 3 then
      v_bad := 'prompts must be an array of up to 3';
    else
      for pr in select * from jsonb_array_elements(p->'prompts') loop
        if (select count(*) from jsonb_object_keys(pr)) <> 2 or not (pr ? 'prompt_key' and pr ? 'body')
           or pr->>'prompt_key' not in ('classifier', 'review_brief', 'consultant')
           or char_length(coalesce(pr->>'body', '')) not between 50 and 20000 then
          v_bad := 'invalid prompt entry';
        end if;
      end loop;
    end if;
  end if;
  if v_bad is null and not (p ? 'settings' or p ? 'prompts') then v_bad := 'empty patch'; end if;

  if v_bad is not null then
    insert into intake.config_patches (patch_id, payload, mode, status, reason)
    values (v_id, p, o.remote_patching_mode, 'REJECTED', 'not allowed: ' || v_bad);
    return jsonb_build_object('ok', false, 'result', 'rejected', 'reason', 'not allowed: ' || v_bad);
  end if;

  -- Governance-safe = tightens only (threshold up, SLAs down), no ROI-baseline or prompt changes
  for k in select jsonb_object_keys(coalesce(p->'settings', '{}'::jsonb)) loop
    if k = 'confidence_threshold' then
      v_safe := v_safe and (p->'settings'->>k)::numeric >= o.confidence_threshold;
    elsif k = 'mins_saved_per_ticket' then
      v_safe := false;
    else
      v_safe := v_safe and (p->'settings'->>k)::numeric <= (to_jsonb(o)->>k)::numeric;
    end if;
  end loop;

  insert into intake.config_patches (patch_id, payload, mode, status, reason)
  values (v_id, p, o.remote_patching_mode, 'RECEIVED', left(p->>'reason', 500));

  if o.remote_patching_mode = 'auto_safe' and v_safe then
    return intake.patch_apply_internal(v_id, 'auto_safe') || jsonb_build_object('patch_id', v_id);
  end if;

  v_token := encode(extensions.gen_random_bytes(32), 'hex');
  update intake.config_patches
     set status = 'PENDING_CLIENT', approval_token_hash = encode(extensions.digest(v_token, 'sha256'), 'hex')
   where patch_id = v_id;
  return jsonb_build_object('ok', true, 'result', 'pending_client', 'patch_id', v_id,
                            'approval_token', v_token, 'governance_safe', v_safe);
end;
$$;
revoke all on function intake.patch_receive(jsonb) from public;
grant execute on function intake.patch_receive(jsonb) to n8n_intake;
