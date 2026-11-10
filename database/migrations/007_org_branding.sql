-- Module 7: white-labelling and self-service configuration
-- * organization_settings: exactly one row per deployment (single-tenant white-label model)
-- * organization_settings_history: append-only, one full snapshot per version (audit and rollback)
-- * org_settings_apply(): the only write path. It validates every field, bumps the version and keeps
--   the COO and escalation notification routes in sync with the org emails.
-- * Views and report_snapshot now read thresholds, rates, timezone and currency from org settings.
--   intake.settings keeps only the model prices (USD).
-- * Every audit record stamps the org_config_version that routed it.

-- ---------------------------------------------------------------------------
-- 1. Settings table + history
-- ---------------------------------------------------------------------------
create table intake.organization_settings (
  id                       smallint primary key default 1 check (id = 1),
  org_name                 text not null check (char_length(org_name) between 1 and 120),
  logo_url                 text check (logo_url is null or logo_url ~ '^https://[^\s"''<>]+$'),
  primary_hex              text not null default '#0f172a' check (primary_hex ~ '^#[0-9a-fA-F]{6}$'),
  accent_hex               text not null default '#059669' check (accent_hex  ~ '^#[0-9a-fA-F]{6}$'),
  coo_email                text not null check (char_length(coo_email) <= 254
                                                and coo_email ~* '^[^@\s<>"]+@[^@\s<>"]+\.[^@\s<>"]+$'),
  escalation_lead_email    text not null check (char_length(escalation_lead_email) <= 254
                                                and escalation_lead_email ~* '^[^@\s<>"]+@[^@\s<>"]+\.[^@\s<>"]+$'),
  currency_code            text not null default 'USD' check (currency_code ~ '^[A-Z]{3}$'),
  fx_usd_to_local          numeric(14,6) not null default 1 check (fx_usd_to_local > 0),
  hourly_admin_cost        numeric(12,2) not null default 25 check (hourly_admin_cost >= 0),
  mins_saved_per_ticket    integer not null default 12 check (mins_saved_per_ticket between 0 and 240),
  confidence_threshold     numeric(3,2) not null default 0.85 check (confidence_threshold between 0.50 and 0.99),
  incident_sla_mins        integer not null default 15  check (incident_sla_mins between 5 and 2880),
  ops_sla_mins             integer not null default 240 check (ops_sla_mins between 5 and 2880),
  review_sla_mins          integer not null default 60  check (review_sla_mins between 5 and 2880),
  critical_review_sla_mins integer not null default 15  check (critical_review_sla_mins between 5 and 2880),
  report_timezone          text not null default 'Africa/Nairobi',
  active_branches          jsonb not null default '["Head Office"]'::jsonb
                             check (jsonb_typeof(active_branches) = 'array'
                                    and jsonb_array_length(active_branches) between 1 and 50),
  version                  integer not null default 1,
  updated_at               timestamptz not null default now(),
  updated_by               text not null default 'migration'
);
alter table intake.organization_settings enable row level security;

create table intake.organization_settings_history (
  version     integer primary key,
  snapshot    jsonb not null,
  changed_by  text not null,
  changed_at  timestamptz not null default now()
);
alter table intake.organization_settings_history enable row level security;

create trigger organization_settings_history_immutable
  before update or delete on intake.organization_settings_history
  for each row execute function intake.block_mutation();
create trigger organization_settings_history_no_truncate
  before truncate on intake.organization_settings_history
  for each statement execute function intake.block_truncate();

create or replace function intake.org_settings_record_history()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into intake.organization_settings_history (version, snapshot, changed_by)
  values (new.version, to_jsonb(new), new.updated_by);
  return new;
end;
$$;

create trigger organization_settings_history_write
  after insert or update on intake.organization_settings
  for each row execute function intake.org_settings_record_history();

create trigger organization_settings_no_delete
  before delete on intake.organization_settings
  for each row execute function intake.block_mutation();

-- Demo / default row (placeholders; each deployment sets its own values through 00_org_config_form)
insert into intake.organization_settings (
  org_name, primary_hex, accent_hex, coo_email, escalation_lead_email, currency_code,
  hourly_admin_cost, mins_saved_per_ticket, confidence_threshold, report_timezone, active_branches)
select 'Demo Ops Co.', '#0f172a', '#059669', 'coo@example.com', 'ops-lead@example.com', 'USD',
       coalesce((select value::numeric from intake.settings where key = 'hourly_rate_usd'), 25),
       coalesce((select value::integer from intake.settings where key = 'minutes_saved_per_auto_routed'), 12),
       coalesce((select value::numeric from intake.settings where key = 'ambiguity_threshold'), 0.85),
       coalesce((select value from intake.settings where key = 'report_timezone'), 'Africa/Nairobi'),
       '["Head Office","Branch North","Branch South","Branch East","Branch West","Remote"]'::jsonb;

-- intake.settings now holds only model prices
delete from intake.settings
 where key in ('report_timezone', 'minutes_saved_per_auto_routed', 'hourly_rate_usd', 'ambiguity_threshold');

-- ---------------------------------------------------------------------------
-- 2. Read functions
-- ---------------------------------------------------------------------------
create or replace function intake.get_org_settings()
returns jsonb
language sql
stable
security definer
set search_path = ''
as $$
  select to_jsonb(o) from intake.organization_settings o where id = 1;
$$;

-- Public-safe subset for public pages (intake form, review/audit pages, dashboard)
create or replace function intake.get_org_branding()
returns jsonb
language sql
stable
security definer
set search_path = ''
as $$
  select jsonb_build_object('org_name', org_name, 'logo_url', logo_url, 'primary_hex', primary_hex,
                            'accent_hex', accent_hex, 'currency_code', currency_code,
                            'active_branches', active_branches, 'version', version)
    from intake.organization_settings where id = 1;
$$;

-- ---------------------------------------------------------------------------
-- 3. Write path: validate, version, sync routes
-- ---------------------------------------------------------------------------
create or replace function intake.sync_email_route(p_event text, p_old text, p_new text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_channel text;
begin
  select channel into v_channel
    from intake.notification_routes
   where event_type = p_event and channel in ('gmail', 'outlook', 'smtp')
   order by enabled desc, created_at desc limit 1;
  if v_channel is null then
    select channel into v_channel from intake.notification_routes
     where channel in ('gmail', 'outlook', 'smtp') order by created_at desc limit 1;
  end if;
  v_channel := coalesce(v_channel, 'gmail');

  if p_old is distinct from p_new then
    update intake.notification_routes set enabled = false
     where event_type = p_event and target = p_old and channel in ('gmail', 'outlook', 'smtp');
  end if;
  insert into intake.notification_routes (event_type, channel, target, notes)
  values (p_event, v_channel, p_new, 'synced from organization_settings')
  on conflict (event_type, channel, target) do update set enabled = true;
end;
$$;

create or replace function intake.org_settings_apply(p jsonb, p_actor text)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  allowed constant text[] := array['org_name', 'logo_url', 'primary_hex', 'accent_hex', 'coo_email',
    'escalation_lead_email', 'currency_code', 'fx_usd_to_local', 'hourly_admin_cost',
    'mins_saved_per_ticket', 'confidence_threshold', 'incident_sla_mins', 'ops_sla_mins',
    'review_sla_mins', 'critical_review_sla_mins', 'report_timezone', 'active_branches'];
  email_re constant text := '^[^@\s<>"]+@[^@\s<>"]+\.[^@\s<>"]+$';
  cur    intake.organization_settings;
  v_old  jsonb;
  v_new  jsonb;
  v_err  jsonb := '{}'::jsonb;
  k      text;
  v_num  numeric;
  v_br   jsonb;
  diff   jsonb := '{}'::jsonb;
begin
  if p is null or jsonb_typeof(p) <> 'object' then
    return jsonb_build_object('ok', false, 'errors', jsonb_build_object('_', 'Expected a JSON object.'));
  end if;

  select * into cur from intake.organization_settings where id = 1 for update;
  v_old := to_jsonb(cur);

  for k in select jsonb_object_keys(p) loop
    if not (k = any(allowed)) then
      v_err := v_err || jsonb_build_object(k, 'This setting cannot be changed here.');
    end if;
  end loop;

  -- Normalise: blank logo_url clears it; branches from a newline string are accepted too
  v_new := v_old || (select coalesce(jsonb_object_agg(key, value), '{}'::jsonb)
                       from jsonb_each(p) where key = any(allowed));
  if v_new->>'logo_url' = '' then v_new := v_new || jsonb_build_object('logo_url', null); end if;
  if jsonb_typeof(v_new->'active_branches') = 'string' then
    v_new := v_new || jsonb_build_object('active_branches',
      (select coalesce(jsonb_agg(b order by first_pos), '[]'::jsonb)
         from (select (array_agg(trim(x) order by n))[1] as b, min(n) as first_pos
                 from regexp_split_to_table(v_new->>'active_branches', E'[\\r\\n]+') with ordinality as t(x, n)
                where trim(x) <> ''
                group by lower(trim(x))) s));
  end if;

  if char_length(coalesce(v_new->>'org_name', '')) not between 1 and 120 then
    v_err := v_err || '{"org_name":"Enter a name of 1 to 120 characters."}';
  end if;
  if v_new->>'logo_url' is not null and v_new->>'logo_url' !~ '^https://[^\s"''<>]+$' then
    v_err := v_err || '{"logo_url":"Use an https:// link, or upload a file."}';
  end if;
  if coalesce(v_new->>'primary_hex', '') !~ '^#[0-9a-fA-F]{6}$' then
    v_err := v_err || '{"primary_hex":"Use a 6-digit hex colour like #0f172a."}';
  end if;
  if coalesce(v_new->>'accent_hex', '') !~ '^#[0-9a-fA-F]{6}$' then
    v_err := v_err || '{"accent_hex":"Use a 6-digit hex colour like #059669."}';
  end if;
  if coalesce(v_new->>'coo_email', '') !~* email_re or char_length(v_new->>'coo_email') > 254 then
    v_err := v_err || '{"coo_email":"Enter a valid email address."}';
  end if;
  if coalesce(v_new->>'escalation_lead_email', '') !~* email_re or char_length(v_new->>'escalation_lead_email') > 254 then
    v_err := v_err || '{"escalation_lead_email":"Enter a valid email address."}';
  end if;
  if coalesce(v_new->>'currency_code', '') !~ '^[A-Z]{3}$' then
    v_err := v_err || '{"currency_code":"Use a 3-letter ISO currency code like USD or KES."}';
  end if;
  if not exists (select 1 from pg_catalog.pg_timezone_names where name = v_new->>'report_timezone') then
    v_err := v_err || '{"report_timezone":"Use an IANA time zone like Africa/Nairobi."}';
  end if;

  begin v_num := (v_new->>'fx_usd_to_local')::numeric;
        if v_num is null or v_num <= 0 then raise exception 'x'; end if;
  exception when others then v_err := v_err || '{"fx_usd_to_local":"Enter a rate greater than 0."}'; end;
  begin v_num := (v_new->>'hourly_admin_cost')::numeric;
        if v_num is null or v_num < 0 then raise exception 'x'; end if;
  exception when others then v_err := v_err || '{"hourly_admin_cost":"Enter a cost of 0 or more."}'; end;
  begin v_num := (v_new->>'mins_saved_per_ticket')::numeric;
        if v_num is null or v_num <> trunc(v_num) or v_num not between 0 and 240 then raise exception 'x'; end if;
  exception when others then v_err := v_err || '{"mins_saved_per_ticket":"Enter whole minutes from 0 to 240."}'; end;
  begin v_num := (v_new->>'confidence_threshold')::numeric;
        if v_num is null or v_num not between 0.50 and 0.99 then raise exception 'x'; end if;
  exception when others then v_err := v_err || '{"confidence_threshold":"Enter a value from 0.50 to 0.99."}'; end;
  foreach k in array array['incident_sla_mins', 'ops_sla_mins', 'review_sla_mins', 'critical_review_sla_mins'] loop
    begin v_num := (v_new->>k)::numeric;
          if v_num is null or v_num <> trunc(v_num) or v_num not between 5 and 2880 then raise exception 'x'; end if;
    exception when others then
      v_err := v_err || jsonb_build_object(k, 'Enter whole minutes from 5 to 2880.');
    end;
  end loop;

  v_br := v_new->'active_branches';
  if jsonb_typeof(v_br) <> 'array' or jsonb_array_length(v_br) not between 1 and 50
     or exists (select 1 from jsonb_array_elements(v_br) e
                 where jsonb_typeof(e) <> 'string' or char_length(trim(e #>> '{}')) not between 1 and 80)
     or (select count(distinct lower(trim(e #>> '{}'))) from jsonb_array_elements(v_br) e) <> jsonb_array_length(v_br) then
    v_err := v_err || '{"active_branches":"List 1 to 50 unique branch names, each up to 80 characters."}';
  end if;

  if v_err <> '{}'::jsonb then
    return jsonb_build_object('ok', false, 'errors', v_err);
  end if;

  select coalesce(jsonb_object_agg(key, jsonb_build_object('from', v_old->key, 'to', v_new->key)), '{}'::jsonb)
    into diff
    from unnest(allowed) key
   where v_old->key is distinct from v_new->key;

  if diff = '{}'::jsonb then
    return jsonb_build_object('ok', true, 'result', 'unchanged', 'version', cur.version);
  end if;

  update intake.organization_settings
     set org_name                 = v_new->>'org_name',
         logo_url                 = v_new->>'logo_url',
         primary_hex              = lower(v_new->>'primary_hex'),
         accent_hex               = lower(v_new->>'accent_hex'),
         coo_email                = lower(v_new->>'coo_email'),
         escalation_lead_email    = lower(v_new->>'escalation_lead_email'),
         currency_code            = v_new->>'currency_code',
         fx_usd_to_local          = (v_new->>'fx_usd_to_local')::numeric,
         hourly_admin_cost        = (v_new->>'hourly_admin_cost')::numeric,
         mins_saved_per_ticket    = (v_new->>'mins_saved_per_ticket')::integer,
         confidence_threshold     = (v_new->>'confidence_threshold')::numeric,
         incident_sla_mins        = (v_new->>'incident_sla_mins')::integer,
         ops_sla_mins             = (v_new->>'ops_sla_mins')::integer,
         review_sla_mins          = (v_new->>'review_sla_mins')::integer,
         critical_review_sla_mins = (v_new->>'critical_review_sla_mins')::integer,
         report_timezone          = v_new->>'report_timezone',
         active_branches          = (select jsonb_agg(trim(e #>> '{}')) from jsonb_array_elements(v_new->'active_branches') e),
         version                  = version + 1,
         updated_at               = now(),
         updated_by               = left(coalesce(p_actor, 'unknown'), 254)
   where id = 1
  returning * into cur;

  perform intake.sync_email_route('COO_REPORT',     lower(v_old->>'coo_email'),             cur.coo_email);
  perform intake.sync_email_route('SLA_ESCALATION', lower(v_old->>'escalation_lead_email'), cur.escalation_lead_email);

  return jsonb_build_object('ok', true, 'result', 'applied', 'version', cur.version, 'changes', diff);
end;
$$;

-- Rollback is a forward change: it re-applies an earlier snapshot as a new version
create or replace function intake.org_settings_rollback(p_version integer, p_actor text)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_snap jsonb;
begin
  select snapshot into v_snap from intake.organization_settings_history where version = p_version;
  if v_snap is null then
    return jsonb_build_object('ok', false, 'errors', jsonb_build_object('version', 'No such version.'));
  end if;
  return intake.org_settings_apply(v_snap - 'id' - 'version' - 'updated_at' - 'updated_by',
                                   coalesce(p_actor, 'unknown') || ' (rollback to v' || p_version || ')');
end;
$$;

-- ---------------------------------------------------------------------------
-- 4. CONFIG_CHANGED event, org_config_version on records, org_snapshot on reports
-- ---------------------------------------------------------------------------
alter table intake.notification_routes drop constraint notification_routes_event_type_check;
alter table intake.notification_routes add constraint notification_routes_event_type_check
  check (event_type in ('INCIDENT_ALERT', 'QUEUE_NOTICE', 'REVIEW_REQUEST', 'REVIEW_DECIDED',
                        'DOWNSTREAM_DISPATCH', 'SLA_ESCALATION', 'COO_REPORT', 'ERROR_ALERT',
                        'CONFIG_CHANGED'));

alter table intake.intake_audit_logs add column org_config_version integer;
alter table intake.executive_reports add column org_snapshot jsonb;

create or replace function intake.stamp_org_config_version()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if new.org_config_version is null and not new.is_demo then
    new.org_config_version := (select version from intake.organization_settings where id = 1);
  end if;
  return new;
end;
$$;

create trigger intake_audit_logs_stamp_config
  before insert on intake.intake_audit_logs
  for each row execute function intake.stamp_org_config_version();

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
      rule_calibration, ai_model, html, delivered_to, org_snapshot)
    values ((p->>'period_start')::date, (p->>'period_end')::date, p->>'origin_execution_id',
      p->>'run_kind', coalesce(p->>'data_scope', 'live'), p->'snapshot', p->'synthesis',
      p->>'synthesis_status', p->>'roi_headline', p->'bleed_diagnostics', p->'rule_calibration',
      p->>'ai_model', p->>'html', coalesce(p->'delivered_to', '[]'::jsonb),
      coalesce(p->'org_snapshot', intake.get_org_settings()))
    returning * into r;
  exception when unique_violation then
    return jsonb_build_object('ok', false, 'result', 'duplicate_scheduled_report');
  end;
  return jsonb_build_object('ok', true, 'result', 'archived', 'id', r.id);
end;
$$;

-- ---------------------------------------------------------------------------
-- 5. Views read org settings (one source of truth). Money is shown in the org's currency.
-- ---------------------------------------------------------------------------
create or replace view intake.vw_intake_facts as
with s as (
  select report_timezone as tz, confidence_threshold as amb from intake.organization_settings where id = 1
),
f as (
  select l.*, (l.created_at at time zone s.tz) as local_ts, s.amb,
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
  case when sla_closed_at is not null
       then round(greatest(0, extract(epoch from sla_closed_at - sla_deadline) / 60)::numeric, 1)
       else 0 end                                                       as sla_overrun_min,
  resolved_at,
  round((extract(epoch from resolved_at - created_at) / 60)::numeric, 1) as ttr_minutes,
  ai_cost_usd,
  ai_cost_estimated,
  (sla_closed_at is null and status not in ('REJECTED', 'RESOLVED') and sla_deadline < now())
                                                                        as open_overdue,
  org_config_version
from f;

drop view intake.vw_executive_live_dashboard;
create view intake.vw_executive_live_dashboard as
with s as (
  select mins_saved_per_ticket::numeric as mins, hourly_admin_cost as rate, fx_usd_to_local as fx,
         currency_code as ccy
    from intake.organization_settings where id = 1
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
         coalesce(sum(ai_cost_usd), 0)                                         as ai_cost_usd_raw,
         bool_or(ai_cost_estimated)                                            as ai_cost_includes_estimates,
         count(distinct org_config_version)                                    as config_versions_in_period
    from intake.vw_intake_facts
   group by period_month, data_scope
)
select m.period_month, m.data_scope, s.ccy                                     as currency_code,
       m.total_requests,
       lag(m.total_requests) over w                                            as prior_month_requests,
       round((m.total_requests - lag(m.total_requests) over w) * 100.0
             / nullif(lag(m.total_requests) over w, 0), 1)                     as mom_delta_pct,
       m.auto_routed, m.incident_desk, m.operations_queue, m.human_review,
       round(m.auto_routed * s.mins / 60, 1)                                   as admin_hours_saved,
       round(m.auto_routed * s.mins / 60 * s.rate, 2)                          as labor_value_local,
       round(m.ai_cost_usd_raw, 2)                                             as ai_cost_usd,
       round(m.ai_cost_usd_raw * s.fx, 2)                                      as ai_cost_local,
       m.ai_cost_includes_estimates,
       round(m.auto_routed * s.mins / 60 * s.rate / nullif(m.ai_cost_usd_raw * s.fx, 0), 1) as roi_multiple,
       round(m.sla_met * 100.0 / nullif(m.sla_measurable, 0), 1)               as sla_compliance_pct,
       m.sla_breaches, m.ambiguity_rate_pct, m.avg_frustration, m.sensitive_catches,
       m.injection_blocks, m.low_confidence_holds, m.decisions, m.overrides,
       round(m.overrides * 100.0 / nullif(m.decisions, 0), 1)                  as override_rate_pct,
       m.mean_ttr_min, m.p95_ttr_min, m.mean_approval_latency_min,
       m.config_versions_in_period
  from m cross join s
window w as (partition by m.data_scope order by m.period_month);

grant select on intake.vw_executive_live_dashboard to bi_reader;

-- report_snapshot: assumptions now come from org settings, plus the config versions in force
create or replace function intake.report_snapshot(p_month date, p_scope text default 'live')
returns jsonb
language sql
stable
security definer
set search_path = ''
as $$
  with p as (select date_trunc('month', p_month)::date as m, p_scope as sc),
  facts as (select f.* from intake.vw_intake_facts f, p where f.period_month = p.m and f.data_scope = p.sc),
  org as (select o.* from intake.organization_settings o where id = 1)
  select jsonb_build_object(
    'period_start', (select m from p),
    'period_end',   (select (m + interval '1 month')::date from p),
    'scope',        p_scope,
    'currency_code', (select currency_code from org),
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
    'bleed_candidates', coalesce((select jsonb_agg(c order by (c->>'hours_lost')::numeric desc)
       from (select c from (
               select jsonb_build_object('dimension', 'branch_route', 'key', submitting_branch || ' / ' || route_destination,
                        'sla_breaches', count(*) filter (where sla_breached_effective),
                        'open_overdue', count(*) filter (where open_overdue),
                        'p95_ttr_min', round(percentile_cont(0.95) within group (order by ttr_minutes)::numeric, 1),
                        'hours_lost', round(sum(sla_overrun_min) / 60, 1)) c
                 from facts group by submitting_branch, route_destination
               union all
               select jsonb_build_object('dimension', 'channel_ambiguity', 'key', inbound_channel,
                        'ambiguous_requests', count(*) filter (where is_ambiguous),
                        'hours_lost', round(count(*) filter (where is_ambiguous)
                                            * (select mins_saved_per_ticket from org) / 60.0, 1))
                 from facts group by inbound_channel
               union all
               select jsonb_build_object('dimension', 'review_hold', 'key', rule_applied,
                        'held', count(*),
                        'approved_unchanged', count(*) filter (where human_final_decision = 'APPROVED'),
                        'hours_lost', round(coalesce(sum(approval_latency_min) filter (where human_final_decision = 'APPROVED'), 0) / 60, 1))
                 from facts where route_destination = 'HUMAN_REVIEW' group by rule_applied
             ) u
             where (c->>'hours_lost')::numeric > 0 or coalesce((c->>'open_overdue')::int, 0) > 0
             order by (c->>'hours_lost')::numeric desc
             limit 6) t), '[]'::jsonb),
    'config_changes', coalesce((select jsonb_agg(jsonb_build_object('version', h.version, 'changed_at', h.changed_at,
                                   'confidence_threshold', h.snapshot->'confidence_threshold',
                                   'incident_sla_mins', h.snapshot->'incident_sla_mins',
                                   'ops_sla_mins', h.snapshot->'ops_sla_mins',
                                   'review_sla_mins', h.snapshot->'review_sla_mins') order by h.version)
                                  from intake.organization_settings_history h, p
                                 where h.changed_at >= p.m and h.changed_at < p.m + interval '1 month'), '[]'::jsonb),
    'assumptions', (select jsonb_build_object(
       'report_timezone', report_timezone,
       'currency_code', currency_code,
       'mins_saved_per_ticket', mins_saved_per_ticket,
       'hourly_admin_cost', hourly_admin_cost,
       'fx_usd_to_local', fx_usd_to_local,
       'confidence_threshold', confidence_threshold,
       'definitions', jsonb_build_object(
         'admin_hours_saved', 'Auto-routed requests (Incident Desk + Operations Queue) x manual triage minutes avoided.',
         'labor_value_local', 'Admin hours saved x hourly admin cost, in the organisation''s currency.',
         'roi_multiple', 'Labour value avoided / AI spend (converted to local currency at the configured FX rate).',
         'sla_compliance_pct', 'Items whose SLA outcome is known that met it. Review items: decided by the deadline. Others: resolved by the deadline.',
         'ttr', 'resolved_at - created_at (work completed, via team link or ticketing callback).',
         'override', 'Reviewer approved the work but sent it to a different destination than the rules proposed.',
         'hours_lost', 'Closed items only: SLA overrun, ambiguity rework, and review wait on items later approved unchanged. Still-open overdue items are counted separately as open_overdue.'))
       from org)
  );
$$;

-- ---------------------------------------------------------------------------
-- 6. Privileges
-- ---------------------------------------------------------------------------
revoke all on all functions in schema intake from public, anon, authenticated;
grant execute on function
  intake.get_org_settings(),
  intake.get_org_branding(),
  intake.org_settings_apply(jsonb, text),
  intake.org_settings_rollback(integer, text),
  intake.report_archive(jsonb),
  intake.report_snapshot(date, text)
to n8n_intake;
-- sync_email_route and the trigger functions stay internal.
