-- Fix: "hours lost" counted overrun for still-open items up to now(), so a few stale items inflated
-- the bleed ranking (e.g. 950+ hours on one branch). Overrun now counts only once the SLA step has
-- closed, and still-open overdue items are reported separately as open_overdue.

create or replace view intake.vw_intake_facts as
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
  -- Overrun counts only once the SLA step has closed, so open items don't accrue unbounded "lost hours"
  case when sla_closed_at is not null
       then round(greatest(0, extract(epoch from sla_closed_at - sla_deadline) / 60)::numeric, 1)
       else 0 end                                                       as sla_overrun_min,
  resolved_at,
  round((extract(epoch from resolved_at - created_at) / 60)::numeric, 1) as ttr_minutes,
  ai_cost_usd,
  ai_cost_estimated,
  (sla_closed_at is null and status not in ('REJECTED', 'RESOLVED') and sla_deadline < now())
                                                                        as open_overdue
from f;

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
                        'open_overdue', count(*) filter (where open_overdue),
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
             where (c->>'hours_lost')::numeric > 0 or coalesce((c->>'open_overdue')::int, 0) > 0
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
         'hours_lost', 'Closed items only: SLA overrun, ambiguity rework, and review wait on items later approved unchanged. Still-open overdue items are counted separately as open_overdue.'))
       from settings)
  );
$$;
