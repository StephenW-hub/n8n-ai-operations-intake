-- Demo data v2 for the Executive Intelligence engine. It holds three prior calendar months of synthetic
-- requests across all six dimensions, every row flagged is_demo = true (data_scope = 'demo' in the
-- views), so live KPIs stay clean. Deterministic (setseed): the demo dashboard looks the same on every
-- install. Run as the database owner after schema.sql.
--
-- Seeded patterns that the report and dashboard should surface:
--   * Monday and mid-morning / mid-afternoon peaks (time dimension)
--   * WhatsApp: more ambiguity and higher frustration (channel dimension)
--   * Branch East: TTR bottleneck, P95 about 3x the other branches (branch dimension)
--   * LOW_CONFIDENCE holds are ~85% approved unchanged (override drift -> calibration 0.85 -> 0.80)
--   * Mixed MEDICAL / LEGAL / FINANCIAL / PII interceptions; injection attempts mostly rejected
--   * Month-over-month growth (81 -> 94 -> 108)

select setseed(0.42);

insert into intake.requester_directory (contact, branch, department)
values ('demo.requester@example.com', 'Head Office', 'Operations')
on conflict do nothing;

with s as (
  select coalesce((select value from intake.settings where key = 'report_timezone'), 'UTC') as tz
),
gen as (
  select k, g from (values (1, 108), (2, 94), (3, 81)) v(k, n), generate_series(1, n) g
),
r as (
  select k, g, random() r1, random() r2, random() r3, random() r4, random() r5, random() r6,
         random() r7, random() r8, random() r9, random() r10, random() r11, random() r12,
         random() r13, random() r14, random() r15, random() r16
    from gen
),
a as (
  select r.*, s.tz,
         (date_trunc('month', now() at time zone s.tz) - make_interval(months => k)) as m_start,
         case when r5 < 0.45 then 'web_form' when r5 < 0.75 then 'email'
              when r5 < 0.95 then 'whatsapp' else 'api' end as channel,
         case when r6 < 0.34 then 'Head Office' when r6 < 0.50 then 'Branch North'
              when r6 < 0.65 then 'Branch South' when r6 < 0.81 then 'Branch East'
              when r6 < 0.93 then 'Branch West' else 'Remote' end as branch,
         (array['Finance','IT','Operations','HR','Campus/Facilities','Customer Service'])[1 + floor(r7 * 6)::int] as department,
         (array[8,9,9,9,10,10,10,10,11,11,12,13,14,14,15,15,15,16,17,18,19,21])[1 + floor(r3 * 22)::int] as hr
    from r cross join s
),
b as (
  select a.*,
         case when r8 < 0.10 then 'INCIDENT_DESK'
              when r8 < 0.30 + case when channel = 'whatsapp' then 0.12 else 0 end then 'HUMAN_REVIEW'
              else 'OPERATIONS_QUEUE' end as route,
         -- day: 12% snapped to the Monday of that week (inside the month)
         greatest(m_start, case when r2 < 0.12
                                then date_trunc('week', m_start + make_interval(days => floor(r1 * 28)::int))
                                else m_start + make_interval(days => floor(r1 * 28)::int) end)
           + make_interval(hours => hr, mins => floor(r4 * 60)::int) as local_ts
    from a
),
c as (
  select b.*,
         (local_ts at time zone tz) as created_at,
         case when route <> 'HUMAN_REVIEW' then null
              when r9 < case when channel = 'whatsapp' then 0.70 else 0.55 end then 'LOW_CONFIDENCE'
              when r9 < 0.88 then 'SENSITIVE_DATA'
              else 'PROMPT_INJECTION' end as hr_kind,
         (branch = 'Branch East') as east
    from b
),
d as (
  select c.*,
         case when hr_kind = 'LOW_CONFIDENCE' then round((0.55 + r10 * 0.29)::numeric, 3)
              else round((0.86 + r10 * 0.13)::numeric, 3) end as conf,
         case when route = 'INCIDENT_DESK' then 'CRITICAL'
              when route = 'OPERATIONS_QUEUE' then case when r10 < 0.6 then 'LOW' else 'MEDIUM' end
              when hr_kind = 'SENSITIVE_DATA' then case when r4 < 0.12 then 'CRITICAL' else 'HIGH' end
              when hr_kind = 'LOW_CONFIDENCE' then 'MEDIUM'
              else 'LOW' end as urgency,
         case when hr_kind = 'SENSITIVE_DATA' then
                case when r7 < 0.25 then 'MEDICAL' when r7 < 0.45 then 'LEGAL'
                     when r7 < 0.75 then 'FINANCIAL' else 'PII' end
              else 'NONE' end as category,
         case when hr_kind is null then null
              when hr_kind = 'LOW_CONFIDENCE' then case when r12 < 0.85 then 'APPROVED' when r12 < 0.93 then 'OVERRIDDEN' else 'REJECTED' end
              when hr_kind = 'SENSITIVE_DATA' then case when r12 < 0.70 then 'APPROVED' when r12 < 0.80 then 'OVERRIDDEN' else 'REJECTED' end
              else case when r12 < 0.90 then 'REJECTED' else 'APPROVED' end end as decision,
         case when r13 < 0.75 then 8 + r14 * 45 else 65 + r14 * 150 end as approval_min,
         case when route = 'OPERATIONS_QUEUE' then (case when r13 < 0.85 then 30 + r14 * 190 else 250 + r14 * 400 end) * case when east then 3 else 1 end
              when route = 'INCIDENT_DESK'    then (case when r13 < 0.80 then 4 + r14 * 10 else 16 + r14 * 45 end) * case when east then 2.5 else 1 end
              else (60 + r15 * 300) * case when east then 3 else 1 end end as work_min,
         (k = 1 and r16 < 0.06) as still_open
    from c
),
e as (
  select d.*,
         case when route = 'HUMAN_REVIEW' then case when urgency = 'CRITICAL' then 'INCIDENT_DESK' else 'OPERATIONS_QUEUE' end end as post_route,
         case when route = 'INCIDENT_DESK' then 15 when route = 'OPERATIONS_QUEUE' then 240
              when urgency = 'CRITICAL' then 15 else 60 end as sla_min
    from d
),
f as (
  select e.*,
         case when route <> 'HUMAN_REVIEW' then route
              when hr_kind = 'LOW_CONFIDENCE' then case when r11 < 0.8 then 'OPERATIONS_QUEUE' else 'INCIDENT_DESK' end
              when hr_kind = 'PROMPT_INJECTION' then 'OPERATIONS_QUEUE'
              else post_route end as ai_route,
         case decision when 'APPROVED' then post_route
                       when 'OVERRIDDEN' then case when post_route = 'OPERATIONS_QUEUE' then 'INCIDENT_DESK' else 'OPERATIONS_QUEUE' end
         end as final_route,
         case when route = 'HUMAN_REVIEW' then created_at + make_interval(secs => approval_min * 60) end as reviewed_at
    from e
),
g as (
  select f.*,
         case when route <> 'HUMAN_REVIEW' then case when still_open then null else created_at + make_interval(secs => work_min * 60) end
              when decision = 'REJECTED' then reviewed_at
              when still_open then null
              else reviewed_at + make_interval(secs => work_min * 60) end as resolved_at,
         case when route = 'HUMAN_REVIEW' then approval_min > sla_min
              when still_open then true
              else work_min > sla_min end as breached
    from f
)
insert into intake.intake_audit_logs (
  origin_execution_id, inbound_channel, requester_email, submitting_branch, department,
  request_text, concise_brief, intent, urgency, urgency_score, confidence_score,
  sentiment_frustration_score, ai_model, models_used, ai_input_tokens, ai_output_tokens,
  ai_cost_usd, review_brief, review_model, sensitive_flags, sensitive_data_category,
  injection_flags, ai_predicted_route, route_destination, post_review_route, rule_applied,
  sla_minutes, sla_deadline, status, reviewer_id, human_final_decision, human_final_route,
  human_reviewed_at, resolved_at, resolution_source, sla_breached, escalated_at,
  is_test, is_demo, decision_history, created_at)
select
  'demo-v2-' || k || '-' || g,
  channel,
  'demo.requester@example.com',
  branch,
  department,
  '[demo] synthetic request ' || k || '-' || g,
  '[demo] ' || case route when 'INCIDENT_DESK' then 'Service outage reported'
                          when 'HUMAN_REVIEW' then 'Request held for review'
                          else 'Routine operational request' end,
  case when route = 'INCIDENT_DESK' then (array['payment_gateway_outage','network_outage','system_down'])[1 + g % 3]
       when hr_kind = 'LOW_CONFIDENCE' then 'unclear_request'
       when hr_kind = 'SENSITIVE_DATA' then 'records_request'
       when hr_kind = 'PROMPT_INJECTION' then 'policy_override_attempt'
       else (array['access_request','facilities_repair','report_request','procurement'])[1 + g % 4] end,
  urgency,
  case urgency when 'CRITICAL' then 0.95 when 'HIGH' then 0.75 when 'MEDIUM' then 0.5 else 0.25 end,
  conf,
  round(least(0.99, 0.12 + r15 * 0.30
                    + case channel when 'whatsapp' then 0.25 when 'email' then 0.05 else 0 end
                    + case when breached then 0.15 else 0 end
                    + case when hr_kind = 'LOW_CONFIDENCE' then 0.08 else 0 end)::numeric, 3),
  'claude-sonnet-5-5',
  case when route = 'HUMAN_REVIEW' then '["claude-sonnet-5-5","claude-opus-5-5"]'::jsonb else '["claude-sonnet-5-5"]'::jsonb end,
  (1400 + r16 * 600)::int + case when route = 'HUMAN_REVIEW' then 2000 else 0 end,
  (250 + r14 * 150)::int  + case when route = 'HUMAN_REVIEW' then 700 else 0 end,
  round(((1400 + r16 * 600) * 2 + (250 + r14 * 150) * 10
         + case when route = 'HUMAN_REVIEW' then 2000 * 4 + 700 * 20 else 0 end)::numeric / 1e6, 6),
  case when route = 'HUMAN_REVIEW' then '[demo] reviewer brief' end,
  case when route = 'HUMAN_REVIEW' then 'claude-opus-5-5' end,
  case when category <> 'NONE' then jsonb_build_array(lower(category)) else '[]'::jsonb end,
  category,
  case when hr_kind = 'PROMPT_INJECTION' then '["instruction_override"]'::jsonb else '[]'::jsonb end,
  ai_route,
  route,
  post_route,
  case when route = 'INCIDENT_DESK' then 'CRITICAL_INCIDENT'
       when route = 'OPERATIONS_QUEUE' then 'DEFAULT_QUEUE' else hr_kind end,
  sla_min,
  created_at + make_interval(mins => sla_min),
  case when route = 'OPERATIONS_QUEUE' then case when resolved_at is null then 'QUEUED' else 'RESOLVED' end
       when route = 'INCIDENT_DESK'    then case when resolved_at is null then 'OPEN_INCIDENT' else 'RESOLVED' end
       when decision = 'REJECTED' then 'REJECTED'
       when resolved_at is null then decision
       else 'RESOLVED' end,
  case when route = 'HUMAN_REVIEW' then 'demo.reviewer@example.com' end,
  decision,
  final_route,
  reviewed_at,
  resolved_at,
  case when resolved_at is null then null
       when decision = 'REJECTED' then 'review_reject'
       when r16 < 0.5 then 'ticketing_callback' else 'team_link' end,
  breached,
  case when breached and (route = 'HUMAN_REVIEW' or route = 'INCIDENT_DESK')
       then created_at + make_interval(mins => sla_min + 5) end,
  false,
  true,
  jsonb_build_array(jsonb_build_object('step', 'DEMO_SEED', 'at', created_at)),
  created_at
from g
on conflict (origin_execution_id) do nothing;
