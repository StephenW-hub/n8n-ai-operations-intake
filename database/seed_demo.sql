-- Optional demo data for the monthly COO report: synthetic records over the previous two calendar
-- months, all flagged is_demo = true. Reports ignore them unless include_demo = true, so real KPIs
-- stay clean. Deterministic (setseed), so the demo report looks the same on every install.
-- Run as the database owner (for example in the Supabase SQL editor). The rows are append-only.

select setseed(0.42);

with params as (
  select date_trunc('month', now()) - interval '1 month' as last_m,
         date_trunc('month', now()) - interval '2 month' as prev_m
),
gen as (
  -- 84 records last month, 66 the month before (MoM growth)
  select g, (select last_m from params) + (random() * 27 + 1) * interval '1 day' + random() * interval '10 hours' as ts
    from generate_series(1, 84) g
  union all
  select 1000 + g, (select prev_m from params) + (random() * 27 + 1) * interval '1 day' + random() * interval '10 hours'
    from generate_series(1, 66) g
),
shaped as (
  select g, ts,
         (array['Finance','IT','Operations','HR','Campus/Facilities','Customer Service'])[1 + (g * 7 % 6)] as department,
         case when g % 10 in (0, 1) then 'HUMAN_REVIEW'
              when g % 10 = 2       then 'INCIDENT_DESK'
              else 'OPERATIONS_QUEUE' end as route,
         g % 3 as hr_kind,
         random() as r1, random() as r2
    from gen
)
insert into intake.intake_audit_logs (
  origin_execution_id, channel, requester_email, department, request_text, concise_brief, intent,
  urgency, urgency_score, confidence_score, ai_model, models_used, review_brief, review_model,
  sensitive_flags, injection_flags, route, rule_applied, sla_minutes, sla_deadline, status,
  reviewer_id, review_decision, reviewed_at, resolved_at, escalated_at, is_test, is_demo,
  decision_history, created_at)
select
  'demo-' || g,
  'form',
  'demo.requester@example.com',
  department,
  '[demo] synthetic request #' || g,
  '[demo] ' || case route when 'INCIDENT_DESK' then 'Service outage reported'
                          when 'HUMAN_REVIEW'  then 'Request held for review'
                          else 'Routine operational request' end,
  case route when 'INCIDENT_DESK' then (array['payment_gateway_outage','network_outage','system_down'])[1 + g % 3]
             when 'HUMAN_REVIEW'  then (array['records_request','unclear_request','policy_question'])[1 + hr_kind]
             else (array['access_request','facilities_repair','report_request','procurement'])[1 + g % 4] end,
  case route when 'INCIDENT_DESK' then 'CRITICAL' when 'HUMAN_REVIEW' then 'MEDIUM' else 'LOW' end,
  case route when 'INCIDENT_DESK' then 0.95 else round((0.2 + r1 * 0.4)::numeric, 3) end,
  case when route = 'HUMAN_REVIEW' and hr_kind = 1 then round((0.45 + r2 * 0.35)::numeric, 3)
       else round((0.86 + r2 * 0.13)::numeric, 3) end,
  'claude-sonnet-5-5',
  case when route = 'HUMAN_REVIEW' then '["claude-sonnet-5-5","claude-opus-5-5"]'::jsonb
       else '["claude-sonnet-5-5"]'::jsonb end,
  case when route = 'HUMAN_REVIEW' then '[demo] reviewer brief' end,
  case when route = 'HUMAN_REVIEW' then 'claude-opus-5-5' end,
  case when route = 'HUMAN_REVIEW' and hr_kind = 0 then '["national_id"]'::jsonb else '[]'::jsonb end,
  case when route = 'HUMAN_REVIEW' and hr_kind = 2 then '["instruction_override"]'::jsonb else '[]'::jsonb end,
  route,
  case route when 'INCIDENT_DESK' then 'CRITICAL_INCIDENT'
             when 'OPERATIONS_QUEUE' then 'DEFAULT_QUEUE'
             else (array['SENSITIVE_DATA','LOW_CONFIDENCE','PROMPT_INJECTION'])[1 + hr_kind] end,
  case route when 'INCIDENT_DESK' then 15 when 'HUMAN_REVIEW' then 60 else 240 end,
  ts + make_interval(mins => case route when 'INCIDENT_DESK' then 15 when 'HUMAN_REVIEW' then 60 else 240 end),
  case route when 'INCIDENT_DESK' then 'OPEN_INCIDENT' when 'OPERATIONS_QUEUE' then 'QUEUED'
             else case when r1 < 0.8 then 'APPROVED' else 'REJECTED' end end,
  case when route = 'HUMAN_REVIEW' then 'demo.reviewer@example.com' end,
  case when route = 'HUMAN_REVIEW' then case when r1 < 0.8 then 'APPROVED' else 'REJECTED' end end,
  -- ~75% of reviews decided inside the 60-minute SLA, the rest late (and escalated)
  case when route = 'HUMAN_REVIEW' then ts + make_interval(mins => case when r2 < 0.75 then 20 + (r1 * 35)::int else 75 + (r1 * 90)::int end) end,
  case when route = 'HUMAN_REVIEW' then ts + make_interval(mins => case when r2 < 0.75 then 20 + (r1 * 35)::int else 75 + (r1 * 90)::int end) end,
  case when route = 'HUMAN_REVIEW' and r2 >= 0.75 then ts + interval '70 minutes' end,
  false,
  true,
  jsonb_build_array(jsonb_build_object('step', 'DEMO_SEED', 'at', ts)),
  ts
from shaped
on conflict (origin_execution_id) do nothing;
