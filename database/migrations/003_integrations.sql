-- Integrations: channel-agnostic notification routing.
-- Workflows never hard-code a channel. They send a neutral message with an event_type to the
-- 05 Notification Dispatcher. The dispatcher looks up routes here and fans out to Gmail, Outlook,
-- SMTP, Slack, Teams or a signed webhook into Jira, ServiceNow, Zendesk, Zapier, Make and others.
-- A client is re-pointed by editing rows. Nobody edits a workflow.
--
-- target formats:
--   gmail / outlook / smtp : an email address, or '$requester' (the request's own requester_email)
--   slack                  : channel name or id, e.g. '#ops-incidents'
--   teams                  : '<teamId>/<channelId>'
--   webhook                : https URL (POST, JSON body, X-Intake-Signature: sha256=<hmac>)

create table intake.notification_routes (
  id          uuid primary key default gen_random_uuid(),
  event_type  text not null check (event_type in (
                'INCIDENT_ALERT', 'QUEUE_NOTICE', 'REVIEW_REQUEST', 'REVIEW_DECIDED',
                'DOWNSTREAM_DISPATCH', 'SLA_ESCALATION', 'COO_REPORT', 'ERROR_ALERT')),
  channel     text not null check (channel in ('gmail', 'outlook', 'smtp', 'slack', 'teams', 'webhook')),
  target      text not null check (char_length(target) between 1 and 500),
  enabled     boolean not null default true,
  is_demo     boolean not null default false,
  notes       text,
  created_at  timestamptz not null default now(),
  unique (event_type, channel, target),
  check (channel <> 'webhook' or target like 'https://%')
);
alter table intake.notification_routes enable row level security;
-- Routes are admin-managed in SQL. n8n gets read access only, through get_routes().

create or replace function intake.get_routes(p_event_type text)
returns jsonb
language sql
stable
security definer
set search_path = ''
as $$
  select coalesce(jsonb_agg(jsonb_build_object(
           'route_id', id, 'event_type', event_type, 'channel', channel, 'target', target)
           order by channel, target), '[]'::jsonb)
    from intake.notification_routes
   where event_type = p_event_type and enabled;
$$;

revoke all on function intake.get_routes(text) from public, anon, authenticated;
grant execute on function intake.get_routes(text) to n8n_intake;
