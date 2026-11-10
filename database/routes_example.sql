-- Example notification routes. Copy this, replace the targets, and run it as the database owner.
-- Each event can fan out to several channels. To re-point a client, edit these rows; the workflows stay as they are.
-- Channels: gmail | outlook | smtp | slack | teams | webhook

insert into intake.notification_routes (event_type, channel, target, notes) values
  -- Simple setup: one email inbox for everything (pick gmail, outlook or smtp to match the client)
  ('INCIDENT_ALERT',      'gmail',   'incident-desk@example.com',  'Critical incidents'),
  ('QUEUE_NOTICE',        'gmail',   'ops-queue@example.com',      'Routine requests'),
  ('REVIEW_REQUEST',      'gmail',   'reviewers@example.com',      'Approval cards with Approve/Reject links'),
  ('REVIEW_DECIDED',      'gmail',   '$requester',                 'Tell the requester the outcome (only on an authenticated intake)'),
  ('DOWNSTREAM_DISPATCH', 'gmail',   'ops-queue@example.com',      'Approved items handed to the target team'),
  ('SLA_ESCALATION',      'gmail',   'ops-manager@example.com',    'Overdue reviews'),
  ('COO_REPORT',          'gmail',   'coo@example.com',            'Monthly executive briefing'),
  ('ERROR_ALERT',         'gmail',   'automation-admin@example.com','Workflow failures')
on conflict do nothing;

-- Microsoft 365 client instead of Gmail:
--   update intake.notification_routes set channel = 'outlook' where channel = 'gmail';
-- Slack for incidents as well as email:
--   insert into intake.notification_routes (event_type, channel, target) values ('INCIDENT_ALERT', 'slack', '#ops-incidents');
-- Microsoft Teams channel:
--   insert into intake.notification_routes (event_type, channel, target) values ('INCIDENT_ALERT', 'teams', '<teamId>/<channelId>');
-- Open a ticket in Jira / ServiceNow / Zendesk via Zapier, Make or a native inbound webhook (HMAC-signed JSON):
--   insert into intake.notification_routes (event_type, channel, target) values ('DOWNSTREAM_DISPATCH', 'webhook', 'https://hooks.zapier.com/hooks/catch/...');
-- Pause a route without deleting it:
--   update intake.notification_routes set enabled = false where id = '<route id>';
