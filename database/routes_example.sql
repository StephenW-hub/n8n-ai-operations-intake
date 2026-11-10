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
-- Open a ticket in Jira / ServiceNow / Zendesk via Zapier, Make or a native inbound webhook (HMAC-signed JSON):
--   insert into intake.notification_routes (event_type, channel, target) values ('DOWNSTREAM_DISPATCH', 'webhook', 'https://hooks.zapier.com/hooks/catch/...');
-- Pause a route without deleting it:
--   update intake.notification_routes set enabled = false where id = '<route id>';

-- Google Chat space (incoming webhook URL) / Teams channel via a Teams "Workflows" webhook URL:
--   insert into intake.notification_routes (event_type, channel, target) values ('REVIEW_REQUEST', 'google_chat', 'https://chat.googleapis.com/v1/spaces/.../messages?key=...');
--   insert into intake.notification_routes (event_type, channel, target) values ('INCIDENT_ALERT', 'teams', 'https://<tenant>.webhook.office.com/...');

-- ---------------------------------------------------------------------------
-- CRM / ticketing (one enabled row per event + system). The ticket is created when a request clears
-- the gate, and later events (escalation, decision) update the same ticket.
-- ---------------------------------------------------------------------------
-- insert into intake.ticket_routes (event_type, system, config) values
--   ('TICKET_CREATE', 'jira',       '{"project_key":"OPS","issue_type":"Task"}'),
--   ('TICKET_UPDATE', 'jira',       '{"project_key":"OPS"}');
-- Zendesk:    ('TICKET_CREATE', 'zendesk',    '{"tags":["ops-intake"]}')
-- HubSpot:    ('TICKET_CREATE', 'hubspot',    '{"pipeline":"0","stage":"1"}')
-- Salesforce: ('TICKET_CREATE', 'salesforce', '{"origin":"Ops Intake"}')
-- Anything else (ServiceNow, Freshdesk, Monday, ClickUp, Zapier, Make):
--             ('TICKET_CREATE', 'webhook',    '{"url":"https://..."}')

-- ---------------------------------------------------------------------------
-- Document storage (exactly one enabled target). Files never go into Postgres; only the link,
-- checksum and safe file name are kept in the audit record.
-- ---------------------------------------------------------------------------
-- insert into intake.storage_targets (provider, config) values ('gdrive', '{"folder_id":"<private folder id>"}');
-- SharePoint: ('sharepoint', '{"site_id":"...","drive_id":"...","folder_id":"..."}')
-- OneDrive:   ('onedrive',   '{"folder_id":"..."}')
-- AWS S3:     ('s3',         '{"bucket":"client-ops-intake","prefix":"attachments/","region":"eu-west-1"}')
-- Optional external malware scan before upload: add "scan_url":"https://..." to the config.
