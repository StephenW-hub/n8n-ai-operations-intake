-- 012: Linear as a ticketing system (config: {"team_id": "<uuid>", "team_key": "OPS"}).
alter table intake.ticket_routes drop constraint ticket_routes_system_check;
alter table intake.ticket_routes add constraint ticket_routes_system_check
  check (system in ('jira', 'zendesk', 'hubspot', 'salesforce', 'linear', 'webhook'));
alter table intake.ticket_routes add constraint ticket_routes_linear_team_check
  check (system <> 'linear' or (config->>'team_id') ~ '^[0-9a-f-]{36}$');
