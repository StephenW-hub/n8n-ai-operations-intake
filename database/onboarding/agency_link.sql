-- Onboarding: link a client deployment to the agency Command Center (Module 8).
-- Run as the CLIENT database owner in the client's Supabase SQL editor, after schema.sql.
-- Nothing here is sent anywhere. Secrets are created inside Vault and never printed in this repo,
-- in workflow JSON or in chat.
--
-- 1. Generate two random secrets inside the client database (run once):
select vault.create_secret(encode(extensions.gen_random_bytes(32), 'hex'),
                           'ops_intake_telemetry_secret', 'client -> agency telemetry signing');
select vault.create_secret(encode(extensions.gen_random_bytes(32), 'hex'),
                           'ops_intake_patch_secret', 'agency -> client patch verification');

-- 2. Link the deployment. client_id is issued by the agency registry; region is the hosting region.
--    The endpoint is the agency's A1 telemetry receiver URL.
select intake.agency_link_set('<client-uuid-from-agency-registry>', 'eu-west',
                              'https://<agency-n8n-host>/webhook/agency-telemetry');

-- 3. Hand the two secrets to the agency over a secure channel (for example a password manager share),
--    never email or chat. Read them here, in the SQL editor only:
--      select name, decrypted_secret from vault.decrypted_secrets
--       where name in ('ops_intake_telemetry_secret', 'ops_intake_patch_secret');
--    The agency stores them in ITS Vault against this client_id (agency repo: onboarding/register_client.sql).

-- 4. Choose the client's controls (they can change these at any time in 00_org_config_form):
select intake.org_privacy_apply(
  '{"telemetry_enabled": true, "remote_patching_mode": "client_approval", "marketing_consent": false, "redact_before_llm": true}',
  'onboarding');

-- 5. Route patch approval requests to the client admin (any email channel the client uses):
-- insert into intake.notification_routes (event_type, channel, target, notes)
-- values ('PATCH_APPROVAL_REQUEST', 'gmail', '<client-admin-email>', 'approves agency config patches'),
--        ('PATCH_APPLIED',          'gmail', '<client-admin-email>', 'patch outcome notices');

-- To unlink: set telemetry_enabled = false and remote_patching_mode = 'off' via org_privacy_apply,
-- then delete the two Vault secrets.
