-- One-off maintenance for installs that loaded the v1 demo seed (before migration 005).
-- The v1 demo rows lack the new dimensions (branch, channel mix, frustration, category, overrides,
-- resolution times), so they would distort the demo dashboards.
--
-- What it does, transparently:
--   1. Disables the append-only guard (owner only; the application roles can never do this)
--   2. Deletes ONLY synthetic rows flagged is_demo = true. Real and test records are untouched.
--   3. Re-enables the guard
-- Then run database/seed_demo.sql (v2).

begin;
alter table intake.intake_audit_logs disable trigger intake_audit_logs_guard;
delete from intake.intake_audit_logs where is_demo;
alter table intake.intake_audit_logs enable trigger intake_audit_logs_guard;
commit;
