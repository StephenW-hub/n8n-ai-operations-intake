# Architecture: Controlled Ops Intake, Governance & Executive Intelligence Engine

**Audience:** technical buyers, a client's security or data-protection lead, and engineers deploying or extending the system.

**Build status:** the database layer (migrations 001–010) is built and tested. The n8n workflows are specified below and are being built against it. Sections marked *(planned)* describe workflows not yet published.

## 1. What the system does
Staff send loosely written operational requests through a web form, email, WhatsApp or an API.

| Step | What happens |
|---|---|
| Extract | **Claude extracts signals** (intent, urgency, confidence, sensitive data, frustration, injection attempts). It never decides anything. |
| Route | **Fixed rules decide** the route, the SLA and when to escalate: Incident Desk, Operations Queue or Human Review. |
| Record | Every request becomes an **immutable, time-bound audit record** with an append-only `decision_history`. |
| Review | Human Review is a **decoupled, idempotent approval checkpoint** keyed by `origin_execution_id`. There are no long-running waits. |
| Report | A **monthly executive briefing** and **BI views** turn the audit log into ROI, SLA and friction intelligence across six dimensions. |
| Configure | Each deployment is **white-labelled** and **configured by the client** without editing workflows. |
| Monitor | Optional: a deployment can send **zero-PII health telemetry** to the provider's Command Center and accept **signed, allow-listed, client-approved configuration patches**. |

## 2. Deployment model and trust boundaries
```
┌──────────────────────── CLIENT TENANT (single-tenant, client-controlled) ───────────────────────┐
│  Requesters ─► n8n (client)  ─────────►  Postgres/Supabase  `intake` schema (all raw data, PII)  │
│                 │   │                     ▲      ▲                                                │
│                 │   └─► Anthropic API (client's own key; redacted text) ◄─ LLM data boundary     │
│                 └─► Client's tools: email/Slack/Teams/Chat, Jira/Zendesk/HubSpot/Salesforce,     │
│                     Drive/SharePoint/S3 (attachments)                                            │
│  BI tools ──(bi_reader: PII-free views only)──┘                                                   │
└──────────────┬───────────────────────────────────────────▲────────────────────────────────────────┘
               │ zero-PII telemetry (HMAC-signed, opt-out)  │ config patches (HMAC-signed, allow-listed,
               ▼                                            │ client-approved by default, auto-rollback)
┌──────────────────────── PROVIDER: Agency Command Center (separate private system) ────────────────┐
│  agency_telemetry_hub · deterministic criticality scoring · 4-quadrant cockpit · patch dispatcher │
└────────────────────────────────────────────────────────────────────────────────────────────────────┘
```
- **One organisation per deployment.** The client's own n8n, database, storage and Anthropic account, or the provider's accounts dedicated to that client.
- **No raw data ever crosses** to the provider. That covers request text, emails, attachments, briefs, names and amounts.
- **The Command Center lives in a separate private repository and database.** This repository contains only the client-side sender and receiver, and the contracts that govern them.

## 3. Components

### 3.1 Workflows (`workflows/`)
| # | Workflow | Entry points | Purpose |
|---|---|---|---|
| 00 | Org Config Form *(planned)* | `/form/ops-config` (Basic Auth), `POST /webhook/ops-config` (Header Auth) | Client self-service: name, logo, colours, currency, rates, thresholds, SLAs, branches, recipients, privacy toggles, rollback |
| 01 | Intake & Router *(planned)* | `/form/ops-intake`, `POST /webhook/ops-intake`, Gmail trigger, WhatsApp trigger, test-only sub-workflow trigger | Validate → attachments (07) → redact → Claude Sonnet signals → **Rules Code node** → Opus review brief (review holds) → `intake_create` → notify (05) → ticket (06) → acknowledge |
| 02 | Human Review Callback *(planned)* | `GET/POST /webhook/ops-review`, `GET /webhook/ops-record`, `GET/POST /webhook/ops-resolve`, `POST /webhook/ops-resolve/system` (HMAC), `GET/POST /webhook/ops-patch-approval` | Approve / Reject / Override; read-only audit page; resolve links; ticketing "resolved" callbacks; client approval of agency patches |
| 03 | SLA Watchdog *(planned)* | Schedule, every 10 min | `sla_sweep()` → escalate overdue reviews and P1 incidents |
| 04 | Monthly Executive Report *(planned)* | Hourly on day 1, fires at the org's local 08:00 (manual run too) | `report_snapshot` → Claude consultant synthesis → sanity check → white-labelled HTML → notify → archive → monthly telemetry pulse |
| 05 | Notification Dispatcher *(planned)* | Sub-workflow | Gmail / Outlook / SMTP / Slack / Teams / Google Chat / signed webhook; branded cards |
| 06 | Ticket Sync *(planned)* | Sub-workflow | Jira / Zendesk / HubSpot / Salesforce / webhook; create on gate-clear, update on events |
| 07 | Attachment Vault *(planned)* | Sub-workflow | Magic-byte check, SHA-256, safe name, upload to Drive / SharePoint / OneDrive / S3; link written to the record |
| 08 | Live Dashboard *(planned)* | `GET /webhook/ops-dashboard-demo` (public, demo data), `GET /webhook/ops-dashboard` (Basic Auth) | Branded Chart.js page from `report_snapshot` |
| 09 | Error Handler *(planned)* | Error Trigger | Alert via 05 (direct Gmail fallback); zero-PII error ping via 10 |
| 10 | Telemetry Emitter *(planned)* | Daily schedule, called by 04 and 09 | `telemetry_build()` → signed POST to the agency → `telemetry_mark()` |
| 11 | Config Patch Receiver *(planned)* | `POST /webhook/apply-config-patch` (HMAC) | `verify_patch` → `patch_receive` → client approval or auto-safe apply → acceptance gate → keep or roll back → signed result |

### 3.2 Database (`database/`)
`schema.sql` is a one-file install of migrations 001–010. Everything lives in the private `intake` schema, which the Supabase REST API doesn't expose. RLS is on everywhere, with no policies. **The only write path is `SECURITY DEFINER` functions.**

| Area | Tables | Key functions |
|---|---|---|
| Audit | `intake_audit_logs` (immutable classification; append-only history; monotonic SLA breach) | `intake_create`, `review_decide`, `review_preview`, `resolve_with_token`, `resolve_by_system`, `sla_sweep`, `record_view`, `append_event`, `get_record` |
| Executive | `executive_reports` (append-only, one scheduled report per month, frozen `org_snapshot`) | `report_snapshot`, `report_archive`, `report_already_sent` |
| BI | views `vw_intake_facts`, `vw_dash_channel_heatmap`, `vw_dash_branch_ttr`, `vw_dash_override_drift`, `vw_dash_risk_shield`, `vw_executive_live_dashboard` | role `bi_reader` (views only) |
| Org / white-label | `organization_settings` (one row), `organization_settings_history` (append-only) | `get_org_settings`, `get_org_branding`, `org_settings_apply`, `org_privacy_apply`, `org_settings_rollback` |
| Connectors | `notification_routes`, `ticket_routes`, `storage_targets`, `requester_directory` | `get_routes`, `get_ticket_routes`, `get_ticket_ref`, `get_storage_target`, `lookup_requester` |
| Prompts | `prompt_versions` (immutable text, one active per key) | `get_active_prompts` |
| Telemetry | `telemetry_outbox` (append-only record of everything sent) | `telemetry_build`, `telemetry_mark`, `telemetry_assert_safe` |
| Patching | `config_patches` (append-only), `patch_nonces` | `verify_patch`, `patch_receive`, `patch_preview`, `patch_decide`, `patch_record_gate`, `patch_result_build` |

**Roles:**
- **`n8n_intake`:** EXECUTE on the listed functions only.
- **`bi_reader`:** SELECT on the six views only.
- **Owner-only:** the onboarding helpers (`agency_link_set`) and internal helpers (`hmac_hex`, `patch_apply_internal`, `resolve_record`, `sync_email_route`).

## 4. Governance rules (deterministic)
The Rules Code node reads thresholds and SLAs from `organization_settings` at run time. Claude's JSON is re-validated, and deterministic detectors for IDs, cards, IBANs, phones, medical and legal terms, and injection phrases run alongside it. **A flag is set if either Claude or a detector raises it.**

| Order | Condition | Route | SLA |
|---|---|---|---|
| 1 | AI output missing or invalid | HUMAN_REVIEW (`AI_UNAVAILABLE`), fails closed | review SLA |
| 2 | Sensitive data | HUMAN_REVIEW (`SENSITIVE_DATA`) | review SLA (critical-review SLA if urgency is CRITICAL) |
| 3 | Injection suspected | HUMAN_REVIEW (`PROMPT_INJECTION`) | review SLA |
| 4 | Confidence < `confidence_threshold` (default 0.85) | HUMAN_REVIEW (`LOW_CONFIDENCE`) | review SLA |
| 5 | Urgency CRITICAL | INCIDENT_DESK (`CRITICAL_INCIDENT`) | incident SLA (15) |
| 6 | Otherwise | OPERATIONS_QUEUE (`DEFAULT_QUEUE`) | ops SLA (240) |

Each record also stores:
- `org_config_version` and `prompt_version`, so any decision can be traced to the rulebook and the prompt that produced it.
- `ai_predicted_route`: Claude's advisory guess, kept for drift analysis and never used to route.

## 5. Executive intelligence (six dimensions)
**The six dimensions:** channel · time (weekday × hour) · branch · route/department with mean and P95 TTR · risk category · human judgment (override drift). Frustration and AI cost are tracked across all of them.

**How the monthly report is built:**
1. `report_snapshot(month, scope)` produces one chart-ready JSON from the views. It includes a deterministic **bleed ranking**.
2. Claude (`claude-sonnet-5-5`) receives **aggregates only** and writes:
   - a 1-sentence ROI headline
   - 3 quantified bleed diagnostics
   - 1 advisory rule-calibration proposal
3. A deterministic check rejects any synthesis citing numbers that aren't in the snapshot.

`docs/bi-dashboards.md` covers connecting a BI tool to the views.

## 6. Client endpoints and how each is protected
| Endpoint | Protection |
|---|---|
| `/form/ops-intake`, `POST /webhook/ops-intake` | Public demo form with length, type and size caps. The API takes an optional `X-Intake-Key` (Header Auth). |
| `/webhook/ops-review` | GET shows a page only. POST decides, needs the per-record review token (32 random bytes, only the SHA-256 stored), expires after 72 h, single-use. |
| `/webhook/ops-record` | Per-record view token. Shows a PII-free summary only. |
| `/webhook/ops-resolve` | Per-record resolve token, single-use. |
| `/webhook/ops-resolve/system` | HMAC from the ticketing tool, plus the ticket id must match the one on file. |
| `/form/ops-config`, `/webhook/ops-config` | Basic Auth / Header Auth. Validation in the database. Versioned history, admin alert, rollback. |
| `/webhook/ops-patch-approval` | Per-patch approval token, expires after 7 days. |
| **`/webhook/apply-config-patch`** | **HMAC-SHA256** over `timestamp.nonce.raw_body` with a Vault-held secret; **±5 min** timestamp window; **single-use nonce**; `client_id` match; **allow-list** (six numeric settings and three prompt keys, bounds-checked); client-controlled `remote_patching_mode` (`off` / `client_approval` default / `auto_safe` for tightening-only changes); **automatic acceptance gate with rollback**; append-only `config_patches` log. Patches can never carry SQL, code, credentials, recipients, branding, routes or workflow JSON. |
| `/webhook/ops-dashboard-demo` | Public; synthetic demo data only. |
| `/webhook/ops-dashboard` | Basic Auth. |

**Payload encryption.** Transport is TLS. Patches and telemetry carry no secrets or personal data, so there's no separate payload encryption, and we don't claim any.

## 7. Privacy and compliance (Module 9)
**Roles.**
- The client is the **Data Controller** for all operational data.
- The provider acts as **Data Processor** when it configures or supports the deployment, and is controller only of its own non-personal service telemetry.
- Sub-processors depend on hosting: Anthropic (client's own key), Supabase, n8n, and whichever connectors the client enables. The DPA in `legal/` covers both hosting variants.

**Zero-PII telemetry, enforced in code:**
1. `telemetry_build()` assembles payloads from counts, percentages, versions, IDs and error codes only.
   - n8n error messages are **never** sent. They're mapped to an `error_class` enum.
   - Branch names, intents, amounts and free text are never sent.
2. `telemetry_assert_safe()` blocks the payload if any key isn't on an exact allow-list, or any string doesn't match a closed set of patterns (UUID, region, period, timestamp, version, workflow code, n8n node type, enums).
3. Every payload is stored in `telemetry_outbox`, so the client can audit what left.
4. `telemetry_enabled` is a client kill switch.
5. The receiving hub validates the schema strictly again.

**Telemetry fields (exhaustive):**

| Kind | Fields |
|---|---|
| Common to all | `client_id`, `region`, `kind`, `sent_at`, `app_version`, `org_config_version`, `prompt_versions{classifier,review_brief,consultant}`, `consecutive_failures`, `active_user_seats` |
| heartbeat | `requests_24h`, `pending_review`, `open_overdue` |
| monthly_pulse | `period`, `monthly_volume`, `sla_compliance_pct`, `override_rate_pct`, `ambiguity_rate_pct`, `admin_hours_saved`, `confidence_drift_pct` |
| error | `error_logs[{workflow_code, node_type, error_class, count}]` |
| patch_result | `patch_id`, `status`, `cases_passed`, `cases_total` |

The MSA's Mechanism 1 clause lists exactly these fields.

**LLM data handling:**
- The client's own Anthropic key is used, so Anthropic's commercial terms apply to the client directly.
- **Zero Data Retention is a contractual arrangement between the client's organisation and Anthropic, not a configuration switch.** It's an onboarding checklist item.
- `redact_before_llm` (default on) replaces detected identifiers with typed placeholders before any model call.
- The executive report sends aggregates only.

**Data residency and retention:**
- The client chooses the database and storage regions.
- Attachments go to the client's own storage, never into Postgres.
- Audit records are append-only by design; retention and deletion periods are set per the client's DPA.
- Telemetry retention is stated in the MSA.

**What append-only does and doesn't guarantee.** The guarantees bind the application roles (`n8n_intake`, `bi_reader`). A database owner can still run migrations. Owner-run maintenance is committed and documented, for example `database/maintenance/005_reseed_demo.sql`, which removes synthetic demo rows only.

## 8. Repository layout
```
ARCHITECTURE.md · README.md · CLAUDE.md
database/   schema.sql · migrations/001–010 · seed_demo.sql · routes_example.sql · onboarding/agency_link.sql · maintenance/
workflows/  00_org_config_form … 11_config_patch_receiver (n8n JSON exports, credential names only)
tests/      six_case_acceptance_gate.json · telemetry_zero_pii_test.json
legal/      master_services_agreement.md · data_processing_addendum.md · client_privacy_architecture_one_pager.md · README.md
docs/       bi-dashboards.md · client-deployment.md · white-label-config.md · telemetry-and-patching.md
```
The Agency Command Center (telemetry hub, scoring, cockpit, patch dispatcher) is maintained in a separate **private** repository.

## 9. Known limits
- **Not live-tested yet:** the connectors other than Gmail, Google Drive and webhook (Outlook, SMTP, Slack, Teams, Google Chat, Jira, Zendesk, HubSpot, Salesforce, SharePoint/OneDrive, S3, WhatsApp) are built and validated, but each still needs a client account to test against.
- **Voice notes are deferred.**
- **There's no built-in malware scan.** An optional scanner hook exists.
- **The FX rate for AI cost is manual.**
- **"Hours saved" is an assumption,** set in organisation settings.
- **TTR needs a resolution signal:** a team resolve click or a ticketing callback.
- **The public demo form has no rate limit.** A spend cap on the Anthropic key bounds abuse.
- **Calibration proposals and Command Center drafts are advisory.** A human approves every change, email and post.
- **The legal templates aren't legal advice.** Counsel must review them in each jurisdiction.
