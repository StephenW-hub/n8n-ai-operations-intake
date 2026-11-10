# Master Services Agreement (template)

> **Template, not legal advice.** Have a qualified lawyer review and adapt this for the jurisdictions involved before use. Items marked **[confirm with counsel]** vary by jurisdiction.

**This Master Services Agreement ("Agreement") is made between:**
- **[Provider legal name]**, of [address] (the **"Provider"**); and
- **[Client legal name]**, of [address] (the **"Client"**).

**Effective date:** [date].

---

## 1. Definitions
- **"Engine"** means the Provider's Controlled Operations Intake, Governance and Executive Intelligence software: the n8n workflows, database schema, prompts and documentation.
- **"Client Environment"** means the single-tenant deployment of the Engine dedicated to the Client. That is its workflow host, database, file storage and AI provider account, whether these are held in the Client's accounts or in accounts the Provider operates for the Client.
- **"Client Data"** means all data processed in the Client Environment, including request text, attachments, personal data, audit records and reports.
- **"Service Telemetry"** means the non-personal operational metrics described in Clause 6 and Schedule 2.
- **"Configuration Patch"** means a change to the Engine's configuration under Clause 7.
- **"DPA"** means the Data Processing Addendum attached as Schedule 3.

## 2. Services
2.1 The Provider will:
- deploy, configure and support the Engine in the Client Environment, as described in Schedule 1 (Services and Service Levels)
- provide updates
- provide the monthly executive reporting features described in Schedule 1

2.2 **The Engine supports human decisions; it doesn't replace them.**
- AI models are used only to extract signals from requests.
- Routing, SLAs and escalations are decided by fixed, configurable rules.
- Final approvals in the Human Review process are made by the Client's personnel.

2.3 **The Client is responsible for:**
- the accuracy of the rules, thresholds and recipients it configures
- the decisions its reviewers make
- its use of the Engine's outputs

## 3. Client Environment and data location
3.1 Client Data stays in the Client Environment, and the Provider won't copy it out except:
- as required to provide support at the Client's documented instruction, under the DPA; or
- as required by law.

3.2 **Data location.** The Client chooses the hosting regions for the database and file storage. The regions in use at the effective date are listed in Schedule 1.

3.3 **AI provider.** By default the Client uses its own AI provider account and API key, and its own commercial agreement with that provider governs. The Client is responsible for arranging any **zero data retention** or similar terms with its AI provider. The Provider will assist with the onboarding checklist in Schedule 1.

## 4. Fees
[Fees, tiers, volume limits, invoicing, payment terms, late payment, taxes.]
Tier volume limits are used for capacity planning and upgrade conversations only. **The Engine doesn't stop processing requests when a limit is reached.**

## 5. Confidentiality and intellectual property
5.1 Each party will keep the other's confidential information confidential. [Standard confidentiality terms.]

5.2 **Ownership:**
- **The Provider owns** the Engine and its underlying know-how.
- **The Client owns** Client Data, its branding assets and its reports.
- **The Client receives** a [non-exclusive, non-transferable] licence to use the Engine for its internal operations during the Term. [Adjust if the Engine is sold outright.]

## 6. Mechanism 1: Service Telemetry
6.1 **Purpose.** To keep the Engine healthy, detect failures early, plan capacity and improve the service, the Client Environment may send Service Telemetry to the Provider's monitoring system.

6.2 **Content.** Service Telemetry is limited to the fields in **Schedule 2**:
- aggregate counts, percentages, version numbers, an opaque deployment identifier, region, and error-type codes
- **no** names, email addresses, phone numbers, request or attachment content, free text, branch or department names, intents, or monetary amounts

The Engine enforces this technically:
- a payload containing any other field or value is blocked before it's sent
- the Client can inspect every payload sent in its own system, in the telemetry outbox

6.3 **Changes.** The Provider won't add a field to Schedule 2 without **[30] days'** prior written notice to the Client. **[Confirm with counsel whether consent is required instead of notice in the relevant jurisdiction.]**

6.4 **Opt-out.** The Client may switch Service Telemetry off at any time in the Engine's configuration form. If it does, proactive monitoring and some service levels in Schedule 1 may no longer apply.

6.5 **Retention.** The Provider keeps Service Telemetry for **[24] months**, then deletes it or aggregates it beyond attribution to the Client.

6.6 **Status.** The parties intend Service Telemetry to be non-personal data.
- If any of it is personal data under applicable law, the DPA applies to it.
- **[Confirm with counsel. For example, `active_user_seats` is a count only, and no identifiers are sent.]**

## 7. Remote configuration patches
7.1 **Scope.** The Provider may send Configuration Patches through the Engine's signed patch endpoint, limited to:
- **(a) these numeric settings:**
  - confidence threshold
  - incident, operations, review and critical-review SLA minutes
  - minutes saved per request
- **(b) new versions of** the classifier, review-brief and consultant prompts

**Configuration Patches can never contain:** code, database commands, credentials, recipients, branding, routing tables, or workflow definitions.

7.2 **Client control.** The Client chooses the patch mode in the configuration form:
- **"off":** no patches are accepted.
- **"client approval" (default):** each patch waits until an authorised Client user approves it.
- **"auto-safe":** patches that only tighten governance are applied automatically, i.e. a higher confidence threshold or shorter SLAs. All other patches still need approval.

7.3 **Safeguards.** Every patch is:
- signed and time-limited, and can be used only once
- checked against the allowed ranges
- recorded in an append-only patch log in the Client Environment

After any threshold or prompt change, the Engine runs its acceptance tests automatically and **rolls the change back** if they fail.

7.4 **Responsibility.**
- **The Provider is responsible** for the content of the patches it proposes.
- **The Client is responsible** for its approval decisions.
- **Patches never change Client Data.**

## 8. Case studies and marketing (opt-in)
8.1 The Provider won't refer to the Client, or publish any results derived from the Client's use of the Engine, unless the Client has opted in. The opt-in is recorded as `marketing_consent` in the configuration and in writing.

8.2 Even with that opt-in, the Provider must:
- submit each proposed publication (for example a social media post or case study) to the Client for written approval before publishing
- not identify the Client by name unless the Client expressly agrees
- use only aggregate figures

## 9. Data protection
The parties will comply with the DPA (Schedule 3), which takes precedence over this Agreement for the processing of personal data.

## 10. Warranties and liability
[Service warranties, AI output disclaimer (AI-extracted signals may be inaccurate, and the rules and human review exist for that reason), liability caps, exclusions, indemnities. **[Confirm with counsel.]**]

## 11. Term and termination
11.1 [Term, renewal, termination for convenience or for cause.]

11.2 **On termination:**
- the Provider will stop Service Telemetry ingestion and patching for the Client Environment
- **at the Client's choice,** the Provider will either return Client Data held in Provider-operated accounts in a machine-readable format and then delete it, or delete it directly, within **[30] days** unless law requires retention
- the Provider will delete the Client's Service Telemetry, or aggregate it beyond attribution, under Clause 6.5

## 12. General
Governing law: **[jurisdiction]**. Disputes: [forum or arbitration]. Notices, assignment, entire agreement, order of precedence (DPA > MSA > Schedules > orders). **[Confirm with counsel.]**

---

## Schedule 1: Services, service levels and onboarding checklist
- **Deployment:** [Client-owned accounts / Provider-operated accounts]. **Regions:** database [region], storage [region].
- **Service levels:** [support hours, response targets, monitoring (applies while Service Telemetry is on)].
- **Onboarding checklist:**
  - [ ] Client AI provider account and API key created by the Client, with a spend limit
  - [ ] **Zero data retention** requested and confirmed by the Client with its AI provider, if required **[confirm the provider's current terms]**
  - [ ] `redact_before_llm` on
  - [ ] Organisation settings, branches and recipients set in the configuration form
  - [ ] Service Telemetry on or off, patch mode and marketing consent chosen by the Client
  - [ ] Acceptance tests pass (6 of 6)

## Schedule 2: Service Telemetry fields (exhaustive)
| Payload kind | Fields |
|---|---|
| All payloads | `client_id` (opaque deployment UUID), `region`, `kind`, `sent_at`, `app_version`, `org_config_version`, `prompt_versions` (classifier, review_brief, consultant: integers), `consecutive_failures`, `active_user_seats` (a count only) |
| Daily heartbeat | `requests_24h`, `pending_review`, `open_overdue` (counts) |
| Monthly pulse | `period` (YYYY-MM), `monthly_volume`, `sla_compliance_pct`, `override_rate_pct`, `ambiguity_rate_pct`, `admin_hours_saved` (whole hours), `confidence_drift_pct` |
| Error ping | `error_logs`: `workflow_code` (00–11), `node_type` (software component name), `error_class` (one of AUTH, API_KEY_INVALID, RATE_LIMIT, TIMEOUT, WEBHOOK_TIMEOUT, DB_UNAVAILABLE, VALIDATION, UPSTREAM_5XX, UNKNOWN), `count` |
| Patch result | `patch_id`, `status`, `cases_passed`, `cases_total` |

## Schedule 3: Data Processing Addendum
See `data_processing_addendum.md`.
