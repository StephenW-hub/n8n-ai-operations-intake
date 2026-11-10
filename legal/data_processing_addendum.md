# Data Processing Addendum (template)

> **Template, not legal advice.** It's written to reflect GDPR Article 28-style processor terms and to be adaptable for the UK GDPR and Kenya's Data Protection Act 2019. Requirements differ by jurisdiction and change over time. Have a qualified lawyer review and adapt it. Items marked **[confirm with counsel]** need jurisdiction-specific confirmation.

This Addendum forms part of the Master Services Agreement between **[Provider]** ("Processor") and **[Client]** ("Controller"). If it conflicts with the Agreement, this Addendum prevails for the processing of personal data.

## 1. Roles
1.1 **The Controller** decides why and how personal data in the Client Environment is processed. That includes requests, attachments, audit records, reviewer actions and reports.

1.2 **The Processor** processes that personal data only to deploy, configure, support and maintain the Engine, and only as described in Annex 1.

1.3 **Service Telemetry** (MSA Clause 6 and Schedule 2) is designed to contain no personal data. If any of it qualifies as personal data under applicable law, this Addendum applies to it. **[Confirm with counsel.]**

1.4 **Deployment variants:**
- **Variant A, Client-owned accounts:** the Controller contracts directly with its hosting and AI providers. The Processor accesses the Client Environment only to provide the services.
- **Variant B, Provider-operated accounts:** the Processor holds the hosting accounts for the Client Environment. The providers in Annex 3 are the Processor's sub-processors.

[Select one variant.]

## 2. Processor obligations
The Processor will:
1. **Instructions.** Process personal data only on the Controller's documented instructions, including on transfers, unless the law requires otherwise. If the law requires otherwise, it'll tell the Controller first unless the law forbids that.
2. **Confidentiality.** Ensure that everyone authorised to process the personal data is bound by confidentiality.
3. **Security.** Implement the technical and organisational measures in Annex 2.
4. **Sub-processors.**
   - Engage only the sub-processors in Annex 3.
   - Give **[30] days'** notice of any new or replacement sub-processor, with a right to object.
   - Impose data protection obligations on each sub-processor equivalent to this Addendum.
   - Remain liable for each sub-processor's performance.
5. **Data subject rights.** Help the Controller respond to requests to access, correct, erase, restrict or port data, or to object, as far as is possible given the nature of the processing.
   - *The Engine supports this:* records are findable by reference and execution ID.
   - *Note:* the audit log is append-only by design. Erasure requires an owner-level procedure agreed with the Controller, and that procedure is documented and logged. **[Confirm with counsel how legal retention duties interact with erasure requests.]**
6. **Assistance.** Help the Controller with security, breach notification, data protection impact assessments and prior consultation, taking into account the nature of the processing.
7. **Breach notification.**
   - Notify the Controller **without undue delay**, and in any case within **[24/48] hours**, after becoming aware of a personal data breach affecting Client Data.
   - Include the information then available, and provide updates.
   - *For reference only:*
     - **GDPR / UK GDPR:** controllers must generally notify the supervisory authority within 72 hours of becoming aware.
     - **Kenya:** timelines under the Data Protection Act 2019 apply. **[Confirm the current Kenyan deadlines for controllers and processors with counsel.]**
8. **Deletion or return.** At the end of the services, and at the Controller's choice, delete or return all personal data held in Processor-operated accounts, and delete existing copies, unless the law requires storage.
9. **Audits.** Provide the information needed to show compliance, and allow and contribute to audits by the Controller or its mandated auditor, on **[30] days'** notice and no more than **[once a year]** unless a breach has occurred.
10. **Registration.** Where local law requires processors to register with a regulator (for example the Office of the Data Protection Commissioner in Kenya), the Processor will do so. **[Confirm applicability and thresholds with counsel.]**

## 3. Controller obligations
The Controller will:
- ensure it has a lawful basis for the processing and gives the required notices to data subjects
- configure the Engine (rules, recipients, connectors, retention) in line with its own obligations
- arrange its own terms with the AI provider when it uses its own account, including any zero data retention arrangement

## 4. International transfers
4.1 Personal data is hosted in the regions the Controller chooses (Annex 1).

4.2 Any transfer outside the country or region of origin will rely on an appropriate mechanism:
- **EU/EEA:** the European Commission's Standard Contractual Clauses, or an adequacy decision.
- **UK:** the International Data Transfer Agreement, or the UK Addendum to the SCCs.
- **Kenya:** the transfer conditions and safeguards under the Data Protection Act 2019 and its regulations.

**[Confirm the current mechanisms and any documentation or notification duties with counsel.]**

4.3 **AI model processing.** Model processing may take place outside the hosting region, depending on the AI provider. The Controller should review the AI provider's data-processing and transfer terms. **[Confirm with counsel.]**

## 5. Liability
Liability under this Addendum is subject to the limitations in the Agreement, except where the law forbids limiting it. **[Confirm with counsel.]**

---

## Annex 1: Description of processing
| Item | Description |
|---|---|
| Subject matter | Operating the Engine: intake, classification, routing, review, notification, ticketing, storage of attachments, reporting |
| Duration | The term of the Agreement plus the return or deletion period |
| Nature and purpose | Triage and route internal operational requests; keep an audit trail; support human review; produce aggregate management reporting |
| Data subjects | The Controller's staff and contractors who submit or handle requests; any people mentioned in requests or attachments |
| Personal data | Requester email or phone, request text, attachment content, reviewer and resolver identifiers, notes. **May include special-category data** if requesters include it (e.g. health). The Engine detects such data and routes those requests to human review. |
| Processing operations | Collection, storage, structuring, AI-assisted signal extraction (with identifiers redacted when `redact_before_llm` is on), retrieval, disclosure to configured recipients and tools, restriction, erasure |
| Hosting regions | Database: [region]. File storage: [region]. AI provider: [per the AI provider's terms] |
| Retention | Audit records: [period set by the Controller]. Attachments: [period]. Reports: [period]. Service Telemetry: 24 months (MSA 6.5) |

## Annex 2: Technical and organisational measures
**Isolation**
- A single-tenant Client Environment.
- A private database schema that the hosting provider's public API doesn't expose.
- Row-level security on every table.
- Writes only through audited database functions.

**Least privilege**
- Separate database roles for the application and for BI read access. The BI role reads PII-free views only.
- Credentials are held in the workflow platform's credential store or the database's encrypted vault, never in code or exported workflows.

**Integrity**
- Classification records are immutable.
- Decision history is append-only.
- Decisions are final, and SLA breaches can't be cleared. This is enforced by database triggers.
- Configuration and prompts are versioned, with history.

**Access to actions**
- Single-use, expiring, hashed tokens for review, resolution and patch-approval links.
- Viewing a link (GET) never changes data.
- Basic or header authentication for administration endpoints.

**Integrations**
- HMAC-signed callbacks.
- Timestamp windows and single-use nonces for configuration patches.
- An allow-list of patchable settings.
- Automatic acceptance testing and rollback.

**Minimisation**
- Identifiers are redacted before AI processing (configurable).
- Executive reporting and telemetry use aggregates only.
- Telemetry is gated by an exact key allow-list and value patterns, and every payload is kept in an outbox the Controller can audit.

**Encryption**
- TLS in transit.
- The hosting provider's encryption at rest.
- Vault-encrypted secrets.

**Attachments**
- The file type is checked against the file's contents, and size limits apply.
- Files are hashed (SHA-256), renamed safely and stored in the Controller's storage, not in the database.
- An optional malware-scanning hook is available.

**Resilience**
- An error-alert workflow.
- An SLA watchdog.
- AI failures fail closed to human review.

**People**
- Confidentiality obligations.
- Access limited to the personnel who need it.

## Annex 3: Sub-processors
| Sub-processor | Service | Location | Variant |
|---|---|---|---|
| [Hosting provider, e.g. Supabase] | Database and file storage | [region] | B (or the Controller's provider in A) |
| [Workflow platform, e.g. n8n Cloud] | Workflow execution | [region] | B (or the Controller's in A) |
| [AI provider, e.g. Anthropic] | AI signal extraction and report drafting | [per the provider's terms] | Controller's own account by default |
| [Email/chat/ticketing/storage providers the Controller enables] | Notifications, tickets, attachments | [per provider] | Per configuration |
