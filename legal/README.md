# Legal templates

> **Templates only, not legal advice.** These documents are starting points written to match how the software actually works. Before using them with any client, have a qualified lawyer review and adapt them for:
> - **your jurisdiction and the client's**, for example the EU/EEA (GDPR), the UK (UK GDPR and the Data Protection Act 2018), or Kenya (Data Protection Act 2019 and its regulations)
> - **the client's sector**, for example health, finance or the public sector
>
> Every item marked **[confirm with counsel]** is a point where requirements differ by jurisdiction or change over time.

| File | Purpose | Signed by |
|---|---|---|
| `master_services_agreement.md` | Commercial terms, service scope, the **Mechanism 1 telemetry clause**, the remote configuration clause and the case-study consent clause | Provider and client |
| `data_processing_addendum.md` | Controller–processor terms (GDPR Art. 28 style), security measures, sub-processors, transfers and breach handling | Provider and client; attached to the MSA |
| `client_privacy_architecture_one_pager.md` | Plain-language summary for a client's Data Protection Officer or security reviewer | Not signed; shared during procurement |

**Keep the documents in sync with the code:**
- The telemetry field list in the MSA (Schedule 2) must stay identical to the allow-list in `database/migrations/009_telemetry_key_allowlist.sql` and the table in `ARCHITECTURE.md` §7.
- If a field is added to the code, the MSA schedule must be updated, and clients notified, **before** that field is sent.

**Placeholders** appear in `[square brackets]`: `[Provider]`, `[Client]`, `[jurisdiction]`, and so on.
