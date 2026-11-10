# Privacy architecture at a glance

*For your Data Protection Officer or security reviewer. A plain-language summary; the contract is in the MSA and DPA.*

## Where your data lives
**Everything stays in your environment.** That covers every request, attachment, audit record and report, held in a deployment dedicated to your organisation: your workflow host, your database and your file storage, in the regions you choose.

**Our access is limited to deploying and supporting it,** under the Data Processing Addendum.

## What the AI sees
- **Your own AI provider account and key are used,** so your agreement with the provider applies. You can arrange zero data retention with the provider directly; we include it in the onboarding checklist.
- **Identifiers are masked before the AI sees a request.** National IDs, card and bank numbers, phone numbers and emails become placeholders such as `[NATIONAL_ID]`. You control this setting, and it's on by default.
- **The AI only extracts signals.** Routing, deadlines and escalations come from fixed rules you configure.
- **Sensitive or unclear requests always go to a person** on your team for review.

## What leaves your environment: only this, and only if you allow it
If you switch on service health monitoring, your deployment sends us:
- counts, percentages and version numbers
- an anonymous deployment ID
- your region
- error-type codes

**Never sent:** names, emails, phone numbers, request or attachment content, free text, branch or department names, or money amounts.

- **It's enforced in code.** Any payload containing anything else is blocked before it's sent.
- **You can check it.** Every payload is kept in a log in your own database.
- **You can stop it.** You can switch monitoring off at any time.

| Sent | Example |
|---|---|
| Daily heartbeat | requests in 24 h = 37, pending reviews = 2, overdue = 0 |
| Monthly pulse | volume = 108, SLA compliance = 64.8%, hours saved = 17, override rate = 9.5% |
| Error notice | workflow 01, component "postgres", type DB_UNAVAILABLE, count 1 |

## How configuration changes reach you
We can propose small configuration changes: a threshold, a deadline, or an improved AI instruction.
- **We can't send code, database commands, passwords, recipients or branding.**
- **By default, nothing changes until someone on your side approves it.** Your options are: off; approve each one; or apply automatically only when the change makes governance stricter.
- **Every change is signed, single-use and logged,** and **automatically rolled back** if the built-in acceptance tests fail.

## Your controls
| Control | Where |
|---|---|
| Health monitoring on/off | Configuration form |
| Patch mode: off / approve each / auto-apply stricter only | Configuration form |
| Case-study consent: off by default | Configuration form |
| AI identifier masking | Configuration form |
| Recipients, thresholds, deadlines, branches, branding | Configuration form (versioned; can be rolled back) |

## Integrity guarantees
- Each request's classification and routing decision **can't be edited** after it's recorded.
- The decision history is **append-only**.
- Approvals are **final** and recorded **once**, even if a link is clicked twice.
- SLA breaches **can't be erased**.

*These guarantees are enforced by the database for the application's accounts. Owner-level maintenance is documented and logged.*
