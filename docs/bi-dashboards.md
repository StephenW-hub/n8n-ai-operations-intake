# BI dashboards: the views and how to connect them

The engine publishes six **PII-free** PostgreSQL views in the `intake` schema. They're built for
dashboard tools and for the monthly COO/CFO report.

- **What the views never contain:** request text, email addresses, phone numbers, review notes,
  reviewer briefs or security tokens.
- **What they leave out:** test records are excluded.
- **Common filter columns:** every view has `period_month` (local month, set by the `report_timezone`
  setting) and `data_scope` (`live` or `demo`). Filter on `data_scope = 'live'` for real operations.
  The `demo` scope holds synthetic showcase data.

## The six dimensions

| # | Dimension | Where to find it |
|---|---|---|
| 1 | Channel (web form, email, WhatsApp, API) | `vw_dash_channel_heatmap`, `vw_intake_facts.inbound_channel` |
| 2 | Time / peak load (weekday × hour) | `vw_dash_channel_heatmap` |
| 3 | Branch | `vw_dash_branch_ttr` |
| 4 | Route / department, time-to-resolution | `vw_dash_branch_ttr`, `vw_intake_facts.department` |
| 5 | Risk (sensitive-data category, injection attempts) | `vw_dash_risk_shield` |
| 6 | Human judgment (override drift) | `vw_dash_override_drift` |

**Across all dimensions:** `sentiment_frustration_score` (0–1) and `ai_cost_usd`. The cost figure is used for ROI.

## View catalogue

| View | One row per | Use it for |
|---|---|---|
| `vw_executive_live_dashboard` | month × scope | **Scorecards:** volume, month-on-month %, hours saved, labour $ avoided, AI spend, ROI ×, SLA compliance %, ambiguity %, frustration, sensitive catches, injection blocks, override rate, mean/P95 TTR |
| `vw_dash_channel_heatmap` | month × channel × weekday × hour | **Heatmap:** volume, ambiguity %, SLA breach %, frustration index |
| `vw_dash_branch_ttr` | month × branch × route | **Bar chart:** mean and P95 TTR, breaches, overrun hours |
| `vw_dash_override_drift` | month × rule × AI suggestion × human decision × final route | **Stacked bars:** where reviewers agree, override or reject, and how long approval takes |
| `vw_dash_risk_shield` | month × sensitive category | **Governance panel:** interceptions by PII, financial, legal and medical, plus injection blocks |
| `vw_intake_facts` | request | Drill-down and custom charts (still PII-free) |

## Definitions
- **Admin hours saved:** requests routed automatically × the minutes of manual triage avoided. The minutes come from the setting `minutes_saved_per_auto_routed`.
- **Labour value avoided:** hours saved × the `hourly_rate_usd` setting.
- **ROI ×:** labour value avoided ÷ AI spend for the month.
- **SLA compliance:**
  - Which items count: those whose SLA outcome is known.
  - Review items must be decided by their deadline.
  - Incident Desk and Operations Queue items must be resolved by theirs.
- **TTR (time to resolution):** `resolved_at − created_at`. An item is resolved when the team clicks "Mark resolved" or a ticketing tool reports it closed.
- **Override:** the reviewer approved the work but sent it to a different destination than the rules proposed.
- **Ambiguous:** confidence below the `ambiguity_threshold` setting (0.85 by default).

You change these assumptions in `intake.settings`, not in workflows. The live dashboard and the monthly report pick up the new values automatically.

## Connecting a BI tool
1. Set a password for the read-only role. Run this once in the Supabase SQL editor:
   ```sql
   alter role bi_reader with password '<strong password>';
   ```
2. Connect through the Supabase **Session pooler**, which works over IPv4:

   | Setting | Value |
   |---|---|
   | Host | your pooler host |
   | Port | 5432 |
   | Database | `postgres` |
   | User | `bi_reader.<project-ref>` |
   | SSL | required |

3. Pick the `intake` schema and the views above.
   - `bi_reader` can read **only** these views.
   - Every table and function is denied.

**Tools that connect directly to Postgres:** Retool, Apache Superset, Metabase, Power BI (PostgreSQL connector) and Looker Studio (PostgreSQL connector).

**Notion can't query a database directly.** Getting this data into Notion takes a scheduled push (sync) workflow, which is an optional add-on.

## Widget recipes
- **Peak-load heatmap:** from `vw_dash_channel_heatmap`, x = `hour_of_day`, y = `day_name` (order by `day_of_week`), colour = `sum(volume)`. Add a filter on `inbound_channel`.
- **Branch bottlenecks:** from `vw_dash_branch_ttr`, a grouped bar of `mean_ttr_min` and `p95_ttr_min` by `submitting_branch`. Sort by `p95_ttr_min`.
- **Override drift:** from `vw_dash_override_drift`, a stacked bar of `decisions` by `rule_applied`, split by `human_final_decision`.
- **Executive scorecards:** from `vw_executive_live_dashboard`, one row for `period_month = <month>` and `data_scope = 'live'`.
- **Trend line:** the same view, ordered by `period_month`, showing `total_requests`, `sla_compliance_pct` and `roi_multiple`.

## One JSON for apps
`intake.report_snapshot(month, scope)` returns every section above as one JSON document with flat arrays of objects, ready to bind to chart widgets. The monthly report and the live dashboard workflow both use it. It runs as the n8n role, not as `bi_reader`.
