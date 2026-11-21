# Scan pipeline audit: scan 47b5dfc4 (2026-11-21)

Scan: "Fyn deep scan - nikto + light pass for 404 host (grant-limited)",
id `47b5dfc4-5d03-49b3-8c20-51eed448d307`, profile `deep`, config `{}`.
Ran 09:19:12 to 14:46:49 UTC (5 h 27 min), status `completed`, coverage `incomplete`.
Authorization: GET/HEAD, ports 80/443, 1 request/s, actions http_probe, passive_recon,
vulnerability_scan (no active_test).

## Root causes

| Symptom | Cause | Evidence | Fix (commit) |
|---|---|---|---|
| Findings page mixes scans, rows do nothing | `FindingsList.tsx` loaded the first 50 findings of all scans, no scan filter, rows not linked | old `frontend/src/pages/FindingsList.tsx` | URL filters, scan scope, links, pagination (4d3a42c) |
| Findings sorted oddly | `order_by(Finding.severity)` is alphabetical: info above low/medium | `api/routes/findings.py` | risk-ordered CASE (2d2f2d8) |
| "Recon 2 / Scope 1 / Vuln 25" vs 34 stored | phase count fell back to `count` (hosts, subdomains) | `tasks.py` `_update_phase_status`; DB: 5+4+18+7 rows | phases store persisted rows; API computes `stored_findings` from rows (2d2f2d8) |
| Clicking a finding shows nothing useful | Evidence tab rendered `finding.request/response`, which the API never sends; evidence lives in `finding.evidence` | old `FindingDetail.tsx` | evidence, identification, explanations, history (4d3a42c) |
| No report could be made | reports table had 0 rows; full PDF crashed on a nikto title containing `</_next/...>` (reportlab markup); downloads named `.bin` | reproduced in API container | escaping, assessment report, extensions (4d3a42c) |
| HTML report | target-controlled titles/URLs unescaped (stored XSS) | `report_service.generate_html_report` | `html.escape` (4d3a42c) |
| Nuclei on https:443 "failed" | nuclei default max-host-error 30 dropped the host at 1 rps; nikto later ran fine and the site answered 200 | phase tool_outputs; manual GET | `-max-host-error 100`, progress stats, raw artifacts (4d3a42c) |
| Nuclei on http:80 "timeout" | light pass inherited info severity: 3,135 templates in a fixed 30 min at 1 rps | `nuclei -tl` counts | no info, timeout from rate (~94 min at 1 rps) (4d3a42c) |
| Nikto skipped on http:80 | by design: root answers 404 (separate nginx server, not a redirect) | recon http_hosts | reason + status shown; `full_scan_4xx_hosts` opt-out (4d3a42c) |
| Pentest (SQLmap/Dalfox/ffuf) | not run: grant has no active_test | phase `active_test_not_authorized` | shown as Not tested / not authorized |
| SARIF had no CWE rule ids; module untracked | read `cwe` not `cwe_id`; `.gitignore` `reports/` hid `src/netra/reports` | `git check-ignore` | fixed, anchored rule (ff0eab4) |

Counts for this scan now reconcile everywhere (DB, `/findings/summary`, scan page, reports):
34 stored = scope 5 (passive_posture) + recon 4 (http_analysis) + vuln 25 (nikto 18, nuclei 7);
5 low, 29 info. Dedup is per scan (`finding_service.py`), so retries and other scans never
add rows to it.

## Tool integration audit

| Tool | State | Notes |
|---|---|---|
| recontool (passive) | functional | 917 raw results, passive only |
| passive_posture | functional | DNS SPF/DMARC/CAA |
| httpx | functional | status, title, tech, headers; 2 hosts |
| tls_probe | functional | no findings on this scan |
| nuclei | functional, was fragile | pinned templates; now progress + artifacts |
| nikto 2.6.1 | functional | filtered non-exploit tests, JSON parser |
| sqlmap, dalfox | integrated, gated | run only with active_test in the grant |
| ffuf | integrated as parser_not_implemented | no fuzzing results yet |
| katana / naabu / dnsx / subfinder (direct) | absent | see backlog |
| authenticated crawling | absent | |

## OWASP Top 10:2025 coverage for this scan

A01 requires credentials · A02 partially tested (10 findings) · A03 partially tested ·
A04 partially tested · A05 not tested (no active_test) · A06 manual review ·
A07 requires credentials · A08 manual review · A09 manual review · A10 failed/interrupted
(nuclei runs did not complete). Computed by `services/owasp_coverage.py` from the actual runs.

## Backlog

P0
- Re-run Fyn (fast or full) on the fixed worker to confirm nuclei completes at 1 rps.
- Configuration snapshot at scan start (profile values), so old reports keep their meaning.
- Download endpoint for raw tool artifacts (files are saved; only names are shown).

P1
- Separate tables for tool executions and report artifacts (today JSON in scan_phases.tool_outputs).
- Cross-tool dedup into "unique issues" (e.g. X-Content-Type-Options from httpx, nuclei, nikto).
- Enforce finding status transitions in PATCH (rules exist in FindingService, PATCH is permissive but audited).
- Report jobs on Celery instead of in-process tasks.
- Katana crawl (scoped, rate-limited) to give nuclei/nikto real paths; naabu only within granted ports.

P2
- Authenticated scanning profile (credentials vault, two-role access-control checks).
- EPSS / CISA KEV enrichment for CVE findings; CVSS 4.0 vectors where tools provide them.
- OWASP API Security Top 10 (2023) matrix for API targets.

## Using it

1. Scans → open the scan → Overview shows stored counts, severity and tool outcomes.
2. Findings tab (or "View all N findings") lists only this scan; filters stay in the URL.
3. Click a finding: Details, Evidence, Remediation, History; "Back to findings" keeps the scan.
4. Tool execution tab: every run with status, reason, progress and artifact names.
5. Coverage & limitations: OWASP Top 10:2025 matrix and what was not assessed.
6. Reports tab: Assessment PDF, JSON, CSV or SARIF; download when status is completed.
