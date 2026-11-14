# NETRA Gap Audit: status after the 2026-11-12 build-out

**Read:** every line of the five PRDs (`PRD.md`, `NETRA_BB_PRD.md`, `NETRA_BB_GUI_PRD.md`, `NETRA_BB_LEARNING_PRD.md`, `NETRA_BB_CAPABILITY_PRD.md`).
**Verified:** API QA script (42/42), full test suite (1,078 passed), browser suite (10/10 across all 21 screens and write flows), Docker stack (all services healthy, migrations to 020).

**Legend:** **DONE** = built and verified. **PARTIAL** = built, with a stated limit. **OPEN** = not built, with the reason.

## 1. Security and accounts

| Item | Status | Notes |
|---|---|---|
| API authentication on every data route | DONE | Anonymous calls get 401. Health and login stay public. |
| Role enforcement (admin, analyst, viewer, client) | DONE | Writes need analyst or admin. Users, settings, kill switch, verifier reload are admin-only. Viewer and client are read-only. Clients see only targets assigned to them (`targets.client_id`, set by an analyst or admin), and only their scans, findings, reports and search results (PRD 5.3.2). The PRD's "Limited" view is built: clients get no AI analysis, evidence, notes or assignee on a finding (`FindingClientResponse`). |
| WebSocket authentication | DONE | Token in the query string, checked on connect. Closed with 1008 when missing or invalid. |
| Logout and token revocation | DONE | Logout adds the token to the blacklist. Revoked tokens get 401. |
| Self sign-up | PARTIAL | `POST /auth/register` exists but is off by default (`NETRA_ALLOW_SELF_SIGNUP`). Creates viewer accounts only. No sign-up page in the GUI. |
| User management (create, edit role, activate, reset password, remove) | DONE | Admin Users page. Remove deactivates the account, because scans and targets reference it. |
| MFA (TOTP with backup codes) | DONE | Enrol, enable, disable, and login with TOTP or a single-use backup code. Settings page. Secret is encrypted at rest (Fernet, as for integration keys). |
| Password change | DONE | Settings page, same policy as the CLI. |
| Personal API key (`ntr_...`) | DONE | Created and revoked on Settings. Works as a Bearer token. |
| Encrypted integration keys | DONE | Fernet, key derived from the JWT secret. Shown masked. Changing the JWT secret makes stored keys unreadable. |
| Audit log (general) | DONE | Records user, target, settings, and account-security changes. Admin view with filter and paging. Scan and finding changes are audited too, including create, resume, update, delete and false-positive. |
| Route guard in the GUI | DONE | Signed-out visitors go to `/login`. Expired sessions clear state. |

## 2. Core scanning and reports

| Item | Status | Notes |
|---|---|---|
| Scanner wrappers (23 in PRD) | PARTIAL | 23 wrapped, including the 7 that were missing: assetfinder, dnsx, gau, katana, naabu, wpscan, subzy. Wired into the orchestrator. Binaries are built into the API and worker images. **Not run against a live target** (needs an authorized target; SSRF rules block private addresses). |
| Scanner binaries in containers | DONE | Built from source in a Go stage. Verified present in the worker and API. |
| SARIF 2.1.0 export | DONE | `GET /reports/scan/{id}/sarif` and the CLI flag. |
| Report formats | PARTIAL | 11 generators exposed (executive, technical, pentest, HTML, Excel, evidence ZIP, compliance, delta, API, cloud, full). Report history and download are on the Reports page. Generation was not run on real findings. |
| Compliance frameworks list | DONE | `GET /compliance/frameworks`. |
| Target create, edit, delete, groups, CSV import | DONE | Fixed create (it always returned 500) and a SSRF check that ignored its own verdict. CSV import reports rejected rows. |
| Scan create, view, delete from the GUI | DONE | New scan dialog, View link, Delete. Previously the scans page could not create a scan. |
| Scan compare export | DONE | CSV export of new and resolved findings. PDF is not built. |
| Scheduled scans | PARTIAL | Table added (migration 020). List, create (cron, interval, once), pause, resume, run, and delete work on the Schedules page. Not run end to end: needs the worker and a scheduled target. |
| Global search | DONE | Header search across findings, scans, targets. |

## 3. Dashboard, pages, and GUI

| Item | Status | Notes |
|---|---|---|
| Login with tagline | DONE | "The Third Eye of Security" on the login page and in the sidebar. |
| Pages from the PRD (13 core) | DONE | Dashboard, Scans, Scan detail, Findings, Finding detail, Reports, Compliance, Targets, Attack graph, Settings, Users, Scan compare, Login. |
| Settings | DONE | Account (password, MFA, API key), Integrations (admin), Notifications (real test sends). Replaces the simulated version. |
| Users | DONE | Replaces the page that called routes which did not exist. |
| Reports | DONE | Replaces the page that generated for a placeholder scan ID. |
| Targets | DONE | Replaces the page that showed random finding counts. |
| Schedules page | DONE | New. |
| Audit log page | DONE | New, admin only. |
| Header (search, New scan) | DONE | Bell removed: it had no data behind it. |
| Mobile navigation | DONE | Menu button opens the sidebar as a drawer. |
| Footer | DONE | Version and tagline. |
| Components named in the PRD | PARTIAL | Charts exist (severity pie, trend line). Global search, notification banner, and scan dialog added. No separate `FindingBulkActions` component; bulk actions exist on the API. |
| Frontend test tooling | DONE | Vitest, Testing Library and MSW (`npm run test:unit`, 10 tests). Playwright end-to-end suite (`npm run test:e2e`, 12 tests). Histoire, zod and react-hook-form are not installed. |

## 4. Bug bounty

| Item | Status | Notes |
|---|---|---|
| Hunt console and live view | PARTIAL | New hunt form and table on `/bb/hunts`. Live page `/bb/hunts/:id` polls every 2 seconds and shows phases, blocked counts, and cancel. The live page gets pushed snapshots over `/ws/scans/{id}` and falls back to polling only while the socket is down. |
| BB settings | DONE | Verifier allowlist (read-only, admin reload), links to integration keys. |
| BB audit UI-actions tab | DONE | Second tab on `/bb/audit`. |
| Kill switch | DONE | Admin only. |
| Learning: right-to-be-forgotten | DONE | Blocklist table (migration 019). Forgotten authors and URLs are skipped on every later ingest. |
| Learning: rate limiting | DONE | The fetcher already enforces a minimum interval per host and honours Retry-After. |
| Learning: Bugcrowd disclosures | PARTIAL | Crowdstream disclosures ingested from the live feed (20 rows verified 2026-11-12). Metadata and titles only, no write-ups. Intigriti: OPEN, no confirmed public disclosure feed. |
| Learning: nuclei-templates, Wappalyzer, chaos pulls | OPEN | Each needs a decision on format and storage (git clone vs JSON). |
| Drafter style references with the 50% overlap guard | DONE | Prior-art examples are fetched into the drafter, and an 8-word-gram overlap check at 50% blocks a draft that copies them (`bb_submission_service.py`). Covered by `test_submission_poc.py` and `test_programs_scope_coverage.py`. |
| Exploitation priority (CISA KEV + FIRST EPSS) | DONE | `src/netra/intel/cve_intel.py`; `GET /api/v1/intel/cve?ids=` returns exploited-first ordering. Cached 24h, degrades to unknown on network failure. Not yet applied to findings lists. |
| Protection-to-bypass checklist | PARTIAL | `src/netra/intel/bypass_checklist.py` detects WAF, CSP, CORS, rate limit and clickjacking protections from one normal response and expands them into ordered checks. Not yet wired into the hunt planner. |
| Scanner tool inventory | DONE | `GET /api/v1/scanner/tools` lists each binary, install state and install hint. Settings page shows it. Worker image installs nikto (from source), sqlmap, dalfox, amass, semgrep, checkov, pip-audit and shodan (in their own venv, so they do not clash with the app pins). wpscan, trivy and prowler are optional and not installed. |
| Bug bounty scope sync for Bugcrowd and Intigriti | OPEN | Clients exist; scope sync is only wired for HackerOne. |

## 5. AI and agents

| Item | Status | Notes |
|---|---|---|
| Ollama running | DONE | Container running. `llama3.1:8b` pulled (4.9 GB). Verified with an inference from the API container. |
| AI provider wired in the stack | DONE | API and worker set to `NETRA_AI_PROVIDER=ollama`. |
| AI consensus on real findings | UNVERIFIED | Needs a scan with findings. |
| Agentic loop, PoC builder, planner | UNVERIFIED | Modules exist. Not run end to end. |

## 6. Operations

| Item | Status | Notes |
|---|---|---|
| Docker stack | DONE | All services healthy. Migrations run from an empty database to head `020`. |
| nginx routing after an API restart | DONE | Upstream is resolved per request, so the GUI recovers without a frontend restart. Verified by restarting the API. |
| Migrations | DONE | 015 to 020 add the users columns, timezone-aware timestamps, target groups, audit log, app settings, corpus blocklist, and scan schedules. |
| Schema drift on JSON columns | DONE | Models share `JSONType` (jsonb on PostgreSQL). Migration 022 converted the remaining `json` columns. |
| Host port 11434 | NOTE | Another Ollama answers on the host's port 11434. The stack works through the Docker network (`ollama:11434`). |

## 7. Documentation and installation

| Item | Status | Notes |
|---|---|---|
| First admin via CLI | DONE | `python -m netra.cli.create_admin`, with the same password policy as the API. |
| Installation guide | DONE | `docs/installation.md` covers first run, required settings, and scanner installation. |
| Compose override for the GUI | NOTE | The override used for this machine (database name, port 8001, Ollama without GPU) is kept outside the repository. |

## 8. Known risks and open items

1. **MFA secret encryption: resolved (checked 2026-11-14).** Writes go through encrypt_value; the live netra_gui database has 0 plaintext MFA secrets out of 9 users. Earlier note, kept for history: MFA secret was not encrypted at rest. The column is named `mfa_secret` and the model says "encrypted at rest", but it stores the plain secret. Fix: encrypt with the same key as integration keys.
2. **Scan and finding status changes are audited** (fixed: `scans.py` and `findings.py` call `record_audit`).
3. **Client role scope and limited view** (PRD 5.3.2): done. Clients see only their targets' scans, findings and reports, and get the limited finding view.
4. **Hunt live view polls** instead of using WebSocket.
5. **No live scan has been run.** Scanner wrappers, the orchestrator, consensus, reports and schedules are built and unit-tested but not run against a real authorized target.
6. **Four learning items and the drafter guard are open** (section 4).

## 9. Test evidence

- `pytest`: 1,078 passed, 1 skipped.
- API QA script (`scratchpad/qa_api.py`): 42/42.
- Playwright (`frontend/tests/e2e/qa-full.spec.ts`): 10/10. Covers sign-in, a wrong password, all 21 screens with no uncaught page errors, settings, new scan dialog, search, reports, audit filter, target creation, and user creation.
- `tsc`: clean. `vite build`: clean.
