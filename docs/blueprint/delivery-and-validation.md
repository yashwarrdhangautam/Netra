# Delivery work packages and verification

Version 1.0 — 2026-11-16. Architecture delivery plan, not an executable code patch. The initial authoring ran no application checks. The review pass started Stage 0; see [actual results and remaining work](../validation/stage-0-baseline.md). Planned commands below are not all complete. All paths are repository relative; source paths start with src/netra/.

## 1. Execution discipline

Use the approved stage design to prepare a source-specific executable task plan immediately before coding. Keep one implementer responsible for each shared contract and a reviewer responsible for evidence. For each package: reproduce a concrete failure with a meaningful test, change the smallest coherent component, run targeted checks, review the diff, then run the integration gate. Record commit IDs and results. Do not substitute test counts for behavioral acceptance.

Future executable plans should use the writing-plans skill and name exact edits, test cases and commands against the current source. This design package intentionally does not invent entire future implementations before the baseline is established.

## 2. Stage 0 — baseline work instructions

Repository root: C:\Users\CyberFlux\Documents\Netra\Netra.

- [ ] Record git rev-parse HEAD, git status --short and environment versions in docs/validation/stage-0-baseline.md. Preserve unrelated work. Record Python, Poetry, Node, npm, Docker and Compose versions; if unavailable, record blocked rather than pass.
- [ ] Inspect tests/conftest.py and test-specific fixtures before running suites; use disposable test databases and broker, never customer services. Match CI's required NETRA_DATABASE_URL and NETRA_CELERY_BROKER_URL without recording secret values.
- [ ] Run the following from the root with installed locked dependencies. Capture exit codes, failures and skips separately. Do not update lockfiles to make the baseline pass.

```powershell
poetry run pytest --cov=netra --cov-report=xml
poetry run ruff check src/
poetry run mypy src/
npm --prefix frontend run lint
npm --prefix frontend run build
npm --prefix frontend run test:unit
npm --prefix frontend run test:e2e
```

Expected healthy result: each exits zero; any current failure becomes a named baseline defect with reproduction and impact. Browser dependencies and test-server setup follow frontend/playwright.config.ts; environment failures are not product test passes. Full frontend test combines unit/E2E, so do not rerun it after both individually pass without a reason.

- [ ] Inspect actual database column/check-constraint definitions and migration head on a disposable copy. ORM scan.profile and target.target_type are String(20), but live schema parity remains unverified.
- [ ] Inventory scan launch, resume, scheduled, retry, recheck, MCP and Hunt entry points; add file/function references and authorization path for each.
- [ ] Back up a disposable deployment and rehearse restore; record elapsed time, counts and key recovery. Never test destructive restore against the working instance.
- [ ] Create the pre-stabilisation tag only when the intended baseline commit and working-tree state are recorded; do not overwrite an existing tag.

Exit G0: evidence file exists, failures classified, entry points mapped and rollback/recovery procedure concrete. Existing failures can be accepted as baseline only with explicit scope; no newly introduced failures pass a stage.

## 3. Stage 1 packages

| ID | Files / responsibility | Required checks and exit condition |
|---|---|---|
| P1 Authorization | New src/netra/services/scan_authorization.py and src/netra/schemas/authorization.py; existing target schemas/routes/services | Missing/expired/revoked authorization denies; ordinary metadata updates cannot forge it; mutation audit and current-policy check |
| P2 Scope enforcement | New src/netra/scanner/scope_gate.py; existing worker/tasks.py, scanner/orchestrator.py, mcp/server.py, api/routes/findings.py | Every entry point passes a typed context; wildcard boundaries, excludes, redirects, malformed inputs and unavailable policy deny; required blocked work is incomplete |
| P3 Verify existing roles and ownership | api/routes/scans.py and target mutations; existing role dependency | Admin/analyst allowed only for owned/assigned context; viewer/client write denied; cross-client reads, exports and events denied |
| P4 Process safety | scanner/tools/base.py and process_control.py; docker-compose.yml | Minimal env; bounded output; process-group timeout/cancel; full UUID workspace; limits enforced; no default data-service exposure |
| P5 Input/config safety | schemas/scan.py; target types; scanner adapters; db/models/credential.py | Typed profile keys; reject secrets/unknown keys; safe source-root containment; option/path attacks refused; no plaintext credential writes via supported paths |
| P6 Outcomes | ToolResult and worker phase persistence; schemas/scan.py; frontend/src/pages/ScanDetail.tsx and components/scans/PhaseTimeline.tsx | Five states, required set, cancellation, truncation, old coverage unknown; API/UI/reports agree |
| P7 Profiles and CLI | scanner/profiles.py, db/models/scan.py and target.py, cli/main.py; .github/workflows/netra-scan.yml and netra-reusable.yml | sast/iac and source/image types aligned; unknown profiles rejected rather than standard fallback; unsupported modes explicit; CLI and CI cannot report a fake success |
| P3A Audit completeness | src/netra/api/routes/scans.py, findings.py and services/audit.py; tests/test_api/ | Verify existing scan/finding events, actor/object identity, transactional rollback, bulk coverage, redaction and access; fix only reproduced gaps |
| P8 Wrappers | scanner/tools/generic.py and tool-specific modules; tests/test_scanner/fixtures/ (new) | License verification for each selected tool/ruleset blocks adoption in P8; then seven supported adapters with real finding/clean/malformed samples, pinned versions, accepted exits and per-tool network policy matrix |
| P9 Consolidation | worker/tasks.py, scanner/orchestrator.py; caller inventory | Standard chain owns supported phases; preserve Hunt behavior except shared policy fixes; API phase contract and existing Hunt tests pass |

The abbreviated source paths in this table are under src/netra/ unless they explicitly begin frontend/, tests/, .github/ or name docker-compose.yml. New module names are design proposals; inspect neighboring conventions before creating them and record any equivalent placement in the task plan.

P1/P2 tests: add tests/test_services/test_scan_authorization.py and tests/test_scanner/test_scope_gate.py. Include authorization expiry between enqueue and execution, excluded nested subdomain, example.com.evil.test, IDNA/trailing dot, IP literal, scope change on retry and database failure. Enumerate MCP registrations and worker entry points so adding a new path cannot bypass the gate silently.

The newer stabilization review reports existing role/ownership checks; independently verify them and change production code only for a reproduced gap. P3 extends tests/test_api/test_scans.py and test_client_scope.py with table-driven role/object cases. P4 adds tests/test_scanner/test_process_limits.py using benign fixture processes that spawn children, exceed output caps and print a synthetic secret-bearing environment. Verify no surviving children and no synthetic secret in output. P5 tests source symlinks, URL credentials/control characters, rejected option prefixes and unknown config keys; reject direct and bulk plaintext credential writes through supported application paths. Model hooks alone do not protect arbitrary raw SQL.

P6 extends tests/test_worker/test_phase_outcomes.py. Cases: completed zero; unavailable required; skipped not-applicable; scope-blocked required; partial malformed output; timeout; cancelled; truncated; missing historical coverage. P7 adds CLI exit tests and exact phase/target-kind matrix tests. P8 fixtures identify tool version and capture command; malicious output is data and never executable. P9 runs tests/test_bugbounty/test_worker_tasks.py and the complete affected orchestrator tests after inventory; do not delete based on a text search alone.

Section 6.6 adds mandatory cases: cancelling prevents successor phases, resume reconstructs only eligible work under current authorization, duplicate deliveries do not execute the same attempt twice, and lost workers cannot create a falsely completed scan. P4 covers child termination, P6 state persistence and P9 scheduler integration; P10 strengthens these with leases. Each package adds its specific regression tests. Run poetry run pytest on the touched test files before the full Stage 1 gate. Full gate repeats Stage 0 commands once after all packages; review added skips and changed expectations. Update README readiness wording and all generated report coverage views. A reduction in test count requires explanation, but a stable count alone is not acceptance.

## 4. Stage 2 — lab protocol

Create docs/validation/stage-2-lab.md and versioned fixtures under tests/fixtures/lab/. Pin target/tool/rules/database artifacts and record hashes. Use only controlled local targets on a dedicated lab network; never publish vulnerable services beyond localhost. Define explicit lab scope and private-range exception in that deployment only.

| Fixture | Required result |
|---|---|
| Juice Shop + manual tool captures | NETRA output matches normalized reviewed manual baseline; zero detections can be valid |
| Source rule trigger + clean file | Named pinned rule IDs versus completed zero |
| Fabricated secret | Expected Gitleaks detection; no real secret used |
| Pinned dependency advisory fixture | Expected advisory IDs with pinned database timestamp |
| Terraform misconfiguration | Named Checkov rule IDs |
| Pinned container digest | Matches reviewed Trivy baseline with fixed vulnerability data |
| Out-of-scope decoy | Zero HTTP requests and zero prohibited connections, including redirects and secondary requests |
| Missing binary / timeout / bad JSON | unavailable / failed / parse_error; each required case incomplete |
| Revoked authorization | No new execution; active execution termination within defined capability |

Capture per tool: version, digest, sanitized argv, policy version, duration, exit, state, required flag, finding count, raw artifact hash, expected versus observed and reviewer. Capture before/after decoy logs and network counters; an access log alone cannot prove no raw network probe. Stage 1's documented DNS limitation means passing the lab is G1, not G2.

Generate every currently supported report format from captured results, open it and check coverage, provenance and role access. Unsupported formats are explicitly listed, not counted as validated. Lab acceptance differences need an explained cause and an updated expectation or defect; never loosen a negative safety assertion to pass.

Teardown removes only named lab containers/networks/volumes after evidence export. Record names before teardown; do not use broad volume pruning.

## 5. Stage 3 and 4 work packages

- [ ] P10 Implement versioned JobEnvelope, controller lease persistence, restricted result capabilities and idempotent ingestion according to execution-and-products.md.
- [ ] P11 Implement dedicated execution network, ephemeral sandboxes, DNS/destination enforcement and revocation; run every isolation acceptance case before customer use.
- [ ] P12 Assess dependencies and the 13 Hunt pages, then obtain approval for the cut method/repository topology implementing the user direction: fix first, then separate into two directories. Preserve shared-control updates through the approved mechanism. Preserve existing API reads through compatibility adapters.
- [ ] P13 Run clean Windows/WSL2 and Kali installation/upgrade/restore drills; record exact host versions, steps, failures, duration and installed image digests. No claim of passing from documentation inspection.
- [ ] P14 Exercise Hunt import → operator-reviewed scope → passive collection → approved active test → evidence review → draft export. Verify changed scope invalidates approvals, passive mode emits no target probes and external submission is not automatic.

G2/G5 can pass before all Hunt product enhancements. An early customer assessment still requires G6, even if the main managed-monitoring pilot remains scheduled at 5c.

## 6. Stage 5 work packages

| Package | Dependency | Deliverable | Acceptance evidence |
|---|---|---|---|
| P15 Organizations and migration | Stable shared contracts | Membership, tenant ownership, engagement/policy records and staged legacy mapping | Two-tenant negative suite; worker/search/report/WebSocket coverage; reversible backfill |
| P16 Secrets | P15 | Write-only references, separate keys, rotation and revocation | No secret disclosure; cross-tenant denial; restore with keys; old credentials revoked |
| P17 Asset identity | P15 | Assets, observations, relationships and ownership | Stable identities; no IP/name-only false merges; auditable manual overrides |
| P18 Connector framework + GitHub | P16/P17 | Resumable read-only inventory and available findings | Pagination, replay, rate limits, entitlement gaps, stale data, partial failure and revocation |
| P19 AWS then Azure | P18 | Provider account/region/subscription adapters | Scoped permission snapshots, incomplete region visibility, no remediation writes |
| P20 Correlation and risk | P17/P18 | Issue/occurrence history and versioned explainable scores | No cross-asset/tenant merge; fixed vectors; unknown input labeling; reopening |
| P21 Remediation + authenticated scans | P16/P20/G2 | Scoped credentials and verified closure workflow | No auto-close on incomplete scan; credentials scoped to target; evidence-backed retest |
| P22 Dashboards and pilot | P20/P21/G1–G6 as applicable | Role views, immutable reports, documented support | Persona journeys, coverage honesty, scale measurements, pilot signoff |
| P23 Compliance evidence | P22 | Versioned mappings, evidence manifests, expiring exceptions | No-findings does not imply compliance; provenance/permissions/expiry tests |
| P24 AI/MCP governance | P15/P16/shared policy | Provider inventory, data policy, deterministic action validation | Injection attempts denied; budget limits; AI-off workflow; no cross-tenant retrieval |

Each package creates its own executable plan when its dependencies pass. Provider API details and third-party licenses are verified then against selected versions; no network/API or licensing assertion in this package substitutes for that check.

## 7. Traceability and stop conditions

| Requirement | Packages | Gate |
|---|---|---|
| S1/S2 scope, D4/D5 | P1/P2/P10/P11 | G1/G2 |
| S3 role/ownership | P3/P15 | G1/G4 |
| S4/S5/S6 subprocess/input/path | P4/P5/P11 | G1/G2 |
| S7 config and secret handling | P5/P16/P21 | G1/G3 |
| S8 deployment/restore | P4/P13 | G5 |
| S9 isolation, D7 | P4/P10/P11 | G2 |
| Outcomes and profiles, D6 | P6/P7 | G1 |
| Section 6.6 cancellation/resume/duplicate execution | P4/P6/P9/P10 | G1/G2 |
| Real wrappers/rules, D2/D3 | P8 | G1 |
| Consolidation/product separation | P9/P12/P14 | G1/G2 |
| Enterprise inventory/risk | P15–P22 | G3/G4/G6 |
| Evidence/AI governance | P23/P24 | G6 plus product acceptance |

Stop promotion on policy bypass, secret leakage, cross-tenant access, false clean result, unexplained data loss or failed restore. Capture the failing case, fix it, rerun relevant checks and retain evidence. Do not retry a failed customer scan through a weaker execution path.

## 8. Review record template

For every package record: ID; design version; before/after commit; scope; files changed; test command and exit code; pass/fail/skip counts; fixtures/tool versions; observed limitations; review findings and resolution; rollback path; gate status (not started / in progress / passed / blocked). A gate becomes passed only with linked evidence and reviewer identity.

## 9. Documentation validation performed

The authoring session checks package file presence, relative links, required stage/gate coverage, decision consistency and whitespace. Initial authoring ran no application checks. The subsequent review ran the local tests/static checks recorded in ../validation/stage-0-baseline.md; scans, migrations, container deployment, provider calls and license verification were not performed. Document completion and software readiness are different statuses.

## 10. Rough sizing and first deliverable — proposals

These are order-of-magnitude person-day estimates for one experienced builder assisted by coding tools, not measured productivity or commitments. A person-day means roughly six focused engineering hours including tests/review. Add 30–50% contingency for integration, baseline failures and environment work; exclude waiting for approvals/provider access. Re-estimate after G0 and G1. Packages overlap; do not mechanically sum overlapping stage totals and per-package estimates.

| Scope | Effort range | First evidence |
|---|---|---|
| Stage 0 | 1–3 days | docs/validation/stage-0-baseline.md with command exits and real counts |
| P1–P3 and P3A | 4–8 days | Authorization/scope/role/audit regression matrix |
| P4–P7 | 5–10 days | Process, state, cancellation and profile tests |
| P8–P9 | 6–12 days | Captured adapter fixtures and pipeline parity |
| Stage 2 | 3–6 days | Lab record, zero decoy traffic and opened reports |
| P10–P13 (Stage 3) | 12–25 days | G2 isolation and G5 install/restore evidence |
| P14 (Stage 4) | 4–8 days | All Hunt routes and workflow checked |
| P15–P18 (5a foundation + GitHub) | 15–30 days | Tenant/secret/asset/connector tests |
| P19 (AWS + Azure) | 10–20 days | Per-provider permission and completeness evidence |
| P20–P21 (5b) | 10–20 days | Correlation, risk and verified-remediation evidence |
| P22 (5c) | 5–10 days | Pilot journeys, operational signoff and measurements |
| P23 (5d) | 8–15 days | Evidence/exception review workflow |
| P24 (5e) | 8–15 days | AI-off and adversarial policy tests |

First deliverable is the Stage 0 baseline, not a scanner feature or customer pilot. A restricted assessment pilot after Stages 0–3 and G6 is roughly 31–64 person-days before contingency (about 8–19 full-time weeks with contingency). Hunt adds its Stage 4 validation if enabled. A managed-monitoring pilot through 5c is several additional months; do not promise a date before Stage 5 assessment. Later work may reuse existing capabilities, so these ranges must narrow after assessment.

P3A source inventory: scan.create/update/delete/resume and finding.create/update/delete/bulk_update/false_positive/retest already call record_audit. tests/test_api/test_scan_dispatch.py asserts scan.create. Verify each other event with success and rollback cases; require state change and audit to commit atomically, correct actor/resource identity, sanitized changed-field summaries and no duplicate event on retry. Record denial events separately without recording secret request bodies. Worker/system mutations need explicit service identity; route hooks alone do not prove coverage.

G6 also requires completed authorization/data-handling records and an offboarding/incident rehearsal from service-readiness.md. The reported Intigriti/Chaos exposure is an immediate operator rotation action, not deferred until P16; do not use those integrations until revocation is confirmed.


## Current handoff

The implementation-start request is recorded in specification revision 6. Review the [P1/P2 task plan](../superpowers/plans/2026-11-16-p1-p2-authorization-scope.md) and [Stage 0 continuation](../validation/stage-0-baseline.md). Baseline checks now include disposable schema/restore, live role probes, all browser cases passing across a full run and targeted retry, and 64% coverage. G0 remains pending known-failure disposition; 492 type errors are not waived. No application implementation or commit has occurred.
