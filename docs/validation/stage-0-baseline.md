# Stage 0 baseline — partial, gate not passed

Date: 2026-11-16 (Asia/Calcutta). Baseline HEAD: 24d22381da41701a8262b8c86da01344c0d63aeb. Working tree contained documentation changes; application source was not changed by this review. Commands ran from C:\Users\CyberFlux\Documents\Netra\Netra. No scanner, customer assessment, migration, provider credential validation or container deployment was intentionally launched.

## Environment

Local .venv Python 3.13.13; Poetry 2.4.0; Node v24.15.0; npm 11.12.1; Docker CLI 29.4.0; Compose CLI v5.1.2. Docker daemon health was not checked. CI specifies Python 3.12, so local results are not proof of CI-version parity. Poetry emits a requests dependency compatibility warning. No packages/lockfiles were changed.

## Results

| Check | Actual invocation / result | Exit | Evidence |
|---|---|---|---|
| Backend initial | .venv/Scripts/python.exe -m pytest --no-cov -q; stopped loading conftest, netra not importable; no test result | 4 | stage-0-logs/backend-tests.log |
| Backend retry | Same command with process-local PYTHONPATH set to repository src; 1198 passed, 1 skipped, 1 warning in 27.21 s | 0 | stage-0-logs/backend-tests-src.log |
| Backend lint | .venv/Scripts/python.exe -m ruff check src/; all checks passed | 0 | stage-0-logs/backend-lint.log |
| Backend types | .venv/Scripts/python.exe -m mypy src/; 492 errors in 118 files, 219 source files checked | 1 | stage-0-logs/backend-types.log |
| Frontend lint | npm.cmd --prefix frontend run lint; passed | 0 | stage-0-logs/frontend-lint.log |
| Frontend build | npm.cmd --prefix frontend run build; TypeScript/Vite build passed | 0 | stage-0-logs/frontend-build.log |
| Frontend unit | npm.cmd --prefix frontend run test:unit; 3 files, 10 tests passed, no failed tests | 0 | stage-0-logs/frontend-unit.log |
| Browser E2E | Not run: NETRA_E2E_EMAIL/PASSWORD absent, no disposable signed-in backend established | not run | Test prerequisites inspected in frontend/tests/e2e/*.spec.ts |

Each executed command also has an adjacent .exit file. Backend run disabled coverage explicitly; no fresh coverage percentage/XML was produced. The initial import failure was corrected only through a process-local source path; no editable install or application fix was made. Tests use the in-memory SQLite fixture in tests/conftest.py; passing them does not verify PostgreSQL migrations or a live Celery deployment.

The warning is Starlette's deprecated httpx TestClient usage. The single skip remains a skip, not proof of that test's behavior. Frontend build produced ordinary ignored build output; no source edit was made. Type-check failure examples include missing annotations in MCP, incompatible FastAPI lifespan typing, and untyped CLI calls; the full log is the baseline defect inventory, not 492 newly introduced regressions.

## Open baseline work

- Classify type errors by root cause and agree a baseline disposition; do not silently remove strict checking.
- Verify Python 3.12/locked dependency parity and coverage in the intended test environment.
- Prepare a disposable backend/browser test identity and run E2E without using customer credentials or a live customer deployment.
- Inspect actual schema/migration head on a disposable database copy; verify scan profile/target-kind constraints.
- Record running-worker concurrency and role-by-route behavior in the configured deployment, beyond unit tests.
- Complete the scan-launch/retry/resume/MCP/Hunt caller inventory with actual function references.
- Perform scoped backup/restore drill on a copy and record rollback/recovery evidence.
- Review intended baseline/tag state before creating pre-stabilisation; no tag was created in this pass.

G0 status: IN PROGRESS, not passed. Stage 1 implementation is not started or approved by this record. G1–G6 remain unverified. Reported exposed Intigriti/Chaos credentials were not used; account-owner revocation remains unverified.

## Implementation-start continuation — 2026-11-16

The user supplied a handoff requesting implementation start. Stage 1–2 design and D4–D7 are treated as approved on that basis; no credential rotation is inferred. No application source was modified. The new P1/P2 plan is at ../superpowers/plans/2026-11-16-p1-p2-authorization-scope.md.

### Newly executed checks

| Check | Observed result | Evidence |
|---|---|---|
| Docker availability | Engine 29.4.0 responsive; existing NETRA containers running | Read-only docker info/ps |
| Effective existing worker concurrency | prefork max-concurrency=4, four child processes, 3600/3700-second limits | Read-only celery inspect stats; only pool data printed |
| Disposable PostgreSQL migration | All migrations applied to 022_jsonb_alignment; exit 0 | stage-0-logs/disposable-migration.log and .exit |
| Disposable schema | scans.profile and targets.target_type are varchar(20); no CHECK constraints on scans/targets | stage-0-logs/schema-check.log |
| Synthetic restore | pg_dump custom archive restored to separate baseline_restore database; revision, sentinel row and 34 public tables verified; about 0.6 seconds | stage-0-logs/restore-check.log, including archive SHA-256 |
| Running API roles | 20/20 expected statuses across admin/analyst/viewer/client; create/update/delete/resume using missing IDs plus unassigned-client read | stage-0-logs/live-role-matrix.log and .exit |
| Browser initial attempt | 13 environment failures: Docker internal-only network did not publish the frontend host port | stage-0-logs/frontend-e2e-disposable.log |
| Browser corrected network | 12 passed, 1 failed; scanner-inventory test lacked a broker/worker in the minimal temporary stack | stage-0-logs/frontend-e2e-retry.log |
| Browser inventory retry | 1 passed after adding a disposable broker/worker; no scanner task was requested | stage-0-logs/frontend-e2e-inventory.log |
| Backend coverage | 1198 passed, 1 skipped, 1 warning; total coverage 64%; exit 0 | stage-0-logs/backend-coverage.log and coverage.xml |
| Caller inventory | API, direct worker, phases, scheduler, retest, orchestrator, Hunt, agentic, MCP and CLI paths mapped | stage-0-caller-inventory.md |

Browser evidence is 12 passing cases in the corrected full run plus the remaining case passing in the targeted retry; it is not a claim that one complete run passed all 13. API role writes used nonexistent IDs to exercise permissions without queueing a scan; they do not prove successful authorized scan execution. The synthetic restore verifies schema/data dump recovery, not customer-volume recovery or production key restoration. Existing deployment schema/data was not inspected or changed. The earlier note that coverage/E2E were not run describes the first baseline pass and is superseded by this continuation.

### Disposable environment and cleanup

Dedicated network netra-stage0-20261116-review was internal. PostgreSQL used tmpfs, fresh schema and synthetic data, with no existing volume mounts or published database port. API used repository src mounted read-only, no .env file, no provider credentials, and a generated temporary signing key. Frontend served the current local build; only its port 18173 was published to 127.0.0.1 through a second temporary bridge network. The test broker/worker was on the internal network; no beat scheduler ran. Existing NETRA services were not restarted or reconfigured.

An initial seed attempt used the wrong password-helper name and failed before writes; corrected to get_password_hash. Browser accounts and any test-created records were disposable. Passwords/tokens were not printed or saved in this report. All five labeled temporary containers and both empty networks were removed after evidence capture. Their data was discarded; no ongoing test services remain.

### Type-check classification and proposed disposition

All 492 errors were categorized from mypy error lines into stage-0-logs/type-error-categories.json. Largest categories: type-arg 162; no-untyped-def 80; attr-defined 46; untyped-decorator 39; no-untyped-call 31; no-any-return 30; arg-type 27. These are pre-existing findings, not waived or fixed. Categories are not root-cause proof; attr-defined/import errors in touched paths still require investigation.

Proposed baseline disposition for user review: proceed with narrowly scoped P1/P2 while tracking the existing type failures separately; require all new authorization modules and changed behavior to pass targeted tests/lint and no unexplained new mypy errors. Fix touched-path functional defects such as the scheduler session import as part of the relevant package. Do not turn off strict checking, remove tests or label the full type check as passed. CI/Python 3.12 parity remains unverified by this Windows Python 3.13 test run; the disposable runtime image uses the project's Python 3.12 image, but its complete dependency lock parity was not audited.

G0 remains IN PROGRESS pending review of the known-failure disposition and recovery/environment limitations. No pre-stabilisation tag or commit was created; the requested handoff explicitly reserves commits for user instruction. The tag must identify an agreed baseline and must not hide uncommitted documentation. P1/P2 application implementation has not started; the plan is reviewable but not a generated complete patch set. Exposed-credential revocation remains unverified.
