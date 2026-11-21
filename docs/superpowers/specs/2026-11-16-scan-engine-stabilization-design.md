# Stage 1 and Stage 2 design: scan engine stabilisation and lab validation

- Status: revision 6. Stage 1–2 design and D4–D7 treated as approved by the user request to start implementation on 2026-11-16. Application implementation has not started. G0 baseline disposition and the new P1/P2 task plan remain separate review gates. Later stages are direction only; no commit authorized.
- Date: 2026-11-16
- Baseline commit: `24d2238`
- Evidence: code reading only. No tests, scans or containers were run to produce this document. "Confirmed" below means confirmed by reading the cited lines.
- Independent review: revision 2 was reviewed read-only by a second model (OpenAI Codex CLI 0.169.0). Each of its claims was then checked against the code. Revision 3 corrects one wrong finding (S3), three wrong details (S7, S9, 6.2) and adds the issues it found that held up (S1, S2, S8, S9, 6.6, Stage 2).

## 1. Where this sits in the larger plan

Stage numbers are unchanged. Stage 5 is divided into five parts so each milestone has one home.

| Milestone | Stage | Content |
|---|---|---|
| 1. Foundation security, stabilisation, validation | 0, 1, 2 | Baseline, security controls, scan engine fixes, lab validation. **This document covers 1 and 2.** |
| 2. Enterprise and Hunt boundaries | 3, 4 | Dependency review, cut-method decision, split, execution isolation design, clean-machine installs on Windows and Kali, then Hunt's own end-to-end run |
| 3. Connector framework and asset inventory | 5a | Organisation and tenant model, secure credential store, asset model, connectors: GitHub, then AWS or Azure |
| 4. Posture, correlation, contextual risk | 5b | Posture and entitlement checks, findings tied to assets, risk engine, authenticated scanning |
| 5. Dashboards, reporting, pilot readiness | 5c | Role views, trend definitions, first managed-service pilot |
| 6. Compliance and evidence | 5d | Control library, evidence, exceptions |
| 7. AI/MCP governance and advanced | 5e | AI and MCP inventory, product graph |

Planning assumptions (provisional): first customer is a small-to-mid SaaS or product company on GitHub with AWS or Azure, served as a managed assessment and monitoring service. NETRA Hunt is a working name. The cut method for the split is not decided here.

Every stage follows: assessment, design, approval, implementation plan, approval, implementation, testing, review.

## 2. Decisions already made

- **D1. Strict scope allow-listing.** Only explicitly authorised targets are scanned. Discovered subdomains, IPs, redirects and related infrastructure never inherit authorisation. Enforcement fails closed.
- **D2. Pinned Semgrep rules.** A reviewed, version-controlled local rule set. No rules fetched during an assessment. Subject to the licence check in section 6.4.
- **D3. Prowler, Shodan and the LLM-security wrapper are deferred.** They return an explicit `unavailable` status with a reason.

## 3. Customer readiness gates

These are not Stage 1 deliverables. They are conditions that later stages must meet, recorded here so they cannot be skipped.

| Gate | Condition | Met by |
|---|---|---|
| G1 | Scan authorisation and scope enforced on every path, validated in the lab. The standard pipeline and the MCP server are covered in Stages 1 and 2; the bug-bounty path has its own scope gate, which is validated in Stage 4 | Stages 1, 2 and 4 |
| G2 | Scan execution isolated from platform secrets, the database and the broker, with resource limits and egress control, validated | Stage 3 design, then its own validation |
| G3 | Secure credential store; no customer secret in a plaintext field | Stage 5a |
| G4 | Tenant isolation | Stage 5a |
| G5 | Clean-machine installs pass on Windows (Docker Desktop with WSL 2) and Kali; backup and restore tested | Stage 3 exit |
| G6 | Signed scope, data handling schedule, offboarding and incident process, operational owner and pilot acceptance | Before any customer assessment |

- No customer assessment of any kind before G1, G2, G5 and G6.
- No stored customer credentials before G3.
- No second customer on one deployment before G4.

## 4. Stage 0: baseline (precondition)

- Run the full test suite, frontend checks and lint. Record the results.
- Tag the commit `pre-stabilisation`.
- Record the role-by-route behaviour of the running API, so authorisation claims rest on application behaviour and not on reading one route file.
- Confirm what the worker's real concurrency is.
- Confirm the profile column type, in case adding a profile value needs a migration.
- Stage 1 does not start until the baseline is recorded.

## 5. Stage 1 work order

Security controls come first. Scanner functionality is not expanded until they pass.

| Step | Content | Sections |
|---|---|---|
| 1a | Security controls | 6.1 |
| 1b | Execution states, profile lifecycle, cancel and resume | 6.2, 6.3, 6.6 |
| 1c | Real wrappers | 6.4 |
| 1d | Pipeline consolidation | 6.5 |

## 6. Stage 1 design, issue by issue

### 6.1 Security controls (step 1a)

#### S1. Scope is not enforced in the standard pipeline

- **Current behaviour.**
  - `Target.scope_includes` and `scope_excludes` are stored and returned by the target routes but never read by the pipeline. The first step runs subfinder and passes every result on (`worker/tasks.py:123-172`).
  - The chain fails open. If the scope step fails it returns an ordinary result, and the next step falls back to cached subdomains or the root target and probes anyway (`worker/tasks.py:116-118`, `215-218`).
  - Discovery runs with `follow_redirects=True` on up to 50 discovered hosts (`worker/tasks.py:226-230`).
  - Nothing records that a target is authorised to be tested at all.
  - A finding re-check request has an ownership and SSRF check but no scope check (`api/routes/findings.py:349-362`).
- **Proposed change.**
  - A target can be scanned only when it has an authorisation record: who authorised, when, a reference, and an expiry.
  - In scope means: the registered value itself, plus hosts matching an explicit include rule, minus anything matching an exclude rule. Exclude always wins.
  - Discovery never grants authorisation. Discovered hosts may proceed only if they match an already explicitly authorised rule and permitted method; otherwise store them as "discovered, not authorised" and do not resolve, probe or crawl them.
  - One scope gate, called immediately before every tool invocation and every application-controlled outbound request made on a target's behalf, including the finding re-check. For internal requests made by scanner binaries, maintain a per-tool enforcement matrix; disable redirects/crawling or unsupported modes when destination scope cannot be enforced. Full network-level enforcement is G2, not a Stage 1 claim.
  - Tools that follow redirects or crawl are run with redirects off or restricted to in-scope hosts.
  - Any error building or evaluating the scope stops the action.
  - The chain fails closed: a failed or blocked scope step stops the scan. No later step falls back to cached or root targets, and cached discoveries are re-checked against the current scope before use.
  - The authorisation in force is copied onto the scan when it starts. Only an admin can write or revoke an authorisation. Revocation is checked before each phase, and a revoked scan stops.
  - Wildcard include rules match on whole labels only, so `*.example.com` does not match `badexample.com`.
- **Security impact.** Removes the path to testing third-party systems without permission. This is the highest-severity item.
- **Functional impact.** Scans cover less by default. Existing targets cannot be scanned until an authorisation record is added. Scans report discovered hosts for the operator to review.
- **Test cases.** In-scope host passes. Out-of-scope subdomain blocked. Exclude beats include. Expired authorisation blocks. Missing authorisation blocks. Malformed rule blocks. A redirect to another host is not followed. A failed scope step stops the chain. A cached out-of-scope host is not used. Revocation mid-scan stops the next phase. Wildcard label-boundary cases. A pipeline test asserts no tool receives an out-of-scope value.
- **Acceptance.** All of the above pass, and the Stage 2 decoy host receives zero requests.
- **Limitations and deferred.** The gate works on names and addresses as given; a tool does its own DNS lookup, so DNS rebinding is not covered until execution isolation (G2). The authorisation record is a minimal form; the full engagement model belongs to Stage 5a.

#### S2. MCP scanner tools take any target with no scope check

- **Current behaviour.** `nuclei_scan(target, templates, ...)` and about twenty similar tools run a scanner on a caller-supplied string (`mcp/server.py:110-127` and following). The federated bug-bounty tools check scope (`mcp/server.py:87`), but against rules the caller passes in the same request (`mcp/server.py:455-468`), so the caller authorises itself. `templates` accepts a path.
- **Proposed change.** Every MCP scanner tool calls the same scope gate as the pipeline, against registered and authorised targets. The federated tools load scope rules from the stored program, never from the caller; their `scope_rules` parameter is kept for compatibility and ignored. If the database cannot be reached, the tool refuses. `templates` is limited to names inside the pinned template directory. Deferred tools return `unavailable`. Tool names and parameters do not change.
- **Security impact.** High. An AI agent connected to this server can currently direct a scanner at any address.
- **Functional impact.** MCP tools work only on registered, authorised targets.
- **Test cases.** Unregistered target refused. Authorised target allowed. Out-of-scope target refused. Database down refused. Path-style `templates` value refused.
- **Acceptance.** No MCP tool reaches a wrapper without a passing scope decision; a test enumerates all registered tools to prove it.
- **Limitations and deferred.** The MCP server trusts the local process that starts it. Its place in the two products is a Stage 3 question.

#### S3. Scan route authorisation (corrected: no defect found)

- **Correction.** Revision 2 said any signed-in user could start a scan. That was wrong. I read the route file and missed the application wiring.
- **Current behaviour.** Every data router is mounted with `require_access`, which rejects write methods for viewer and client (`api/app.py:104-114`, `api/routes/auth.py:469-480`). Client reads are filtered by assigned target (`api/routes/scans.py:101`, `151`).
- **Proposed change.** No behaviour change. Add a table-driven test of every scan route against every role, so this protection cannot be lost when routers are rearranged at the split.
- **Security impact.** None today. The test guards against regression.
- **Functional impact.** None.
- **Test cases.** For each write route: admin and analyst allowed, viewer and client 403. A client reading another client's scan gets 404.
- **Acceptance.** The test exists and passes against the unchanged code.
- **Limitations and deferred.** Any analyst can scan any authorised target; ownership is per user, not per organisation (G4).

#### S4. Scanner subprocesses inherit the worker environment

- **Current behaviour.** `CliTool._exec` passes no `env` (`scanner/tools/base.py:79`). The worker environment holds the JWT secret, database URL, and HackerOne, GitHub, Jira and other tokens (`docker-compose.yml:59-86`).
- **Proposed change.** `_exec` passes an allow-listed environment: PATH, HOME, locale, proxy settings, and only the keys a given tool declares.
- **Security impact.** Medium. A compromised or misbehaving tool no longer sees platform secrets through its environment.
- **Functional impact.** None expected. A tool that needs a key declares it.
- **Test cases.** A fixture binary that prints its environment shows none of the secret names.
- **Acceptance.** That test passes for the base class, so every wrapper inherits it.
- **Limitations and deferred.** The process still shares the worker's filesystem and network (G2).

#### S5. Values from tool output become command arguments unchecked

- **Current behaviour.** URLs saved as findings by earlier tools are passed to sqlmap and Dalfox (`worker/tasks.py:429-454`). Wrappers use `exec`, not a shell, so shell injection is not possible, but a value beginning with `-` would be read as an option.
- **Proposed change.** One validator for every value that becomes an argument: it must parse as a host, URL, image name or path of the expected kind, pass the scope gate, and not begin with `-`. Wrappers pass targets through explicit flags.
- **Security impact.** Medium. Hostile content on a scanned site cannot alter a tool's options.
- **Functional impact.** Malformed URLs are skipped and counted.
- **Test cases.** Values such as `--output=/x`, a URL with an embedded newline, and a non-HTTP scheme are rejected.
- **Acceptance.** No wrapper builds an argument list from an unvalidated value; checked by review and tests per wrapper.
- **Limitations and deferred.** None.

#### S6. `source_path` is a free path on the worker

- **Current behaviour.** Code phases read `scan.config["source_path"]` and fall back to the target value (`scanner/orchestrator.py:476`).
- **Proposed change.** Code scans read only from one configured base directory. The path is resolved, symlinks included, and must stay inside it. A source tree containing a symlink that points outside the base is refused before any tool runs.
- **Security impact.** Medium once code phases are reachable. Prevents scanning, and so reporting on, arbitrary worker files.
- **Functional impact.** Source must be placed under the base directory. Repository checkout is not part of Stage 1.
- **Test cases.** `..` traversal, absolute path outside the base, a top-level symlink pointing outside, and a nested symlink pointing outside are all rejected.
- **Acceptance.** Those tests pass.
- **Limitations and deferred.** Checkout from GitHub arrives with the connector in Stage 5a. Copying each scan's source into an immutable per-scan staging area was suggested in review; it is deferred to the scan runner design (G2), where it fits naturally.

#### S7. Plaintext credential fields and free-form scan configuration

- **Current behaviour.**
  - `Credential` stores `token`, `headers` and `cookies` as plain columns (`db/models/credential.py`). No route, service or task imports it. That makes a write unlikely, not impossible.
  - `ScanCreate.config` is an unvalidated `dict` (`schemas/scan.py:17`), stored as plain JSON. A user can put a cookie or token there. Scan responses do not return it (`schemas/scan.py:27-52`), so the exposure is at rest, in backups and in logs.
  - Settings values are encrypted with a key derived from the JWT secret (`core/secretbox.py`).
- **Proposed change.**
  - A guard on the `Credential` model refuses inserts at the database session level, with a test that tries to insert one.
  - `config` is validated against a typed schema for the chosen profile: known keys only, each with a fixed type and range. Free-text values are not accepted.
  - Target values and URLs containing embedded user names or passwords are rejected.
- **Security impact.** Prevents real secrets being stored in plaintext through either path.
- **Functional impact.** Requests with unknown `config` keys get a validation error. The keys the bug-bounty path sets are on the allow-list.
- **Test cases.** Insert into `Credential` raises. Unknown `config` key rejected. Wrong value type rejected. Known keys accepted for each profile. A URL with embedded credentials rejected. Bug-bounty scan creation still works.
- **Acceptance.** Those tests pass.
- **Limitations and deferred.** No secure store is built in Stage 1. The planned approach, for Stage 5a (gate G3):
  - A dedicated secrets key, separate from the JWT secret, with a key identifier stored beside each value so keys can be rotated.
  - Secrets are write-only through the API and referenced by identifier.
  - A secret is decrypted only at the point of use and passed to a tool by environment or standard input, never on the command line.
  - Short-lived access is preferred over stored secrets: role assumption for AWS, federated credentials for Azure, a GitHub App for GitHub.
  - An external secret manager is an option for customer deployments.

#### S8. Deployment exposure

- **Current behaviour.** Postgres is published as `5432:5432` with user and password `netra` (`docker-compose.yml:162-166`). Redis is published as `6379:6379` with no password and is the Celery broker (`:180-181`). Flower is published on 5555 and Ollama on 11434, each under an opt-in profile (`:146`, `:219`). Images use moving tags, including a third-party image at `:latest` (`:193`). A second, older `Dockerfile` sits at the repository root.
- **Proposed change.**
  - Postgres and Redis are not published by default. A separate developer override file publishes them to localhost only.
  - Database and Redis passwords are required from the environment, with no default.
  - Flower binds to localhost and requires a password. Ollama is not published; the API and worker reach it on the internal network.
  - Every image is pinned by digest. The root `Dockerfile` is confirmed unused and flagged for removal.
  - A backup and restore procedure is written and exercised once: database dump plus volume copy before the change, restore steps, and the role password change needed on an existing volume.
- **Security impact.** High on a networked host: anyone who can reach Redis can inject tasks that the worker executes.
- **Functional impact.** Local tools that connect straight to the database need the override file. Existing installs follow a short migration procedure.
- **Test cases.** A test parses the compose file and fails on any data service published beyond localhost, any default password, and any image without a digest.
- **Acceptance.** That test passes, and the restore procedure has been run once on a copy.
- **Limitations and deferred.** TLS between services and secret files instead of environment variables are deferred to the deployment design.
- **Rollback.** Previous compose file plus the backup taken before the change.

#### S9. Scan execution isolation

- **Current behaviour.**
  - All tools for all scans run inside one worker container. The compose file sets a concurrency variable of 4, but the worker command passes no concurrency option (`docker/Dockerfile.worker:50`), so the real value is probably Celery's default of one process per CPU. Stage 0 confirms it.
  - On timeout or cancellation, `_exec` kills only the immediate process (`scanner/tools/base.py:96-103`), although a process-tree kill helper exists (`scanner/tools/process_control.py:81`). Child processes of a tool can be left running, still sending traffic.
  - That container holds the database URL, the broker URL, the JWT secret and platform tokens, and can reach Postgres, Redis, the API and the internet.
  - The worker runs as a non-root user, which is good.
  - There are no CPU, memory or process limits in the compose file.
  - Each tool call has a 300-second default timeout (`scanner/tools/base.py:68`); each task has a 3,600-second limit (`worker/celery_app.py:25`). A phase that runs sqlmap on 20 URLs can exceed the task limit.
  - Scan output directories are named by the first 8 characters of the scan ID and share one volume.
- **Risk assessment.**

  | Risk | Path | Severity |
  |---|---|---|
  | Tool compromise leads to platform compromise | A scanner parsing hostile responses is exploited; the attacker reads the JWT secret or database credentials, or injects tasks into Redis | High |
  | One scan reads another's data | Shared volume and shared process space | High with more than one customer |
  | Scanner reaches internal services | The tool resolves names itself and can reach Redis, Postgres or a cloud metadata address | High |
  | Resource exhaustion | No limits; one heavy scan starves the rest | Medium |
  | Phase killed mid-run | Tool timeouts add up past the task limit | Medium |
  | Tool keeps probing after it was stopped | Only the parent process is killed | Medium |

- **Proposed change in Stage 1 (minimum, no new services).**
  - Environment allow-list (S4).
  - Timeout and cancellation kill the whole process tree and wait for it to end.
  - Worker concurrency set explicitly.
  - Per-scan working directory using the full scan ID, private permissions, removed by a retention rule.
  - Per-tool timeout from the profile, and a per-phase budget that fits inside the task limit.
  - A cap on captured output size.
  - Compose limits on the worker: CPU, memory, process count, no privilege escalation, capabilities dropped.
- **Not solved in Stage 1.** Credential boundary, network egress and cross-scan separation need a separate scan runner that has no database or broker access, plus an egress policy that blocks private ranges and metadata addresses. That is its own design, scheduled in Stage 3 where execution policy per product is defined (gate G2).
- **Functional impact.** Long phases are cut at a budget and reported as incomplete instead of being killed without a record.
- **Test cases.** Timeout produces a `failed` state with a reason. A fixture tool that starts a child process leaves no process running after timeout or cancel. Output over the cap is truncated and flagged. The compose test asserts the limits exist.
- **Acceptance.** Those tests pass. The document and the README state that the platform is for lab use only, and not for any customer assessment, until G2 is met.
- **Limitations.** Dropping capabilities may change how the port scanner works as a non-root user; this is checked in the implementation plan.

### 6.2 Accurate execution states (step 1b)

- **Current behaviour.**
  - A tool run is recorded only as success or failure, and only in memory (`worker/tasks.py:42-51`). The phase row keeps a status, a count and a note; the individual runs are not saved (`worker/tasks.py:668-704`). A phase fails only when every run failed (`:54-69`).
  - A tool that exits cleanly with output the wrapper cannot read yields zero findings and counts as success. `parse_json_lines` silently drops malformed lines (`scanner/tools/base.py:118`).
  - The `netra scan` CLI command is a placeholder that prints "Scan complete — 0 findings" without scanning (`cli/main.py:224`). Two CI workflows use it with `--fail-on` (`.github/workflows/netra-scan.yml:55`, `netra-reusable.yml:61`), so that gate always passes.
- **Proposed change.**

  | Tool-run state | Meaning |
  |---|---|
  | `completed` | Ran and output parsed. Findings count recorded, and it may be zero |
  | `skipped` | Not applicable to the profile, disabled by configuration, or blocked by scope. Reason recorded |
  | `unavailable` | Not installed, deferred, or missing a required key. Reason recorded |
  | `failed` | Would not start, bad exit code, or timeout. Reason recorded |
  | `parse_error` | Ran, but the output could not be read. Raw output kept |

  - Expected coverage is written when the scan starts: the list of tools the profile requires for this target. It is the fixed denominator, so a run that never happened shows as missing and cannot drop out of the count.
  - Every run is saved in the existing `ScanPhase.tool_outputs` JSON. No schema change.
  - `skipped` carries one of two reasons that are treated differently. Disabled by profile or configuration does not count against the outcome. Blocked by scope or authorisation on required work does.
  - A run whose output was truncated at the size cap is not `completed`.
  - The scan lifecycle status values stay as they are. The API adds one field, `outcome`: `complete` when every expected tool is `completed`, otherwise `incomplete`, with a per-tool coverage list.
  - Reports and the scan page show the coverage list. "No findings" is shown only for a `complete` scan.
  - The CLI `scan` command exits non-zero with a clear "not available" message until it is wired to the real pipeline (decision D6). The two workflows are corrected to match.
- **Security impact.** Removes false assurance, which is a security defect in an assessment product.
- **Functional impact.** Additive API field. Scans that used to look clean may now show as incomplete.
- **Test cases.** One test per state. A clean fixture gives `completed` with zero and `outcome: complete`. A missing binary gives `unavailable` and `incomplete`. Malformed output gives `parse_error`. An expected tool with no recorded run gives `incomplete`. Truncated output gives `incomplete`. The CLI test asserts a non-zero exit.
- **Acceptance.** Every tool run in every phase ends in exactly one of the five states. No code path reports zero findings for a tool that did not complete.
- **Limitations and deferred.** A visual redesign of the scan page is not included; the coverage list is added to the existing page.

### 6.3 Profiles run only applicable phases (step 1b)

- **Current behaviour.**
  - The Celery chain runs the same six web phases for every profile (`worker/tasks.py:707-723`). A `container` or `cloud` scan would run subdomain discovery against its target value.
  - The profile list and the profile enum disagree. The enum has `mobile` and `custom` with no configuration and lacks `sast` and `iac`, which the configuration defines (`db/models/scan.py:33-46`, `scanner/profiles.py`). The API therefore cannot create a `sast` or `iac` scan.
  - `deep` sets code-scanning flags although a domain target has no source.
- **Proposed change.**
  - Each profile declares its phase list. The chain is built from it.
  - Every scan has the same lifecycle: authorisation and scope check, the profile's phases, analysis, reporting.

  | Profile | Phases |
  |---|---|
  | `quick`, `standard`, `deep`, `api_only` | Recon, discovery, ports, vulnerability scan, active tests (as the profile allows) |
  | `sast` | Static analysis, secrets, dependencies |
  | `iac` | Infrastructure-as-code checks |
  | `container` | Image scan |
  | `cloud`, `ai_llm`, `mobile`, `custom` | Rejected at creation with "not available" and the reason |

  - Each profile declares the target kinds it accepts. A mismatch is rejected at creation.
  - The code flags are removed from `deep`.
- **Security impact.** A code or image scan no longer sends network probes.
- **Functional impact.** `sast` and `iac` become creatable. Four profiles that never worked now say so.
- **Test cases.** For each profile, the built chain equals the declared list. Mismatched target kind rejected. Deferred profiles rejected with a reason.
- **Acceptance.** Those tests pass. No phase runs outside its profile.
- **Limitations and deferred.** New target kinds for source directories and images are needed; if the profile or target-type column is a database enum, one additive migration is raised in the plan for approval.

### 6.4 Real wrappers (step 1c)

- **Current behaviour.** Nikto, sqlmap, Dalfox, Semgrep, Trivy, Checkov and pip-audit inherit `PassthroughTool`, which runs `<binary> <target>` and parses nothing (`scanner/tools/generic.py:8`). `tests/test_scanner/` covers their registration in the tool inventory but has no invocation or parser tests for them.
- **Proposed change.**

  | Tool | Invocation (flags confirmed against the installed version in the plan) | Parsed |
  |---|---|---|
  | Nikto | Host flag, JSON output file, non-interactive | JSON |
  | sqlmap | URL flag, batch mode, level and risk from the profile, no data extraction | Result log |
  | Dalfox | `url` mode, JSON | JSON |
  | Semgrep | `scan`, JSON, pinned local rules, no network | JSON |
  | Trivy | `image` and `config` modes, JSON | JSON |
  | Checkov | Directory mode, JSON | JSON |
  | pip-audit | Requirements file, JSON | JSON |

  - `CliTool` gains per-tool accepted exit codes, because several tools exit non-zero when they find something.
  - Tool versions are pinned in the worker image and recorded with each run.
- **Security impact.** sqlmap never extracts data and runs only when the profile enables active tests and the URL passes S1 and S5.
- **Functional impact.** These tools produce findings for the first time.
- **Test cases.** Each parser is tested against output captured from the real tool in the lab: one sample with findings, one clean, one malformed.
- **Acceptance.** Seven wrappers, three captured samples each, all parser tests passing. No `PassthroughTool` remains in a phase that reports results.
- **Limitations and deferred.**
  - sqlmap has no stable machine-readable output; its parser is the most fragile.
  - Semgrep rule licence: my recollection, not verified, is that the registry rules carry a licence restricting use inside a competing or resold service. This must be checked before any rule is committed. If it does not permit a managed service, the fallback is a small set of our own rules.
  - Trivy needs its vulnerability database. It is loaded before the assessment, not during.
  - Prowler, Shodan and the LLM-security wrapper remain `unavailable`.

### 6.5 Pipeline consolidation (step 1d)

- **Current behaviour.** `worker/tasks.py` and `scanner/orchestrator.py` both implement recon, vulnerability scanning and active tests.
- **Dependency inventory (confirmed by search).**

  | Caller | Uses |
  |---|---|
  | `POST /scans`, resume, scheduler | `run_scan`, the Celery chain |
  | Bug-bounty routes and `scan_service` | `run_bugbounty_scan`, which calls `ScanOrchestrator.execute` |
  | Tests | `tests/test_bugbounty/test_agentic_orchestrator.py`, `test_worker_tasks.py` exercise the orchestrator |
  | MCP server | Calls wrappers directly; neither pipeline |
  | CLI | Placeholder; neither pipeline |
  | Frontend | Reads phases through the scans API (`PhaseTimeline.tsx`, `api/scans.ts`, `BBHuntDetail.tsx`) |

  The orchestrator's standard path is reached only if a non-bug-bounty profile is sent to `run_bugbounty_scan`. No caller does that.
- **Proposed change.**
  - The Celery chain is the single standard pipeline and gains the code, container and IaC phases.
  - Preserve the orchestrator's bug-bounty workflow and public contracts, while applying shared authorization and execution-state fixes wherever that path can invoke tools.
  - The orchestrator's standard path is removed only after: Stage 0 confirms no caller, a test proves a non-bug-bounty profile sent to it is refused, and both orchestrator test files still pass.
  - Preserve existing phase names and fields. Coverage and outcome fields are additive; update API models, frontend types, scan views and report renderers together. New code/image phases require explicit contract tests.
- **Security impact.** One place to enforce scope and states instead of two.
- **Functional impact.** None intended for any working feature.
- **Test cases.** Existing bug-bounty tests unchanged and passing. Phase API contract test. Frontend checks and the Playwright suite pass.
- **Acceptance.** One implementation of each standard phase. All tests from the Stage 0 baseline still pass.
- **Limitations and deferred.** The two remaining paths (standard and bug-bounty) are separated properly at the split in Stage 3.
- **Rollback.** The removal is one commit on its own, revertible without touching the rest.

### 6.6 Cancel, resume and duplicate execution (step 1b)

- **Current behaviour.**
  - Updating a scan's status only changes the database row (`api/routes/scans.py:178-179`). Setting a scan to cancelled does not, from this route, stop the tools already running.
  - Resume queues the whole pipeline again from the start (`api/routes/scans.py:267-278`).
  - Nothing claims a scan before running it, so a redelivered or double-queued task runs the scan twice (`worker/tasks.py:766-774`). Tasks use late acknowledgement, which makes redelivery after a worker restart normal.
- **Proposed change.**
  - Starting a scan is an atomic claim: one conditional update moves it from pending to running, and a task that loses the claim exits.
  - Cancel stops the running process tree and is checked before each phase and each tool call.
  - Resume continues from the first phase that is not completed, and re-checks authorisation and scope first.
- **Security impact.** A cancelled scan stops sending traffic to the target. A target is not scanned twice by accident.
- **Functional impact.** Cancel becomes effective. Resume becomes cheaper.
- **Test cases.** The same scan queued twice runs once. Cancel during a tool run leaves no process and no later phase. Resume skips completed phases. Resume after authorisation was revoked is refused.
- **Acceptance.** Those tests pass.
- **Limitations and deferred.** Pausing a tool mid-run is not supported; cancel and resume work at tool boundaries.

## 7. Stage 1 summary

- **Excluded.** Prowler, Shodan, LLM-security scanning, authenticated scanning, repository checkout, the secure credential store, the scan runner and egress control, tenancy, the asset model, UI redesign, the split.
- **Architecture and data model.** No new services or databases. No new Python dependencies expected. The inspected ORM uses String(20) for profile and target kind, but deployed constraints and migrations must be checked in Stage 0. Add source/image target kinds and align profile enums/configuration. Any required migration is documented and tested on a copy before application.
- **Dependencies.** Stage 0. Docker running and your approval to start the lab container for sample capture. Approval of proposals D4 to D7 and the shared contracts in docs/blueprint/.
- **Definition of done.**
  - Every acceptance criterion in sections 6.1 to 6.6 is met.
  - Steps were completed in order 1a to 1d.
  - All required behavior checks pass, with no unexplained regression from Stage 0; lint, type check and frontend checks pass. Test-count or skip changes must be explained; counts alone do not prove coverage.
- **Rollback.** Work is on a branch with one commit per issue. `pre-stabilisation` is the return point.

## 8. Stage 2: lab validation

### Problem it solves

No full scan has been checked against a target with known contents, so no NETRA result is yet evidence.

### Approach

Two kinds of expectation, kept separate:

- **Fixtures with results known by construction.** We write them, so we know what must be found.
- **A reviewed manual baseline.** For Juice Shop, each applicable tool is run once by hand in the lab and its output reviewed. The product run must then reproduce that result. This tests the wrapper and pipeline, not the tool's detection power. A tool is not required to find a particular Juice Shop issue.

### Fixtures and applicability

| Tool | Fixture | Expected |
|---|---|---|
| Recon tools, Nuclei, Nikto, ffuf | Juice Shop container | Matches the reviewed manual baseline |
| sqlmap, Dalfox | A small page we write with one injectable query parameter and one reflected parameter | Each tool reports its known issue. This is the required positive result |
| sqlmap, Dalfox | Juice Shop, on the parameterised URLs the crawl finds | Matches the baseline; zero is acceptable here and recorded |
| Semgrep | Small source file written to trigger named pinned rules | Those rule IDs |
| Gitleaks | File with a fabricated secret | That detection |
| pip-audit | Requirements file pinning versions with known advisories | Those advisory IDs |
| Checkov | Terraform file with specific misconfigurations | Those check IDs |
| Trivy | One image pinned by digest | Matches the reviewed baseline for that digest |

### Negative and safety checks

- A clean fixture gives `completed` with zero findings and `outcome: complete`.
- A removed binary gives `unavailable`; a forced timeout gives `failed`; corrupted output gives `parse_error`. Each makes the scan `incomplete`.
- A decoy container sits outside the scope. An in-scope fixture links and redirects to it. Its access log must show zero requests.
- A target without an authorisation record cannot be scanned.
- A viewer and a client cannot start a scan.
- Authorisation revoked during a scan: the next phase does not start.
- Cancel during a tool run: the tool's process tree is gone and the lab target's log shows requests stop.
- The same scan delivered twice runs once.
- Worker restarted mid-scan: the scan resumes or ends `incomplete`, and never runs a phase twice.
- A fixture tool that prints its environment shows no platform secret.

### Deliverables

- A `lab` compose profile on the internal network, removed after the run.
- The fixtures, under version control.
- A validation record in `docs/validation/`: per tool, version, command, duration, state, findings count, comparison with the expectation.
- Every report format generated from real results and opened.
- A regression test for every defect fixed.

### Explicitly excluded

- Any third-party or internet target.
- Detection-rate or accuracy claims.
- Bug-bounty hunt validation (Stage 4).
- Clean-machine installs. They are not dropped: they are gate G5 at Stage 3 exit.

### Architecture, data model, security

No data-model change. The lab is reachable only through the lab allow-list, which is empty by default and audited. The vulnerable container is never published beyond localhost.

### Dependencies

Stage 1 complete and approved. Docker running. Your approval to start the lab.

### Definition of done

- Every applicable tool reaches the expected state and result for its fixture, or the difference is explained in the record and accepted by you.
- All negative and safety checks pass.
- All report formats open from real data and show the coverage list.
- You have reviewed the validation record.

### Known limitations

- Juice Shop is one technology stack. Results do not transfer to others.
- Lab timing does not predict behaviour on large targets.
- Passing Stage 2 meets gate G1 only. It does not make the platform ready for customer assessments.

### Rollback

Remove the lab profile and containers. Defects are fixed forward with tests.

## 9. Stage 1–2 decisions — approval recorded

Stage 1–2 decisions D4–D7 are recorded under the implementation-start request. The revision 3 review provenance is retained above; this authoring session did not conduct that external review.

- **D4. Authorisation record storage.** Use validated target metadata in Stage 1, admin-only authorization writes, immutable scan-start snapshot, version/digest, revocation and audit. Recheck current policy at execution. Dedicated engagement/policy tables arrive in Stage 5a.
- **D5. Include rules.** Support explicit leading-label wildcards: *.example.com matches one or more subdomain labels but not the apex or example.com.evil.test. Normalize hostname representations; exclusions win. See the execution design for URL/method constraints.
- **D6. CLI scan command.** Make it report "not available" with a non-zero exit now; update both CI workflows so neither claims a successful assessment. Integrate the real API-backed CLI as a separate follow-up after the pipeline is validated.
- **D7. Isolation timing.** Define the boundary now; implement and validate after Stage 2, before customers, independently of the product split. Stage 1–2 remains controlled-lab use only.

## 10. Integration clarifications

The master planning entry point is [NETRA blueprint](../../blueprint/README.md). Its execution and product design specifies authorization shape, wildcard matching, ToolRun/JobEnvelope contracts and isolation acceptance. Its delivery document maps S1–S9 and all stages to work packages. This revision supersedes contradictory ordering in the historical docs/PLAN.md; neither document is evidence that tests passed.

- Unknown profile names must be rejected, replacing the current fallback to standard. The model/API/configuration lists and supported target kinds must agree.
- Authorization updates cannot use arbitrary target metadata writes to bypass role checks. Record policy version/digest and recheck current authorization at enqueue, dispatch, retry, resume and recheck. Scheduled jobs and Hunt must be inventoried explicitly.
- The subprocess environment allow-list must not inherit arbitrary proxy settings or a shared HOME containing credentials. Use a private home and only reviewed proxy configuration. Environment filtering is not process/filesystem isolation.
- Output caps apply during streaming capture, not after communicate has already buffered unlimited output. Terminate and reap descendant processes on timeout/cancel. Truncated/unparseable required output cannot produce complete coverage.
- A model insert hook is not a universal database security boundary. Block plaintext credential writes through all supported application paths, test bulk-write paths, and review raw-SQL exposure. Configuration allowlists do not sanitize secrets embedded in otherwise permitted URLs or raw evidence; reject URL credentials and redact exports.
- Stage 1 source scans use a resolved approved directory; immutable staged input and race-resistant sandbox mounts are part of G2. Source/image target types are necessary additions, not already-supported model values.
- Semgrep/tool/rule licenses are an unresolved verification dependency, not an asserted restriction. No external rule set is adopted until its exact license/version and intended use are checked. Author-owned rules are the fallback; tool licensing still requires review.
- The lab decoy check includes network counters as well as HTTP access logs. Document scanner DNS limitations; Stage 2 does not certify the G2 boundary.
- Isolated execution is implemented and validated as its own Stage 3 workstream; completion does not depend on splitting repositories. No fallback to the shared legacy worker for customer work.
- Historical outcome records remain coverage_unknown/incomplete unless evidence supports reconstruction. API/report compatibility includes these records.

No application changes, scans or tests were executed when producing revision 4.


Revision 4 release interpretation: G1 is evaluated per enabled product path. Stage 2 validates standard/MCP paths; Hunt requires its Stage 4 validation before that product is enabled for customer use. Untested paths must be disabled in a pilot deployment. Completion/coverage contracts in the blueprint apply to each enabled path.


## 11. Revision 5 review boundary

Preserve the user direction of two separate product directories: fix first, then separate; cut method and repository topology are decided only after the Stage 3 dependency review. D4–D7 and blueprint D9–D12 are proposed, not approved. Stage 0–2 is the next review scope, not an automatic implementation approval. Stages 3–5e require their own assessment before design approval. Runtime alternatives, topology and service worksheets are linked from the blueprint. P3A verifies existing scan/finding audit hooks; P12/P14 cover the 13 Hunt pages. P8 adoption is blocked on exact tool/rule license verification. Credential rotation for the reported Intigriti/Chaos disclosure remains unverified and must precede reuse.


Revision 5 baseline note: the review pass subsequently ran local checks, recorded separately in [Stage 0 baseline](../../validation/stage-0-baseline.md). These results do not constitute lab validation or approval of this design.


## 12. Revision 6 implementation handoff

The user's request to start implementation is treated as approval of the Stage 1–2 design and D4–D7, consistent with the supplied Claude handoff. Earlier revision notes retain historical approval status only. This does not confirm exposed credential revocation or approve D9–D12/later stages. The [P1/P2 plan](../plans/2026-11-16-p1-p2-authorization-scope.md) is newly prepared for review. Stage 0 continuation records actual disposable-stack checks and outstanding baseline disposition. No application source has been changed by this handoff.
