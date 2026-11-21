# P1/P2 authorization and scope enforcement implementation plan

> **For agentic workers:** Use the executing-plans workflow after this plan is reviewed and the Stage 0 disposition is accepted. Steps use checkbox tracking. Do not interpret this document as a command to run scanners or as permission to commit.

**Goal:** Refuse standard scans and MCP network operations unless current, administrator-recorded authorization and explicit scope permit the requested action.

**Architecture:** Store a validated authorization record in Target.metadata_, take an immutable policy snapshot in Scan.checkpoint_data, and reload current policy before every permitted launch. Reuse ScopeValidator for deny-first host/wildcard/IP matching; add strict rule/input compilation and scheme/port semantics rather than introducing a second hostname matcher. Keep existing router-level role checks and audit services.

**Tech Stack:** Python 3.12 target, FastAPI/Pydantic 2, SQLAlchemy async sessions, PostgreSQL JSONB, Celery, pytest/httpx. Local baseline Python is 3.13; record version-specific verification separately.

**Status:** Prepared for review on 2026-11-16 against 24d2238. Stage 1–2 design/D4–D7 approval is inferred from the user's request to start implementation; this source-specific plan is newly written. G0 disposition is still outstanding. No application code is implemented by this file. Git commits and pre-stabilisation tagging remain separate from authoring authorization.

## 1. Prerequisites and boundaries

- [ ] Review docs/validation/stage-0-baseline.md and its continuation. Accept/classify known baseline failures before coding; do not relabel failed checks as passed.
- [ ] Verify current branch and working tree. Preserve documentation and any concurrent edits. Use a task branch in the current checkout; do not implement directly on main or copy product directories.
- [ ] Do not use Intigriti/Chaos credentials. Rotation is unverified. No provider credential is needed for this package's tests.
- [ ] Use fake adapters and controlled fixtures only. Stage 2 real adapter/lab captures remain separate.
- [ ] No database migration is expected for metadata/snapshots; disposable schema confirms profile/target kind varchar(20). This does not authorize adding unsupported source/image modes early.

## 2. Exact file map

Create:
- src/netra/schemas/authorization.py — strict request/stored record schemas.
- src/netra/services/scan_authorization.py — record validation, digest, grant/revoke, snapshot and freshness.
- src/netra/scanner/scope_gate.py — strict input/rule compilation and per-action scope check using the existing matcher.
- tests/test_services/test_scan_authorization.py — expiry, revocation, snapshots, digest and mutation cases.
- tests/test_scanner/test_scope_gate.py — boundary/canonicalization/action cases.
- tests/test_api/test_target_authorization.py — admin routes and denied forged metadata.
- tests/test_worker/test_scope_enforcement.py — fake-tool invocation/retry/discovery cases.
- tests/test_mcp/test_scope_enforcement.py — registered tool inventory and DB-backed policy cases.

Modify:
- src/netra/api/routes/targets.py — actual route-local TargetCreate/TargetUpdate schemas, grant/revoke endpoints, invalidate authorization on scope/value mutation. The similarly named src/netra/schemas/target.py is not the API's active request schema; keep its contract consistent but do not assume editing it protects routes.
- src/netra/api/routes/scans.py — authorize before persisting/queueing, snapshot on creation, reauthorize resume, prevent caller-controlled snapshots.
- src/netra/api/routes/findings.py — scope/method check before SSRF lookup and _retest_request.
- src/netra/worker/tasks.py — entry guard, per-phase reload and per-tool check; preserve failed status when policy denies.
- src/netra/worker/scheduler.py — authorization before scan creation/dispatch; fix the nonexistent AsyncSessionLocal import as part of integrating a real async helper, with regression evidence.
- src/netra/bugbounty/scope.py — URL scheme and effective-port tests/fix only; preserve shared matcher behavior otherwise.
- src/netra/mcp/server.py — typed guard around all scanner tools; trusted stored program scope for federation.
- src/netra/scanner/tools/httpx.py and nuclei.py — verified safe redirect/template configuration only; unsupported modes fail closed until P8 capability review.
- Existing tests/test_api/test_scan_dispatch.py, tests/test_bugbounty/test_scope.py and relevant MCP/worker fixtures — explicitly provision authorization where execution is intended; do not globally bypass the gate in conftest.

## 3. Contract fixed for this plan

Reserve metadata_["scan_authorization"] for the server-managed record. Reserve checkpoint_data["authorization_snapshot"] for server-only snapshots. Metadata authorization is not accepted through arbitrary target create/update/import payloads. Use model ConfigDict(extra="forbid") on active target request schemas; identify any frontend callers sending extras before making this stricter.

Request fields: evidence_reference (nonblank string), expires_at (timezone-aware future datetime), allowed_actions (nonempty subset of passive_recon/http_probe/port_scan/vulnerability_scan/active_test/retest), http_methods (nonempty subset GET/HEAD/POST/PUT/PATCH/DELETE/OPTIONS), ports (nonempty list, integers 1–65535), max_requests_per_second (1–300). Actions and HTTP methods are separate concepts; tool adapters may expose only methods they can enforce. Unknown fields are rejected.

Stored fields add version=1, authorization_id UUID, authorized_by server actor UUID, authorized_at UTC, policy_version positive integer, scope_digest SHA-256, revoked_at optional UTC. Do not let the client supply authorizer, version, timestamps or digest. policy_version increments under a row lock. UTC timestamp comparison uses an explicit now parameter in pure tests. Revocation is terminal for that authorization ID; a fresh grant creates a fresh ID/version.

Digest covers target_type, canonical target value, canonical includes/excludes, allowed_actions, http_methods, ports and rate. Evidence_reference is provenance, not a network fetch. Do not fetch arbitrary evidence URLs. Snapshot stores the full validated record plus canonical policy and target ID; compare both authorization_id and digest/version with current stored authorization on execution. Any mismatch requires reauthorization; never silently refresh a queued scan's snapshot.

Supported P1/P2 targets are current domain, IP, URL, IP range and explicit domain list. A domain list is split into individual normalized entries and each is authorized; never pass a joined list as one hostname. Source/image authorization is unavailable until P7/P5 define those target contracts. Unknown profile or unsupported mode must not bypass these checks.

## 4. Task A — schema and pure policy helpers

- [ ] Add schema tests first, using the real Pydantic model; assert unknown fields, empty evidence, naive/past expiry, duplicate methods, invalid action and invalid ports fail. Use fixed UTC datetimes in tests.
- [ ] Define AuthorizationRequest and AuthorizationRecord in schemas/authorization.py with ConfigDict(extra="forbid", frozen=True), AwareDatetime fields, field constraints, and model validators. Keep stored server fields out of the request model.
- [ ] Add a pure canonical_policy(target, request) function and policy_digest(policy) in services/scan_authorization.py. Serialization is UTF-8 JSON with sorted keys and compact separators; sort/deduplicate set-like lists after validation. Canonicalization must reject invalid entries rather than drop them.

Digest implementation:

```python
import hashlib
import json

def policy_digest(policy: dict[str, object]) -> str:
    encoded = json.dumps(policy, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()
```

- [ ] Use an AuthorizationDenied exception carrying a stable reason code, not raw database/provider exceptions. Reason codes: authorization_missing, authorization_invalid, authorization_expired, authorization_revoked, policy_changed, target_missing, scope_denied, action_denied, policy_unavailable.

```python
class AuthorizationDenied(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)
```

- [ ] Implement validate_current_record(target, now) to parse stored JSON, verify timezone/expiry/revocation, recompute canonical policy digest and return the validated record. Catch Pydantic/value errors as authorization_invalid; never catch AuthorizationDenied and turn it into an allow.
- [ ] Run the new helper tests before integration, with source on PYTHONPATH:

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location) 'src')
& .\.venv\Scripts\python.exe -m pytest --no-cov tests/test_services/test_scan_authorization.py -q
```

Expected progression: initial import/assertion failure, then all explicit helper cases pass. Record both outputs; do not assume this document's snippets were executed.

## 5. Task B — reuse and tighten matcher behavior

The current ScopeValidator correctly implements wildcard label boundaries and deny-first order. Its _match_url ignores URL scheme and treats an omitted rule port as unrestricted. Its constructor does not reject malformed deny rules. Reuse matching but correct these explicit problems.

- [ ] Add the following regression in tests/test_bugbounty/test_scope.py before changing _match_url:

```python
from netra.bugbounty.scope import AssetType, RuleType, ScopeRule, ScopeValidator

def test_https_rule_does_not_authorize_http_or_other_port():
    validator = ScopeValidator([
        ScopeRule(RuleType.IN, AssetType.URL, "https://api.example.org/api")
    ])
    assert validator.check("https://api.example.org/api/users").allowed
    assert validator.check("https://api.example.org:443/api/users").allowed
    assert not validator.check("http://api.example.org/api/users").allowed
    assert not validator.check("https://api.example.org:8443/api/users").allowed
    assert not validator.check("https://api.example.org/apix").allowed
```

- [ ] Replace URL matcher logic with the existing host/path logic plus explicit scheme and effective-port comparison:

```python
def _effective_port(target: ParsedTarget) -> int | None:
    if target.port is not None:
        return target.port
    return {"http": 80, "https": 443}.get(target.scheme or "")

def _match_url(rule_pattern: str, parsed: ParsedTarget) -> bool:
    rule = parse_target(rule_pattern)
    if rule.host is None or parsed.host is None or rule.host != parsed.host:
        return False
    if rule.scheme is not None and rule.scheme != parsed.scheme:
        return False
    if (rule.scheme is not None or rule.port is not None) and (
        _effective_port(rule) != _effective_port(parsed)
    ):
        return False
    return rule.path == "/" or parsed.path == rule.path or parsed.path.startswith(rule.path + "/")
```

Unqualified legacy host/path rules retain their prior meaning unless an explicit port exists. Standard authorization compiler requires full HTTP(S) URLs for URL rules. Review affected Hunt tests and document this tightening; do not widen the rule to make legacy tests pass.

- [ ] Implement strict compile_rules in scanner/scope_gate.py: accept current registered target and explicit includes, compile excludes first, validate every rule before constructing ScopeValidator. Classify canonical IP/CIDR with ipaddress, wildcard only as a leading '*.', domain through IDNA label validation, and URL with urllib.parse plus HTTP(S), username/password, explicit-port, control-character and path checks. Reject embedded wildcard, option-like strings, unknown scheme, percent-encoded authority delimiters, invalid CIDR and an empty or malformed exclusion. Do not use the permissive parser as the input validator.
- [ ] Preserve excludes independently of per-action allow filters. A matching deny cannot disappear because the first matching allow uses a different method. After address scope passes, check allowed action, HTTP method and port from the stored policy. A bare host is not permission for every port.
- [ ] Add a parameter matrix for exact apex, nested wildcard, apex exclusion, suffix attack, case/trailing-dot/IDNA, mapped IPv4/IPv6, CIDR boundary, credentials in URL, leading dash, newline/tab, malformed exclusion, path traversal and URL default/explicit ports. Assert denies do not invoke DNS or a tool.

```python
import pytest
from netra.bugbounty.scope import AssetType, RuleType, ScopeRule, ScopeValidator

@pytest.mark.parametrize("candidate,allowed", [
    ("a.example.org", True), ("a.b.example.org", True),
    ("example.org", False), ("example.org.evil.test", False),
    ("blocked.example.org", False),
])
def test_existing_wildcard_and_exclusion_contract(candidate, allowed):
    validator = ScopeValidator([
        ScopeRule(RuleType.IN, AssetType.WILDCARD, "*.example.org"),
        ScopeRule(RuleType.OUT, AssetType.DOMAIN, "blocked.example.org"),
    ])
    assert validator.check(candidate).allowed is allowed
```

- [ ] Run new scope tests and the complete existing Hunt scope suite; all must pass. Confirm no second wildcard matcher was introduced.

## 6. Task C — administrator grant/revoke API

- [ ] Add PUT /api/v1/targets/{target_id}/authorization and DELETE at the same path. Both depend on require_admin from netra.api.rbac, load Target under SELECT FOR UPDATE, and use the shared record service. Repeated revoke is idempotent and does not create a new grant.
- [ ] Grant builds the record using current target and server actor, assigns a NEW metadata dict so SQLAlchemy tracks JSON mutation, and records target.authorization.grant in the same transaction. Do not log evidence contents or secrets; log authorization ID, policy version, expiry and scope digest.
- [ ] Revoke replaces the stored record with revoked_at and records target.authorization.revoke atomically. Subsequent gate calls fail. Stage 1 cannot claim instant interruption of an already-running scanner; that is bounded by tool timeout/cancellation, strengthened by G2 leases.
- [ ] Any update changing value/scope_includes/scope_excludes invalidates authorization atomically, even if made by an analyst. Do not let analysts change the policy then retain an admin signature. A new admin grant is required. Use explicit fields-set comparison; changes only to name/group do not invalidate it.
- [ ] Reject authorization keys in create/import/update payloads through actual route schemas, including the older schema aliases. Snapshot fields are never accepted via ScanCreate.config.
- [ ] Tests use four roles: only admin grant/revoke succeeds; analyst/viewer/client get 403; nonexistent object 404 without metadata writes; two concurrent grants increment versions safely; failed audit/commit leaves both record and audit unchanged; unrelated metadata survives; scope change invalidates authorization.

JSON persistence pattern inside the locked transaction:

```python
target.metadata_ = {**(target.metadata_ or {}), "scan_authorization": record.model_dump(mode="json")}
await record_audit(
    db, actor=current_user, action="target.authorization.grant",
    resource_type="target", resource_id=str(target.id),
    detail={"authorization_id": str(record.authorization_id),
            "policy_version": record.policy_version, "scope_digest": record.scope_digest},
)
await db.commit()
```

Here record is the validated AuthorizationRecord created by the grant service; current_user is require_admin's User. The service does not commit independently. Grant/revoke response contains validated authorization metadata but no secret material.

## 7. Task D — scan creation, snapshot and fresh execution

- [ ] Introduce async prepare_scan_authorization(db, target_id, *, now) returning a JSON-safe snapshot. It loads the Target, calls validate_current_record, compiles current scope and returns target_id, record and canonical policy. No caller config is merged into this object.
- [ ] Introduce async require_scan_authorization(db, scan_id, *, now) returning (scan, target, record, validator). Use populate_existing=True or db.refresh for current values, not a stale identity-map object. Require a valid stored snapshot and matching ID/version/digest. Reject cancelled scans. A legacy scan lacking a snapshot is denied until explicit reauthorization.
- [ ] In create_scan, obtain snapshot before db.add/commit or run_scan.delay. Put it under checkpoint_data.authorization_snapshot, set scan.user_id=current_user.id, and persist scan.create audit in the same transaction as creation. Then queue. Return 403 with a stable authorization reason for policy denial and 503 for policy storage unavailable. A broker enqueue failure must not masquerade as successful execution; preserve a failed dispatch state/reason for later retry.
- [ ] In resume_scan, validate current policy against the stored snapshot BEFORE status changes or enqueue. A revoked/changed policy never refreshes implicitly. Add an explicit administrator reauthorization workflow if resuming under a new grant is required; until implemented, require a new scan.
- [ ] Update the successful dispatch regression to grant authorization through the API before creating a scan. Add missing/expired/revoked grant cases; assert no Scan row and no delay call for creation denies. Add resume cases asserting unchanged status and no enqueue on denial.

Snapshot merge shape:

```python
scan.checkpoint_data = {
    **(scan.checkpoint_data or {}),
    "authorization_snapshot": snapshot,
}
```

- [ ] At run_scan dispatch, load authorization before setting RUNNING and before create_scan_pipeline. At the start of each network phase reload authorization, even if a previous phase already checked it. Validate each individual target immediately before each tool call. A previous_result payload is untrusted data, never authorization.
- [ ] Add tests for grant expiry after enqueue, revoke between phases, scope changes between retries and forged checkpoint/config snapshots. Mock the tool .run methods with AsyncMock and assert not awaited on denied inputs. The snapshot is a historical ceiling; current policy may narrow or revoke it but cannot broaden execution silently.

## 8. Task E — discovered targets, safe adapters and denial recording

- [ ] _execute_scope_resolution may retain discovered names as evidence, but produce separate authorized_subdomains and discovered_not_authorized lists. Do not resolve/probe the latter. Include a discovered name only if the explicit current policy already authorizes it; never append a new allow rule from scanner output.
- [ ] _execute_recon checks every host before httpx; pass follow_redirects=False explicitly. Validate every returned URL again before vulnerability scanning. _execute_vuln_scan checks each destination/action. _execute_active_test checks each finding URL and HTTP method before sqlmap/Dalfox; FFUF path expansion must stay inside the authorized URL prefix.
- [ ] At retest_finding, load scan/target policy and require retest + GET before SSRF DNS checking and before _retest_request; retain follow_redirects=False.
- [ ] Nuclei templates must resolve from a reviewed fixed name-to-local-artifact mapping. Unknown names, path traversal, remote templates, code/headless/OAST or arbitrary secondary destinations are unavailable until their policy behavior is reviewed in P8. Do not invent flags: confirm supported installed-version flags through local help and a lab capture. Disable any mode whose internal destinations cannot be constrained.
- [ ] Generic wrappers cannot be assumed safe because kwargs were passed; PassthroughTool ignores them. Keep unsafe/unreviewed modes unavailable until P8 implements their actual controls. Record this in the per-tool capability matrix and avoid silently calling a passthrough binary.
- [ ] Record required blocked work in ScanPhase.tool_outputs as state=skipped, required=true, reason_code plus action and sanitized target. Mark the phase BLOCKED and scan FAILED (existing lifecycle) so old report paths cannot declare a successful clean assessment. P6 later adds complete/incomplete presentation; P1/P2 already must prevent false success.

Proposed denial entry:

```python
entry = {
    "tool": tool_name, "state": "skipped", "required": True,
    "reason_code": denial.code, "target": sanitized_target,
    "policy_version": policy_version,
}
phase.tool_outputs = {**(phase.tool_outputs or {}), "policy_denials": [entry]}
phase.status = PhaseStatus.BLOCKED
scan.status = ScanStatus.FAILED
scan.error_message = denial.code
```

Append to existing denial records rather than overwrite them in the final implementation; sanitized_target excludes URL credentials/query values. tool_name is from the adapter registry, not caller code. Add a regression proving reporting does not overwrite a blocked phase/scan as completed.

## 9. Task F — scheduled dispatch and direct entry coverage

- [ ] Refactor execute_scheduled_scan's DB work into one async helper called once by asyncio.run; use async_session_factory, not the nonexistent AsyncSessionLocal. The helper loads schedule/target, validates authorization, creates scan plus server snapshot atomically, and returns the scan ID. Only the outer task dispatches it after commit. Do not reuse an async session across separate event loops.
- [ ] Existing schedule.config remains untrusted and cannot supply an authorization_snapshot. Expired/revoked targets produce a recorded blocked run and no scan dispatch. Recheck on every scheduled occurrence, not only schedule creation.
- [ ] Direct .delay/run_scan and direct phase calls must deny missing snapshots; no assumption that the API was the only entry. Existing standard ScanOrchestrator paths must either use the same gate or refuse standard execution until P9 removes them. Do not retain an unguarded fallback.
- [ ] Hunt continues its stored-program scope path; do not interpret a program handle as a domain or silently copy program scope into standard authorization. Changes to shared URL matching require Hunt regression tests. G1 for Hunt is not claimed until its Stage 4 validation.

## 10. Task G — MCP registration coverage and trusted scope

- [ ] Preserve public tool names/signatures. Add a registration-level guard using functools.wraps so direct Python calls and MCP-dispatched calls both execute the guard. Reject malformed bulk target lists and authorize each item.
- [ ] Standard MCP target resolution must identify exactly one registered authorized policy that covers the requested target/action. Zero matches denies; multiple matches denies as ambiguous, never unions independent grants. Operators can resolve ambiguity by server-side binding to one target ID. The bound target ID comes from trusted server configuration, not tool arguments.
- [ ] For federated BB tools, ignore caller-supplied scope_rules for authority. Bind the local MCP server to a program ID through trusted configuration; load that program and active rules from the database. Missing binding, missing program, invalid rule or database outage denies. Keep the parameter only for compatibility and document that it no longer authorizes work. Validate downstream arguments independently of caller claims.
- [ ] Source/image tools remain unavailable until supported P5/P7 target kinds and path containment exist. Prowler/Shodan/LLM security return unavailable without invoking binaries. Discovery/inventory resources that do not contact a target are classified explicitly; new registrations without a policy classification fail the inventory test.
- [ ] Tests enumerate every @mcp.tool registration from the module AST and compare against the explicit target-tool/read-only/deferred registry. A newly added tool must make the test fail until classified. Parameterize all target tools with missing authorization and assert no binary resolution/execution or federated client invocation. Test DB outage, ambiguous target, supplied fake scope rules, forbidden template path and redirect option.

## 11. Validation commands and expected outcomes

Run focused tests as each task lands; add each listed new test file before referencing it:

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location) 'src')
& .\.venv\Scripts\python.exe -m pytest --no-cov tests/test_services/test_scan_authorization.py tests/test_scanner/test_scope_gate.py tests/test_api/test_target_authorization.py tests/test_worker/test_scope_enforcement.py tests/test_mcp/test_scope_enforcement.py tests/test_api/test_scan_dispatch.py tests/test_bugbounty/test_scope.py -q
& .\.venv\Scripts\python.exe -m ruff check src/ tests/
& .\.venv\Scripts\python.exe -m pytest --no-cov -q
npm.cmd --prefix frontend run lint
npm.cmd --prefix frontend run build
npm.cmd --prefix frontend run test:unit
```

All focused policy tests must pass; full-suite regressions must be resolved, not bypassed by auto-authorizing every fixture. Existing type failures are separately baselined; run mypy on changed modules and compare full diagnostics to the recorded baseline, with no unexplained new errors. Browser tests use a fresh disposable deployment and synthetic accounts. Capture explicit pass/fail/skip counts.

After application code changes, run graphify update . as required by AGENTS.md. Review its changes separately. No external-target test is allowed for this package. Stage 2 decoy and G2 isolation remain future acceptance evidence, not inferred from mocked adapters.

## 12. Review checklist, boundaries and rollback

- [ ] Every outbound standard entry is listed in the caller inventory and guarded; unavailable modes cannot call binaries.
- [ ] Authorization is not client-writable; scope edits invalidate signatures; DB outages/expiry/revocation fail closed.
- [ ] No second wildcard matcher; malformed deny rules block policy construction.
- [ ] Snapshot and current policy both constrain work; no stale ORM object bypasses revocation.
- [ ] Policy denial cannot become a successful zero-finding scan through exception handling/reporting.
- [ ] Existing router RBAC remains enforced; grant/revoke is admin-only.
- [ ] Hunt matching regressions pass, and unvalidated Hunt execution is not advertised as G1 complete.
- [ ] No customer/provider secrets in logs, tests, plan, or snapshots.
- [ ] Reviewer confirms exact diff and limitations before merging or deploying.

Rollback: retain metadata/snapshot records as inert JSON, disable new execution, and restore the last reviewed application version only in the local lab. Do not roll back authorization enforcement while allowing customer scans. No destructive schema rollback is needed. Commit only after explicit user instruction, grouping schema/policy, API integration, worker integration and MCP integration separately.

## 13. Known limits and executable-plan boundary

The plan fixes contracts, integration sites and test cases; Tasks A/C–G still require writing their complete source patches against current files. The complete digest and URL matcher replacements above are concrete, but they are not the entire implementation. Do not claim all-code-generated or implement every task from snippets alone. The first execution batch is A–C after G0 disposition and review; prepare/review each full patch before applying it. Unsupported scanner modes fail closed until their installed-version controls are verified. Customer execution remains prohibited until G2 and other applicable gates pass.


## Execution record — 2026-11-18

User authorized implementation with the existing type failures tracked separately. Authorization, API, worker/scheduler, retest and MCP enforcement are implemented; see [implementation evidence and availability restrictions](../../validation/p1-p2-implementation.md). Unreviewed adapters explicitly remain unavailable until P8. The previous text describes the pre-execution plan; complete patches now exist in the working tree. No commit or deployment was performed. Final full-suite result is stored in docs/validation/p1-p2-suite-final.log.
