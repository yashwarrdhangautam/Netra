# Execution isolation and product boundaries

Version 1.1 — 2026-11-16. Direction only: Stage 3 assessment, design approval, implementation and validation required. Runtime alternatives and Windows/Kali topology are proposed in [ADR-001](review-amendments.md).

## 1. Threat boundary and deployment

Treat target responses, source trees, archives, tool output and AI-produced arguments as untrusted. The control plane authorizes work; an ephemeral sandbox executes a fixed adapter; ingestion validates output. The trusted controller may manage the container runtime, but its socket is never mounted into API-facing or scanner processes. Prefer a dedicated Linux runner host or VM for pilot execution. Docker on a shared host is not assumed to protect against all kernel exploits.

Control-plane network contains API, database, broker and controller management endpoint. Execution network has no route to those services. An explicit artifact gateway is the only result channel. Apply host-level destination filtering in addition to application checks; proxy-only enforcement cannot cover raw TCP tools. Block private, loopback, link-local, multicast and metadata destinations by default for IPv4 and IPv6. Authorized internal assessments use a dedicated runner/network policy with exact permitted ranges, never a global SSRF-disable switch. Local lab exceptions are similarly isolated and empty by default.

The runner is non-root, read-only root filesystem, private temporary workspace, no host directories except prepared read-only input, dropped capabilities, no privilege escalation and CPU/memory/PID limits. Initial defaults: 2 CPU, 2 GiB RAM, 256 processes and one job per sandbox; profile-specific limits can be selected after measured lab results. Tools needing privileges must use a separately reviewed adapter or remain unavailable; do not enable broad privileges for all tools.

## 2. Job contract

Proposed JobEnvelope version 1:

| Field | Meaning and validation |
|---|---|
| schema_version | Exactly 1; reject unsupported versions |
| job_id / scan_id / attempt_id | Server-generated UUIDs; distinct retry attempts |
| organization_id / engagement_id | Server-bound identity, never trusted from a client body |
| authorization_id / policy_version / policy_digest | Immutable reference plus digest of canonical policy |
| issued_at / expires_at | UTC lease window; expired jobs refused |
| profile_id / profile_version | Reviewed execution specification |
| target_kind / target_value | Canonical validated target |
| adapter_id / adapter_version | Allowlisted adapter, not a shell command |
| tool_image_digest / rules_digest | Pinned artifacts |
| limits | Tool/phase deadline, rate, output/artifact caps |
| input_artifacts | Scoped read references with expected hashes and sizes |
| result_capability | Short-lived, single-attempt upload permission |

The controller authenticates both sender and runner, signs canonical job content and rejects tampering. Job delivery is at least once; only the current attempt lease may accept results. The controller stores job state before dispatch, acknowledges durable result ingestion before marking completion, and rejects replayed/expired capabilities. No arbitrary argv, executable, mount, environment variable or network policy enters from a caller. The adapter builds argv from typed parameters.

## 3. Authorization semantics

Stage 1 authorization metadata shape: version=1, authorization_id, authorized_by (operator identity), authorized_at, expires_at, evidence_reference, policy_version, scope_digest, allowed_methods and limits. Only admins can change authorization; analysts may execute already-authorized work, subject to ownership restrictions. Never infer authorization from who created the target. Log old/new versions and actor; reject malformed dates, expiry before issue and unsigned/missing evidence references. An evidence reference points to an operator-reviewed record; it is not proof supplied by an AI.

Canonicalize hostnames to lowercase IDNA and remove a terminal dot. Reject credentials in URLs, control characters, ambiguous encodings and option-like values. *.example.com matches one or more labels below example.com, never example.com itself or example.com.evil.test. Match full label boundaries. Exclude rules have precedence. IP authorization is separate from hostname authorization; resolving an authorized hostname does not authorize scanning every port or virtual host on its address. URL rules specify scheme/host/port and optional path boundary; a /api prefix does not match /apix. Methods, ports and rate budgets are independent constraints.

Recheck at creation, dispatch, each adapter invocation, retry and resume. A version change pauses pending work for reauthorization. Revocation cancels active work and removes its network allowance. A lease lasts at most 60 seconds; renew only while authorization remains valid. When policy service is unavailable, no new work starts and existing execution loses its lease. Acceptance requires measured cancellation within the lease bound, including descendant processes.

## 4. Egress and tool support

Resolve names through the controlled resolver; validate every returned A/AAAA address. Enforce destination IP/port rules outside the sandbox and re-evaluate on DNS changes. Host identity checks remain in HTTP-aware adapters/proxy; shared IP allowlisting alone is insufficient to authorize every hostname. Disable redirects/crawling unless each destination is enforceable. A non-HTTP tool uses a policy-constrained address/port list. If a tool cannot preserve the authorization contract, reject that mode.

The Stage 1 tool capability matrix must record: target kinds, redirect behavior, DNS behavior, secondary requests, supported method controls, rate controls, output format, accepted exit codes and permitted adapter flags. Use no external target to discover these behaviors: capture them in the lab. Feed downloads and registry access occur in a separate artifact preparation step; record their provenance. Execution cannot silently fetch updated templates.

## 5. Results and evidence

ToolRun v1 contains scan/attempt/tool identifiers, policy/profile/tool/rules versions, timestamps, state, required flag, exit code, reason code, findings count, artifact hashes, truncation flag and parser version. States: completed, skipped, unavailable, failed, parse_error. Required work not completed makes coverage incomplete. Not-applicable tools have required=false and a recorded reason. Empty required sets are invalid profile definitions. Historical scans without run evidence are incomplete with coverage_unknown, not backfilled as clean.

A cancelled scan retains partial evidence and is incomplete. Truncation that prevents a parser from proving completeness is parse_error with output_truncated; successful partial parsing cannot silently become completed. Raw outputs may contain secrets: restrict access, redact export copies, hash originals and expire according to retention. Treat HTML/report content as data, escape it, disallow active scripts and remote-resource retrieval during rendering.

Ingestion rejects oversized archives, path traversal, symlinks, decompression bombs, invalid schemas, unknown run IDs and wrong attempt/tenant bindings. Normalize into observations only after validation. Artifact names are server-generated; the uploader cannot select another customer's path.

## 6. Failure, retry and recovery

- Timeout: terminate the full process group, reap children, capture bounded diagnostics, state failed.
- Lost heartbeat: expire lease, revoke network/result capabilities, mark incomplete; no implicit successful completion.
- Duplicate result: same attempt plus checksum is idempotent; different checksum is quarantined and audited.
- Retry: fresh attempt/workspace with current policy; preserve prior evidence. Retry read-only operations at most twice by default; active tests require a retry policy that accounts for side effects.
- Cancellation: prevent successor phases and retries; revoke lease and wait for process/network teardown confirmation.
- Controller restart: reconcile recorded leases with live sandboxes and terminate orphans before admitting new work.
- Storage failure: report incomplete; do not acknowledge successful persistence or discard the sole result copy before bounded recovery expires.

## 7. Enterprise/Hunt separation

Shared package contracts: scope decisions, execution envelopes, adapters, ToolRun, evidence storage, finding normalization and audit events. Enterprise owns organization inventory, engagement workflows, connector state, risk and remediation. Hunt owns programs, scope imports, hypotheses, verification approvals and submission drafts. Product modules consume services rather than importing one another's routes/tasks.

The user direction is two directories after stabilization. Stage 3 compares a controlled copy with explicit shared-code maintenance against extracted/versioned shared packages; repository topology remains undecided. Inventory dependencies and the 13 Hunt pages before approving the cut. Retain current API compatibility through adapters while moving business logic into services. Existing standard and Hunt callers must be inventoried before deletion. Version shared contracts; support reading the previous persisted result format during migration. Package-level dependency checks enforce that shared execution does not import product-specific models.

Hunt passive mode performs no target probes; public-source collection still obeys provider limits and data policy. Active mode requires explicit approved methods and scope. A program scope update invalidates pending approvals. AI-generated tests are proposals; deterministic policy decides execution. Submission remains an operator-reviewed draft/export. Cross-program evidence and retrieval are separated by access policy.

## 8. Acceptance and rollout

Required tests: compromised fixture cannot read platform environment/files, contact database/broker/metadata, mount host paths, contact the decoy, bypass IPv6 policy or read another run's workspace; redirect/rebinding fixtures denied; expired/revoked jobs stop; child processes die; duplicate/cross-attempt upload denied; required-tool failures remain incomplete; controller restart removes orphans.

Rollout: feature-flag runner routing in local lab, compare normalized results to the stabilized baseline, migrate one profile at a time, then enable it for all supported customer modes. No automatic fallback to the legacy shared worker for customer work. Rollback disables new customer jobs, preserves evidence and restores the last validated runner image/policy; reverting isolation is not an acceptable production fallback.
