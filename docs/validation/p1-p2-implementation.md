# P1/P2 authorization implementation record

Date: 2026-11-18. Scope: authorization and scope enforcement under the approved Stage 1–2 plan. Existing type failures were accepted by the user as separately tracked; credential rotation remains deferred and unverified. No credentials were used or rotated. No commits, deployment or customer scans were performed.

## Implemented behavior

- Strict typed authorization request and server-owned record in Target.metadata_. Admin-only grant/revoke endpoints: PUT and DELETE /api/v1/targets/{target_id}/authorization. Services lock the row and write audit events in the same transaction. Revocation is idempotent; regrant changes identity/version.
- Ordinary target create/update schemas reject arbitrary metadata. Scope/value edits revoke an existing grant. Grant fields include evidence reference, aware expiry, allowed actions, HTTP methods, explicit ports and maximum request rate.
- Standard scan creation requires current authorization before persistence/dispatch, stores a server-generated snapshot in checkpoint_data, binds the initiating user, and audits creation atomically. Dispatch failure is explicit. Resume refuses changed/revoked/expired grants and legacy scans without snapshots.
- Strict rule compilation rejects malformed exclusions, ambiguous URLs, encoded structural paths, credentials/control characters and invalid target kinds. Shared deny-first wildcard/IP matcher remains the authority. URL scope now preserves scheme, effective port and path boundaries.
- Worker dispatch and phases reload current records and compare snapshots; per-target checks run before the reachable HTTP adapter. Policy denies persist as failed/blocked required work, cannot be overwritten by reporting and survive delayed status updates. Cancelled scans remain cancelled. PATCH cannot forge completed/running outcomes.
- Scheduled occurrences create current snapshots in one async session/event loop using async_session_factory. Caller configuration cannot supply the stored snapshot. Legacy standard ScanOrchestrator refuses execution rather than retaining an unguarded fallback.
- Finding retests require current scope and GET/retest permission before SSRF resolution and HTTP. Existing SSRF checks and redirects-off behavior remain.
- Every MCP registration is classified and guarded. Standard operations require one unambiguous stored policy or a server-bound target. Caller-provided federated scope is ignored; program identity/rules come from NETRA_MCP_PROGRAM_ID and the database.

## Availability limits

Only reviewed HTTP probing is enabled through MCP: supply explicit HTTP(S) URLs, follow_redirects=False; grant methods/ports apply and max_requests_per_second is sent to httpx's rate-limit flag. Bare worker probe hosts expand only to explicitly permitted HTTP/HTTPS ports. Tool-internal DNS and network-level rebinding protection remain G2 limitations.

Passive provider adapters, nuclei/nmap/nikto/sqlmap/Dalfox/ffuf, source/image tools and federation are unavailable until their source rates, secondary destinations, methods and installed-version flags are verified in P8 (source/image target support also depends on P5/P7). The standard scope-discovery phase therefore records adapter_unavailable and full scans remain blocked; this is an intentional availability restriction, not a successful zero-finding scan. No existing tool is advertised as lab-validated by this change.

A revocation check immediately before a call does not terminate an already-running subprocess. Bounded process cancellation belongs to P4/P6; network leases/egress isolation to G2. No customer execution is ready on the strength of these changes.

## Operator grant example

Send an authenticated admin request; replace the target ID and future expiry. The evidence reference must identify actual reviewed authorization; the example does not grant legal permission by itself.

```json
{
  "evidence_reference": "local-lab-engagement-record",
  "expires_at": "2026-11-30T12:00:00+05:30",
  "allowed_actions": ["http_probe", "retest"],
  "http_methods": ["GET", "HEAD"],
  "ports": [80, 443],
  "max_requests_per_second": 2
}
```

Revoke with DELETE at the same authorization endpoint. An edited or newly granted policy requires a new scan; queued work never silently adopts broader permissions. Existing target records need explicit grants before scanning. New authorization UI is outside P1/P2; use the authenticated API.

## Validation

- Core tests cover expiry, revocation, snapshots, regrant, malformed policies, method/port/action restrictions, database outage and cancellation.
- API tests cover administrator roles, forged metadata/config, mutation invalidation, audit rollback, missing grant, resume refusal and forbidden lifecycle overwrite.
- Retest tests confirm no HTTP or DNS on scope denial and retain the authorized-private-target SSRF regression.
- Worker tests cover direct dispatch/phase denial, stale snapshots, port/rate handling, cancellation/reporting, and scheduled snapshot creation.
- MCP tests enumerate registrations and cover missing/ambiguous policy, outage, bulk targets, trusted program rules, explicit URL restrictions, unavailable adapters and rate argv.
- Source Ruff passed; frontend lint/build passed; 10 frontend unit tests passed.
- Full mypy: 488 errors versus baseline 492. Normalized file/message comparison finds zero introduced diagnostics and four removed. See p1-p2-type-comparison.json. Type checking remains failed overall.
- Full backend final result: 1275 passed, 1 skipped, 1 warning in 96.07 seconds; exit 0. Evidence: p1-p2-suite-final.log and .exit.
- Graphify AST update completed: 8593 nodes, 15003 edges. HTML visualization skipped because graph exceeds its configured size threshold.

The earlier failing suite reflected pre-update test fixtures being collected while integration edits were underway. Only the final stable run is the regression result. No browser E2E deployment was repeated in this source pass; the Stage 0 browser evidence is retained separately. G1–G6 are not newly passed by this record.
