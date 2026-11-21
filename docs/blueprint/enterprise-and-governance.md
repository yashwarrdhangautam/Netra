# Enterprise, inventory, risk and governance

Version 1.0 — 2026-11-16. Direction only for Stages 5a–5e, not an approved design. No stage-specific current-state assessment has been completed. Each stage requires the assessment checklist in review-amendments.md before its design and implementation plan can be approved. Entities and endpoints below are proposed, not existing API promises.

## 1. Organization and access model

Organization is the ownership boundary. Membership binds a user to an organization and role; roles are admin, analyst, viewer and client. Admin manages membership, connection policy and retention. Analyst creates authorized assessments, triages findings and prepares reports. Viewer reads allowed organizational data. Client reads only assigned engagements/assets and released reports. A role never overrides engagement scope. Platform operators use separate audited administration with no routine unrestricted customer-data access.

Every customer-owned row carries organization_id. Derive active organization from authenticated membership, validate object ownership in services, and include organization in joins and uniqueness constraints. PostgreSQL row-level security adds defense in depth; application connections must not bypass it. Set tenant context transaction-locally and clear it with pooled connections. Background jobs, scheduled work, exports, WebSockets, caches, search and artifact downloads use the same identity boundary. A supplied UUID is not authorization. Deny cross-organization object access with a non-enumerating response.

Audit events contain actor/service identity, organization, action, object identity, timestamp, correlation ID and sanitized old/new values. Record permission, authorization, secret-reference, export and report-release changes. Ordinary users cannot modify audit history; periodically export signed/hash-manifested audit batches to separately controlled storage.

## 2. Canonical data model

All entities have server-generated UUID, created_at and updated_at unless immutable.

| Entity | Required fields and invariants |
|---|---|
| Organization | name, status, retention_policy; deletion is a controlled lifecycle |
| Membership | organization_id, user_id, role; unique pair |
| Engagement | organization_id, name, owner_id, start/end, status, authorization evidence reference |
| AuthorizationPolicy | engagement_id, version, include/exclude rules, methods, limits, expiry, evidence digest; immutable versions |
| Connection | organization_id, provider, provider_account_id, secret_ref, permission snapshot, status |
| SyncRun | connection_id, cursor/checkpoint, start/end, state, counts, error reason, completeness |
| Asset | organization_id, kind, canonical_key, display_name, lifecycle, first_seen/last_seen |
| AssetObservation | asset_id, connection_id or scan_id, provider resource ID, observed_at, content_hash, source evidence |
| AssetRelationship | organization_id, from_asset_id, to_asset_id, kind, source, confidence, first_seen/last_seen |
| AssetOwnership | asset_id, team/contact reference, business criticality, environment; audited changes |
| Assessment | engagement_id, policy version, scan IDs, frozen coverage and time window |
| FindingOccurrence | asset_id, assessment/source ID, rule identity, location, evidence reference, timestamps |
| Issue | organization_id, fingerprint, state, owner, severity, first_seen/last_seen; groups occurrences |
| RiskAssessment | issue_id, model_version, inputs, score, explanation, calculated_at |
| EvidenceArtifact | organization_id, object key, digest, MIME type, size, provenance, retention/hold state |
| RemediationTask | issue_id, assignee, due_at, status, external_reference, verification evidence |
| Exception | issue/control ID, approver, rationale, compensating evidence, expiry |
| ReportSnapshot | assessment_id, versions, immutable included evidence IDs, released_by/at |
| ControlDefinition / ControlMapping | framework/version/control ID, source/license provenance, mapping rationale |

Use composite organization-aware foreign keys where practical to prevent cross-organization relationships. No global deduplication of private customer findings. Shared public vulnerability metadata contains no customer identifiers.

Current Finding rows remain available. Introduce occurrences/issues alongside them, dual-read through a compatibility service, backfill only where asset identity is established, and label unresolved rows legacy_unmapped. Do not guess an asset from a title. Remove legacy paths only after counts, exports and access controls reconcile.

## 3. Asset identity and lifecycle

Canonical keys are provider scoped: repository by provider/account/stable repository ID; cloud resource by provider/account/region/resource ID; container by registry/repository/digest; DNS name by normalized hostname; endpoint by normalized scheme/host/port/path according to explicit rules. Names and IP addresses are aliases/observations, not universal identity. Shared IPs and reused names must not merge unrelated resources.

Relationships include belongs_to, deployed_from, exposes, depends_on and resolves_to. Preserve source and confidence; inferred relationships are visibly distinct from provider-observed ones. Asset discovery never creates scan authorization.

Connector syncs upsert by stable key. Mark unseen resources stale only after a complete successful listing, and tombstone after two consecutive complete listings plus the configured grace period (default seven days). Partial/error syncs never delete assets. Manual ownership/criticality survives provider refresh. Conflicting observations remain inspectable with precedence: explicit reviewed ownership for business data; newest authoritative provider observation for provider state.

## 4. Credential lifecycle

Use SecretReference identifiers, never secret values, in API responses, scan config, logs or job envelopes. Secret creation is write-only. Encrypt at rest with a dedicated key independent of JWT signing; store key identifier and ciphertext, with encryption keys outside the database. Decrypt only at the consuming service boundary. Short-lived provider credentials are preferred where supported.

Connector permissions are read-only by default and scoped to selected accounts/repositories. The exact provider permission list must be checked against current official documentation at implementation time. Do not copy unverified scopes from historical docs. A successful connection test records identity and granted permissions without listing secrets.

Rotation creates a new secret version, verifies it, atomically switches the reference and revokes the old credential; failed verification leaves the old reference active until operator action. Revocation disables future jobs and invalidates cached credentials. Tests cover leaked-value redaction, wrong-key failure, key rotation, deleted-reference use, cross-tenant reference denial and encrypted backup restore. Authenticated scanners receive only the target-specific short-lived secret needed by the adapter and never the connector's broader credentials.

## 5. Connector contract and rollout

Proposed connector interface operations: validate_configuration, inspect_permissions, enumerate_assets(cursor), fetch_observations(resource_ids), health and revoke_local_access. Each result declares provider version, observed_at, pagination cursor, completeness and retry_after. Cursor advances only after the page and normalized observations commit. An idempotency key includes organization, connection, resource ID and observation hash.

On 429 respect provider retry guidance; on transient errors use bounded exponential backoff with jitter; on 401/403 stop and show permission remediation. Persist partial progress and make missing coverage visible. Validate webhook signatures and timestamp windows; deduplicate delivery IDs. Scheduled reconciliation remains necessary because webhooks can be lost. External links and provider response text are untrusted input.

Order:
1. GitHub: repository identity, ownership metadata and available security observations. Capability/entitlement absence is unavailable, not zero vulnerabilities. Importing observations is distinct from obtaining source for SAST. Checkout uses a pinned commit into a prepared sandbox with no hooks or executable repository setup; submodules/LFS require explicit policy.
2. AWS: selected accounts/regions, read-only inventory and posture observations with scoped assumed-role access. Failed regions remain visible.
3. Azure: selected tenants/subscriptions with federated credentials where supported; subscription failures remain visible.

A connection page exposes permission coverage, last complete/partial sync, freshness, error and disconnect action. Disconnect stops sync and revokes local secret access; retained evidence follows the organization's retention agreement. No provider remediation writes are included in this contract.

Acceptance: replayed pages do not duplicate assets; interrupted sync resumes; revoked credentials stop; partial lists do not delete; cross-tenant data is denied; provider failure leaves prior inventory labeled stale; hashes/provenance permit tracing a displayed observation to its source.

## 6. Finding correlation and explainable risk

Keep raw observations immutable. Normalize rule/tool identity, canonical asset, location/parameter, vulnerability identifiers and evidence hash. Within an organization, correlate by asset plus vulnerability/rule identity and normalized location. Never merge solely on title or CVE across different assets. Human merge/split actions are reversible and audited.

Issue states preserve existing vocabulary where feasible: new, confirmed, in_progress, resolved, verified, false_positive and accepted_risk. Resolution requires documented fix or a comparable complete retest; disappearance in an incomplete scan cannot close an issue. Reappearance reopens with a new occurrence. Exceptions require an expiry and approver, and do not delete findings.

Proposed risk model v1 uses normalized inputs from 0 to 1: severity 0.40, exposure 0.25, exploitation evidence 0.20, business criticality 0.15. Score = round(100 × weighted sum). This is a prioritization heuristic, not a probability. Unknown inputs use 0.5 and are shown as unknown; low detection confidence is displayed separately rather than reducing urgent risk to zero. Every score stores raw inputs, freshness, sources and model version. Verified exploitation evidence can force review priority regardless of numeric rank. Reweighting produces new assessments without overwriting historical scores.

Test fixed vectors and missing/stale inputs; verify monotonicity for increased severity/exposure with other inputs fixed. Validate ranking against a manually reviewed pilot set before adoption. AI may explain inputs but cannot invent them or silently modify scores.

## 7. Enterprise workflows and dashboards

Organization onboarding → membership → connection permission review → inventory reconciliation → owner/criticality assignment → explicit engagement authorization → assessment → analyst triage → remediation → comparable retest → released report.

Executive overview: inventory freshness, open issue trends, overdue remediation and coverage gaps. Analyst view: evidence, affected asset, required-tool coverage, confidence, provenance and reproducible review steps. Client view: assigned assets/engagements and explicitly released reports only. Administrator view: memberships, connections, audit, retention, runner health and backup status.

Trend definitions are versioned: new means first occurrence in interval; reopened means a previously resolved issue reappears; verified resolution requires qualifying evidence; stale/unknown coverage is its own series. Compare only compatible scope/profile windows, or display the difference. No percentage improvement can hide newly excluded assets.

Proposed pilot scale target: 1,000 assets and 10,000 occurrences in one deployment; benchmark paginated list p95 under one second and a 1,000-occurrence report under two minutes. Measure with recorded hardware/data/concurrency. These are acceptance targets, not current performance claims. Report jobs are asynchronous and show failure/retry status.

## 8. Compliance and evidence

Model framework version, control ID, source provenance, license and mapping rationale. A vulnerability-to-control link is supporting evidence, not proof that the entire control passes/fails. Distinguish not_assessed, evidence_pending, partially_supported, supported and exception. Human reviewers approve conclusions and record the assessment period.

Evidence manifests contain artifact hashes, collection time, source, scope, tool/rule versions, reviewer and access policy. Preserve immutable report snapshots; corrections create a new version. Exceptions expire and return to review. Never advertise certification or copy full licensed control catalogs without rights verification.

Acceptance: a control with no scanner findings remains not_assessed unless sufficient independent evidence exists; stale evidence is flagged; unauthorized viewers cannot download artifacts; changed evidence creates a new report snapshot; expired exceptions surface for review.

## 9. AI and MCP governance

Maintain inventory of model provider/version, endpoint, purpose, data classification, configured retention/export policy and allowed tools. Default core workflows work without AI. External model use is organization-controlled and opt-in for permitted data classes; redact secrets before transmission and record what category was sent.

Treat retrieved reports, repository text and target responses as untrusted content. Do not interpret their instructions as tool authority. Require structured proposed actions, then validate with deterministic schemas, roles, scope, method allowlists and budgets. Cap model calls, tokens, elapsed time and tool attempts. Store summaries and supporting evidence references; do not require private model reasoning as audit evidence.

MCP uses authenticated caller identity and the same policy services. The Stage 1 local-process trust assumption ends before remote/multi-user MCP exposure. No arbitrary shell, path, template or credential access. Prompt injection tests include instructions embedded in pages, code comments and retrieved reports attempting to change scope or export data. Expected result: no unauthorized action, a recorded deny reason and unchanged policy.

## 10. Migration and rollback

Use expand → backfill → validate → switch reads → contract. Add organization/engagement/asset tables and nullable links first; assign legacy data through an explicit operator-reviewed mapping. Do not silently put several customers into one default organization. Backfill in resumable batches and verify counts, orphan checks, organization consistency and representative report parity before enforcing non-null constraints.

Test migration on a database copy and restore the backup. Feature flags disable new connectors/risk views without deleting imported evidence. Roll back application code only to a schema-compatible version; otherwise restore through the tested recovery procedure. Destructive schema contraction gets its own reviewed release after the compatibility window.
