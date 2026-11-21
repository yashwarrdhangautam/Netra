# Service readiness worksheets

2026-11-16 — proposed operational templates for G6. These are unsigned working records, not a completed customer agreement or a legal opinion. Fill every field, review with the parties and obtain authorized signatures before use. No retention, notification or data-transfer commitment is accepted by publishing this file.

## Authorization letter / rules of engagement

Engagement ID: __________
Customer legal/entity name and authorized signatory: __________
NETRA service operator and responsible person: __________
Basis of customer's authority over each target, and required third-party permissions: __________
Evidence reference and policy version/digest: __________
Start/end date and timezone; expiry: __________
Exact targets, ports, URL paths, wildcard interpretation and exclusions (attach immutable list): __________
Allowed test methods and explicit prohibited actions: __________
Maximum request rate, concurrency, duration and maintenance window: __________
Approved source addresses and runner location: __________
Test accounts and secret-reference IDs (never secret values): __________
Expected operational impact and agreed stop triggers: __________
Customer emergency contact / alternate / channel: __________
Operator emergency contact / alternate / channel: __________
Stop mechanism: either named contact may halt work; operator cancels pending jobs, revokes active leases/network allowances and confirms cessation with timestamps.
Evidence handling, report recipients and retention worksheet reference: __________
Customer signatory / date: __________
Operator signatory / date: __________

Authorization covers only the attached scope and methods. Newly discovered assets require matching existing explicit authorization or a separately approved policy revision. Provider/third-party restrictions must be resolved before work, not inferred from ownership of a hostname.

## Data handling schedule

Record the parties and their agreed responsibilities; data categories collected; purpose; permitted storage/processing regions; approved model providers/subprocessors; whether external AI is disabled; authorized personnel and recipients; transfer/encryption method; access audit; artifact classification and redaction rules; retention periods for raw data, reviewed evidence, reports and audit logs; backup retention; holds; export format; deletion date; incident contact and agreed notification timing.

Do not store customer credentials in this schedule. Use write-only secret references. Raw evidence can contain customer data even when tests are read-only. Set the minimum collection necessary for the agreed finding. Record explicit permission before exporting evidence to external AI or ticket systems. The blueprint's 7/90/365-day durations are proposals; the signed schedule governs the engagement.

Acceptance: operator can locate every storage copy, document who can access it, demonstrate redacted export and show that retention jobs honor holds and backup expiry. Record any limitation before signature.

## Offboarding and deletion runbook

1. Confirm requester identity, engagement IDs, legal/contractual holds and agreed end date; record approver.
2. Stop schedules, pending scans, retries, connector sync and external exports. Revoke active leases, target credentials and local connection access; ask the credential owner to revoke provider grants where needed.
3. Offer agreed final export over an approved channel; manifest hashes, record recipient acknowledgement and expiry of download links.
4. Enumerate database records, raw artifacts, report snapshots, caches, search indexes, temporary runner workspaces and external copies created by approved integrations.
5. Delete eligible live copies through scoped procedures and verify absence. Preserve only specifically authorized audit/hold records, minimized and access-controlled.
6. Record backup set IDs and scheduled expiry. Do not claim immediate deletion from immutable backups; ensure a future restore reapplies the deletion ledger before reopening service.
7. Verify provider credential revocation, expired artifact capabilities, no active jobs and no cross-customer deletion. A second operator reviews the manifest where available.
8. Issue a deletion record listing completed actions, dates, retained exceptions, backup expiry and responsible person. Do not state full deletion while copies remain without disclosing them.

## Incident process for NETRA itself

Triggers: suspected secret exposure, unauthorized target request, tenant/evidence leak, runner escape, compromised dependency, data loss or tampered report. Operator is incident commander until a named substitute accepts.

- Triage: record UTC discovery time, affected deployment/organizations, source and known facts. Preserve sanitized evidence and hashes; do not paste live secrets into chat/tickets.
- Contain: pause affected execution and exports, revoke leases/credentials, isolate runner/network path and preserve necessary evidence before destructive remediation. Stop customer scans if scope enforcement is uncertain.
- Assess: determine affected data/actions, earliest/latest exposure, access logs, credential usage and remaining uncertainty. Separate observed facts from hypotheses.
- Notify: use pre-agreed emergency contacts and contractual/regulatory review to determine recipients and deadlines; no universal statutory deadline is asserted here. Record messages and acknowledgement. Do not speculate about impact as established fact.
- Recover: rotate affected credentials, patch/rebuild from trusted artifacts, restore if necessary and validate authorization, isolation, evidence integrity and access boundaries before resuming.
- Close: obtain owner approval, document timeline/root cause/customer impact, corrective tasks and verification. Track recurrence prevention and update the service process.

G6 requires a tabletop exercise of an unauthorized-request or secret-exposure scenario, with measured contact/containment response and resolved gaps.

## Immediate credential-exposure action

The review reports an Intigriti token and Chaos API key were pasted into an earlier chat. Status: exposure reported; rotation/revocation NOT verified. Do not retrieve or repeat those values and do not test the old credentials as part of baseline work.

Owner: account holder. Revoke the disclosed credentials in the respective provider account controls, create least-privilege replacements only if still needed, update the local protected secret store and restart only consumers that cache them. Review provider usage/audit history around the exposure. Removing chat text does not revoke credentials.

Completion record (no secret values): provider; old credential identifier/fingerprint if safely available; revoke timestamp; provider acknowledgement; replacement reference; affected consumers updated; sanitized validation result; reviewer. If authentication is needed, the owner performs it privately. Until completion is confirmed, do not enable those integrations or use their credentials in tests. This document does not claim rotation occurred.
