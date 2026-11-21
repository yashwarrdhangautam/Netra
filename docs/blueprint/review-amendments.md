# Review amendments and open decisions

2026-11-16 — review disposition, not approval. This file records changes made in response to the blueprint review.

## Approval boundary

Writing the blueprint did not approve D4–D7 or D9–D12. They remain proposals. D1–D3 retain the prior specification's recorded decisions. D8 preserves the user's stated two-directory direction: fix and validate first, then separate Enterprise and Hunt. Directory layout does not determine repository topology. Stage 3 dependency assessment must compare the cut methods and obtain a decision before copying/moving code or selecting repository topology. A one-repository recommendation is an alternative, not an override of that direction.

Stage 0 is assessment. Stage 1–2 are the next approval scope; they are not approved merely by this editing pass. Stages 3–5e remain direction only, pending each stage's current-state assessment, design review and approval. Do not start later implementation from these target designs alone.

## Disposition

| Review point | Change / status |
|---|---|
| D8 conflict | Restored two-directory direction; repository/cut method unresolved at Stage 3 |
| Approval wording | D4–D7/D9–D12 proposed, not selected; no blanket stage approval |
| Hidden tracked edits | Previous authoring added two-line banners to docs/PLAN.md and docs/PRD.md. Retained and explicitly disclosed; no application source edits |
| Stage 5 assessment | Assessment checklist now gates each stage; architecture is directional |
| Isolation alternatives | ADR-001 below compares three options, with runtime/topology proposal |
| Sizing/first deliverable | Delivery document adds rough effort ranges and Stage 0 baseline artifact |
| Service preparation | service-readiness.md contains operational authorization/data/exit/incident worksheets |
| Exposed credentials | Intigriti token and Chaos key rotation recorded as unverified urgent operator action; values never copied |
| G6 | Added to stabilization gate table |
| Hunt pages | All 13 existing page components and routes inventoried in hunt-inventory.md |
| Audit work | Source already contains scan/finding audit calls. P3A verifies completeness/atomicity/redaction rather than assuming implementation is absent |

## ADR-001: scan runtime and host topology

Status: proposed; decide after Stage 0 environment evidence and before P10/P11. The following compares alternatives for the same G2 requirement.

| Option | Isolation and egress | Operations / cost | Decision guidance |
|---|---|---|---|
| Hardened shared Celery worker | Environment/resource controls help, but tool processes share filesystem/kernel and the credential-bearing worker boundary; cannot satisfy the proposed G2 boundary by hardening alone | Lowest implementation/host overhead | Stage 1–2 local lab only; reject for customer execution under current architecture |
| Per-scan containers on dedicated Linux VM | Separate execution host, ephemeral workspaces, no platform credentials; Linux firewall controls; container kernel still shared inside VM | Moderate engineering and one maintained VM; suitable for one active pilot scan | Recommended pilot option, subject to validation |
| Kubernetes Jobs on dedicated worker nodes | Per-job lifecycle and resource limits; isolation depends on node placement, RBAC, runtime and enforced network policy, not Jobs alone | Highest cluster/upgrade/network-policy operating burden | Reconsider for measured concurrency/availability needs; not first pilot default |

Proposed runtime: Docker Engine running Linux containers on a dedicated Linux VM. Pin host OS/kernel baseline, Engine version, container images and firewall rules during Stage 3 implementation assessment; no version is invented here. A trusted controller on the runner host invokes a fixed container specification, never caller-supplied runtime flags. Rootful Engine privileges are confined to that controller/host; no socket goes to scanner/API containers. Use host nftables policy with explicit testing of Docker forwarding chains and IPv6; fail startup if required enforcement cannot be verified. A host firewall is not proven merely by a configuration file.

Proposed Windows topology: Windows with Docker Desktop/WSL2 runs the local control plane and lab for G5 installation tests. Customer scans are dispatched to the dedicated Linux runner VM, not arbitrary Windows subprocesses or the shared Docker Desktop worker. A runner VM hosted on the same physical Windows machine is acceptable only if its network/service boundary passes G2; it is not implied by WSL2 support. The Windows clean-install test must include pairing with a fresh Linux runner, a controlled end-to-end scan, cancellation and denied destinations.

Proposed Kali topology: Kali hosts the operator/control-plane workflow; customer execution uses the same dedicated Linux runner topology. A native Kali development/shared worker remains lab-only. G5 documents both control-plane installation and runner pairing; G2 separately proves isolation. Test host crashes/restarts and runner version incompatibility. If Windows cannot support the paired topology, G5 remains blocked rather than lowering isolation requirements.

Reversal criteria: adopt Kubernetes only after queue/load or availability evidence justifies its operating cost; revisit container runtime if an adapter requires unacceptable privileges; suspend customer work on egress or cross-run bypass. Never silently fall back to the shared worker.

## Stage-specific assessment required before design approval

For 3, 4 and each of 5a–5e, record: existing modules/routes/models; current runtime behavior and tests; already implemented capability; reproducible gaps; deployment constraints; migration/data ownership impact; dependencies; alternatives; estimated effort; acceptance cases and rollback. Separate source observations from runtime results. Stage 5 field names, risk weights, retention periods and scale targets remain proposals until this assessment and stakeholder review.

## Change disclosure

This review pass modifies the four blueprint files and stabilization specification, and adds this review record, service-readiness.md and hunt-inventory.md. It retains the earlier PLAN.md and PRD.md banners. It does not commit, copy product directories, rotate external credentials or approve implementation. Any Stage 0 commands and results are recorded separately under docs/validation/.


## Subsequent implementation-start request

On 2026-11-16 the user supplied the implementation-start handoff. Stage 1–2 design/D4–D7 approval is now recorded in specification revision 6; the status above describes the earlier review pass. D9–D12 and later-stage designs remain proposals. G0 and the new P1/P2 plan are separate review items. Actual additional baseline results are in ../validation/stage-0-baseline.md; no application source was changed.
