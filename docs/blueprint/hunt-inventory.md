# Hunt frontend inventory

2026-11-16. Source inventory only; no page has been runtime-validated in this review. Source: frontend/src/routeTree.gen.tsx and frontend/src/pages/bb/. Preserve these 13 registered pages during the two-directory cut; do not replace them with the six conceptual navigation groups in the master blueprint.

| Component/file under frontend/src/pages/bb/ | Registered route | Stage 3/4 verification |
|---|---|---|
| BBConsole.tsx | /bb | Summary counts, selected program and empty/error states |
| BBPrograms.tsx | /bb/programs | Program import, identity and read permissions |
| BBScope.tsx | /bb/scope | Reviewed scope, excludes, changes invalidate approvals |
| BBHunts.tsx | /bb/hunts | Create/list, profile permissions and pagination |
| BBHuntDetail.tsx | /bb/hunts/$huntId | Phase evidence, cancellation, resume and coverage |
| BBSettings.tsx | /bb/settings | Provider controls, secret redaction and role restrictions |
| BBTriage.tsx | /bb/triage | Finding status, assignment and audited mutations |
| BBSubmissions.tsx | /bb/submissions | Draft listing and destination isolation |
| BBSubmissionDetail.tsx | /bb/submissions/$submissionId | Reviewed evidence/export; no automatic submission |
| BBAudit.tsx | /bb/audit | Actor/action/object/time and permitted visibility |
| BBDoctor.tsx | /bb/doctor | Actual runner/tool availability; no secret disclosure |
| BBFindingLab.tsx | /bb/findings/$findingId | Evidence access, scoped verification and redaction |
| BBGraph.tsx | /bb/graph | Provenance and distinction between observed/inferred links |

P12 must inventory each page's API calls, shared components, state stores and permissions before deciding the cut method. P14 must exercise each route with authorized and denied identities, loading/error/empty states, deep links and a scoped lab workflow. This inventory confirms files/routes exist, not that the proposed checks currently pass.
