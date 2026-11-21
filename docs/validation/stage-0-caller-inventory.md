# Stage 0 caller inventory

2026-11-16, source inspection at 24d2238. This is an inventory, not a claim these paths are already authorization-gated. P1/P2 plan: ../superpowers/plans/2026-11-16-p1-p2-authorization-scope.md.

| Entry | Existing path | Planned enforcement |
|---|---|---|
| API create | api/routes/scans.py:create_scan → worker/tasks.py:run_scan.delay | Grant before creation, snapshot before dispatch |
| API resume | api/routes/scans.py:resume_scan → run_scan.delay | Current policy versus saved snapshot before state/queue changes |
| Direct worker dispatch | worker/tasks.py:run_scan → create_scan_pipeline | Gate before RUNNING/chain creation |
| Scope/recon | worker/tasks.py:_execute_scope_resolution, _execute_recon | Reload per phase; per-input check; split discovery from permission |
| Vulnerability/active phases | worker/tasks.py:_execute_vuln_scan, _execute_active_test | Each destination/action; ignore claimed scope in previous_result |
| Schedule | worker/scheduler.py:execute_scheduled_scan → run_scan.delay | Current grant per occurrence; fix nonexistent AsyncSessionLocal integration |
| Recheck | api/routes/findings.py:retest_finding → _retest_request | Scope/action before DNS/HTTP; redirects remain off |
| Direct orchestrator standard path | scanner/orchestrator.py phase methods | Shared gate or explicit refusal; no unguarded fallback before P9 |
| Hunt creation | services/scan_service.py:create_bugbounty_scan → run_bugbounty_scan | Separate stored program policy; do not authorize a program handle as domain |
| Hunt execution | worker/tasks.py:run_bugbounty_scan → scanner/orchestrator.py:_execute_bugbounty | Stored BBScopeRule validator; Stage 4 runtime validation outstanding |
| Hunt active actions | bugbounty/recon/active.py:_gate and run_active_recon | Keep deny-first gate; revalidation requirements reviewed in Stage 4 |
| Agentic actions | bugbounty/agentic/executor.py:run_plan/_scope_block_reason/_execute_choice | Deterministic stored policy; AI never supplies authority |
| Standard MCP | mcp/server.py:registered scanner tools | Registry classification, DB-bound target and action check |
| Federated MCP | mcp/server.py:_call_federated_bb | Replace caller-supplied scope_rules authority with server-bound stored program |
| CLI standard scan | cli/main.py placeholder | D6 explicit unavailable/nonzero; cannot report fabricated completion |

Paths above are under src/netra/. Requeue/retry/direct invocation must pass the same execution guard even if an API or scheduler previously validated. New tool registrations require a test update and classification, not implicit authorization.

Known source issues relevant to planning: the standard pipeline trusts discovered names; ScopeValidator URL matching ignores scheme; route-local target schemas differ from schemas/target.py; scheduler imports AsyncSessionLocal absent from db/session.py; generic wrappers ignore control kwargs. These need reproduction/targeted tests before changing production behavior.
