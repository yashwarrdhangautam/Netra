# Stage 2 lab validation record

Date: 2026-11-18. Host: Windows 11, Docker Desktop running. Repository state: uncommitted on `feat/netra-bb-module`.

This record covers what was run and what it showed. Items marked **not run** are open and are not claimed as passed.

## Tools and versions

| Tool | Version | How installed | Used for |
|---|---|---|---|
| nuclei | v3.3.7 | `go install .../nuclei/v3/cmd/nuclei@v3.3.7` | vuln scan |
| nuclei templates | commit `1cb2d50b4f0f5cbdb600165b0afe556b4623f29a` (pinned) | `sync_pinned` (depth-1 fetch of that commit) | vuln scan |
| subfinder | v2.6.7 | `go install .../subfinder/v2/cmd/subfinder@v2.6.7` | installed, not yet wired into the chain |
| dalfox | v2.13.0 | `go install github.com/hahwul/dalfox/v2@latest` | active test (XSS) |
| sqlmap | 1.8.9 (git tag) | cloned from GitHub at tag `1.8.9`, run by `netra-tools\bin\sqlmap.cmd` | active test (SQLi) |
| semgrep | 1.161.0 (engine) / 8.30.1 CLI | pip | SAST wrapper (not in the web chain) |
| checkov | 3.2.533 | pip | IaC wrapper (not in the web chain) |
| pip-audit | 2.10.0 | pip | dependency wrapper (not in the web chain) |
| trivy | 0.76.2 | winget `AquaSecurity.Trivy` | IaC config mode (not in the web chain) |
| gitleaks | installed | winget | not yet wrapped |
| nikto | **not installed**: clone of the 2.5.0 archive tag was denied by the auto-mode permission check | — | recorded as `unavailable` |
| ffuf | **not installed** | — | recorded as `unavailable` |

## Targets

- **Lab page** (`tests/fixtures/lab/vuln_server.py`), served on 127.0.0.1 on a free port during the tests. Known by construction:
  - `/item?id=` is SQL-injectable in `id` (SQLite, string concatenation).
  - `/reflect?q=` reflects `q` unescaped into HTML.
  - `/?x=1` uses no vulnerable parameter. It is the clean case.
- **Juice Shop** container, already running, published on `127.0.0.1:3000`. It is not part of the compose stack, and its host publishing is still open (see below).

## Manual baselines (run once by hand, reviewed)

Arguments identical to the product's nuclei call: `-jsonl -silent -no-color -severity critical,high,medium -rate-limit 150 -templates <pinned>`.

| Target | Result | Saved file |
|---|---|---|
| Juice Shop `http://127.0.0.1:3000` | 1 finding: `prometheus-metrics` (medium) at `/metrics`. Reviewed: a real exposure of the metrics endpoint | `docs/validation/stage-2-baselines/nuclei-juice-shop-3000.jsonl` |
| Lab page `http://127.0.0.1:8765` | 0 findings. Templates loaded: 1,169 of 3,618. 3,481 requests sent | `docs/validation/stage-2-baselines/nuclei-lab-page-8765.jsonl` (empty) |

## Product runs (through the real phase functions, with the authorization gate)

Each test grants a real authorization record for the lab port, creates the scan with its server-side snapshot, and calls the product's `_execute_vuln_scan` / `_execute_active_test`. The tool subprocesses are real.

| Test | Expectation | Result |
|---|---|---|
| Authorized vuln scan | nuclei `completed` with 0 findings (matches the baseline); nikto `unavailable` | **Pass** |
| Authorized active test | sqlmap `completed` with the known `id` injection; dalfox `completed` with the known `q` reflection; ffuf `unavailable` | **Pass** |
| Ungranted scan | Scan fails at the gate; no nuclei process starts | **Pass** |
| Coverage with an unavailable tool | Scan outcome `incomplete`, nikto reported as `unavailable` | **Pass** |

Run: `NETRA_TOOLS_DIR=C:/Users/CyberFlux/netra-tools/tools-dir PYTHONPATH=src pytest tests/test_lab` with the Go, Python 3.12 and Trivy directories on PATH. Result: **4 passed in 359 s**.

Tool-level evidence (fixtures used by the parser tests, captured from the same tools):
- semgrep: 2 findings from the NETRA rules (`subprocess-shell-true`, `eval-call`); a clean run.
- checkov: `CKV2_AWS_62` and others on the IaC fixture; a clean run on a directory with no resources.
- pip-audit: 37 advisories across 3 packages on `requests==2.19.0`; a clean run on `six==1.16.0`.
- trivy config: `AWS-0086` and 8 others on the IaC fixture; a clean run.
- dalfox: the verified reflection on `q`; a clean run on `/?x=1`.
- sqlmap: the boolean-based blind injection on `id`; a "not injectable" run on `/?x=1`.

Each parser also has a truncated-output sample. Those are checked to be `parse_error`, not clean.

## Negative and safety checks (spec section 8)

| Check | Status |
|---|---|
| Clean fixture gives `completed` with zero findings | **Pass** (nuclei on the lab page; semgrep/checkov/pip-audit/trivy/dalfox clean samples) |
| Removed binary gives `unavailable` | **Pass** (unit test: missing binary; nikto and ffuf in the product runs) |
| Forced timeout gives `failed` | Covered by the existing process-control tests. Not repeated against a lab tool |
| Corrupted output gives `parse_error` | **Pass** (truncated samples for every new parser) |
| Decoy container outside scope, zero requests | **Not run** |
| Target without an authorization record cannot be scanned | **Pass** (ungranted test) |
| Viewer and client cannot start a scan | Covered by the existing role-matrix tests (P3). Not repeated here |
| Authorization revoked during a scan stops the next phase | **Not run** |
| Cancel during a tool run leaves no process | **Not run**. Cancel is checked between phases only |
| Same scan delivered twice runs once | Covered by unit tests of the claim (`tests/test_worker/test_claim_and_stop.py`). Not a broker-level test |
| Worker restarted mid-scan | **Not run** |
| Fixture tool prints its environment with no platform secret | **Not run** |

## Known limits of this run

- The product's web chain still runs only: recon (httpx), vuln scan (nuclei, nikto unavailable), active test (sqlmap, dalfox, ffuf unavailable). Subfinder and passive discovery stay blocked by design (`adapter_unavailable`), so the scope phase still fails closed.
- The Juice Shop product run was **not** executed. Only the manual baseline exists.
- Nothing here measures detection rate or accuracy. This is a wrapper and pipeline check against known contents.
- `dalfox` headless checks are off. Its headless-only entries are excluded from findings.
- Tool versions are not yet pinned in a worker image (spec 6.4). The versions above are the ones on this host.
- The `netra-tools\bin` launcher for sqlmap and the Python 3.12 directory must be first on PATH for `checkov` on this machine. The hermes venv's `python` shadows the checkov launcher otherwise.

## Open items before Stage 2 can be called complete

1. Run the remaining negative checks above, in particular the decoy target, revocation during a scan, and cancel during a tool run.
2. Run the product pipeline against Juice Shop and compare with the saved baseline.
3. Move the lab page and Juice Shop onto an internal lab compose profile, not host-published ports.
4. Install nikto and ffuf, or keep them recorded as `unavailable` and accept the incomplete coverage.
5. Generate the report formats from real results and open them.
