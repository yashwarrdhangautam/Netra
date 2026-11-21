> Planning update (2026-11-16): The [master blueprint](blueprint/README.md) supersedes the work ordering below. This file remains a historical status record; its test counts and completion claims have not been rerun by the blueprint authoring task.

# NETRA plan

Status as of 2026-11-14. Each item says what is verified and what is not.

## Done and verified

- Security: submission drafts need analyst or admin; docs off outside development; the app refuses to start outside development with the built-in JWT secret. Tests in `tests/test_api/test_security_hardening.py`.
- Intelligence: CISA KEV and FIRST EPSS priority (live-checked); protection checks from httpx headers; eval harness with 15 labelled cases (self-written, so a regression check, not proof of accuracy).
- Sources: pinned nuclei templates and payload library synced on the worker; the payload library is also in the API container.
- Intigriti researcher API: lists all 233 programs and reads scope (read-only, live-checked).
- Recon manifest and arsenal map, served from scan checkpoints.
- Install guides for Windows and Kali, written from the compose file. Not yet run on clean machines.
- Test suite: 1198 passing, 1 skipped.

## Not yet verified

- **End-to-end scan against a live target.** Nothing has run the full chain against a target we are authorised to test.
- **Scanner tools in a real scan.** The wrappers are tested with mocked output. nikto, sqlmap, dalfox and amass are installed in the worker image, but none has run in a real scan.
- **Clean install.** The Windows and Kali guides have not been run on a clean machine.
- **Bugcrowd scope sync.** Needs customer-side credentials. Blocked.

## Next, in order

1. **Lab validation** against OWASP Juice Shop, a deliberately vulnerable app we run ourselves. Start the container, point a NETRA scan at it, and record what each phase found. Blocked right now: starting the container was refused by the auto-mode classifier. Needs your approval.
2. Fix whatever the lab run breaks. Add a regression test for each fix.
3. Clean-machine installs on Windows (Docker Desktop with WSL 2) and Kali (VM). Record the time and every error.
4. Public release: tag v1.1.0, add a README demo, and publish the limits (no live-target results yet).
5. Only after step 1 passes: a scan of a third-party target, with written authorisation, scope and rate agreed first.

## Flip conditions

- If the lab run finds scanner output that is wrong or empty, step 2 becomes the first priority and the public release waits.
- If a clean install takes more than two attempts on either platform, release as alpha and say so in the README.
