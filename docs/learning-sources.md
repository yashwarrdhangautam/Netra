# Learning and intelligence sources: decisions

Each source is recorded with what it gives NETRA, how it is used, and what is still open.

| Source | Decision | Status | Where |
|---|---|---|---|
| CISA Known Exploited Vulnerabilities | Read at runtime for exploitation status | Built, cached 24h | `src/netra/intel/cve_intel.py` |
| FIRST EPSS | Read at runtime for exploit likelihood | Built, cached 24h | `src/netra/intel/cve_intel.py` |
| nuclei-templates (MIT) | Pinned to a commit, checked before each scan | Built; sync on the worker host | `src/netra/scanner/tools/template_pin.py` |
| PayloadsAllTheThings (MIT) | Pinned checkout, parsed into passages with source and commit | Built; sync on the worker host | `src/netra/intel/payloads.py` |
| Protection checks (from httpx response headers) | Ordered checks per protection, no extra traffic | Built and wired into the httpx tool | `src/netra/intel/bypass_checklist.py` |
| ProjectDiscovery Chaos | Subdomains from the Chaos API when a key is set | Client built and mock-tested; not run live (no key) | `src/netra/intel/chaos.py` |
| HackerOne disclosed reports | Existing harvester and corpus | Already built | `src/netra/bugbounty/learning/sources/hackerone.py` |
| Bugcrowd disclosures | Metadata-only feed, reference only | Built as a reference feed | `src/netra/bugbounty/learning/sources/bugcrowd.py` |
| Intigriti | No public disclosure feed exists; the harvester is a stub by design. Curate write-ups by hand, the way Claude-BugHunter does. Write-ups are cited by URL, never copied. | Decision made, no scraper | this file |
| Wappalyzer fingerprints | httpx `-tech-detect` already fingerprints the stack for every live host, so a second fingerprint set would duplicate it. Revisit if httpx coverage proves too thin. | Decision made, not built | this file |
| Bugcrowd and Intigriti scope sync | Needs API tokens and endpoint confirmation for each program platform | Blocked on credentials | this file |

## Licensing

Ingested content keeps its upstream licence and commit. The notices are in
`THIRD_PARTY_NOTICES.md`. Report write-ups are never copied into the repository; they are cited by
URL.

## Open items

- Scope sync for Bugcrowd and Intigriti: needs a token for each platform and the confirmed API
  endpoints. No code is written until both are available.
- Chaos: needs `NETRA_CHAOS_API_KEY` before the live call can be verified.
- The pinned checkouts (nuclei-templates, PayloadsAllTheThings) must be synced on each worker host
  before the scanner and the payload endpoint can use them.
