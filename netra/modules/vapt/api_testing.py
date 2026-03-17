"""
pentest/api_testing.py
API security testing: GraphQL introspection dump, REST verb fuzzing,
mass assignment, BOLA/IDOR (unauthenticated), rate limiting, versioning.
"""

import json
import re
import urllib.request
import urllib.parse
from pathlib import Path
from typing import List, Dict

from netra.core.config   import CONFIG
from netra.core.utils    import run_cmd, status, banner, truncate, C
from netra.core.database import FindingsDB
from netra.core.notify   import notify_finding


def run_api_tests(
    live_urls: List[str],
    workdir: str,
    scan_id: str = "",
    tech_map: dict = None,
) -> int:
    """Run API security tests. Returns total findings."""
    banner("API TESTING", "GraphQL · REST · Mass Assign · BOLA")

    workdir     = Path(workdir)
    pentest_dir = workdir / "pentest"
    pentest_dir.mkdir(exist_ok=True)
    tech_map = tech_map or {}
    db    = FindingsDB()
    total = 0

    total += _test_graphql(live_urls, scan_id, db, tech_map)
    total += _test_verb_fuzzing(live_urls, scan_id, db)
    total += _test_mass_assignment(live_urls, scan_id, db, tech_map)
    total += _test_bola(live_urls, scan_id, db)
    total += _test_api_docs_exposure(live_urls, scan_id, db)

    status(f"API tests complete: {total} findings", "ok")
    return total


# ═══════════════════════════════════════════════════════════════════════
#  GraphQL Introspection
# ═══════════════════════════════════════════════════════════════════════

INTROSPECTION_QUERY = '{"query":"{ __schema { types { name fields { name type { name } } } } }"}'

def _test_graphql(urls: list, scan_id: str, db: FindingsDB,
                  tech_map: dict) -> int:
    status("GraphQL introspection testing...", "run")
    count = 0
    gql_paths = ["/graphql", "/graphiql", "/v1/graphql", "/api/graphql", "/query", "/gql"]

    tested = set()
    for url in urls[:30]:
        base = _get_base_url(url)
        for path in gql_paths:
            gql_url = base + path
            if gql_url in tested:
                continue
            tested.add(gql_url)

            body = _post_json(gql_url, INTROSPECTION_QUERY)
            if not body or "__schema" not in body:
                continue

            host = _extract_host(gql_url)
            try:
                data = json.loads(body)
                types = data.get("data", {}).get("__schema", {}).get("types", [])
                type_names = [t.get("name", "") for t in types if not t.get("name", "").startswith("__")]
            except Exception:
                type_names = []

            Path(workdir) / "pentest" / f"graphql_{_safe(host)}_introspection.json"

            finding = {
                "scan_id":     scan_id,
                "title":       f"GraphQL Introspection Enabled ({host})",
                "template_id": "pentest-graphql-introspection",
                "severity":    "high",
                "cvss_score":  7.5,
                "category":    "api",
                "owasp_web":   "A01:2021",
                "owasp_api":   "API3:2023",
                "host":        host,
                "url":         gql_url,
                "description": f"GraphQL introspection enabled. {len(type_names)} types exposed: {', '.join(type_names[:10])}.",
                "evidence":    f"Endpoint: {gql_url}\nTypes: {len(type_names)}",
                "impact":      "Full API schema exposed. Attacker can enumerate all queries, mutations, types.",
                "remediation": "Disable introspection in production. Use query whitelisting.",
                "confidence":  98,
            }
            fid = db.add_finding(finding)
            if fid:
                count += 1
                notify_finding(finding)
                status(f"HIGH: GraphQL introspection — {host}", "finding")

    status(f"GraphQL: {count} findings", "ok" if not count else "warn")
    return count


# ═══════════════════════════════════════════════════════════════════════
#  REST Verb Fuzzing
# ═══════════════════════════════════════════════════════════════════════

def _test_verb_fuzzing(urls: list, scan_id: str, db: FindingsDB) -> int:
    status("REST verb fuzzing...", "run")
    count = 0
    api_urls = [u for u in urls if any(k in u.lower() for k in ["/api/", "/v1/", "/v2/", "/rest/"])][:20]

    for url in api_urls:
        host = _extract_host(url)
        for method in ["PUT", "DELETE", "PATCH"]:
            try:
                req = urllib.request.Request(
                    url, method=method,
                    headers={"User-Agent": "Mozilla/5.0", "Content-Type": "application/json"},
                    data=b"{}",
                )
                with urllib.request.urlopen(req, timeout=8) as resp:
                    if resp.status in (200, 201, 204):
                        finding = {
                            "scan_id":     scan_id,
                            "title":       f"Unprotected {method} — {_extract_path(url)} ({host})",
                            "template_id": f"pentest-verb-{method.lower()}",
                            "severity":    "high",
                            "cvss_score":  7.5,
                            "category":    "api",
                            "owasp_web":   "A01:2021",
                            "owasp_api":   "API5:2023",
                            "host":        host,
                            "url":         url,
                            "description": f"API accepts {method} without authentication.",
                            "evidence":    f"Method: {method}\nStatus: {resp.status}",
                            "impact":      f"Unauthenticated {method} allows data modification/deletion.",
                            "remediation": f"Require authentication for {method}. Implement RBAC.",
                            "confidence":  80,
                        }
                        fid = db.add_finding(finding)
                        if fid:
                            count += 1
                            notify_finding(finding)
                            status(f"HIGH: Unprotected {method} — {host}", "finding")
            except Exception:
                pass

    status(f"Verb fuzzing: {count} findings", "ok" if not count else "warn")
    return count


# ═══════════════════════════════════════════════════════════════════════
#  Mass Assignment
# ═══════════════════════════════════════════════════════════════════════

MASS_ASSIGN_FIELDS = [
    "role", "admin", "is_admin", "isAdmin", "user_type", "userType",
    "privilege", "permissions", "is_staff", "is_superuser",
    "verified", "active", "balance", "credits", "plan", "tier",
]

def _test_mass_assignment(urls: list, scan_id: str, db: FindingsDB,
                          tech_map: dict) -> int:
    status("Mass assignment testing...", "run")
    count = 0

    api_urls = [u for u in urls if any(k in u.lower() for k in
                ["/api/", "/v1/", "/v2/", "/user", "/account", "/profile", "/register"])][:15]

    for url in api_urls:
        host = _extract_host(url)
        payload = {field: "admin" for field in MASS_ASSIGN_FIELDS}
        payload.update({"email": "test@test.com", "name": "test"})

        try:
            body = _post_json(url, json.dumps(payload))
            if not body:
                continue

            resp_data = json.loads(body)
            accepted = [f for f in MASS_ASSIGN_FIELDS
                        if f in str(resp_data) and "error" not in body.lower()]

            if accepted:
                finding = {
                    "scan_id":     scan_id,
                    "title":       f"Mass Assignment — {_extract_path(url)} ({host})",
                    "template_id": "pentest-mass-assignment",
                    "severity":    "high",
                    "cvss_score":  8.1,
                    "category":    "api",
                    "owasp_web":   "A04:2021",
                    "owasp_api":   "API6:2023",
                    "host":        host,
                    "url":         url,
                    "description": f"API accepts privileged fields in request body: {', '.join(accepted[:5])}.",
                    "evidence":    f"Fields accepted: {', '.join(accepted)}\nEndpoint: {url}",
                    "impact":      "Privilege escalation. User can self-assign admin role or modify protected fields.",
                    "remediation": "Use explicit whitelists for accepted fields. Never bind user input directly to models.",
                    "confidence":  75,
                }
                fid = db.add_finding(finding)
                if fid:
                    count += 1
                    notify_finding(finding)
                    status(f"HIGH: Mass assignment — {host}", "finding")

        except (json.JSONDecodeError, Exception):
            pass

    status(f"Mass assignment: {count} findings", "ok" if not count else "warn")
    return count


# ═══════════════════════════════════════════════════════════════════════
#  BOLA / IDOR
# ═══════════════════════════════════════════════════════════════════════

def _test_bola(urls: list, scan_id: str, db: FindingsDB) -> int:
    status("BOLA/IDOR testing (unauthenticated)...", "run")
    count = 0

    id_pattern = re.compile(r"/(\d{1,10})(?:\?|$|/)")

    for url in urls[:30]:
        match = id_pattern.search(url)
        if not match:
            continue

        host     = _extract_host(url)
        orig_id  = match.group(1)
        test_ids = [str(int(orig_id) - 1), str(int(orig_id) + 1), "1", "999999"]

        orig_body = _fetch(url)
        if not orig_body or len(orig_body) < 50:
            continue

        for test_id in test_ids:
            test_url = url.replace(f"/{orig_id}", f"/{test_id}", 1)
            test_body = _fetch(test_url)

            if (test_body and len(test_body) > 50 and
                test_body != orig_body and
                "error" not in test_body.lower()[:200] and
                "not found" not in test_body.lower()[:200] and
                "unauthorized" not in test_body.lower()[:200]):

                finding = {
                    "scan_id":     scan_id,
                    "title":       f"BOLA/IDOR — {_extract_path(url)} ({host})",
                    "template_id": "pentest-bola",
                    "severity":    "high",
                    "cvss_score":  8.6,
                    "category":    "api",
                    "owasp_web":   "A01:2021",
                    "owasp_api":   "API1:2023",
                    "host":        host,
                    "url":         url,
                    "description": f"Replacing ID {orig_id} with {test_id} returns different valid data without authentication.",
                    "evidence":    f"Original: {url}\nTest: {test_url}\nBoth returned valid, different responses.",
                    "impact":      "Unauthorized access to other users' data by manipulating object IDs.",
                    "remediation": "Implement proper authorization checks. Validate that the requesting user owns the resource.",
                    "confidence":  70,
                }
                fid = db.add_finding(finding)
                if fid:
                    count += 1
                    notify_finding(finding)
                    status(f"HIGH: BOLA/IDOR — {host}", "finding")
                break

    status(f"BOLA: {count} findings", "ok" if not count else "warn")
    return count


# ═══════════════════════════════════════════════════════════════════════
#  API Documentation Exposure
# ═══════════════════════════════════════════════════════════════════════

API_DOC_PATHS = [
    "/swagger.json", "/swagger-ui.html", "/swagger-ui/",
    "/api-docs", "/api-docs/", "/openapi.json", "/openapi.yaml",
    "/docs", "/redoc", "/graphiql",
    "/v1/swagger.json", "/v2/swagger.json",
    "/api/swagger.json", "/api/v1/swagger.json",
    "/.well-known/openapi.json",
]

def _test_api_docs_exposure(urls: list, scan_id: str,
                            db: FindingsDB) -> int:
    status("API documentation exposure testing...", "run")
    count = 0

    tested = set()
    for url in urls[:20]:
        base = _get_base_url(url)
        for path in API_DOC_PATHS:
            doc_url = base + path
            if doc_url in tested:
                continue
            tested.add(doc_url)

            body = _fetch(doc_url)
            if not body or len(body) < 100:
                continue

            is_swagger = any(k in body.lower() for k in
                           ["swagger", "openapi", "paths", "components",
                            "api-docs", "graphiql"])

            if is_swagger:
                host = _extract_host(doc_url)
                finding = {
                    "scan_id":     scan_id,
                    "title":       f"API Documentation Exposed ({host})",
                    "template_id": "pentest-api-docs",
                    "severity":    "medium",
                    "cvss_score":  5.3,
                    "category":    "api",
                    "owasp_web":   "A01:2021",
                    "owasp_api":   "API9:2023",
                    "host":        host,
                    "url":         doc_url,
                    "description": f"API documentation is publicly accessible at {path}.",
                    "evidence":    f"URL: {doc_url}\nContent length: {len(body)} chars",
                    "impact":      "Attackers can enumerate all API endpoints, parameters, and data models.",
                    "remediation": "Restrict API docs to authenticated users. Remove Swagger/OpenAPI in production.",
                    "confidence":  95,
                }
                fid = db.add_finding(finding)
                if fid:
                    count += 1
                    notify_finding(finding)
                    status(f"MEDIUM: API docs exposed — {host}{path}", "finding")

    status(f"API docs: {count} findings", "ok" if not count else "warn")
    return count


# ═══════════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════════

def _extract_host(url: str) -> str:
    try:
        return urllib.parse.urlparse(url).netloc
    except Exception:
        return url

def _extract_path(url: str) -> str:
    try:
        return urllib.parse.urlparse(url).path
    except Exception:
        return url

def _get_base_url(url: str) -> str:
    try:
        p = urllib.parse.urlparse(url)
        return f"{p.scheme}://{p.netloc}"
    except Exception:
        return url

def _safe(text: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]", "_", text)[:60]

def _fetch(url: str, timeout: int = 8) -> str:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read(512 * 1024).decode("utf-8", errors="ignore")
    except Exception:
        return ""

def _post_json(url: str, json_body: str, timeout: int = 8) -> str:
    try:
        data = json_body.encode("utf-8")
        req  = urllib.request.Request(
            url, data=data, method="POST",
            headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read(512 * 1024).decode("utf-8", errors="ignore")
    except Exception:
        return ""
