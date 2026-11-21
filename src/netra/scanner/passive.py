"""Posture checks that Recontool does not cover: email authentication, CAA, TLS expiry, headers.

Asset discovery (certificate transparency, subdomain sources, Wayback) belongs to Recontool; see
``tools/recontool.py``. This module only adds findings on top of it.

Two kinds of traffic, kept apart on purpose:

* ``PassivePosture`` talks only to a public DNS-over-HTTPS resolver. It sends nothing to the
  target. The caller must hold the ``passive_recon`` action. Zone-level lookups (email
  authentication, CAA) describe the registered zone of the target host, so they are allowed under
  that action. ``analyze_discovered_names`` turns names Recontool found into observations only;
  they are never probed unless the scope rules already allow them.
* ``probe_tls`` and ``analyze_headers`` look at a host the target owns (one TLS handshake, headers
  from a response a normal request already returns). The caller must hold ``http_probe``.

The resolver is rate limited to the signed ``max_requests_per_second`` of the authorization.
"""

from __future__ import annotations

import asyncio
import re
import ssl
import time
from collections.abc import Callable, Iterable, Mapping
from datetime import UTC, datetime
from typing import Any

import httpx

from netra.scanner.tools.base import ToolResult

DOH_URL = "https://cloudflare-dns.com/dns-query"
USER_AGENT = "NETRA-passive-posture/1.0"
PROVIDER_TIMEOUT_SECONDS = 20.0

SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "server",
    "x-powered-by",
)

# Labels that usually mean "not meant for the public internet".
SENSITIVE_LABELS = (
    "admin", "metabase", "grafana", "kibana", "jenkins", "gitlab", "sonar", "prometheus",
    "tsdb", "influx", "db", "mysql", "postgres", "redis", "ops", "internal", "intranet",
    "staging", "stage", "test", "dev", "qa", "uat", "sandbox", "vpn", "iot", "api-docs",
)  # fmt: skip

_VERSIONED = re.compile(r"\d+\.\d+")


class RateLimiter:
    """Spaces calls at least ``interval`` seconds apart."""

    def __init__(self, interval: float) -> None:
        self.interval = max(0.0, interval)
        self._next = 0.0
        self._lock = asyncio.Lock()

    async def wait(self) -> None:
        async with self._lock:
            now = time.monotonic()
            if self._next > now:
                await asyncio.sleep(self._next - now)
            self._next = max(now, self._next) + self.interval


def _finding(
    title: str,
    severity: str,
    description: str,
    *,
    url: str | None = None,
    evidence: dict[str, Any] | None = None,
    tags: list[str] | None = None,
    cwe_id: str | None = None,
    confidence: int = 90,
) -> dict[str, Any]:
    return {
        "title": title,
        "severity": severity,
        "description": description,
        "url": url,
        "evidence": evidence or {},
        "tags": ["passive", *(tags or [])],
        "cwe_id": cwe_id,
        "confidence": confidence,
    }


# ── Analysis (pure) ───────────────────────────────────────────────────────────


def _txt(records: Mapping[str, list[str]], key: str) -> list[str]:
    # DoH returns long TXT records as adjacent quoted chunks: "abc" "def".
    return [v.replace('" "', "").strip('"') for v in records.get(key, [])]


def analyze_email_auth(zone: str, records: Mapping[str, list[str]]) -> list[dict[str, Any]]:
    """SPF and DMARC posture for a zone that receives mail."""
    if not records.get("MX"):
        return []
    findings: list[dict[str, Any]] = []
    spf = [t for t in _txt(records, "TXT") if t.lower().startswith("v=spf1")]
    dmarc = [t for t in _txt(records, "_dmarc") if t.lower().startswith("v=dmarc1")]
    url = f"dns://{zone}"

    if not spf:
        findings.append(
            _finding(
                f"No SPF record for {zone}",
                "medium",
                f"{zone} receives mail (MX present) but publishes no SPF record, so any server "
                "can send mail that claims to be from this domain without failing SPF.\n\n"
                f"Remediation: publish a TXT record on {zone} such as "
                '"v=spf1 include:<your mail provider> -all".\n'
                "Acceptance: a TXT lookup returns exactly one v=spf1 record ending in -all.",
                url=url,
                evidence={"zone": zone, "mx": records.get("MX", [])},
                tags=["email", "spf"],
            )
        )
    else:
        record = spf[0]
        qualifier = re.search(r"([+\-~?])all\b", record)
        symbol = qualifier.group(1) if qualifier else ""
        if symbol in ("+", "?") or not qualifier:
            severity, label = "high" if symbol == "+" else "medium", "does not restrict senders"
        elif symbol == "~":
            severity, label = "low", "uses soft fail (~all)"
        else:
            severity, label = "", ""
        if severity:
            findings.append(
                _finding(
                    f"SPF record for {zone} {label}",
                    severity,
                    f"SPF is `{record}`. Receivers treat unauthorised senders as acceptable or "
                    "only suspicious, which weakens spoofing protection.\n\n"
                    "Remediation: once every legitimate sender is listed, end the record with "
                    "-all.\nAcceptance: the published record ends in -all and legitimate mail "
                    "still passes SPF.",
                    url=url,
                    evidence={"zone": zone, "spf": record},
                    tags=["email", "spf"],
                )
            )

    if not dmarc:
        findings.append(
            _finding(
                f"No DMARC record for {zone}",
                "medium",
                f"No v=DMARC1 record exists at _dmarc.{zone}, so receivers have no policy for "
                "mail that fails SPF and DKIM.\n\n"
                f"Remediation: publish a TXT record at _dmarc.{zone}, starting with "
                '"v=DMARC1; p=none; rua=mailto:<mailbox>" and moving to quarantine, then reject.\n'
                "Acceptance: the record exists and reports are being received.",
                url=url,
                evidence={"zone": zone},
                tags=["email", "dmarc"],
            )
        )
    else:
        policy = re.search(r"\bp=(\w+)", dmarc[0], re.IGNORECASE)
        if policy and policy.group(1).lower() == "none":
            findings.append(
                _finding(
                    f"DMARC policy for {zone} is monitor-only (p=none)",
                    "low",
                    f"DMARC is `{dmarc[0]}`. Failing mail is still delivered, so the domain can "
                    "be spoofed.\n\n"
                    "Remediation: review the aggregate reports, then move to p=quarantine and "
                    "finally p=reject.\nAcceptance: the published policy is quarantine or reject.",
                    url=url,
                    evidence={"zone": zone, "dmarc": dmarc[0]},
                    tags=["email", "dmarc"],
                )
            )
    return findings


def analyze_caa(zone: str, records: Mapping[str, list[str]]) -> list[dict[str, Any]]:
    if records.get("CAA"):
        return []
    return [
        _finding(
            f"No CAA record for {zone}",
            "info",
            f"{zone} does not restrict which certificate authorities may issue for it.\n\n"
            f'Remediation: publish CAA records, for example `0 issue "letsencrypt.org"`.\n'
            "Acceptance: a CAA lookup returns at least one issue record.",
            url=f"dns://{zone}",
            evidence={"zone": zone},
            tags=["dns", "caa"],
            confidence=80,
        )
    ]


def analyze_discovered_names(
    zone: str,
    names: Iterable[str],
    host: str,
    in_scope: Callable[[str], bool],
) -> list[dict[str, Any]]:
    """Hostnames Recontool found (CT logs and other passive sources). Observed, not probed."""
    others = sorted({n for n in names if n != host and not n.startswith("*.")})
    if not others:
        return []
    unscoped = [n for n in others if not in_scope(n)]
    findings = [
        _finding(
            f"Passive sources list {len(others)} other hostnames for {zone}",
            "info",
            "Passive sources (certificate transparency and others) list these hostnames. They were not contacted. "
            + (
                f"{len(unscoped)} are outside the authorised scope and stay untouched."
                if unscoped
                else "All are inside the authorised scope."
            ),
            url=f"dns://{zone}",
            evidence={"zone": zone, "names": others[:200], "outside_scope": unscoped[:200]},
            tags=["discovery", "attack-surface"],
        )
    ]
    sensitive = [
        n for n in others if any(label in SENSITIVE_LABELS for label in n.split(".")[0].split("-"))
    ]
    if sensitive:
        findings.append(
            _finding(
                f"Internal-looking hostnames exposed in public sources for {zone}",
                "low",
                "These names suggest admin, data or test systems: "
                + ", ".join(sensitive[:20])
                + ".\n\nRemediation: confirm each is access-controlled (SSO, VPN or IP allow "
                "list), remove DNS for retired ones, and use wildcard or private CAs for "
                "internal names so they stay out of public CT logs.\n"
                "Acceptance: each listed host either no longer resolves publicly or answers "
                "unauthenticated requests with 401/403.",
                url=f"dns://{zone}",
                evidence={"zone": zone, "names": sensitive[:50]},
                tags=["discovery", "attack-surface"],
                confidence=60,
            )
        )
    return findings


def security_headers(headers: Mapping[str, Any] | None) -> dict[str, str]:
    """The hardening and disclosure headers of a response, names normalised.

    httpx writes header names with underscores (``strict_transport_security``).
    """
    result: dict[str, str] = {}
    for key, value in (headers or {}).items():
        name = str(key).lower().replace("_", "-")
        if name in SECURITY_HEADERS:
            result[name] = ", ".join(value) if isinstance(value, list) else str(value)
    return result


def analyze_headers(url: str, headers: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Missing hardening headers and technology disclosure from one HTTP response."""
    h = {
        str(k).lower(): (", ".join(v) if isinstance(v, list) else str(v))
        for k, v in headers.items()
    }
    is_https = url.lower().startswith("https://")
    csp = h.get("content-security-policy", "")
    missing: list[tuple[str, str]] = []
    if is_https and "strict-transport-security" not in h:
        missing.append(("Strict-Transport-Security", "max-age=31536000; includeSubDomains"))
    if not csp:
        missing.append(("Content-Security-Policy", "default-src 'self'"))
    if "x-frame-options" not in h and "frame-ancestors" not in csp:
        missing.append(("X-Frame-Options", "DENY"))
    if "x-content-type-options" not in h:
        missing.append(("X-Content-Type-Options", "nosniff"))
    if "referrer-policy" not in h:
        missing.append(("Referrer-Policy", "strict-origin-when-cross-origin"))
    if "permissions-policy" not in h:
        missing.append(("Permissions-Policy", "camera=(), microphone=(), geolocation=()"))

    findings: list[dict[str, Any]] = []
    if missing:
        names = [m[0] for m in missing]
        severity = "low" if set(names) & {"Strict-Transport-Security", "Content-Security-Policy",
                                           "X-Frame-Options", "X-Content-Type-Options"} else "info"  # fmt: skip
        findings.append(
            _finding(
                f"Missing security headers: {', '.join(names)}",
                severity,
                f"The response from {url} lacks: {', '.join(names)}.\n\n"
                "Remediation (set on the reverse proxy or the app, for every route):\n"
                + "\n".join(f"  {n}: {v}" for n, v in missing)
                + "\nAcceptance: a GET to the URL returns every listed header, and the site "
                "still loads without CSP violations in the browser console.",
                url=url,
                evidence={
                    "missing": names,
                    "present": sorted(k for k in h if k in SECURITY_HEADERS),
                },
                tags=["headers"],
                cwe_id="CWE-693",
            )
        )
    disclosed = {
        k: h[k] for k in ("server", "x-powered-by") if k in h and (k == "x-powered-by" or _VERSIONED.search(h[k]))
    }  # fmt: skip
    if disclosed:
        findings.append(
            _finding(
                "Server technology disclosed in response headers",
                "info",
                f"{url} reveals: "
                + ", ".join(f"{k}: {v}" for k, v in disclosed.items())
                + ".\n\nRemediation: nginx `server_tokens off;`, Next.js `poweredByHeader: false`.\n"
                "Acceptance: neither header exposes a product or version.",
                url=url,
                evidence={"headers": disclosed},
                tags=["headers", "disclosure"],
                cwe_id="CWE-200",
            )
        )
    return findings


def analyze_certificate(
    host: str, port: int, cert: Mapping[str, Any], protocol: str
) -> list[dict[str, Any]]:
    """Expiry findings from a verified certificate (see ``probe_tls``)."""
    not_after = cert.get("notAfter")
    if not not_after:
        return []
    expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(str(not_after)), UTC)
    days = (expires - datetime.now(UTC)).days
    if days >= 30:
        return []
    severity, label = ("high", "expired") if days < 0 else ("medium", f"expires in {days} days")
    return [
        _finding(
            f"TLS certificate for {host} {label}",
            severity,
            f"The certificate on {host}:{port} is valid until {expires:%Y-%m-%d} ({protocol}).\n\n"
            "Remediation: renew it and confirm automatic renewal runs.\n"
            "Acceptance: the served certificate is valid for at least 30 more days.",
            url=f"https://{host}:{port}",
            evidence={"not_after": expires.isoformat(), "protocol": protocol},
            tags=["tls"],
            cwe_id="CWE-298",
        )
    ]


# ── Network ───────────────────────────────────────────────────────────────────


async def probe_tls(host: str, port: int = 443, timeout: float = 10.0) -> ToolResult:
    """One verified TLS handshake. A verification failure is itself a finding."""
    started = datetime.now(UTC)
    context = ssl.create_default_context()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=context, server_hostname=host), timeout
        )
    except ssl.SSLCertVerificationError as exc:
        finding = _finding(
            f"TLS certificate for {host} failed verification",
            "high",
            f"A verified handshake to {host}:{port} failed: {exc.verify_message}.\n\n"
            "Remediation: serve a certificate that chains to a public CA and matches the "
            "hostname.\nAcceptance: `openssl s_client -verify_return_error` succeeds.",
            url=f"https://{host}:{port}",
            evidence={"reason": exc.verify_message},
            tags=["tls"],
            cwe_id="CWE-295",
        )
        return ToolResult(
            tool_name="tls_probe", success=True, target=host, started_at=started,
            findings=[finding], metadata={"state": "completed"},
        )  # fmt: skip
    except (OSError, TimeoutError) as exc:
        return ToolResult(
            tool_name="tls_probe", success=False, target=host, started_at=started,
            error=f"tls_unreachable: {type(exc).__name__}",
            metadata={"state": "failed", "reason_code": "tls_unreachable"},
        )  # fmt: skip
    try:
        ssl_object = writer.get_extra_info("ssl_object")
        cert = ssl_object.getpeercert() or {}
        protocol = ssl_object.version() or "unknown"
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
    return ToolResult(
        tool_name="tls_probe", success=True, target=host, started_at=started,
        findings=analyze_certificate(host, port, cert, protocol),
        metadata={"state": "completed", "protocol": protocol},
    )  # fmt: skip


def _answers(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [a for a in payload.get("Answer", []) if isinstance(a, dict)]


class PassivePosture:
    """Email-auth and CAA collection for one host's zone, through a DNS-over-HTTPS resolver."""

    tool_name = "passive_posture"

    def __init__(
        self,
        host: str,
        *,
        max_requests_per_second: int,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if isinstance(max_requests_per_second, bool) or not 1 <= max_requests_per_second <= 300:
            raise ValueError("invalid passive posture rate limit")
        self.host = host.lower().rstrip(".")
        self._client = client
        self._dns_limiter = RateLimiter(1.0 / max_requests_per_second)
        self.requests_made = 0

    async def _doh(self, client: httpx.AsyncClient, name: str, rtype: str) -> dict[str, Any]:
        await self._dns_limiter.wait()
        self.requests_made += 1
        response = await client.get(
            DOH_URL,
            params={"name": name, "type": rtype},
            headers={"accept": "application/dns-json"},
        )
        response.raise_for_status()
        return response.json()

    async def _zone(self, client: httpx.AsyncClient) -> str:
        """The registered zone of the host, from the SOA owner name."""
        payload = await self._doh(client, self.host, "SOA")
        for section in ("Answer", "Authority"):
            for record in payload.get(section, []):
                if isinstance(record, dict) and record.get("type") == 6 and record.get("name"):
                    return str(record["name"]).lower().rstrip(".")
        return self.host

    async def _records(self, client: httpx.AsyncClient, zone: str) -> dict[str, list[str]]:
        records: dict[str, list[str]] = {}
        for rtype in ("MX", "TXT", "CAA"):
            payload = await self._doh(client, zone, rtype)
            records[rtype] = [
                str(a.get("data", "")) for a in _answers(payload) if a.get("type") == _TYPES[rtype]
            ]
        payload = await self._doh(client, f"_dmarc.{zone}", "TXT")
        records["_dmarc"] = [
            str(a.get("data", "")) for a in _answers(payload) if a.get("type") == _TYPES["TXT"]
        ]
        return records

    async def run(self) -> ToolResult:
        started = datetime.now(UTC)
        owns_client = self._client is None
        client = self._client or httpx.AsyncClient(
            timeout=PROVIDER_TIMEOUT_SECONDS, headers={"user-agent": USER_AGENT}
        )
        findings: list[dict[str, Any]] = []
        records: dict[str, list[str]] = {}
        zone = self.host
        error: str | None = None
        try:
            zone = await self._zone(client)
            records = await self._records(client, zone)
            findings += analyze_email_auth(zone, records)
            findings += analyze_caa(zone, records)
        except (httpx.HTTPError, ValueError) as exc:
            error = f"dns_resolver_failed: {type(exc).__name__}"
        finally:
            if owns_client:
                await client.aclose()

        return ToolResult(
            tool_name=self.tool_name,
            success=error is None,
            target=self.host,
            started_at=started,
            findings=findings,
            metadata={
                "state": "completed" if error is None else "failed",
                "reason_code": None if error is None else "providers_unreachable",
                "zone": zone,
                "requests": self.requests_made,
            },
            error=error,
        )


_TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28, "CAA": 257}
