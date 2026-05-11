"""Pure-Python scope validator — the safety gate for NETRA-BB.

This module decides, for every target a tool is about to touch, whether that target is
in scope for the active program. It is pure Python with **zero AI in the path**. AI may
recommend scope changes; only an operator can accept them.

Design rules:
    1. Deny-first match order. Out-of-scope rules win over in-scope rules.
    2. A miss (no rule matched) is treated as DENY, never as ALLOW.
    3. Targets are normalised before matching: lowercased, IDN-decoded to punycode,
       URL-decoded once (defending against double-encoded sneaks), port stripped to
       a separate field, scheme stripped to a separate field.
    4. Wildcard rules (e.g. `*.shopify.com`) match the immediate parent domain and any
       deeper subdomain, but NEVER the apex (`shopify.com`) unless a separate rule
       declares the apex in scope.
    5. CIDR rules use the stdlib `ipaddress` module — no string regex on IPs.
    6. URL path rules require an exact path-prefix match on the normalised path.

If you find a behaviour that surprises you, add a test for it in
tests/test_bugbounty/test_scope.py BEFORE changing this file.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Iterable
from urllib.parse import unquote, urlparse


# ── Asset type enum (mirrors db.models.bb_scope_rule.ScopeAssetType) ────────────
class AssetType(StrEnum):
    """Local mirror of ScopeAssetType for use without DB import.

    Kept in sync with db.models.bb_scope_rule.ScopeAssetType. Tests assert the values
    match.
    """

    DOMAIN = "domain"
    WILDCARD = "wildcard"
    IP = "ip"
    CIDR = "cidr"
    URL = "url"
    MOBILE = "mobile"
    REPO = "repo"
    OTHER = "other"


class RuleType(StrEnum):
    """Allow vs deny."""

    IN = "in"
    OUT = "out"


# ── Public dataclasses ──────────────────────────────────────────────────────────
@dataclass(frozen=True)
class ScopeRule:
    """A single rule. Frozen so rule lists are safely hashable in tests."""

    rule_type: RuleType
    asset_type: AssetType
    pattern: str
    severity_cap: str | None = None
    notes: str | None = None
    active: bool = True


@dataclass(frozen=True)
class ParsedTarget:
    """A target normalised into the fields the validator can match against."""

    original: str
    scheme: str | None
    host: str | None  # punycode, lowercase
    port: int | None
    path: str  # always starts with '/'
    is_ip: bool
    ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address | None
    asset_kind_hint: AssetType  # best guess at what the operator passed in


@dataclass
class ScopeDecision:
    """Output of a validation call."""

    allowed: bool
    reason: str
    matched_rule: ScopeRule | None = None
    severity_cap: str | None = None
    parsed: ParsedTarget | None = None
    notes: list[str] = field(default_factory=list)


class ScopeViolation(Exception):
    """Raised when a tool tries to operate on a target that the validator denies.

    Tool wrappers should let this propagate. The orchestrator turns it into an
    audit-log entry and a dropped phase, never a silent failure.
    """

    def __init__(self, decision: ScopeDecision):
        self.decision = decision
        super().__init__(f"Out of scope: {decision.reason}")


# ── Helpers ─────────────────────────────────────────────────────────────────────
_HOSTNAME_RE = re.compile(
    r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$"
)
_WILDCARD_PATTERN_RE = re.compile(r"^\*\.(?P<root>[a-z0-9.-]+\.[a-z]{2,})$")


def _normalise_host(host: str) -> str:
    """Lowercase + IDN-encode. Strips leading/trailing dots and whitespace.

    Returns empty string on invalid input rather than raising — the validator treats
    empty hosts as 'no match' which means deny.
    """
    if not host:
        return ""
    h = host.strip().strip(".").lower()
    if not h:
        return ""
    try:
        h_ascii = h.encode("idna").decode("ascii")
    except UnicodeError:
        return ""
    return h_ascii.lower()


def _try_parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse a value as an IP address (IPv4 or IPv6). Returns None on miss."""
    try:
        return ipaddress.ip_address(value)
    except (ValueError, TypeError):
        return None


def parse_target(target: str) -> ParsedTarget:
    """Normalise an arbitrary target string into a ParsedTarget.

    Accepts: bare hosts, IPs, URLs (http/https), URLs with ports, IDN domains, paths,
    and the rule-side patterns we use in scope rules (e.g. 'api.example.com:8443/v1').
    """
    if target is None:
        target = ""
    raw = target.strip()
    # Single layer of URL-decoding. We do not loop — a real bug bounty target never
    # legitimately contains percent-encoded structural characters in its host.
    decoded = unquote(raw)

    scheme: str | None = None
    host: str | None = None
    port: int | None = None
    path = "/"
    asset_kind_hint = AssetType.OTHER

    # Try URL parse first.
    if "://" in decoded:
        try:
            u = urlparse(decoded)
            scheme = (u.scheme or None)
            host = u.hostname
            port = u.port
            path = u.path or "/"
            if path == "":
                path = "/"
            asset_kind_hint = AssetType.URL
        except ValueError:
            pass

    if host is None:
        # No scheme present. Split host[:port] from /path before any port logic.
        candidate = decoded
        if candidate.startswith("/"):
            path = candidate
            host = None
        else:
            host_port_part, sep, path_part = candidate.partition("/")
            if sep:
                path = "/" + path_part
            # IPv6 in brackets: [::1]:8080
            ipv6_match = re.match(r"^\[([^\]]+)\](?::(\d+))?$", host_port_part)
            if ipv6_match:
                host = ipv6_match.group(1)
                port_s = ipv6_match.group(2)
                port = int(port_s) if port_s else None
            elif ":" in host_port_part and host_port_part.count(":") == 1:
                h, _, p = host_port_part.partition(":")
                try:
                    port = int(p)
                    host = h
                except ValueError:
                    host = host_port_part
                    port = None
            else:
                host = host_port_part

    # Normalise host (IDN → ascii, lowercase).
    normalised_host: str | None = None
    is_ip = False
    ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None

    if host:
        ip_obj = _try_parse_ip(host)
        if ip_obj is not None:
            is_ip = True
            normalised_host = str(ip_obj)
            asset_kind_hint = AssetType.IP
        else:
            normalised_host = _normalise_host(host)
            if normalised_host and asset_kind_hint == AssetType.OTHER:
                asset_kind_hint = AssetType.DOMAIN

    # Path normalisation: collapse duplicate slashes, strip trailing slash unless root.
    if path != "/":
        path = re.sub(r"/+", "/", path)
        if path.endswith("/") and len(path) > 1:
            path = path.rstrip("/")
    if not path.startswith("/"):
        path = "/" + path

    return ParsedTarget(
        original=raw,
        scheme=scheme,
        host=normalised_host or None,
        port=port,
        path=path,
        is_ip=is_ip,
        ip_obj=ip_obj,
        asset_kind_hint=asset_kind_hint,
    )


# ── Per-rule matchers ───────────────────────────────────────────────────────────
def _match_domain(rule_pattern: str, parsed: ParsedTarget) -> bool:
    if not parsed.host or parsed.is_ip:
        return False
    pattern = _normalise_host(rule_pattern)
    return bool(pattern) and parsed.host == pattern


def _match_wildcard(rule_pattern: str, parsed: ParsedTarget) -> bool:
    if not parsed.host or parsed.is_ip:
        return False
    m = _WILDCARD_PATTERN_RE.match(rule_pattern.lower())
    if not m:
        return False
    root = _normalise_host(m.group("root"))
    if not root:
        return False
    # Wildcard matches deeper subdomains only — NOT the apex.
    return parsed.host.endswith("." + root) and parsed.host != root


def _match_ip(rule_pattern: str, parsed: ParsedTarget) -> bool:
    if not parsed.is_ip or parsed.ip_obj is None:
        return False
    rule_ip = _try_parse_ip(rule_pattern.strip())
    if rule_ip is None:
        return False
    return parsed.ip_obj == rule_ip


def _match_cidr(rule_pattern: str, parsed: ParsedTarget) -> bool:
    if not parsed.is_ip or parsed.ip_obj is None:
        return False
    try:
        net = ipaddress.ip_network(rule_pattern.strip(), strict=False)
    except (ValueError, TypeError):
        return False
    if isinstance(parsed.ip_obj, ipaddress.IPv4Address) and not isinstance(net, ipaddress.IPv4Network):
        return False
    if isinstance(parsed.ip_obj, ipaddress.IPv6Address) and not isinstance(net, ipaddress.IPv6Network):
        return False
    return parsed.ip_obj in net


def _match_url(rule_pattern: str, parsed: ParsedTarget) -> bool:
    """URL rule format: 'host[:port]/path-prefix' or full URL.

    Matches when host (and port if present in rule) matches AND parsed path starts
    with the rule's path. Pure prefix match — case-sensitive on the path.
    """
    rule = parse_target(rule_pattern)
    if rule.host is None or parsed.host is None:
        return False
    if rule.host != parsed.host:
        return False
    if rule.port is not None and parsed.port != rule.port:
        return False
    rule_path = rule.path
    parsed_path = parsed.path
    if rule_path == "/":
        return True
    return parsed_path == rule_path or parsed_path.startswith(rule_path + "/")


def _match_mobile(rule_pattern: str, parsed: ParsedTarget) -> bool:
    """Mobile package matches require the operator to pass the package as the target."""
    if parsed.host is None:
        return False
    return parsed.host.lower() == rule_pattern.strip().lower()


def _match_repo(rule_pattern: str, parsed: ParsedTarget) -> bool:
    """Repo URL match — host + path prefix, ignoring scheme."""
    if parsed.host is None:
        return False
    rule = parse_target(rule_pattern)
    if rule.host is None:
        return False
    if rule.host != parsed.host:
        return False
    if rule.path == "/":
        return True
    return parsed.path.startswith(rule.path)


_MATCHERS = {
    AssetType.DOMAIN: _match_domain,
    AssetType.WILDCARD: _match_wildcard,
    AssetType.IP: _match_ip,
    AssetType.CIDR: _match_cidr,
    AssetType.URL: _match_url,
    AssetType.MOBILE: _match_mobile,
    AssetType.REPO: _match_repo,
    AssetType.OTHER: lambda p, t: False,
}


# ── Validator ──────────────────────────────────────────────────────────────────
class ScopeValidator:
    """Decides whether a target is in scope for a given set of scope rules.

    Constructed with an iterable of ScopeRule. Inactive rules are dropped at
    construction. Decisions are deterministic: deny rules are checked first; the
    first allow-rule match wins; a miss is a deny.
    """

    def __init__(self, rules: Iterable[ScopeRule]):
        active = [r for r in rules if r.active]
        self._deny: list[ScopeRule] = [r for r in active if r.rule_type == RuleType.OUT]
        self._allow: list[ScopeRule] = [r for r in active if r.rule_type == RuleType.IN]

    @property
    def rule_count(self) -> int:
        """Total number of active rules loaded."""
        return len(self._deny) + len(self._allow)

    def check(self, target: str) -> ScopeDecision:
        """Decide whether the given target is in scope.

        Never raises on bad input — bad inputs become 'denied because parse failed'.
        """
        parsed = parse_target(target)

        if parsed.host is None and parsed.path == "/":
            return ScopeDecision(
                allowed=False,
                reason="Empty or unparseable target",
                parsed=parsed,
            )

        for rule in self._deny:
            matcher = _MATCHERS.get(rule.asset_type)
            if matcher is None:
                continue
            if matcher(rule.pattern, parsed):
                return ScopeDecision(
                    allowed=False,
                    reason=f"Matched out-of-scope rule: {rule.asset_type.value}={rule.pattern}",
                    matched_rule=rule,
                    parsed=parsed,
                )

        for rule in self._allow:
            matcher = _MATCHERS.get(rule.asset_type)
            if matcher is None:
                continue
            if matcher(rule.pattern, parsed):
                return ScopeDecision(
                    allowed=True,
                    reason=f"Matched in-scope rule: {rule.asset_type.value}={rule.pattern}",
                    matched_rule=rule,
                    severity_cap=rule.severity_cap,
                    parsed=parsed,
                )

        return ScopeDecision(
            allowed=False,
            reason="No in-scope rule matched (deny by default)",
            parsed=parsed,
        )

    def require(self, target: str) -> ScopeDecision:
        """Check and raise ScopeViolation if denied. Returns decision otherwise."""
        decision = self.check(target)
        if not decision.allowed:
            raise ScopeViolation(decision)
        return decision

    @classmethod
    def from_db_rules(cls, db_rules: Iterable) -> "ScopeValidator":
        """Build a validator from BBScopeRule ORM rows.

        Avoids importing the ORM at module load time so this file stays usable in
        contexts that don't have the DB configured (e.g. unit tests of the validator).
        """
        rules = [
            ScopeRule(
                rule_type=RuleType(r.rule_type),
                asset_type=AssetType(r.asset_type),
                pattern=r.pattern,
                severity_cap=r.severity_cap,
                notes=r.notes,
                active=r.active,
            )
            for r in db_rules
        ]
        return cls(rules)
