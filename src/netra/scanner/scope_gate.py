"""Strict scope compilation around the shared deny-first matcher."""

import ipaddress
import re
from urllib.parse import unquote, urlsplit, urlunsplit

from netra.bugbounty.scope import AssetType, RuleType, ScopeRule, ScopeValidator
from netra.db.models.target import Target

_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _host(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        return str(address)
    except ValueError:
        host = value.removesuffix(".").encode("idna").decode("ascii").lower()
        if len(host) > 253 or not all(_LABEL.fullmatch(label) for label in host.split(".")):
            raise ValueError("invalid hostname") from None
        return host


def canonical_rule(value: str, *, allow_wildcard: bool = False) -> tuple[AssetType, str]:
    if not isinstance(value, str) or not value or value != value.strip() or value.startswith("-"):
        raise ValueError("invalid scope value")
    if any(ord(c) < 33 or ord(c) == 127 for c in value) or "\\" in value:
        raise ValueError("invalid scope characters")
    if value.startswith("*.") and allow_wildcard:
        root = _host(value[2:])
        if "." not in root or "*" in root or re.fullmatch(r"[0-9.]+", root):
            raise ValueError("invalid wildcard")
        return AssetType.WILDCARD, "*." + root
    if "*" in value:
        raise ValueError("invalid wildcard")
    if "://" in value:
        parsed = urlsplit(value)
        if (
            parsed.scheme not in ("http", "https")
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise ValueError("invalid URL")
        if "%" in parsed.netloc or parsed.fragment:
            raise ValueError("ambiguous URL")
        port = parsed.port
        if port is not None and not 1 <= port <= 65535:
            raise ValueError("invalid URL port")
        host = _host(parsed.hostname)
        # Reject encoded structural path characters and dot segments, including nested encoding.
        path = parsed.path or "/"
        decoded = path
        for _ in range(3):
            decoded = unquote(decoded)
        if "%" in decoded or any(p in (".", "..") for p in decoded.split("/")) or "\\" in decoded:
            raise ValueError("ambiguous URL path")
        if decoded != path and decoded.count("/") != path.count("/"):
            raise ValueError("encoded path delimiter")
        if any(ord(c) < 32 or ord(c) == 127 for c in decoded):
            raise ValueError("invalid URL path")
        authority = f"[{host}]" if ":" in host else host
        effective = port or (443 if parsed.scheme == "https" else 80)
        authority += f":{effective}"
        # Query is not authority and may contain ephemeral or confidential values.
        return AssetType.URL, urlunsplit((parsed.scheme, authority, path, "", ""))
    try:
        address = ipaddress.ip_address(value)
        return AssetType.IP, _host(str(address))
    except ValueError:
        if "/" in value:
            network = ipaddress.ip_network(value, strict=False)
            return AssetType.CIDR, str(network)
    return AssetType.DOMAIN, _host(value)


def target_entries(target: Target) -> list[str]:
    kind = str(target.target_type)
    if kind == "domain_list":
        entries = [entry for entry in re.split(r"[,\s]+", target.value.strip()) if entry]
        if not entries:
            raise ValueError("empty domain list")
        for entry in entries:
            if canonical_rule(entry)[0] != AssetType.DOMAIN:
                raise ValueError("domain list requires hosts")
        return entries
    expected = {
        "domain": AssetType.DOMAIN,
        "ip": AssetType.IP,
        "url": AssetType.URL,
        "ip_range": AssetType.CIDR,
    }
    if kind not in expected or canonical_rule(target.value)[0] != expected[kind]:
        raise ValueError("unsupported or mismatched target kind")
    return [target.value]


def compiled_policy_rules(target: Target) -> list[ScopeRule]:
    rules = []
    includes = target.scope_includes if target.scope_includes is not None else []
    excludes = target.scope_excludes if target.scope_excludes is not None else []
    if not isinstance(includes, list) or not isinstance(excludes, list):
        raise ValueError("scope rules must be lists")
    for values, rule_type in (
        (excludes, RuleType.OUT),
        (target_entries(target) + includes, RuleType.IN),
    ):
        if not isinstance(values, list):
            raise ValueError("scope rules must be lists")
        for value in values:
            kind, pattern = canonical_rule(value, allow_wildcard=True)
            rules.append(ScopeRule(rule_type, kind, pattern))
    return rules


def compile_rules(target: Target) -> ScopeValidator:
    return ScopeValidator(compiled_policy_rules(target))
