"""Static guardrail for generated PoCs.

The checker is an allowlist. A PoC is accepted only when its entire text is made
of fenced code blocks tagged ``http``, ``bash`` or ``python``, and every block
passes the strict per-language rules below. Anything else, including prose,
unknown languages, unparseable code or unrecognised constructs, fails closed.
"""

from __future__ import annotations

import ast
import re
import shlex
from collections.abc import Collection
from urllib.parse import urlsplit

_FENCE_RE = re.compile(r"^```[ \t]*([A-Za-z]*)[ \t]*\n(.*?)^```[ \t]*$", re.DOTALL | re.MULTILINE)
_ALLOWED_LANGS = frozenset({"http", "bash", "python"})

_KNOWN_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"})
_READ_METHODS = frozenset({"GET", "HEAD"})

# Method-override headers and override-style body parameters, checked over the whole text.
_OVERRIDE_RE = re.compile(
    r"method[-_ ]?override|x-http-method|x-method-override|\b_method\s*[=:]",
    re.IGNORECASE,
)

# curl: only read-only flags. Anything not listed (data, forms, uploads, output files,
# cookie jars, config files, unknown options) is rejected.
_CURL_SAFE_SHORT = frozenset("sSiILkvGf")
_CURL_SAFE_LONG = frozenset(
    {
        "--silent",
        "--show-error",
        "--include",
        "--head",
        "--location",
        "--insecure",
        "--compressed",
        "--verbose",
        "--get",
        "--fail",
    }
)
_SHELL_META = frozenset("`$<>|&;()\\{}")

# Python: a small set of modules and calls. Anything else (os, subprocess, open, exec,
# eval, __import__, getattr, requests.post, ...) is rejected.
_PY_ALLOWED_MODULES = frozenset({"json", "base64", "urllib.parse", "requests", "httpx", "time"})
_PY_HTTP_CALLS = frozenset({"requests.get", "requests.head", "httpx.get", "httpx.head"})
_PY_SAFE_CALLS = _PY_HTTP_CALLS | frozenset(
    {"print", "len", "str", "int", "json.dumps", "base64.b64encode", "urllib.parse.quote", "urllib.parse.urlencode"}
)
_PY_HTTP_KWARGS = frozenset({"headers", "params", "timeout", "allow_redirects", "verify", "follow_redirects"})


def is_safe_poc(
    text: str,
    *,
    allow_post: bool = False,
    scope_hosts: Collection[str] | None = None,
) -> bool:
    """Return True only if ``text`` is an allowlisted, read-only PoC.

    ``allow_post`` permits POST requests (used for CSRF-style classes only).
    ``scope_hosts``, when given, requires every request host to equal or be a
    subdomain of one of the entries; requests whose host cannot be determined fail.
    """
    if not isinstance(text, str) or not text.strip():
        return False
    if _OVERRIDE_RE.search(text):
        return False

    blocks = _FENCE_RE.findall(text)
    if not blocks or _FENCE_RE.sub("", text).strip():
        return False

    scope = None
    if scope_hosts is not None:
        scope = {h.strip().lower().rstrip(".") for h in scope_hosts if h and h.strip()}

    allowed_methods = _READ_METHODS | ({"POST"} if allow_post else frozenset())
    for lang, body in blocks:
        lang = lang.lower()
        if lang == "http":
            ok = _check_http(body, allowed_methods, scope)
        elif lang == "bash":
            ok = _check_bash(body, allowed_methods, scope)
        elif lang == "python":
            ok = _check_python(body, scope)
        else:
            ok = False
        if not ok:
            return False
    return True


def _host_in_scope(host: str | None, scope: set[str] | None) -> bool:
    if scope is None:
        return True
    if not host:
        return False
    host = host.lower().rstrip(".")
    return any(host == s or host.endswith("." + s) for s in scope)


def _url_host(url: str) -> str | None:
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


def _is_request_line(parts: list[str]) -> bool:
    if len(parts) < 2 or not parts[0].isalpha():
        return False
    target = parts[1]
    return target.startswith("/") or target == "*" or target.lower().startswith(("http://", "https://"))


def _check_http(body: str, allowed_methods: frozenset[str], scope: set[str] | None) -> bool:
    requests: list[dict[str, str | None]] = []
    for raw in body.splitlines():
        parts = raw.split()  # splits on tabs as well as spaces
        if not parts:
            continue
        if _is_request_line(parts):
            if parts[0] not in allowed_methods:
                return False
            target = parts[1]
            requests.append({"target": target, "host": _url_host(target) if target.lower().startswith(("http://", "https://")) else None})
            continue
        if parts[0].upper() in _KNOWN_METHODS:
            # A known method on a line that is not a valid, allowed request line.
            return False
        name, sep, value = raw.partition(":")
        if sep and name.strip().lower() == "host" and requests and requests[-1]["host"] is None:
            requests[-1]["host"] = value.strip().lower().split(":")[0] or None

    if not requests:
        return False
    if scope is not None:
        return all(_host_in_scope(req["host"], scope) for req in requests)
    return True


def _check_bash(body: str, allowed_methods: frozenset[str], scope: set[str] | None) -> bool:
    saw_command = False
    for raw in body.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if any(ch in _SHELL_META for ch in line):
            return False
        try:
            tokens = shlex.split(line, posix=True)
        except ValueError:
            return False
        if not tokens or tokens[0] != "curl":
            return False

        urls: list[str] = []
        i = 1
        while i < len(tokens):
            tok = tokens[i]
            if tok in ("-X", "--request"):
                i += 1
                if i >= len(tokens) or tokens[i] not in allowed_methods:
                    return False
            elif tok.startswith("-X") and not tok.startswith("--"):
                if tok[2:] not in allowed_methods:
                    return False
            elif tok in ("-H", "--header"):
                i += 1
                if i >= len(tokens):
                    return False
            elif tok.startswith("--"):
                if tok not in _CURL_SAFE_LONG:
                    return False
            elif tok.startswith("-"):
                if len(tok) < 2 or not set(tok[1:]) <= _CURL_SAFE_SHORT:
                    return False
            elif tok.lower().startswith(("http://", "https://")):
                urls.append(tok)
            else:
                return False
            i += 1

        if not urls:
            return False
        if scope is not None and not all(_host_in_scope(_url_host(u), scope) for u in urls):
            return False
        saw_command = True
    return saw_command


def _dotted(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return None if base is None else f"{base}.{node.attr}"
    return None


def _check_python(body: str, scope: set[str] | None) -> bool:
    try:
        tree = ast.parse(body)
    except SyntaxError:
        return False

    aliases: dict[str, str] = {}
    urls: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name not in _PY_ALLOWED_MODULES:
                    return False
                if alias.asname:
                    aliases[alias.asname] = alias.name
                else:
                    top = alias.name.split(".")[0]
                    aliases[top] = top
        elif isinstance(node, ast.ImportFrom):
            if node.level or node.module not in _PY_ALLOWED_MODULES:
                return False
            for alias in node.names:
                if alias.name == "*":
                    return False
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        elif isinstance(node, ast.Call):
            dotted = _dotted(node.func)
            if dotted is None:
                return False
            head, dot, rest = dotted.partition(".")
            resolved = aliases.get(head, head) + (dot + rest if dot else "")
            if resolved not in _PY_SAFE_CALLS:
                return False
            if resolved in _PY_HTTP_CALLS:
                if len(node.args) != 1 or any(kw.arg is None or kw.arg not in _PY_HTTP_KWARGS for kw in node.keywords):
                    return False
                arg = node.args[0]
                if not (isinstance(arg, ast.Constant) and isinstance(arg.value, str)):
                    return False
                urls.append(arg.value)

    if scope is not None:
        return all(_host_in_scope(_url_host(u), scope) for u in urls)
    return True
