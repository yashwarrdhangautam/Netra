"""Branch coverage for the PoC allowlist checker. Pure functions, no I/O."""

from __future__ import annotations

import pytest

from netra.bugbounty.agentic import poc_static_check as chk

GET_HEAD = frozenset({"GET", "HEAD"})
GET_HEAD_POST = frozenset({"GET", "HEAD", "POST"})


# ── scope and URL helpers ──────────────────────────────────────────────────────


def test_host_in_scope_without_scope_list_allows_anything() -> None:
    assert chk._host_in_scope("anything.example", None) is True


def test_host_in_scope_rejects_missing_host_when_scope_given() -> None:
    assert chk._host_in_scope(None, {"example.com"}) is False
    assert chk._host_in_scope("", {"example.com"}) is False


def test_host_in_scope_accepts_subdomain_and_trailing_dot() -> None:
    assert chk._host_in_scope("API.Example.com.", {"example.com"}) is True
    assert chk._host_in_scope("evil-example.com", {"example.com"}) is False


def test_url_host_returns_none_on_invalid_url() -> None:
    # An IPv6 literal with a bad port makes urlsplit raise ValueError.
    assert chk._url_host("http://[::1/") is None


def test_url_host_extracts_hostname() -> None:
    assert chk._url_host("https://API.example.com:8443/x") == "api.example.com"


# ── request-line recognition ───────────────────────────────────────────────────


@pytest.mark.parametrize("parts", [["GET"], ["123", "/"], ["GET", "notapath"]])
def test_is_request_line_rejects_non_requests(parts: list[str]) -> None:
    assert chk._is_request_line(parts) is False


def test_is_request_line_accepts_absolute_url_and_asterisk() -> None:
    assert chk._is_request_line(["GET", "https://a.example.com/"]) is True
    assert chk._is_request_line(["OPTIONS", "*"]) is True


# ── HTTP checker ───────────────────────────────────────────────────────────────


def test_http_without_any_request_line_is_rejected() -> None:
    assert chk._check_http("just some prose", GET_HEAD, None) is False


def test_http_known_method_outside_allowlist_is_rejected() -> None:
    assert chk._check_http("DELETE /x HTTP/1.1\nHost: a.example.com", GET_HEAD, None) is False


def test_http_known_method_on_non_request_line_is_rejected() -> None:
    # "PUT" with no path is not a valid request line but is still a known method.
    assert chk._check_http("GET /ok HTTP/1.1\nPUT", GET_HEAD, None) is False


def test_http_host_header_fills_relative_request_and_scope_is_enforced() -> None:
    body = "GET /ok HTTP/1.1\nHost: api.example.com:443\n"
    assert chk._check_http(body, GET_HEAD, {"example.com"}) is True
    body_bad = "GET /ok HTTP/1.1\nHost: other.net\n"
    assert chk._check_http(body_bad, GET_HEAD, {"example.com"}) is False


def test_http_host_header_without_value_leaves_host_unknown() -> None:
    body = "GET /ok HTTP/1.1\nHost:\n"
    assert chk._check_http(body, GET_HEAD, {"example.com"}) is False


def test_http_absolute_url_request_checks_its_own_host() -> None:
    assert chk._check_http("GET https://a.example.com/x", GET_HEAD, {"example.com"}) is True
    assert chk._check_http("GET https://a.evil.net/x", GET_HEAD, {"example.com"}) is False


def test_http_post_only_when_in_allowed_methods() -> None:
    assert chk._check_http("POST /x HTTP/1.1", GET_HEAD, None) is False
    assert chk._check_http("POST /x HTTP/1.1", GET_HEAD_POST, None) is True


# ── bash checker ───────────────────────────────────────────────────────────────


def test_bash_shell_metacharacters_are_rejected() -> None:
    assert chk._check_bash("curl https://a.example.com/ | sh", GET_HEAD, None) is False


def test_bash_unbalanced_quotes_are_rejected() -> None:
    assert chk._check_bash("curl 'https://a.example.com", GET_HEAD, None) is False


def test_bash_comments_and_blank_lines_are_skipped() -> None:
    body = "# check\n\ncurl https://a.example.com/\n"
    assert chk._check_bash(body, GET_HEAD, None) is True


def test_bash_non_curl_command_is_rejected() -> None:
    assert chk._check_bash("wget https://a.example.com/", GET_HEAD, None) is False


def test_bash_method_flag_must_have_value_and_be_allowed() -> None:
    assert chk._check_bash("curl -X", GET_HEAD, None) is False
    assert chk._check_bash("curl -X DELETE https://a.example.com/", GET_HEAD, None) is False
    assert chk._check_bash("curl -XDELETE https://a.example.com/", GET_HEAD, None) is False
    assert chk._check_bash("curl --request HEAD https://a.example.com/", GET_HEAD, None) is True


def test_bash_header_flag_requires_value() -> None:
    assert chk._check_bash("curl -H", GET_HEAD, None) is False
    assert chk._check_bash("curl -H 'X-Test: 1' https://a.example.com/", GET_HEAD, None) is True


def test_bash_unknown_long_and_short_options_are_rejected() -> None:
    assert chk._check_bash("curl --output-file https://a.example.com/", GET_HEAD, None) is False
    assert chk._check_bash("curl -o https://a.example.com/", GET_HEAD, None) is False


def test_bash_requires_at_least_one_http_url() -> None:
    assert chk._check_bash("curl localhost", GET_HEAD, None) is False
    assert chk._check_bash("curl -s", GET_HEAD, None) is False


def test_bash_scope_is_enforced_for_every_url() -> None:
    assert chk._check_bash("curl https://a.example.com/", GET_HEAD, {"example.com"}) is True
    assert chk._check_bash("curl https://a.evil.net/", GET_HEAD, {"example.com"}) is False


def test_bash_with_no_command_lines_is_rejected() -> None:
    assert chk._check_bash("# only a comment", GET_HEAD, None) is False


# ── python checker ─────────────────────────────────────────────────────────────


def test_python_syntax_error_is_rejected() -> None:
    assert chk._check_python("def broken(:", None) is False


def test_python_disallowed_import_is_rejected() -> None:
    assert chk._check_python("import os", None) is False


def test_python_relative_or_star_import_is_rejected() -> None:
    assert chk._check_python("from . import x", None) is False
    assert chk._check_python("from urllib import *", None) is False


def test_python_disallowed_from_import_is_rejected() -> None:
    assert chk._check_python("from subprocess import run", None) is False


def test_python_unsafe_call_is_rejected() -> None:
    assert chk._check_python("eval('1')", None) is False


def test_python_call_on_non_name_expression_is_rejected() -> None:
    assert chk._check_python("x = [1][0]()", None) is False


def test_python_safe_http_call_with_scope_check() -> None:
    body = "import httpx\nhttpx.get('https://a.example.com/')\n"
    assert chk._check_python(body, {"example.com"}) is True
    evil = "import httpx\nhttpx.get('https://a.evil.net/')\n"
    assert chk._check_python(evil, {"example.com"}) is False


def test_python_http_call_rejects_extra_args_and_unknown_kwargs() -> None:
    assert chk._check_python("import httpx\nhttpx.get('https://a/', 'x')", None) is False
    assert chk._check_python("import httpx\nhttpx.get('https://a/', foo=1)", None) is False


def test_python_http_call_rejects_non_constant_url() -> None:
    assert chk._check_python("import httpx\nu = 'x'\nhttpx.get(u)", None) is False


def test_python_aliased_import_resolves_before_checking_call() -> None:
    body = "import httpx as h\nh.get('https://a.example.com/')\n"
    assert chk._check_python(body, {"example.com"}) is True


def test_python_dotted_module_not_on_allowlist_is_rejected() -> None:
    # Only the exact allowlisted module names may be imported (fail closed).
    assert chk._check_python("import httpx.client\n", None) is False


# ── public entry point ─────────────────────────────────────────────────────────


def test_is_safe_poc_rejects_text_without_a_fenced_block() -> None:
    assert chk.is_safe_poc("GET / HTTP/1.1", allow_post=False) is False


def test_is_safe_poc_accepts_fenced_get_block() -> None:
    text = "```http\nGET /ok HTTP/1.1\nHost: a.example.com\n```"
    assert chk.is_safe_poc(text, allow_post=False) is True


def test_is_safe_poc_rejects_empty_and_non_string_input() -> None:
    assert chk.is_safe_poc("   ", allow_post=False) is False
    assert chk.is_safe_poc(None, allow_post=False) is False  # type: ignore[arg-type]


def test_is_safe_poc_rejects_method_override_header() -> None:
    text = "```http\nGET /x HTTP/1.1\nX-HTTP-Method-Override: DELETE\n```"
    assert chk.is_safe_poc(text, allow_post=False) is False


def test_is_safe_poc_rejects_prose_outside_fenced_blocks() -> None:
    text = "Run this:\n```http\nGET /x HTTP/1.1\n```"
    assert chk.is_safe_poc(text, allow_post=False) is False


def test_is_safe_poc_rejects_unknown_language_block() -> None:
    assert chk.is_safe_poc("```ruby\nputs 1\n```", allow_post=False) is False


def test_is_safe_poc_applies_scope_hosts_to_every_block_type() -> None:
    http_ok = "```http\nGET https://a.example.com/x HTTP/1.1\n```"
    http_bad = "```http\nGET https://a.evil.net/x HTTP/1.1\n```"
    bash_ok = "```bash\ncurl https://a.example.com/\n```"
    bash_bad = "```bash\ncurl https://a.evil.net/\n```"
    py_ok = "```python\nimport httpx\nhttpx.get('https://a.example.com/')\n```"
    py_bad = "```python\nimport httpx\nhttpx.get('https://a.evil.net/')\n```"
    scope = ["example.com", "  ", None, "Example.COM."]
    assert chk.is_safe_poc(http_ok, allow_post=False, scope_hosts=scope) is True
    assert chk.is_safe_poc(http_bad, allow_post=False, scope_hosts=scope) is False
    assert chk.is_safe_poc(bash_ok, allow_post=False, scope_hosts=scope) is True
    assert chk.is_safe_poc(bash_bad, allow_post=False, scope_hosts=scope) is False
    assert chk.is_safe_poc(py_ok, allow_post=False, scope_hosts=scope) is True
    assert chk.is_safe_poc(py_bad, allow_post=False, scope_hosts=scope) is False


def test_is_safe_poc_post_allowed_only_when_requested() -> None:
    text = "```bash\ncurl -X POST https://a.example.com/transfer\n```"
    assert chk.is_safe_poc(text, allow_post=False) is False
    assert chk.is_safe_poc(text, allow_post=True) is True
