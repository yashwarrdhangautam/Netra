"""Passive enrichment for discovered bug bounty assets."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

import structlog

from netra.scanner.tools.gitleaks import GitleaksTool

logger = structlog.get_logger()


@dataclass
class AssetEnrichment:
    """Per-asset enrichment data."""

    host: str
    tech: list[str] = field(default_factory=list)
    js_endpoints: list[str] = field(default_factory=list)
    leaked_secrets: list[dict] = field(default_factory=list)


HEADER_RULES = {
    "server": {
        "nginx": "nginx",
        "apache": "apache",
        "cloudflare": "cloudflare",
        "openresty": "openresty",
        "iis": "iis",
        "gunicorn": "gunicorn",
        "envoy": "envoy",
        "awselb": "aws-elb",
        "caddy": "caddy",
        "traefik": "traefik",
    },
    "x-powered-by": {
        "express": "express",
        "php": "php",
        "asp.net": "asp.net",
        "next.js": "nextjs",
        "nuxt": "nuxt",
        "django": "django",
        "rails": "rails",
    },
    "x-generator": {
        "wordpress": "wordpress",
        "drupal": "drupal",
        "joomla": "joomla",
        "shopify": "shopify",
    },
    "set-cookie": {
        "laravel_session": "laravel",
        "csrftoken": "django",
        "connect.sid": "express",
        "_rails_session": "rails",
        "wordpress_": "wordpress",
    },
    "cf-ray": {"": "cloudflare"},
    "x-amz-cf-id": {"": "cloudfront"},
    "x-vercel-id": {"": "vercel"},
    "x-served-by": {"fastly": "fastly"},
}

BODY_RULES = {
    "wp-content": "wordpress",
    "wp-includes": "wordpress",
    "drupal-settings-json": "drupal",
    "joomla!": "joomla",
    "data-reactroot": "react",
    "__react_devtools_global_hook__": "react",
    "__next_data__": "nextjs",
    "nuxt": "nuxt",
    "ng-version": "angular",
    "vue": "vue",
    "svelte": "svelte",
    "webpack": "webpack",
    "gatsby": "gatsby",
    "shopify": "shopify",
    "cdn.shopify.com": "shopify",
    "stripe": "stripe",
    "recaptcha": "recaptcha",
    "hcaptcha": "hcaptcha",
    "csrf-token": "rails",
    "csrftoken": "django",
    "laravel": "laravel",
    "swagger-ui": "swagger",
    "openapi": "openapi",
    "graphql": "graphql",
    "bootstrap": "bootstrap",
    "jquery": "jquery",
    "tailwind": "tailwind",
    "cloudflare": "cloudflare",
    "segment.com": "segment",
    "google-analytics": "google-analytics",
    "gtag(": "google-analytics",
    "sentry": "sentry",
    "datadog": "datadog",
}

JS_ENDPOINT_PATTERNS = [
    re.compile(r"""fetch\(\s*['"](?P<url>[^'"]+)['"]"""),
    re.compile(r"""axios\.(?:get|post|put|patch|delete)\(\s*['"](?P<url>[^'"]+)['"]"""),
    re.compile(r"""XMLHttpRequest\(\)\.open\(\s*['"][A-Z]+['"]\s*,\s*['"](?P<url>[^'"]+)['"]"""),
    re.compile(r"""\.open\(\s*['"][A-Z]+['"]\s*,\s*['"](?P<url>[^'"]+)['"]"""),
]

SECRET_PATTERNS = {
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
}


def fingerprint_tech(headers: dict[str, str], body_snippet: str = "") -> list[str]:
    """Wappalyzer-style header/body fingerprinting."""
    normalized_headers = {k.lower(): str(v).lower() for k, v in headers.items()}
    body = (body_snippet or "").lower()
    tech: set[str] = set()

    for header, needles in HEADER_RULES.items():
        value = normalized_headers.get(header, "")
        if header in normalized_headers:
            for needle, label in needles.items():
                if not needle or needle in value:
                    tech.add(label)

    for needle, label in BODY_RULES.items():
        if needle in body:
            tech.add(label)

    return sorted(tech)


def extract_js_endpoints(js_text: str) -> list[str]:
    """Extract likely HTTP/API endpoints from a JS bundle."""
    endpoints: set[str] = set()
    for pattern in JS_ENDPOINT_PATTERNS:
        for match in pattern.finditer(js_text):
            url = match.group("url").strip()
            if url.startswith(("http://", "https://", "/")):
                endpoints.add(url)
    return sorted(endpoints)


async def hunt_secrets_async(text: str) -> list[dict]:
    """Run gitleaks against arbitrary text, falling back to curated regexes."""
    tool = GitleaksTool()
    if tool.is_installed():
        result = await tool.scan_text(text)
        if result.success:
            return result.findings

    hits: list[dict] = []
    for rule, pattern in SECRET_PATTERNS.items():
        for match in pattern.finditer(text):
            hits.append({"rule": rule, "secret": match.group(0), "start": match.start()})
    return hits


def hunt_secrets(text: str) -> list[dict]:
    """Synchronous regex-only secret hunt for callers that cannot await."""
    hits: list[dict] = []
    for rule, pattern in SECRET_PATTERNS.items():
        for match in pattern.finditer(text):
            hits.append({"rule": rule, "secret": match.group(0), "start": match.start()})
    return hits
