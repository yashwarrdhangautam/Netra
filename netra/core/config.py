"""
netra/core/config.py
Unified configuration system. Single source of truth.
~/.netra.conf persists across sessions.
CONFIG dict is the runtime object used everywhere.
"""

import os
import configparser
from pathlib import Path

NETRA_HOME   = Path(os.environ.get("NETRA_HOME",   Path.home() / ".netra"))
CONFIG_FILE  = Path(os.environ.get("NETRA_CONFIG", NETRA_HOME / "config.yaml"))

# Ensure base directories exist on import
for _d in ["data/scans", "tools/bin", "tools/templates", "logs", "cache"]:
    (NETRA_HOME / _d).mkdir(parents=True, exist_ok=True)

# ── Default runtime config ────────────────────────────────────────────
DEFAULTS = {
    # General
    "output_dir":        str(NETRA_HOME / "data" / "scans"),
    "tools_dir":         str(NETRA_HOME / "tools" / "bin"),
    "logs_dir":          str(NETRA_HOME / "logs"),
    "cache_dir":         str(NETRA_HOME / "cache"),
    "threads":           "10",
    "rate_limit":        "100",          # requests per second
    "timeout":           "10",           # seconds per request
    "severity":          "critical,high,medium",
    "ports":             "80,443,8080,8443,8888,3000,9090,7443",
    "operator":          os.getenv("USER", "operator"),
    "legacy_mode":       "false",        # safe mode for fragile systems

    # Feature toggles
    "auto_screenshot":   "true",
    "js_analysis":       "true",
    "osint_passive":     "true",
    "waf_detection":     "true",
    "cvss_auto":         "true",

    # Scan profile
    "scan_profile":      "balanced",     # fast|balanced|deep|healthcare|legacy|mobile|saas

    # AI (Ollama-based — no API keys needed)
    # "claude_api_key":    "",  # DEPRECATED: using Ollama instead
    "ollama_url":        "http://localhost:11434",
    "ollama_model":      "qwen:14b",  # or: llama2, mistral, neural-chat
    "ai_analysis":       "true",
    "ai_narrative":      "true",

    # Notifications
    "slack_webhook":     "",
    "email_from":        "",
    "email_to":          "",
    "smtp_host":         "",
    "smtp_port":         "587",
    "smtp_user":         "",
    "smtp_pass":         "",
    "notify_on":         "critical,high",
    "notify_complete":   "true",

    # Database
    "db_path":           str(NETRA_HOME / "data" / "findings.db"),

    # Reports
    "report_word":       "true",
    "report_pdf":        "true",
    "report_html":       "true",
    "report_excel":      "true",
    "report_compliance": "true",         # HIPAA / PCI gap report
    "client_name":       "",
    "engagement_name":   "",

    # Integrations
    "jira_url":          "",
    "jira_token":        "",
    "jira_project":      "",
    "defectdojo_url":    "",
    "defectdojo_token":  "",
}

# ── API Keys section ──────────────────────────────────────────────────
API_KEY_DEFAULTS = {
    "shodan":            "",
    "censys_id":         "",
    "censys_secret":     "",
    "virustotal":        "",
    "securitytrails":    "",
    "github":            "",
    "fofa":              "",
    "hunter":            "",
    "haveibeenpwned":    "",
}

# ── Scope section ─────────────────────────────────────────────────────
SCOPE_DEFAULTS = {
    "exclude_domains":   "",
    "exclude_ips":       "",
    "exclude_patterns":  "",
    "include_private":   "false",
}

# ── The runtime CONFIG dict ──────────────────────────────────────────
CONFIG: dict = {}


def load_config() -> dict:
    """
    Load config from ~/.netra.conf.
    Creates it with defaults if it doesn't exist.
    Returns the CONFIG dict (also mutates module-level CONFIG).
    """
    global CONFIG

    parser = configparser.ConfigParser()

    if not CONFIG_FILE.exists():
        _write_defaults(parser)
    else:
        parser.read(CONFIG_FILE)

    CONFIG.update(DEFAULTS)
    CONFIG.update(API_KEY_DEFAULTS)
    CONFIG.update(SCOPE_DEFAULTS)

    for section in ("general", "api_keys", "scope", "notifications",
                    "ai", "integrations", "reports"):
        if parser.has_section(section):
            CONFIG.update(dict(parser[section]))

    Path(CONFIG["output_dir"]).mkdir(parents=True, exist_ok=True)
    Path(CONFIG["db_path"]).parent.mkdir(parents=True, exist_ok=True)

    return CONFIG


def save_config() -> None:
    """Write current CONFIG back to ~/.netra.conf."""
    parser = configparser.ConfigParser()

    parser["general"] = {k: CONFIG[k] for k in DEFAULTS}
    parser["api_keys"] = {k: CONFIG.get(k, "") for k in API_KEY_DEFAULTS}
    parser["scope"] = {k: CONFIG.get(k, "") for k in SCOPE_DEFAULTS}
    parser["notifications"] = {
        k: CONFIG.get(k, "") for k in [
            "slack_webhook", "email_from", "email_to",
            "smtp_host", "smtp_port", "smtp_user", "smtp_pass",
            "notify_on", "notify_complete"
        ]
    }
    parser["ai"] = {
        k: CONFIG.get(k, "") for k in [
            "ollama_url", "ollama_model",
            "ai_analysis", "ai_narrative"
        ]
    }
    parser["integrations"] = {
        k: CONFIG.get(k, "") for k in [
            "jira_url", "jira_token", "jira_project",
            "defectdojo_url", "defectdojo_token"
        ]
    }
    parser["reports"] = {
        k: CONFIG.get(k, "") for k in [
            "report_word", "report_pdf", "report_html",
            "report_excel", "report_compliance",
            "client_name", "engagement_name"
        ]
    }

    with open(CONFIG_FILE, "w") as f:
        parser.write(f)


def _write_defaults(parser: configparser.ConfigParser) -> None:
    """Write default config values to file."""
    parser["general"] = DEFAULTS
    parser["api_keys"] = API_KEY_DEFAULTS
    parser["scope"] = SCOPE_DEFAULTS
    parser["notifications"] = {k: "" for k in [
        "slack_webhook", "email_from", "email_to",
        "smtp_host", "smtp_port", "smtp_user", "smtp_pass",
        "notify_on", "notify_complete"
    ]}
    parser["ai"] = {
        "ollama_url": "http://localhost:11434",
        "ollama_model": "qwen:14b", "ai_analysis": "true", "ai_narrative": "true"
    }
    parser["integrations"] = {
        "jira_url": "", "jira_token": "", "jira_project": "",
        "defectdojo_url": "", "defectdojo_token": ""
    }
    parser["reports"] = {
        "report_word": "true", "report_pdf": "true", "report_html": "true",
        "report_excel": "true", "report_compliance": "true",
        "client_name": "", "engagement_name": ""
    }
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        parser.write(f)


def is_on(key: str) -> bool:
    """Check if a boolean config value is truthy."""
    return str(CONFIG.get(key, "false")).lower() in ("true", "1", "yes", "on")


def get_api_keys_configured() -> list:
    """Return list of API key names that have values set."""
    return [k for k in API_KEY_DEFAULTS if CONFIG.get(k, "").strip()]


def get_excluded_targets() -> set:
    """Return combined set of all excluded targets from scope config."""
    excluded: set = set()
    for field in ("exclude_domains", "exclude_ips", "exclude_patterns"):
        val = CONFIG.get(field, "")
        if val.strip():
            for item in val.replace(";", ",").replace("\n", ",").split(","):
                item = item.strip().lower()
                if item:
                    excluded.add(item)
    return excluded


def filter_targets(targets: list, excluded: set = None) -> list:
    """Remove excluded targets from list. Returns filtered list."""
    if excluded is None:
        excluded = get_excluded_targets()
    if not excluded:
        return targets

    filtered = []
    removed = 0
    for t in targets:
        t_lower = t.strip().lower()
        skip = any(ex in t_lower or t_lower == ex for ex in excluded)
        if skip:
            removed += 1
        else:
            filtered.append(t)

    if removed:
        print(f"  [scope] Removed {removed} excluded targets")
    return filtered


# ── Scan profiles ─────────────────────────────────────────────────────
SCAN_PROFILES = {
    "fast": {
        "description": "Critical vulns only — 1-2 hrs",
        "threads": "20",
        "severity": "critical,high",
        "nuclei_tags": "cve,rce,sqli,xss",
        "skip_phases": ["js_analysis", "screenshots"],
        "timeout": "5",
    },
    "balanced": {
        "description": "OWASP + auth + business logic — 3-5 hrs",
        "threads": "10",
        "severity": "critical,high,medium",
        "nuclei_tags": "cve,rce,sqli,xss,misconfig,exposure,default-login",
        "skip_phases": [],
        "timeout": "10",
    },
    "deep": {
        "description": "Everything including edge cases — 6-12 hrs",
        "threads": "5",
        "severity": "critical,high,medium,low",
        "nuclei_tags": "",          # all templates
        "skip_phases": [],
        "timeout": "15",
    },
    "healthcare": {
        "description": "HIPAA-focused — PHI, session, auth — 3-5 hrs",
        "threads": "8",
        "severity": "critical,high,medium",
        "nuclei_tags": "cve,sqli,xss,default-login,exposure,misconfig",
        "skip_phases": [],
        "timeout": "10",
        "hipaa_checks": True,
        "phi_detection": True,
        "session_timeout_check": True,
    },
    "legacy": {
        "description": "Safe mode for fragile systems — no aggressive tests",
        "threads": "2",
        "severity": "critical,high",
        "nuclei_tags": "cve,default-login,exposure",
        "skip_phases": ["aggressive_payloads", "brute_force"],
        "timeout": "20",
        "legacy_safe": True,
    },
    "mobile": {
        "description": "Mobile backend APIs — Firebase, JWT, device auth",
        "threads": "10",
        "severity": "critical,high,medium",
        "nuclei_tags": "cve,api,jwt,exposure,misconfig",
        "skip_phases": ["screenshots"],
        "timeout": "10",
        "firebase_check": True,
        "mobile_headers": True,
    },
    "saas": {
        "description": "B2B SaaS — multi-tenant, GraphQL, webhooks — 3-5 hrs",
        "threads": "10",
        "severity": "critical,high,medium",
        "nuclei_tags": "cve,api,graphql,misconfig,exposure",
        "skip_phases": [],
        "timeout": "10",
        "multitenant_check": True,
        "graphql_deep": True,
    },
}


def apply_scan_profile(profile_name: str) -> dict:
    """Apply a scan profile to CONFIG. Returns profile dict."""
    profile = SCAN_PROFILES.get(profile_name, SCAN_PROFILES["balanced"])
    CONFIG["scan_profile"] = profile_name
    CONFIG["threads"] = profile.get("threads", CONFIG["threads"])
    CONFIG["severity"] = profile.get("severity", CONFIG["severity"])
    CONFIG["timeout"] = profile.get("timeout", CONFIG["timeout"])
    if profile.get("legacy_safe"):
        CONFIG["legacy_mode"] = "true"
    return profile
