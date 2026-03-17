"""
netra/ai_brain
Multi-persona AI consensus engine for NETRA.
Provides CVSS scoring, MITRE mapping, attack chain discovery,
narrative generation, and compliance audit checks.
"""

from netra.ai_brain.config_audit import (
    audit_config,
    get_standard_description,
    list_standards,
    export_audit_report,
)

__all__ = [
    "audit_config",
    "get_standard_description",
    "list_standards",
    "export_audit_report",
]
