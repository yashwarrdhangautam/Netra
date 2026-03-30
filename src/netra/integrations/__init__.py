"""Third-party integrations for NETRA."""
from netra.integrations.defectdojo import (
    DefectDojoClient,
    defectdojo_client,
    sync_scan_to_defectdojo,
)
from netra.integrations.jira import (
    JiraClient,
    create_finding_ticket,
    jira_client,
    sync_finding_status,
)

__all__ = [
    # DefectDojo
    "DefectDojoClient",
    "defectdojo_client",
    "sync_scan_to_defectdojo",
    # Jira
    "JiraClient",
    "jira_client",
    "create_finding_ticket",
    "sync_finding_status",
]
