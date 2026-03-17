"""
netra/reports/__init__.py
Report engine package for NETRA नेत्र.
Exports all six report generators for use by the CLI and MCP tools.
"""

from netra.reports.word_report       import generate_word_report
from netra.reports.pdf_report        import generate_pdf_report
from netra.reports.html_report       import generate_html_report
from netra.reports.excel_report      import generate_excel_report
from netra.reports.compliance_report import generate_compliance_report
from netra.reports.evidence_zip      import generate_evidence_zip

__all__ = [
    "generate_word_report",
    "generate_pdf_report",
    "generate_html_report",
    "generate_excel_report",
    "generate_compliance_report",
    "generate_evidence_zip",
]
