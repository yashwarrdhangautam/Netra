"""Compliance engine — comprehensive mappings across 6 frameworks."""
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netra.db.models.compliance import ComplianceMapping
from netra.db.models.finding import Finding
from netra.db.seeds.compliance_mappings import CWE_COMPLIANCE_MAP

# ═════════════════════════════════════════════════════════════════════════════
# FRAMEWORK CONTROL DEFINITIONS
# ═════════════════════════════════════════════════════════════════════════════

FRAMEWORK_CONTROLS: dict[str, dict[str, str]] = {
    # ISO 27001:2022 — 93 controls in Annex A
    "iso27001": {
        "A.5.1": "Policies for information security",
        "A.5.2": "Information security roles and responsibilities",
        "A.5.3": "Segregation of duties",
        "A.5.4": "Management responsibilities",
        "A.5.5": "Contact with authorities",
        "A.5.6": "Contact with special interest groups",
        "A.5.7": "Threat intelligence",
        "A.5.8": "Information security in project management",
        "A.5.9": "Inventory of information and other associated assets",
        "A.5.10": "Acceptable use of information and other associated assets",
        "A.5.11": "Return of assets",
        "A.5.12": "Classification of information",
        "A.5.13": "Labelling of information",
        "A.5.14": "Information transfer",
        "A.5.15": "Access control",
        "A.5.16": "Identity management",
        "A.5.17": "Authentication information",
        "A.5.18": "Access rights",
        "A.5.19": "Information security in supplier relationships",
        "A.5.20": "Addressing information security within supplier agreements",
        "A.5.21": "Managing information security in the ICT supply chain",
        "A.5.22": "Monitoring, review and change management of supplier services",
        "A.5.23": "Information security for use of cloud services",
        "A.5.24": "Information security incident management planning and preparation",
        "A.5.25": "Assessment and decision on information security events",
        "A.5.26": "Response to information security incidents",
        "A.5.27": "Learning from information security incidents",
        "A.5.28": "Collection of evidence",
        "A.5.29": "Information security during disruption",
        "A.5.30": "ICT readiness for business continuity",
        "A.5.31": "Legal, statutory, regulatory and contractual requirements",
        "A.5.32": "Intellectual property rights",
        "A.5.33": "Protection of records",
        "A.5.34": "Privacy and protection of personally identifiable information",
        "A.5.35": "Independent review of information security",
        "A.5.36": "Compliance with policies, rules and standards",
        "A.5.37": "Documented operating procedures",
        "A.8.1": "User endpoint devices",
        "A.8.2": "Privileged access rights",
        "A.8.3": "Information access restriction",
        "A.8.4": "Access to source code",
        "A.8.5": "Secure authentication",
        "A.8.6": "Capacity management",
        "A.8.7": "Protection against malware",
        "A.8.8": "Management of technical vulnerabilities",
        "A.8.9": "Configuration management",
        "A.8.10": "Information deletion",
        "A.8.11": "Data masking",
        "A.8.12": "Data leakage prevention",
        "A.8.13": "Information backup",
        "A.8.14": "Redundancy of information processing facilities",
        "A.8.15": "Logging",
        "A.8.16": "Monitoring activities",
        "A.8.17": "Clock synchronization",
        "A.8.18": "Use of privileged utility programs",
        "A.8.19": "Installation of software on operational systems",
        "A.8.20": "Networks security",
        "A.8.21": "Security of network services",
        "A.8.22": "Segregation of networks",
        "A.8.23": "Web filtering",
        "A.8.24": "Use of cryptography",
        "A.8.25": "Secure development life cycle",
        "A.8.26": "Application security requirements",
        "A.8.27": "Secure system architecture and engineering principles",
        "A.8.28": "Secure coding",
        "A.8.29": "Security testing in development and acceptance",
        "A.8.30": "Outsourced development",
        "A.8.31": "Separation of development, test and production environments",
        "A.8.32": "Change management",
        "A.8.33": "Test information",
        "A.8.34": "Protection of information systems during audit testing",
    },
    # PCI DSS v4.0 — 12 requirements with sub-requirements
    "pci_dss": {
        "1.1": "Install and maintain network security controls",
        "1.2": "Build and maintain a secure network configuration",
        "1.3": "Restrict inbound and outbound traffic",
        "1.4": "Restrict traffic between untrusted networks",
        "2.1": "Secure configurations are applied to all system components",
        "2.2": "Develop and maintain configuration standards",
        "2.3": "Encrypt all non-console administrative access",
        "3.1": "Keep cardholder data storage to a minimum",
        "3.2": "Protect stored cardholder data",
        "3.3": "Mask PAN when displayed",
        "3.4": "Render PAN unreadable anywhere it is stored",
        "3.5": "Keep cryptographic keys secure",
        "4.1": "Use strong cryptography and security protocols",
        "4.2": "Never send sensitive authentication data after authorization",
        "5.1": "Deploy anti-malware software",
        "5.2": "Keep anti-malware software current",
        "6.1": "Identify security vulnerabilities",
        "6.2": "Develop secure software and systems",
        "6.2.4": "Software engineering techniques prevent common vulnerabilities",
        "6.5.1": "Injection flaws are addressed",
        "6.5.2": "Buffer overflows are addressed",
        "6.5.3": "Insecure cryptographic storage is addressed",
        "6.5.4": "Improper error handling is addressed",
        "6.5.5": "Insecure communications are addressed",
        "6.5.6": "Improper access control is addressed",
        "6.5.7": "Cross-site scripting is addressed",
        "6.5.8": "Insecure direct object references are addressed",
        "6.5.9": "CSRF is addressed",
        "7.1": "Limit access to system components",
        "7.2": "Establish an access control system",
        "8.1": "Identify users and authenticate access",
        "8.2": "Identify all users with a unique identifier",
        "8.3": "Strong authentication for users and administrators",
        "9.1": "Restrict physical access to cardholder data",
        "10.1": "Implement audit trails",
        "10.2": "Implement automated audit trails",
        "10.3": "Record audit trail entries",
        "10.5": "Secure audit trails",
        "10.6": "Review logs and security events",
        "11.1": "Test for presence of wireless access points",
        "11.2": "Run internal and external network vulnerability scans",
        "11.3": "Run internal and external penetration tests",
        "12.1": "Maintain an information security policy",
        "12.2": "Implement a risk assessment process",
        "12.3": "Develop, maintain and use policies and procedures",
        "12.4": "Ensure security policies and procedures are reviewed",
        "12.5": "Assign responsibility for information security",
        "12.6": "Implement a formal security awareness program",
        "12.7": "Screen personnel before hiring",
        "12.8": "Maintain policies and procedures for service providers",
        "12.9": "Implement an incident response plan",
    },
    # SOC 2 Trust Services Criteria
    "soc2": {
        "CC1.1": "COSO Principle 1: Integrity and Ethical Values",
        "CC1.2": "COSO Principle 2: Board Independence and Oversight",
        "CC1.3": "COSO Principle 3: Organizational Structure",
        "CC1.4": "COSO Principle 4: Commitment to Competence",
        "CC1.5": "COSO Principle 5: Accountability",
        "CC2.1": "COSO Principle 6: Objectives Setting",
        "CC2.2": "COSO Principle 7: Risk Identification and Analysis",
        "CC2.3": "COSO Principle 8: Fraud Risk Assessment",
        "CC3.1": "COSO Principle 9: Risk Response",
        "CC3.2": "COSO Principle 10: Change Management",
        "CC4.1": "COSO Principle 11: Monitoring Performance",
        "CC4.2": "COSO Principle 12: Deficiency Evaluation",
        "CC5.1": "COSO Principle 13: Control Activities Selection",
        "CC5.2": "COSO Principle 14: Technology Controls",
        "CC5.3": "COSO Principle 15: Policies and Procedures",
        "CC6.1": "Logical and Physical Access Controls",
        "CC6.2": "System Credentials and Authentication",
        "CC6.3": "Role-Based Access and Authorization",
        "CC6.4": "Physical Access Security",
        "CC6.5": "Data Transmission and Data Protection",
        "CC6.6": "External Threats and Vulnerabilities",
        "CC6.7": "Change Management for Infrastructure",
        "CC7.1": "System Monitoring and Anomaly Detection",
        "CC7.2": "Incident Response and Recovery",
        "CC7.3": "Incident Communication and Analysis",
        "CC7.4": "Incident Response Testing",
        "CC8.1": "Change Management Authorization",
        "CC8.2": "Change Testing and Approval",
        "CC9.1": "Risk Mitigation for Third Parties",
        "CC9.2": "Vendor Management",
    },
    # HIPAA Security Rule
    "hipaa": {
        "164.308(a)(1)": "Security Management Process",
        "164.308(a)(2)": "Assigned Security Responsibility",
        "164.308(a)(3)": "Workforce Security",
        "164.308(a)(4)": "Information Access Management",
        "164.308(a)(5)": "Security Awareness and Training",
        "164.308(a)(6)": "Security Incident Procedures",
        "164.308(a)(7)": "Contingency Plan",
        "164.308(a)(8)": "Evaluation",
        "164.310(a)(1)": "Facility Access Controls",
        "164.310(a)(2)": "Workstation Use",
        "164.310(a)(3)": "Workstation Security",
        "164.310(b)": "Device and Media Controls",
        "164.312(a)(1)": "Access Control",
        "164.312(a)(2)": "Audit Controls",
        "164.312(b)": "Integrity Controls",
        "164.312(c)(1)": "Transmission Security",
        "164.312(d)": "Person or Entity Authentication",
        "164.312(e)(1)": "Network Security",
        "164.314(a)": "Business Associate Contracts",
        "164.316(a)": "Policies and Procedures",
        "164.316(b)": "Documentation Requirements",
    },
    # NIST CSF 2.0
    "nist_csf": {
        "GV.OC-01": "Organizational context is understood",
        "GV.OC-02": "Supply chain risk management strategy",
        "GV.OC-03": "Legal and regulatory requirements",
        "GV.OC-04": "Ethics and privacy principles",
        "GV.OC-05": "Risk management objectives",
        "GV.OC-06": "Organizational risk tolerance",
        "GV.OC-07": "Cybersecurity risk decisions",
        "GV.OC-08": "Funding for cybersecurity",
        "GV.OC-09": "Cybersecurity policy",
        "GV.OC-10": "Policy review and update",
        "GV.RM-01": "Risk management strategy",
        "GV.RM-02": "Risk tolerance determination",
        "GV.RM-03": "Risk assessment methodology",
        "GV.RM-04": "Risk assessment execution",
        "GV.RM-05": "Risk response prioritization",
        "GV.RM-06": "Risk monitoring",
        "ID.AM-01": "Asset inventories maintained",
        "ID.AM-02": "Software inventories maintained",
        "ID.AM-03": "Communication flows mapped",
        "ID.AM-04": "External information systems catalogued",
        "ID.AM-05": "Resources prioritized by risk",
        "PR.AC-01": "Identity and access management",
        "PR.AC-02": "Physical access control",
        "PR.AC-03": "Remote access control",
        "PR.AC-04": "Access permissions management",
        "PR.AC-05": "Authentication management",
        "PR.AC-06": "Authorization management",
        "PR.DS-01": "Data-at-rest protection",
        "PR.DS-02": "Data-in-transit protection",
        "PR.DS-03": "Data classification",
        "PR.DS-04": "Data retention",
        "PR.DS-05": "Asset disposal",
        "PR.DS-06": "Backup and recovery",
        "PR.DS-07": "Configuration management",
        "PR.DS-08": "Audit logging",
        "PR.DS-09": "Vulnerability management",
        "PR.DS-10": "Malware protection",
        "DE.CM-01": "Continuous monitoring",
        "DE.CM-02": "Event detection",
        "DE.CM-03": "Security event analysis",
        "DE.CM-04": "Vulnerability detection",
        "DE.CM-05": "Detection processes testing",
        "RS.AN-01": "Incident analysis",
        "RS.AN-02": "Incident categorization",
        "RS.AN-03": "Incident impact analysis",
        "RS.AN-04": "Forensic analysis",
        "RS.AN-05": "Incident notification",
        "RS.MI-01": "Incident containment",
        "RS.MI-02": "Incident mitigation",
        "RS.MI-03": "Incident eradication",
        "RS.MI-04": "Incident recovery",
        "RS.CO-01": "Incident coordination",
        "RS.CO-02": "Incident reporting",
        "RS.CO-03": "Information sharing",
        "RS.CO-04": "Voluntary disclosure",
        "RC.RP-01": "Recovery plan execution",
        "RC.RP-02": "Recovery plan testing",
        "RC.RP-03": "Recovery communications",
        "RC.RP-04": "Recovery improvements",
    },
    # CIS Controls v8
    "cis": {
        "1.1": "Establish and maintain detailed enterprise asset inventory",
        "1.2": "Establish and maintain detailed software inventory",
        "1.3": "Utilize active discovery tools",
        "1.4": "Maintain detailed network architecture diagrams",
        "1.5": "Establish and maintain asset inventory for IoT devices",
        "1.6": "Establish and maintain inventory for OT devices",
        "2.1": "Establish and maintain a secure configuration process",
        "2.2": "Establish and maintain a secure configuration for software",
        "2.3": "Configure automatic session locking",
        "2.4": "Implement and manage a firewall on servers",
        "2.5": "Implement and manage a firewall on end-user devices",
        "3.1": "Establish and maintain a data management process",
        "3.2": "Establish and maintain a data classification process",
        "3.3": "Configure data access control lists",
        "3.4": "Encrypt data on end-user devices",
        "3.5": "Encrypt data on removable media",
        "3.6": "Encrypt data in transit",
        "3.7": "Segment data processing and storage",
        "3.8": "Publish data encryption key to authorized users",
        "3.9": "Rotate encryption keys",
        "4.1": "Establish and maintain a secure configuration process",
        "4.2": "Establish and maintain a secure configuration for network infrastructure",
        "4.3": "Implement and manage a firewall on servers",
        "4.4": "Implement and manage a firewall on end-user devices",
        "4.5": "Implement and manage a firewall on cloud infrastructure",
        "5.1": "Establish and maintain a secure configuration process",
        "5.2": "Configure account management",
        "5.3": "Configure access control lists",
        "5.4": "Require MFA for remote network access",
        "5.5": "Require MFA for administrative access",
        "5.6": "Require MFA for all users",
        "5.7": "Establish and maintain a process for account management",
        "6.1": "Establish and maintain a secure configuration process",
        "6.2": "Configure access control lists",
        "6.3": "Require MFA for remote network access",
        "6.4": "Require MFA for administrative access",
        "6.5": "Require MFA for all users",
        "7.1": "Establish and maintain a vulnerability management process",
        "7.2": "Establish and maintain a vulnerability remediation process",
        "7.3": "Perform automated application patch management",
        "7.4": "Perform automated OS patch management",
        "7.5": "Perform automated security updates",
        "7.6": "Manage security updates",
        "8.1": "Establish and maintain an audit log management process",
        "8.2": "Collect audit logs",
        "8.3": "Ensure adequate audit log storage",
        "8.4": "Standardize time synchronization",
        "8.5": "Collect detailed audit logs",
        "8.6": "Perform audit log review",
        "8.7": "Perform audit log retention",
        "8.8": "Perform audit log protection",
        "8.9": "Perform audit log analysis",
        "9.1": "Establish and maintain an email and web browser security process",
        "9.2": "Ensure web browsers are configured securely",
        "9.3": "Maintain and enforce network URL filtering",
        "9.4": "Ensure email systems are configured securely",
        "9.5": "Block or control access to malicious websites",
        "9.6": "Block or control access to malicious email",
        "10.1": "Establish and maintain a malware protection process",
        "10.2": "Configure malware protection",
        "10.3": "Configure automatic malware signature updates",
        "10.4": "Configure periodic scans",
        "11.1": "Establish and maintain a data recovery process",
        "11.2": "Ensure backup data is protected",
        "11.3": "Ensure backups are performed",
        "11.4": "Ensure backups are tested",
        "11.5": "Ensure backups are isolated",
        "12.1": "Establish and maintain a network monitoring and defense process",
        "12.2": "Deploy a network intrusion detection solution",
        "12.3": "Deploy a network intrusion prevention solution",
        "12.4": "Perform traffic filtering",
        "12.5": "Perform network segmentation",
        "12.6": "Perform network traffic analysis",
        "13.1": "Establish and maintain a security awareness and training process",
        "13.2": "Train workforce on authentication methods",
        "13.3": "Train workforce on data handling",
        "13.4": "Train workforce on phishing",
        "13.5": "Train workforce on social engineering",
        "14.1": "Establish and maintain a service provider management process",
        "14.2": "Ensure service provider access is controlled",
        "14.3": "Ensure service provider contracts include security requirements",
        "14.4": "Ensure service provider security is monitored",
        "15.1": "Establish and maintain a security training process",
        "15.2": "Train workforce on secure coding",
        "15.3": "Train workforce on security testing",
        "16.1": "Establish and maintain a secure application development process",
        "16.2": "Train workforce on secure coding practices",
        "16.3": "Perform code review",
        "16.4": "Perform security testing",
        "16.5": "Perform penetration testing",
        "16.6": "Perform application security testing",
        "17.1": "Establish and maintain a security incident response process",
        "17.2": "Assign incident response roles",
        "17.3": "Define incident response procedures",
        "17.4": "Perform incident response testing",
        "17.5": "Perform incident response improvements",
        "18.1": "Establish and maintain a penetration testing process",
        "18.2": "Perform penetration testing",
        "18.3": "Perform red team exercises",
    },
}

# ═════════════════════════════════════════════════════════════════════════════
# CWE → FRAMEWORK MAPPINGS — imported from db/seeds/compliance_mappings.py
# (101 CWEs across 6 frameworks)
# ═════════════════════════════════════════════════════════════════════════════

CWE_TO_CONTROLS: dict[str, dict[str, list[str]]] = CWE_COMPLIANCE_MAP


class ComplianceService:
    """Service for compliance-related business logic."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def map_findings_to_frameworks(
        self, scan_id: uuid.UUID, frameworks: list[str] | None = None
    ) -> dict[str, Any]:
        """Map all findings from a scan to compliance frameworks.

        Args:
            scan_id: Scan UUID
            frameworks: List of frameworks to map (default: all)

        Returns:
            Mapping summary
        """
        if frameworks is None:
            frameworks = list(FRAMEWORK_CONTROLS.keys())

        result = await self.db.execute(
            select(Finding).where(Finding.scan_id == scan_id)
        )
        findings = list(result.scalars().all())

        mappings_created = 0
        for finding in findings:
            cwe = finding.cwe_id
            if not cwe or cwe not in CWE_TO_CONTROLS:
                continue

            controls = CWE_TO_CONTROLS[cwe]
            for framework in frameworks:
                if framework not in controls:
                    continue
                for control_id in controls.get(framework, []):
                    mapping = ComplianceMapping(
                        finding_id=finding.id,
                        framework=framework,
                        control_id=control_id,
                        control_name=f"{framework.upper()} {control_id}",
                        control_description=FRAMEWORK_CONTROLS.get(framework, {}).get(
                            control_id, ""
                        ),
                        status="fail",
                        is_mapped=True,
                    )
                    self.db.add(mapping)
                    mappings_created += 1

        await self.db.commit()
        return {"mappings_created": mappings_created, "frameworks": frameworks}

    async def get_compliance_score(
        self, scan_id: uuid.UUID, framework: str
    ) -> dict[str, Any]:
        """Calculate compliance score for a framework.

        Args:
            scan_id: Scan UUID
            framework: Framework name

        Returns:
            Compliance score and details
        """
        result = await self.db.execute(
            select(ComplianceMapping)
            .where(ComplianceMapping.framework == framework)
            .where(
                ComplianceMapping.finding_id.in_(
                    select(Finding.id).where(Finding.scan_id == scan_id)
                )
            )
        )
        mappings = list(result.scalars().all())

        total_controls = len(set(m.control_id for m in mappings))
        failed_controls = len(
            set(m.control_id for m in mappings if m.status == "fail")
        )
        passed_controls = total_controls - failed_controls

        score = (passed_controls / total_controls * 100) if total_controls > 0 else 100

        return {
            "framework": framework,
            "score": round(score, 1),
            "total_controls_assessed": total_controls,
            "passed": passed_controls,
            "failed": failed_controls,
            "failed_controls": [
                {"control_id": m.control_id, "control_name": m.control_name}
                for m in mappings
                if m.status == "fail"
            ],
        }

    async def get_framework_gap_analysis(
        self, scan_id: uuid.UUID, framework: str
    ) -> dict[str, Any]:
        """Get detailed gap analysis for a framework.

        Args:
            scan_id: Scan UUID
            framework: Framework name

        Returns:
            Gap analysis report
        """
        result = await self.db.execute(
            select(ComplianceMapping, Finding)
            .join(Finding, ComplianceMapping.finding_id == Finding.id)
            .where(ComplianceMapping.framework == framework)
            .where(Finding.scan_id == scan_id)
        )

        rows = result.all()
        gaps = []

        for mapping, finding in rows:
            if mapping.status == "fail":
                gaps.append(
                    {
                        "control_id": mapping.control_id,
                        "control_name": mapping.control_name,
                        "control_description": mapping.control_description,
                        "finding_id": str(finding.id),
                        "finding_title": finding.title,
                        "severity": finding.severity,
                        "remediation_priority": self._get_priority(finding.severity),
                    }
                )

        return {
            "framework": framework,
            "total_gaps": len(gaps),
            "gaps_by_severity": {
                "critical": len([g for g in gaps if g["severity"] == "critical"]),
                "high": len([g for g in gaps if g["severity"] == "high"]),
                "medium": len([g for g in gaps if g["severity"] == "medium"]),
                "low": len([g for g in gaps if g["severity"] == "low"]),
            },
            "gaps": gaps,
        }

    def _get_priority(self, severity: str) -> str:
        """Get remediation priority based on severity."""
        priority_map = {
            "critical": "immediate",
            "high": "urgent",
            "medium": "standard",
            "low": "backlog",
            "info": "roadmap",
        }
        return priority_map.get(severity, "standard")

    def get_available_frameworks(self) -> list[dict[str, str]]:
        """Get list of available compliance frameworks.

        Returns:
            List of framework definitions
        """
        return [
            {
                "id": "iso27001",
                "name": "ISO 27001:2022",
                "description": "Information Security Management",
                "total_controls": len(FRAMEWORK_CONTROLS.get("iso27001", {})),
            },
            {
                "id": "pci_dss",
                "name": "PCI DSS v4.0",
                "description": "Payment Card Industry Data Security Standard",
                "total_controls": len(FRAMEWORK_CONTROLS.get("pci_dss", {})),
            },
            {
                "id": "soc2",
                "name": "SOC 2",
                "description": "Service Organization Control 2",
                "total_controls": len(FRAMEWORK_CONTROLS.get("soc2", {})),
            },
            {
                "id": "hipaa",
                "name": "HIPAA Security Rule",
                "description": "Health Insurance Portability and Accountability Act",
                "total_controls": len(FRAMEWORK_CONTROLS.get("hipaa", {})),
            },
            {
                "id": "nist_csf",
                "name": "NIST CSF 2.0",
                "description": "NIST Cybersecurity Framework",
                "total_controls": len(FRAMEWORK_CONTROLS.get("nist_csf", {})),
            },
            {
                "id": "cis",
                "name": "CIS Controls v8",
                "description": "Center for Internet Security Controls",
                "total_controls": len(FRAMEWORK_CONTROLS.get("cis", {})),
            },
        ]
