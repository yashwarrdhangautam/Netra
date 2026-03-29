"""Comprehensive CWE-to-compliance-framework mappings for NETRA.

This module contains mappings from CWE vulnerability types to control IDs
across 6 major compliance frameworks:
- ISO 27001:2022 (93 controls in Annex A)
- PCI DSS v4.0 (12 requirements with sub-requirements)
- SOC 2 (Trust Services Criteria)
- HIPAA Security Rule
- NIST CSF 2.0
- CIS Controls v8 (18 control groups)

Total: 100+ CWE mappings covering OWASP Top 10, cloud misconfigurations,
cryptographic failures, access control issues, and security misconfigurations.
"""

# Comprehensive CWE → Framework Control mappings
CWE_COMPLIANCE_MAP: dict[str, dict[str, list[str]]] = {
    # ═════════════════════════════════════════════════════════════════════════
    # INJECTION FLAWS (15 CWEs)
    # ═════════════════════════════════════════════════════════════════════════
    "CWE-89": {  # SQL Injection
        "iso27001": ["A.8.25", "A.8.28", "A.8.29"],
        "pci_dss": ["6.2.4", "6.5.1", "6.5.9"],
        "soc2": ["CC6.1", "CC7.1", "CC8.1"],
        "hipaa": ["164.312(a)(1)", "164.312(c)(1)"],
        "nist_csf": ["PR.DS-01", "PR.AC-01"],
        "cis": ["16.1", "16.4", "7.3"],
    },
    "CWE-79": {  # Cross-site Scripting (XSS)
        "iso27001": ["A.8.25", "A.8.26", "A.8.28"],
        "pci_dss": ["6.2.4", "6.5.7"],
        "soc2": ["CC6.1", "CC7.1"],
        "hipaa": ["164.312(a)(1)", "164.312(c)(1)"],
        "nist_csf": ["PR.AC-01", "PR.DS-01"],
        "cis": ["16.1", "16.4", "9.2"],
    },
    "CWE-77": {  # Command Injection
        "iso27001": ["A.8.25", "A.8.28"],
        "pci_dss": ["6.2.4", "6.5.1"],
        "soc2": ["CC6.1", "CC8.1"],
        "hipaa": ["164.312(a)(1)"],
        "nist_csf": ["PR.AC-01"],
        "cis": ["16.1", "16.4"],
    },
    "CWE-78": {  # OS Command Injection
        "iso27001": ["A.8.25", "A.8.28"],
        "pci_dss": ["6.2.4", "6.5.1"],
        "soc2": ["CC6.1", "CC8.1"],
        "hipaa": ["164.312(a)(1)"],
        "nist_csf": ["PR.AC-01"],
        "cis": ["16.1", "16.4"],
    },
    "CWE-94": {  # Code Injection
        "iso27001": ["A.8.25", "A.8.28"],
        "pci_dss": ["6.2.4", "6.5.1"],
        "soc2": ["CC6.1", "CC8.1"],
        "hipaa": ["164.312(a)(1)"],
        "nist_csf": ["PR.AC-01"],
        "cis": ["16.1", "16.4"],
    },
    "CWE-917": {  # Expression Language Injection
        "iso27001": ["A.8.25", "A.8.28"],
        "pci_dss": ["6.5.1"],
        "soc2": ["CC6.1"],
        "hipaa": ["164.312(a)(1)"],
        "nist_csf": ["PR.AC-01"],
        "cis": ["16.1"],
    },
    "CWE-611": {  # XML External Entity (XXE)
        "iso27001": ["A.8.25", "A.8.26"],
        "pci_dss": ["6.5.1"],
        "soc2": ["CC6.1"],
        "hipaa": ["164.312(a)(1)"],
        "nist_csf": ["PR.AC-01"],
        "cis": ["16.1", "16.4"],
    },
    "CWE-91": {  # XML Injection
        "iso27001": ["A.8.25", "A.8.28"],
        "pci_dss": ["6.5.1"],
        "soc2": ["CC6.1"],
        "hipaa": ["164.312(a)(1)"],
        "nist_csf": ["PR.AC-01"],
        "cis": ["16.1"],
    },
    "CWE-90": {  # LDAP Injection
        "iso27001": ["A.8.25", "A.8.28"],
        "pci_dss": ["6.5.1"],
        "soc2": ["CC6.1"],
        "hipaa": ["164.312(a)(1)"],
        "nist_csf": ["PR.AC-01"],
        "cis": ["16.1"],
    },
    "CWE-943": {  # NoSQL Injection
        "iso27001": ["A.8.25", "A.8.28"],
        "pci_dss": ["6.5.1"],
        "soc2": ["CC6.1"],
        "hipaa": ["164.312(a)(1)"],
        "nist_csf": ["PR.AC-01"],
        "cis": ["16.1"],
    },
    "CWE-74": {  # Injection (General)
        "iso27001": ["A.8.25", "A.8.28"],
        "pci_dss": ["6.5.1"],
        "soc2": ["CC6.1"],
        "hipaa": ["164.312(a)(1)"],
        "nist_csf": ["PR.AC-01"],
        "cis": ["16.1"],
    },
    "CWE-116": {  # Improper Encoding/Decoding
        "iso27001": ["A.8.25", "A.8.28"],
        "pci_dss": ["6.5.1"],
        "soc2": ["CC6.1"],
        "hipaa": ["164.312(a)(1)"],
        "nist_csf": ["PR.AC-01"],
        "cis": ["16.1"],
    },
    "CWE-838": {  # Inappropriate Encoding for Output Context
        "iso27001": ["A.8.25", "A.8.28"],
        "pci_dss": ["6.5.1"],
        "soc2": ["CC6.1"],
        "hipaa": ["164.312(a)(1)"],
        "nist_csf": ["PR.AC-01"],
        "cis": ["16.1"],
    },
    "CWE-564": {  # SQL Injection (Hibernate)
        "iso27001": ["A.8.25", "A.8.28"],
        "pci_dss": ["6.5.1"],
        "soc2": ["CC6.1"],
        "hipaa": ["164.312(a)(1)"],
        "nist_csf": ["PR.AC-01"],
        "cis": ["16.1"],
    },
    "CWE-1236": {  # CSV Injection
        "iso27001": ["A.8.25", "A.8.28"],
        "pci_dss": ["6.5.1"],
        "soc2": ["CC6.1"],
        "hipaa": ["164.312(a)(1)"],
        "nist_csf": ["PR.AC-01"],
        "cis": ["16.1"],
    },

    # ═════════════════════════════════════════════════════════════════════════
    # AUTHENTICATION & ACCESS CONTROL (20 CWEs)
    # ═════════════════════════════════════════════════════════════════════════
    "CWE-287": {  # Improper Authentication
        "iso27001": ["A.5.17", "A.8.2", "A.8.5"],
        "pci_dss": ["8.1", "8.2", "8.3"],
        "soc2": ["CC6.1", "CC6.2", "CC6.3"],
        "hipaa": ["164.312(d)", "164.308(a)(4)"],
        "nist_csf": ["PR.AC-01", "PR.AC-05"],
        "cis": ["5.4", "5.5", "6.3", "6.4"],
    },
    "CWE-306": {  # Missing Authentication
        "iso27001": ["A.5.17", "A.8.2", "A.8.5"],
        "pci_dss": ["8.1", "8.2"],
        "soc2": ["CC6.1", "CC6.2"],
        "hipaa": ["164.312(d)", "164.308(a)(4)"],
        "nist_csf": ["PR.AC-01", "PR.AC-05"],
        "cis": ["5.4", "5.5", "6.3"],
    },
    "CWE-862": {  # Missing Authorization
        "iso27001": ["A.8.2", "A.8.3", "A.8.4"],
        "pci_dss": ["7.1", "7.2"],
        "soc2": ["CC6.1", "CC6.3"],
        "hipaa": ["164.312(a)(1)", "164.308(a)(4)"],
        "nist_csf": ["PR.AC-01", "PR.AC-04"],
        "cis": ["5.3", "6.2"],
    },
    "CWE-863": {  # Incorrect Authorization
        "iso27001": ["A.8.2", "A.8.3"],
        "pci_dss": ["7.1", "7.2"],
        "soc2": ["CC6.1", "CC6.3"],
        "hipaa": ["164.312(a)(1)"],
        "nist_csf": ["PR.AC-01", "PR.AC-04"],
        "cis": ["5.3", "6.2"],
    },
    "CWE-798": {  # Hardcoded Credentials
        "iso27001": ["A.5.17", "A.8.5", "A.8.4"],
        "pci_dss": ["2.1", "8.2", "3.5"],
        "soc2": ["CC6.1", "CC6.2"],
        "hipaa": ["164.312(a)(1)", "164.308(a)(5)"],
        "nist_csf": ["PR.AC-01", "PR.AC-05"],
        "cis": ["16.1", "5.5"],
    },
    "CWE-521": {  # Weak Password Requirements
        "iso27001": ["A.5.17", "A.8.5"],
        "pci_dss": ["8.2", "8.3"],
        "soc2": ["CC6.2"],
        "hipaa": ["164.312(d)"],
        "nist_csf": ["PR.AC-05"],
        "cis": ["5.5", "6.4"],
    },
    "CWE-620": {  # Unverified Password Change
        "iso27001": ["A.5.17", "A.8.5"],
        "pci_dss": ["8.2"],
        "soc2": ["CC6.2"],
        "hipaa": ["164.312(d)"],
        "nist_csf": ["PR.AC-05"],
        "cis": ["5.5"],
    },
    "CWE-640": {  # Weak Password Recovery
        "iso27001": ["A.5.17", "A.8.5"],
        "pci_dss": ["8.2"],
        "soc2": ["CC6.2"],
        "hipaa": ["164.312(d)"],
        "nist_csf": ["PR.AC-05"],
        "cis": ["5.5"],
    },
    "CWE-384": {  # Session Fixation
        "iso27001": ["A.8.5", "A.8.25"],
        "pci_dss": ["6.5.9"],
        "soc2": ["CC6.2"],
        "hipaa": ["164.312(d)"],
        "nist_csf": ["PR.AC-05"],
        "cis": ["16.1"],
    },
    "CWE-613": {  # Insufficient Session Expiration
        "iso27001": ["A.8.5"],
        "pci_dss": ["8.1"],
        "soc2": ["CC6.2"],
        "hipaa": ["164.312(d)"],
        "nist_csf": ["PR.AC-05"],
        "cis": ["5.5"],
    },
    "CWE-614": {  # Sensitive Cookie without Secure
        "iso27001": ["A.8.5", "A.8.24"],
        "pci_dss": ["6.5.9"],
        "soc2": ["CC6.2"],
        "hipaa": ["164.312(d)"],
        "nist_csf": ["PR.AC-05"],
        "cis": ["5.5"],
    },
    "CWE-1004": {  # Sensitive Cookie without HttpOnly
        "iso27001": ["A.8.5"],
        "pci_dss": ["6.5.9"],
        "soc2": ["CC6.2"],
        "hipaa": ["164.312(d)"],
        "nist_csf": ["PR.AC-05"],
        "cis": ["5.5"],
    },
    "CWE-308": {  # Single-Factor Authentication
        "iso27001": ["A.5.17", "A.8.5"],
        "pci_dss": ["8.3"],
        "soc2": ["CC6.2"],
        "hipaa": ["164.312(d)"],
        "nist_csf": ["PR.AC-05"],
        "cis": ["5.5"],
    },
    "CWE-307": {  # Improper Restriction of Auth Attempts
        "iso27001": ["A.5.17", "A.8.5"],
        "pci_dss": ["8.2"],
        "soc2": ["CC6.2"],
        "hipaa": ["164.312(d)"],
        "nist_csf": ["PR.AC-05"],
        "cis": ["5.5"],
    },
    "CWE-304": {  # Missing Critical Step in Auth
        "iso27001": ["A.5.17", "A.8.5"],
        "pci_dss": ["8.2"],
        "soc2": ["CC6.2"],
        "hipaa": ["164.312(d)"],
        "nist_csf": ["PR.AC-05"],
        "cis": ["5.5"],
    },
    "CWE-522": {  # Insufficiently Protected Credentials
        "iso27001": ["A.5.17", "A.8.24"],
        "pci_dss": ["3.5", "8.2"],
        "soc2": ["CC6.2"],
        "hipaa": ["164.312(a)(1)"],
        "nist_csf": ["PR.AC-05"],
        "cis": ["5.5"],
    },
    "CWE-256": {  # Plaintext Storage of Password
        "iso27001": ["A.5.17", "A.8.24"],
        "pci_dss": ["3.5", "8.2"],
        "soc2": ["CC6.2"],
        "hipaa": ["164.312(a)(1)"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["5.5"],
    },
    "CWE-257": {  # Storing Passwords in Recoverable Format
        "iso27001": ["A.5.17", "A.8.24"],
        "pci_dss": ["3.5", "8.2"],
        "soc2": ["CC6.2"],
        "hipaa": ["164.312(a)(1)"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["5.5"],
    },
    "CWE-269": {  # Improper Privilege Management
        "iso27001": ["A.8.2", "A.8.3"],
        "pci_dss": ["7.1", "7.2"],
        "soc2": ["CC6.1", "CC6.3"],
        "hipaa": ["164.308(a)(4)"],
        "nist_csf": ["PR.AC-04"],
        "cis": ["5.3", "6.2"],
    },
    "CWE-250": {  # Execution with Unnecessary Privileges
        "iso27001": ["A.8.2", "A.8.3"],
        "pci_dss": ["7.1", "7.2"],
        "soc2": ["CC6.1", "CC6.3"],
        "hipaa": ["164.308(a)(4)"],
        "nist_csf": ["PR.AC-04"],
        "cis": ["5.3", "6.2"],
    },

    # ═════════════════════════════════════════════════════════════════════════
    # DATA EXPOSURE (15 CWEs)
    # ═════════════════════════════════════════════════════════════════════════
    "CWE-200": {  # Information Exposure
        "iso27001": ["A.8.10", "A.8.11", "A.8.12"],
        "pci_dss": ["3.4", "6.5.3"],
        "soc2": ["CC6.5"],
        "hipaa": ["164.312(e)(1)", "164.312(c)(1)"],
        "nist_csf": ["PR.DS-01", "PR.DS-02", "PR.DS-03"],
        "cis": ["3.1", "3.2", "3.3"],
    },
    "CWE-209": {  # Information Exposure Through Error Message
        "iso27001": ["A.8.25", "A.8.26"],
        "pci_dss": ["6.5.4"],
        "soc2": ["CC6.1"],
        "hipaa": ["164.312(c)(1)"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["16.4"],
    },
    "CWE-532": {  # Information Exposure Through Log Files
        "iso27001": ["A.8.15", "A.8.16"],
        "pci_dss": ["10.5", "10.6"],
        "soc2": ["CC7.1"],
        "hipaa": ["164.312(b)"],
        "nist_csf": ["PR.DS-08", "DE.CM-01"],
        "cis": ["8.1", "8.5", "8.8"],
    },
    "CWE-312": {  # Cleartext Storage of Sensitive Information
        "iso27001": ["A.8.24", "A.8.11"],
        "pci_dss": ["3.4", "3.5"],
        "soc2": ["CC6.5"],
        "hipaa": ["164.312(c)(1)"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["3.4"],
    },
    "CWE-319": {  # Cleartext Transmission of Sensitive Information
        "iso27001": ["A.8.24"],
        "pci_dss": ["4.1"],
        "soc2": ["CC6.5"],
        "hipaa": ["164.312(e)(1)"],
        "nist_csf": ["PR.DS-02"],
        "cis": ["3.6"],
    },
    "CWE-359": {  # Privacy Violation / Exposure of Personal Data
        "iso27001": ["A.5.34", "A.8.12"],
        "pci_dss": ["3.4"],
        "soc2": ["CC6.5"],
        "hipaa": ["164.312(c)(1)", "164.514(d)"],
        "nist_csf": ["PR.DS-03"],
        "cis": ["3.2", "3.3"],
    },
    "CWE-538": {  # File/Directory Information Exposure
        "iso27001": ["A.8.10", "A.8.11"],
        "pci_dss": ["3.4"],
        "soc2": ["CC6.5"],
        "hipaa": ["164.312(c)(1)"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["3.1"],
    },
    "CWE-215": {  # Insertion of Sensitive Info into Debug Code
        "iso27001": ["A.8.10", "A.8.15"],
        "pci_dss": ["6.5.3"],
        "soc2": ["CC6.5"],
        "hipaa": ["164.312(c)(1)"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["8.5"],
    },
    "CWE-311": {  # Missing Encryption of Sensitive Data
        "iso27001": ["A.8.24", "A.8.12"],
        "pci_dss": ["3.4", "4.1"],
        "soc2": ["CC6.5"],
        "hipaa": ["164.312(c)(1)", "164.312(e)(1)"],
        "nist_csf": ["PR.DS-01", "PR.DS-02"],
        "cis": ["3.4", "3.6"],
    },
    "CWE-316": {  # Cleartext Storage in Memory
        "iso27001": ["A.8.24"],
        "pci_dss": ["3.5"],
        "soc2": ["CC6.5"],
        "hipaa": ["164.312(c)(1)"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["3.4"],
    },
    "CWE-317": {  # Cleartext Storage in GUI
        "iso27001": ["A.8.24"],
        "pci_dss": ["3.5"],
        "soc2": ["CC6.5"],
        "hipaa": ["164.312(c)(1)"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["3.4"],
    },
    "CWE-318": {  # Cleartext Storage in Executable
        "iso27001": ["A.8.24"],
        "pci_dss": ["3.5"],
        "soc2": ["CC6.5"],
        "hipaa": ["164.312(c)(1)"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["3.4"],
    },
    "CWE-526": {  # Environment Variable Information Exposure
        "iso27001": ["A.8.10", "A.8.11"],
        "pci_dss": ["3.5"],
        "soc2": ["CC6.5"],
        "hipaa": ["164.312(c)(1)"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["3.4"],
    },
    "CWE-497": {  # Exposure of System Data to Unauthorized Control Sphere
        "iso27001": ["A.8.10", "A.8.11"],
        "pci_dss": ["3.4"],
        "soc2": ["CC6.5"],
        "hipaa": ["164.312(c)(1)"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["3.1"],
    },
    "CWE-598": {  # Use of GET Request with Sensitive Query Strings
        "iso27001": ["A.8.24"],
        "pci_dss": ["4.1"],
        "soc2": ["CC6.5"],
        "hipaa": ["164.312(e)(1)"],
        "nist_csf": ["PR.DS-02"],
        "cis": ["3.6"],
    },

    # ═════════════════════════════════════════════════════════════════════════
    # CRYPTOGRAPHIC FAILURES (10 CWEs)
    # ═════════════════════════════════════════════════════════════════════════
    "CWE-327": {  # Use of Broken Cryptography
        "iso27001": ["A.8.24"],
        "pci_dss": ["3.4", "3.5", "4.1"],
        "soc2": ["CC6.5"],
        "hipaa": ["164.312(c)(1)"],
        "nist_csf": ["PR.DS-01", "PR.DS-02"],
        "cis": ["3.4", "3.6", "3.9"],
    },
    "CWE-328": {  # Reversible One-Way Hash
        "iso27001": ["A.8.24"],
        "pci_dss": ["3.5"],
        "soc2": ["CC6.5"],
        "hipaa": ["164.312(c)(1)"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["3.4"],
    },
    "CWE-330": {  # Insufficient Randomness
        "iso27001": ["A.8.24"],
        "pci_dss": ["3.5"],
        "soc2": ["CC6.5"],
        "hipaa": ["164.312(c)(1)"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["3.4"],
    },
    "CWE-331": {  # Insufficient Entropy
        "iso27001": ["A.8.24"],
        "pci_dss": ["3.5"],
        "soc2": ["CC6.5"],
        "hipaa": ["164.312(c)(1)"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["3.4"],
    },
    "CWE-326": {  # Inadequate Encryption Strength
        "iso27001": ["A.8.24"],
        "pci_dss": ["3.4", "4.1"],
        "soc2": ["CC6.5"],
        "hipaa": ["164.312(c)(1)"],
        "nist_csf": ["PR.DS-01", "PR.DS-02"],
        "cis": ["3.4", "3.6"],
    },
    "CWE-295": {  # Improper Certificate Validation
        "iso27001": ["A.8.24"],
        "pci_dss": ["4.1"],
        "soc2": ["CC6.5"],
        "hipaa": ["164.312(e)(1)"],
        "nist_csf": ["PR.DS-02"],
        "cis": ["3.6"],
    },
    "CWE-297": {  # Improper Validation of Host-Specific Certificate
        "iso27001": ["A.8.24"],
        "pci_dss": ["4.1"],
        "soc2": ["CC6.5"],
        "hipaa": ["164.312(e)(1)"],
        "nist_csf": ["PR.DS-02"],
        "cis": ["3.6"],
    },
    "CWE-338": {  # Use of Cryptographically Weak PRNG
        "iso27001": ["A.8.24"],
        "pci_dss": ["3.5"],
        "soc2": ["CC6.5"],
        "hipaa": ["164.312(c)(1)"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["3.4"],
    },
    "CWE-347": {  # Improper Verification of Cryptographic Signature
        "iso27001": ["A.8.24"],
        "pci_dss": ["3.5"],
        "soc2": ["CC6.5"],
        "hipaa": ["164.312(c)(1)"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["3.4"],
    },
    "CWE-916": {  # Use of Password Hash with Insufficient Computational Effort
        "iso27001": ["A.8.24"],
        "pci_dss": ["3.5"],
        "soc2": ["CC6.5"],
        "hipaa": ["164.312(c)(1)"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["3.4"],
    },

    # ═════════════════════════════════════════════════════════════════════════
    # INPUT VALIDATION (15 CWEs)
    # ═════════════════════════════════════════════════════════════════════════
    "CWE-20": {  # Improper Input Validation
        "iso27001": ["A.8.25", "A.8.28"],
        "pci_dss": ["6.5.1"],
        "soc2": ["CC6.1"],
        "hipaa": ["164.312(a)(1)"],
        "nist_csf": ["PR.AC-01"],
        "cis": ["16.1"],
    },
    "CWE-22": {  # Path Traversal
        "iso27001": ["A.8.25", "A.8.26"],
        "pci_dss": ["6.5.1", "6.5.8"],
        "soc2": ["CC6.1"],
        "hipaa": ["164.312(a)(1)"],
        "nist_csf": ["PR.AC-01"],
        "cis": ["16.1", "16.4"],
    },
    "CWE-434": {  # Unrestricted File Upload
        "iso27001": ["A.8.25", "A.8.26"],
        "pci_dss": ["6.5.1"],
        "soc2": ["CC6.1"],
        "hipaa": ["164.312(a)(1)"],
        "nist_csf": ["PR.AC-01"],
        "cis": ["16.1", "16.4"],
    },
    "CWE-352": {  # Cross-Site Request Forgery (CSRF)
        "iso27001": ["A.8.25", "A.8.26"],
        "pci_dss": ["6.5.9"],
        "soc2": ["CC6.1"],
        "hipaa": ["164.312(a)(1)"],
        "nist_csf": ["PR.AC-01"],
        "cis": ["16.1", "16.4"],
    },
    "CWE-918": {  # Server-Side Request Forgery (SSRF)
        "iso27001": ["A.8.25", "A.8.28"],
        "pci_dss": ["6.2.4"],
        "soc2": ["CC6.1"],
        "hipaa": ["164.312(a)(1)"],
        "nist_csf": ["PR.AC-01"],
        "cis": ["16.1", "4.5"],
    },
    "CWE-601": {  # Open Redirect
        "iso27001": ["A.8.25", "A.8.26"],
        "pci_dss": ["6.5.9"],
        "soc2": ["CC6.1"],
        "hipaa": ["164.312(a)(1)"],
        "nist_csf": ["PR.AC-01"],
        "cis": ["16.1"],
    },
    "CWE-502": {  # Deserialization of Untrusted Data
        "iso27001": ["A.8.25", "A.8.28"],
        "pci_dss": ["6.2.4"],
        "soc2": ["CC6.1"],
        "hipaa": ["164.312(a)(1)"],
        "nist_csf": ["PR.AC-01"],
        "cis": ["16.1", "16.4"],
    },
    "CWE-1321": {  # Prototype Pollution
        "iso27001": ["A.8.25", "A.8.28"],
        "pci_dss": ["6.2.4"],
        "soc2": ["CC6.1"],
        "hipaa": ["164.312(a)(1)"],
        "nist_csf": ["PR.AC-01"],
        "cis": ["16.1"],
    },
    "CWE-129": {  # Improper Validation of Array Index
        "iso27001": ["A.8.25", "A.8.28"],
        "pci_dss": ["6.5.2"],
        "soc2": ["CC6.1"],
        "hipaa": ["164.312(a)(1)"],
        "nist_csf": ["PR.AC-01"],
        "cis": ["16.1"],
    },
    "CWE-120": {  # Buffer Overflow (Classic)
        "iso27001": ["A.8.25", "A.8.27", "A.8.28"],
        "pci_dss": ["6.5.2"],
        "soc2": ["CC6.1"],
        "hipaa": ["164.312(a)(1)"],
        "nist_csf": ["PR.AC-01"],
        "cis": ["16.1", "16.4"],
    },
    "CWE-190": {  # Integer Overflow
        "iso27001": ["A.8.25", "A.8.28"],
        "pci_dss": ["6.5.2"],
        "soc2": ["CC6.1"],
        "hipaa": ["164.312(a)(1)"],
        "nist_csf": ["PR.AC-01"],
        "cis": ["16.1"],
    },
    "CWE-400": {  # Uncontrolled Resource Consumption (DoS)
        "iso27001": ["A.8.6", "A.8.14"],
        "pci_dss": ["6.5.1"],
        "soc2": ["CC7.1"],
        "hipaa": ["164.308(a)(7)"],
        "nist_csf": ["PR.DS-06", "DE.CM-01"],
        "cis": ["11.1", "11.3"],
    },
    "CWE-770": {  # Allocation Without Limits
        "iso27001": ["A.8.6"],
        "pci_dss": ["6.5.1"],
        "soc2": ["CC7.1"],
        "hipaa": ["164.308(a)(7)"],
        "nist_csf": ["PR.DS-06"],
        "cis": ["11.1"],
    },
    "CWE-776": {  # XML Recursive Entity Reference
        "iso27001": ["A.8.25", "A.8.28"],
        "pci_dss": ["6.5.1"],
        "soc2": ["CC6.1"],
        "hipaa": ["164.312(a)(1)"],
        "nist_csf": ["PR.AC-01"],
        "cis": ["16.1"],
    },
    "CWE-112": {  # Missing XML Validation
        "iso27001": ["A.8.25", "A.8.28"],
        "pci_dss": ["6.5.1"],
        "soc2": ["CC6.1"],
        "hipaa": ["164.312(a)(1)"],
        "nist_csf": ["PR.AC-01"],
        "cis": ["16.1"],
    },

    # ═════════════════════════════════════════════════════════════════════════
    # CONFIGURATION & MISCONFIGURATION (15 CWEs)
    # ═════════════════════════════════════════════════════════════════════════
    "CWE-16": {  # Configuration
        "iso27001": ["A.8.9"],
        "pci_dss": ["2.1", "2.2"],
        "soc2": ["CC5.2"],
        "hipaa": ["164.308(a)(5)"],
        "nist_csf": ["PR.DS-07"],
        "cis": ["2.1", "4.1"],
    },
    "CWE-2": {  # Environment (7PK)
        "iso27001": ["A.8.9"],
        "pci_dss": ["2.1"],
        "soc2": ["CC5.2"],
        "hipaa": ["164.308(a)(5)"],
        "nist_csf": ["PR.DS-07"],
        "cis": ["2.1"],
    },
    "CWE-693": {  # Protection Mechanism Failure
        "iso27001": ["A.8.9"],
        "pci_dss": ["2.1"],
        "soc2": ["CC5.2"],
        "hipaa": ["164.308(a)(5)"],
        "nist_csf": ["PR.DS-07"],
        "cis": ["2.1"],
    },
    "CWE-1188": {  # Insecure Default Initialization
        "iso27001": ["A.8.9"],
        "pci_dss": ["2.1"],
        "soc2": ["CC5.2"],
        "hipaa": ["164.308(a)(5)"],
        "nist_csf": ["PR.DS-07"],
        "cis": ["2.1"],
    },
    "CWE-665": {  # Improper Initialization
        "iso27001": ["A.8.9"],
        "pci_dss": ["2.1"],
        "soc2": ["CC5.2"],
        "hipaa": ["164.308(a)(5)"],
        "nist_csf": ["PR.DS-07"],
        "cis": ["2.1"],
    },
    "CWE-668": {  # Exposure of Resource to Wrong Sphere
        "iso27001": ["A.8.2", "A.8.3"],
        "pci_dss": ["7.1", "7.2"],
        "soc2": ["CC6.1", "CC6.3"],
        "hipaa": ["164.312(a)(1)"],
        "nist_csf": ["PR.AC-01"],
        "cis": ["5.3", "6.2"],
    },
    "CWE-732": {  # Incorrect Permission Assignment
        "iso27001": ["A.8.2", "A.8.3"],
        "pci_dss": ["7.1", "7.2"],
        "soc2": ["CC6.1", "CC6.3"],
        "hipaa": ["164.312(a)(1)", "164.514(d)"],
        "nist_csf": ["PR.AC-01", "PR.AC-04"],
        "cis": ["5.3", "6.2"],
    },
    "CWE-276": {  # Incorrect Default Permissions
        "iso27001": ["A.8.2", "A.8.3"],
        "pci_dss": ["7.1", "7.2"],
        "soc2": ["CC6.1", "CC6.3"],
        "hipaa": ["164.312(a)(1)"],
        "nist_csf": ["PR.AC-01"],
        "cis": ["5.3", "6.2"],
    },
    "CWE-829": {  # Inclusion of Functionality from Untrusted Sphere
        "iso27001": ["A.8.25", "A.8.30"],
        "pci_dss": ["6.2.4"],
        "soc2": ["CC6.1"],
        "hipaa": ["164.308(a)(5)"],
        "nist_csf": ["PR.AC-01"],
        "cis": ["16.1"],
    },
    "CWE-494": {  # Download Without Integrity Check
        "iso27001": ["A.8.25", "A.8.30"],
        "pci_dss": ["6.2.4"],
        "soc2": ["CC6.1"],
        "hipaa": ["164.308(a)(5)"],
        "nist_csf": ["PR.AC-01"],
        "cis": ["16.1"],
    },
    "CWE-942": {  # Permissive CORS Policy
        "iso27001": ["A.8.25", "A.8.26"],
        "pci_dss": ["6.5.9"],
        "soc2": ["CC6.1"],
        "hipaa": ["164.312(a)(1)"],
        "nist_csf": ["PR.AC-01"],
        "cis": ["16.1"],
    },
    "CWE-1275": {  # Sensitive Cookie with Improper SameSite
        "iso27001": ["A.8.5"],
        "pci_dss": ["6.5.9"],
        "soc2": ["CC6.2"],
        "hipaa": ["164.312(d)"],
        "nist_csf": ["PR.AC-05"],
        "cis": ["5.5"],
    },
    "CWE-346": {  # Origin Validation Error
        "iso27001": ["A.8.25", "A.8.26"],
        "pci_dss": ["6.5.9"],
        "soc2": ["CC6.1"],
        "hipaa": ["164.312(a)(1)"],
        "nist_csf": ["PR.AC-01"],
        "cis": ["16.1"],
    },
    "CWE-610": {  # Externally Controlled Reference
        "iso27001": ["A.8.25", "A.8.26"],
        "pci_dss": ["6.5.1"],
        "soc2": ["CC6.1"],
        "hipaa": ["164.312(a)(1)"],
        "nist_csf": ["PR.AC-01"],
        "cis": ["16.1"],
    },
    "CWE-915": {  # Improperly Controlled Modification of Dynamically-Determined Object Attributes
        "iso27001": ["A.8.25", "A.8.28"],
        "pci_dss": ["6.5.1"],
        "soc2": ["CC6.1"],
        "hipaa": ["164.312(a)(1)"],
        "nist_csf": ["PR.AC-01"],
        "cis": ["16.1"],
    },

    # ═════════════════════════════════════════════════════════════════════════
    # SUPPLY CHAIN & DEPENDENCIES (10 CWEs)
    # ═════════════════════════════════════════════════════════════════════════
    "CWE-937": {  # Using Components with Known Vulnerabilities
        "iso27001": ["A.8.25", "A.8.8"],
        "pci_dss": ["6.2.4", "6.5.1"],
        "soc2": ["CC6.1", "CC7.1"],
        "hipaa": ["164.308(a)(5)"],
        "nist_csf": ["PR.DS-09"],
        "cis": ["7.1", "7.3"],
    },
    "CWE-1104": {  # Use of Unmaintained Third-Party Components
        "iso27001": ["A.8.25", "A.8.8"],
        "pci_dss": ["6.2.4"],
        "soc2": ["CC6.1"],
        "hipaa": ["164.308(a)(5)"],
        "nist_csf": ["PR.DS-09"],
        "cis": ["7.1"],
    },
    "CWE-426": {  # Untrusted Search Path
        "iso27001": ["A.8.9"],
        "pci_dss": ["2.1"],
        "soc2": ["CC5.2"],
        "hipaa": ["164.308(a)(5)"],
        "nist_csf": ["PR.DS-07"],
        "cis": ["2.1"],
    },
    "CWE-427": {  # Uncontrolled Search Path
        "iso27001": ["A.8.9"],
        "pci_dss": ["2.1"],
        "soc2": ["CC5.2"],
        "hipaa": ["164.308(a)(5)"],
        "nist_csf": ["PR.DS-07"],
        "cis": ["2.1"],
    },
    "CWE-1035": {  # Vulnerable Third-Party Component
        "iso27001": ["A.8.25", "A.8.8"],
        "pci_dss": ["6.2.4"],
        "soc2": ["CC6.1"],
        "hipaa": ["164.308(a)(5)"],
        "nist_csf": ["PR.DS-09"],
        "cis": ["7.1"],
    },
    "CWE-353": {  # Missing Support for Integrity Check
        "iso27001": ["A.8.24"],
        "pci_dss": ["3.5"],
        "soc2": ["CC6.5"],
        "hipaa": ["164.312(c)(1)"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["3.4"],
    },
    "CWE-345": {  # Insufficient Verification of Data Authenticity
        "iso27001": ["A.8.24"],
        "pci_dss": ["3.5"],
        "soc2": ["CC6.5"],
        "hipaa": ["164.312(c)(1)"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["3.4"],
    },
    "CWE-1357": {  # Reliance on Insufficiently Trustworthy Component
        "iso27001": ["A.8.25", "A.8.30"],
        "pci_dss": ["6.2.4"],
        "soc2": ["CC6.1"],
        "hipaa": ["164.308(a)(5)"],
        "nist_csf": ["PR.AC-01"],
        "cis": ["16.1"],
    },
    "CWE-506": {  # Embedded Malicious Code
        "iso27001": ["A.8.25", "A.8.30"],
        "pci_dss": ["6.2.4"],
        "soc2": ["CC6.1"],
        "hipaa": ["164.308(a)(5)"],
        "nist_csf": ["PR.AC-01"],
        "cis": ["16.1"],
    },
    "CWE-511": {  # Logic/Time Bomb
        "iso27001": ["A.8.25", "A.8.30"],
        "pci_dss": ["6.2.4"],
        "soc2": ["CC6.1"],
        "hipaa": ["164.308(a)(5)"],
        "nist_csf": ["PR.AC-01"],
        "cis": ["16.1"],
    },
}


def get_cwe_mappings(cwe_id: str) -> dict[str, list[str]]:
    """Get compliance framework mappings for a CWE.

    Args:
        cwe_id: CWE identifier (e.g., "CWE-89")

    Returns:
        Dictionary mapping framework names to lists of control IDs
    """
    return CWE_COMPLIANCE_MAP.get(cwe_id, {})


def get_all_mapped_cwes() -> list[str]:
    """Get list of all CWE IDs with compliance mappings.

    Returns:
        List of CWE identifiers
    """
    return list(CWE_COMPLIANCE_MAP.keys())


def get_frameworks_for_cwe(cwe_id: str) -> list[str]:
    """Get list of frameworks that have mappings for a CWE.

    Args:
        cwe_id: CWE identifier

    Returns:
        List of framework names
    """
    mappings = CWE_COMPLIANCE_MAP.get(cwe_id, {})
    return list(mappings.keys())
