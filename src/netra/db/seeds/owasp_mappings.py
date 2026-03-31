"""Seed OWASP mappings for compliance."""


def get_owasp_top_10_2021() -> list[dict]:
    """Get OWASP Top 10 2021 mappings.

    Returns:
        List of OWASP Top 10 categories with descriptions
    """
    return [
        {
            "id": "A01:2021",
            "name": "Broken Access Control",
            "description": "Restrictions on what authenticated users are allowed "
                          "to do are often not properly enforced.",
        },
        {
            "id": "A02:2021",
            "name": "Cryptographic Failures",
            "description": "Failures related to cryptography which often lead to "
                          "exposure of sensitive data.",
        },
        {
            "id": "A03:2021",
            "name": "Injection",
            "description": "SQL, NoSQL, OS, and LDAP injection vulnerabilities "
                          "occur when untrusted data is sent to an interpreter.",
        },
        {
            "id": "A04:2021",
            "name": "Insecure Design",
            "description": "Missing or ineffective control design related to "
                          "specific threats.",
        },
        {
            "id": "A05:2021",
            "name": "Security Misconfiguration",
            "description": "Missing appropriate security hardening or improperly "
                          "configured permissions.",
        },
        {
            "id": "A06:2021",
            "name": "Vulnerable and Outdated Components",
            "description": "Using components with known vulnerabilities that may "
                          "be unsupported.",
        },
        {
            "id": "A07:2021",
            "name": "Identification and Authentication Failures",
            "description": "Confirmation of the user's identity, authentication, "
                          "and session management are not implemented correctly.",
        },
        {
            "id": "A08:2021",
            "name": "Software and Data Integrity Failures",
            "description": "Code and infrastructure that does not protect against "
                          "integrity violations.",
        },
        {
            "id": "A09:2021",
            "name": "Security Logging and Monitoring Failures",
            "description": "Insufficient logging, detection, monitoring, and "
                          "active response.",
        },
        {
            "id": "A10:2021",
            "name": "Server-Side Request Forgery (SSRF)",
            "description": "Web applications fetching remote resources without "
                          "validating user-supplied URLs.",
        },
    ]
