# Security Policy

## Supported Versions

We release security updates and patches for the following versions:

| Version | Status      | Support Until |
|---------|-------------|---------------|
| 1.x     | Supported   | 2027-12-31    |
| 0.x     | Not Supported | 2025-03-31  |

We recommend upgrading to the latest 1.x release to receive all security patches.

## Reporting Security Vulnerabilities

We take security seriously. If you discover a security vulnerability in NETRA, please report it responsibly to us.

### How to Report

Please email security vulnerabilities to: **security@netra.dev**

Alternatively, you may report a private security advisory on GitHub:
1. Go to the NETRA repository
2. Click "Security" tab → "Report a vulnerability"
3. Complete the form with details about the vulnerability

**Please do not file public GitHub issues for security vulnerabilities.**

### What to Include in Your Report

To help us triage and respond quickly, please include:

- A clear description of the vulnerability
- The affected version(s)
- Steps to reproduce (if applicable)
- Potential impact assessment
- Your contact information
- Your name/affiliation (for Hall of Fame attribution, if desired)

## Response Timeline

We aim to follow these timelines for all security reports:

- **Acknowledgment**: Within 48 hours of report receipt
- **Triage & Assessment**: Within 7 days of acknowledgment
- **Fix Development**: Within 30 days for critical vulnerabilities
- **Public Disclosure**: Coordinated with reporter (see Disclosure Policy below)

For issues with extended complexity, we will communicate expected delays within the initial response window.

## Disclosure Policy

We practice **coordinated disclosure**:

1. Reporter submits vulnerability
2. We acknowledge receipt and begin assessment
3. We develop and test a fix
4. We release a patched version
5. We publish a security advisory (typically same day as release)
6. We credit the reporter in our advisory (unless they prefer anonymity)

**Disclosure Window**: We request a 90-day coordinated disclosure window. During this period, we ask that you do not publicly disclose the vulnerability while we work on a fix. After 90 days, we may disclose the vulnerability if no patch is available.

## Scope

### In Scope

Security vulnerabilities in NETRA's codebase, including:
- Authentication and authorization flaws
- SQL injection or similar injection attacks
- Cryptographic weaknesses
- Data exposure or leakage
- Privilege escalation
- Remote code execution
- Dependencies with known CVEs

### Out of Scope

The following are typically out of scope:
- Social engineering attacks
- Phishing
- Physical security issues
- Self-XSS (cross-site scripting in your own browser)
- Missing security headers (unless they introduce material risk)
- Rate limiting bypass for non-critical endpoints
- Issues already public in GitHub issues or discussions

When in doubt, report it anyway. We prefer to review and decline than to miss a genuine vulnerability.

## Safe Harbor

We commit to not pursuing legal action against anyone who:
- Reports a vulnerability in good faith
- Complies with this disclosure policy
- Does not access more data than necessary to confirm the vulnerability
- Does not modify or damage any systems

## Hall of Fame

We recognize and thank security researchers who responsibly disclose vulnerabilities:

- Your name and details will be added here with your permission
- You may request anonymity, a pseudonym, or full attribution
- We will link to your website or social media (if provided)

### Previous Security Reporters

*To be updated with each responsible disclosure*

---

## Questions?

For questions about this security policy, contact us at security@netra.dev.

Thank you for helping keep NETRA secure.
