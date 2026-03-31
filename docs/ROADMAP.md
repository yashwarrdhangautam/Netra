# NETRA Roadmap

This document outlines the planned development roadmap for NETRA, including completed milestones, upcoming features, and long-term vision.

---

## Vision

**NETRA** aims to become the de facto standard for automated security orchestration, combining the breadth of multiple security tools with AI-powered validation and compliance automation.

**Mission:** Reduce the time from vulnerability discovery to remediation by 10x through intelligent orchestration, AI validation, and automated reporting.

---

## Version History

| Version | Release Date | Key Features |
|---------|--------------|--------------|
| 0.1.0 | March 2025 | Initial release, 10 tool wrappers |
| 0.5.0 | August 2025 | AI consensus engine, dashboard alpha |
| 0.9.0 | January 2026 | MCP server, compliance mapping |
| 1.0.0 | March 2026 | Full release, 18 tools, React dashboard |

---

## v1.x (Current) - ✅ Complete

### v1.0.0 - March 2026 ✅

**Scanning Engine**
- ✅ 18 security tool wrappers
- ✅ 6-phase pipeline orchestration
- ✅ Checkpoint-based resumption
- ✅ 9 scan profiles (quick, standard, deep, cloud, api_only, container, ai_llm, mobile, custom)

**AI Brain**
- ✅ 4-persona consensus engine (Attacker, Defender, Analyst, Skeptic)
- ✅ Anthropic Claude integration (Sonnet 4, Opus 4.5)
- ✅ Ollama local LLM support (Llama 3.1, Mistral, Qwen)
- ✅ Attack chain discovery via DFS graph analysis
- ✅ False positive reduction (~60%)

**Dashboard**
- ✅ React 18 + TypeScript frontend
- ✅ 10 pages (Dashboard, Scans, Findings, Reports, Compliance, Settings, etc.)
- ✅ Real-time WebSocket updates
- ✅ Attack chain visualization (react-force-graph-2d)
- ✅ Dark mode with shadcn/ui components

**Reports**
- ✅ 13 report formats (Executive PDF, Technical PDF, HTML, Word, Excel, SARIF, etc.)
- ✅ Compliance audit reports (6 frameworks)
- ✅ Delta/comparison reports
- ✅ Evidence ZIP with chain of custody

**Compliance**
- ✅ CIS Benchmarks (Linux, Docker, Kubernetes)
- ✅ NIST Cybersecurity Framework
- ✅ PCI-DSS v4.0
- ✅ HIPAA §164.312
- ✅ SOC2 Type II
- ✅ ISO 27001
- ✅ 101 CWE cross-reference mappings

**Security**
- ✅ JWT authentication with refresh tokens
- ✅ TOTP-based MFA with backup codes
- ✅ RBAC (Admin/Analyst/Viewer/Client)
- ✅ CSRF protection, SSRF detection
- ✅ Rate limiting (SlowAPI)
- ✅ Content Security Policy headers

**Integrations**
- ✅ MCP server for Claude Desktop (18 tools exposed)
- ✅ GitHub Actions CI/CD
- ✅ SARIF upload to GitHub Security
- ✅ DefectDojo integration (import)
- ✅ Slack webhooks
- ✅ Email notifications

**Infrastructure**
- ✅ Docker Compose (production-ready)
- ✅ PostgreSQL + SQLite support
- ✅ Celery + Redis task queue
- ✅ Alembic migrations
- ✅ Multi-stage Docker builds

---

## v2.0 (Q2 2026) - 🚧 In Progress

**Target Release:** June 2026

### REST API Enhancements

| Feature | Status | Priority |
|---------|--------|----------|
| OAuth 2.0 authentication | 📋 Planned | High |
| API key management | 📋 Planned | High |
| Rate limiting per API key | 📋 Planned | Medium |
| API documentation (OpenAPI 3.0) | 📋 Planned | High |
| SDK generation (Python, JavaScript, Go) | 📋 Planned | Medium |

### Scheduled Scans

| Feature | Status | Priority |
|---------|--------|----------|
| Cron-based scheduling | 📋 Planned | High |
| Recurring scan configurations | 📋 Planned | High |
| Email notifications on completion | 📋 Planned | Medium |
| Slack notifications on findings | 📋 Planned | Medium |
| Scan schedule dashboard | 📋 Planned | Medium |

### Plugin System

| Feature | Status | Priority |
|---------|--------|----------|
| Custom scanner plugin API | 📋 Planned | High |
| Custom report format plugins | 📋 Planned | High |
| Plugin marketplace | 📋 Planned | Low |
| Plugin sandboxing | 📋 Planned | Medium |
| Example plugins (5+) | 📋 Planned | Medium |

### Enhanced Integrations

| Feature | Status | Priority |
|---------|--------|----------|
| DefectDojo bidirectional sync | 📋 Planned | High |
| Jira ticket auto-creation | 📋 Planned | High |
| Jira status sync (remediation tracking) | 📋 Planned | Medium |
| ServiceNow integration | 📋 Planned | Medium |
| Slack native app | 📋 Planned | Medium |
| Microsoft Teams integration | 📋 Planned | Low |
| Discord bot | 📋 Planned | Low |

### Dashboard Improvements

| Feature | Status | Priority |
|---------|--------|----------|
| Customizable dashboard widgets | 📋 Planned | Medium |
| Saved filter presets | 📋 Planned | Medium |
| Bulk operations on findings | 📋 Planned | High |
| Finding comments and collaboration | 📋 Planned | Medium |
| Export to Confluence | 📋 Planned | Low |

---

## v2.5 (H2 2026) - 📋 Planned

**Target Release:** October 2026

### Real-Time Threat Detection

| Feature | Status | Priority |
|---------|--------|----------|
| Continuous monitoring mode | 📋 Planned | Medium |
| Real-time alerting | 📋 Planned | High |
| Anomaly detection | 📋 Planned | Medium |
| Integration with SIEM systems | 📋 Planned | Medium |

### Collaborative Features

| Feature | Status | Priority |
|---------|--------|----------|
| Multi-user findings review | 📋 Planned | Medium |
| Assignment and workflow | 📋 Planned | High |
| Review comments and threads | 📋 Planned | Medium |
| Approval workflows | 📋 Planned | Low |

### Custom Compliance Frameworks

| Feature | Status | Priority |
|---------|--------|----------|
| Framework builder UI | 📋 Planned | Medium |
| Custom control definitions | 📋 Planned | High |
| Import existing frameworks | 📋 Planned | Medium |
| Share custom frameworks | 📋 Planned | Low |

### Multi-Tenancy

| Feature | Status | Priority |
|---------|--------|----------|
| Tenant isolation | 📋 Planned | High |
| Per-tenant branding | 📋 Planned | Medium |
| Tenant-specific configurations | 📋 Planned | High |
| Cross-tenant reporting (MSSP) | 📋 Planned | Medium |

### White-Label Reporting

| Feature | Status | Priority |
|---------|--------|----------|
| Custom branding templates | 📋 Planned | High |
| Logo and color customization | 📋 Planned | High |
| Custom report sections | 📋 Planned | Medium |
| Template marketplace | 📋 Planned | Low |

---

## v3.0 (2027) - 🔮 Vision

**Target Release:** Q1 2027

### AI Advancements

| Feature | Status | Priority |
|---------|--------|----------|
| Fine-tuned security LLM | 🔮 Research | High |
| Automated exploit generation | 🔮 Research | Medium |
| Auto-remediation code suggestions | 🔮 Research | High |
| Natural language query interface | 🔮 Research | Medium |

### Advanced Scanning

| Feature | Status | Priority |
|---------|--------|----------|
| Mobile app binary scanning (APK/IPA) | 🔮 Planned | Medium |
| Thick client application testing | 🔮 Planned | Low |
| GraphQL-specific testing | 🔮 Planned | Medium |
| gRPC security testing | 🔮 Planned | Low |

### Enterprise Features

| Feature | Status | Priority |
|---------|--------|----------|
| SSO/SAML integration | 🔮 Planned | High |
| SCIM user provisioning | 🔮 Planned | Medium |
| Audit logging (immutable) | 🔮 Planned | High |
| Data residency controls | 🔮 Planned | Medium |
| Air-gapped deployment | 🔮 Planned | Low |

---

## Beyond v3.0 - 🌟 Long-Term Vision

### AI-Powered Features

- **Autonomous pentesting agent** with full human-in-the-loop approval workflow
- **Predictive vulnerability scoring** based on threat intelligence
- **Auto-generated security tests** for CI/CD
- **Natural language security queries** ("Show me all SQL injection risks")

### Platform Expansion

- **Managed NETRA Cloud** service for teams who don't want self-hosting
- **NETRA Marketplace** for community plugins, templates, and integrations
- **NETRA Academy** for security training and certification
- **NETRA Community** edition with limited features for individuals

### Security Research

- **NETRA Labs** for publishing original security research
- **Vulnerability disclosure program** for NETRA itself
- **Open-source threat intelligence** sharing
- **Partnership with universities** for security research

---

## Feature Request Process

### How to Request a Feature

1. **Check existing issues** - Search [GitHub Issues](https://github.com/yashwarrdhangautam/netra/issues) for similar requests
2. **Create a new issue** - Use the "Feature Request" template
3. **Provide context** - Explain your use case, expected behavior, and priority
4. **Community discussion** - Engage with maintainers and community feedback
5. **Prioritization** - Maintainers evaluate based on impact, effort, and alignment

### Prioritization Criteria

| Factor | Weight | Description |
|--------|--------|-------------|
| **User Impact** | 30% | How many users will benefit? |
| **Security Value** | 25% | Does it improve security outcomes? |
| **Technical Feasibility** | 20% | Can we build it well? |
| **Strategic Alignment** | 15% | Does it fit the vision? |
| **Community Demand** | 10% | How many users requested it? |

---

## Contributing to Roadmap Items

Want to help build these features? Here's how:

### Development Contributions

1. **Pick an issue** - Look for `good first issue` or `help wanted` labels
2. **Comment your interest** - Let maintainers know you're working on it
3. **Follow the guide** - See [CONTRIBUTING.md](CONTRIBUTING.md)
4. **Submit a PR** - Get your code reviewed and merged

### Non-Code Contributions

- 📖 **Documentation** - Improve guides, add examples
- 🎨 **Design** - Help with UI/UX improvements
- 🧪 **Testing** - Report bugs, verify fixes
- 📢 **Advocacy** - Write blog posts, give talks
- 💰 **Sponsorship** - Support development financially

---

## Release Schedule

| Version | Target Date | Status |
|---------|-------------|--------|
| v1.0.0 | March 2026 | ✅ Released |
| v1.1.0 | April 2026 | 📋 Planned |
| v1.2.0 | May 2026 | 📋 Planned |
| v2.0.0 | June 2026 | 📋 Planned |
| v2.1.0 | July 2026 | 📋 Planned |
| v2.5.0 | October 2026 | 📋 Planned |
| v3.0.0 | Q1 2027 | 🔮 Vision |

### Release Cadence

- **Patch releases (v1.0.x):** Every 2 weeks for bug fixes
- **Minor releases (v1.x.0):** Monthly for new features
- **Major releases (vX.0.0):** Quarterly for breaking changes

---

## Known Limitations (Not Planned)

These items are explicitly **not** on the roadmap:

| Feature | Reason |
|---------|--------|
| Social engineering testing | Out of scope for automated tool |
| Physical security testing | Requires human presence |
| Binary exploitation | Too complex, high false positive risk |
| Real-time network monitoring | Different product category |
| Malware analysis | Different product category |

---

## Contact

For roadmap questions, suggestions, or to get involved:

- 📝 **Issues:** [GitHub Issues](https://github.com/yashwarrdhangautam/netra/issues)
- 💬 **Discussions:** [GitHub Discussions](https://github.com/yashwarrdhangautam/netra/discussions)
- 📧 **Email:** roadmap@netra.dev
- 🐦 **Twitter:** [@NETRA_Sec](https://twitter.com/NETRA_Sec) (coming soon)

---

*Last updated: March 2026 | NETRA v1.0.0*
