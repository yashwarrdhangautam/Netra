"""
pentest/network.py
Network-level testing: CVE matching against service_map.json,
default network service credentials, banner grabbing.
"""

import json
import re
from typing import Dict, List

from netra.core.config   import CONFIG
from netra.core.utils    import status, banner, C
from netra.core.database import FindingsDB
from netra.core.notify   import notify_finding


# ═══════════════════════════════════════════════════════════════════════
#  Known CVE patterns matched against nmap service banners
# ═══════════════════════════════════════════════════════════════════════

# (product_regex, version_regex, cve_id, severity, cvss, description, remediation)
KNOWN_CVES = [
    # Apache
    (r"apache", r"2\.4\.(49|50)",  "CVE-2021-41773", "critical", 9.8,
     "Apache HTTP Server path traversal + RCE.",
     "Upgrade Apache to 2.4.51+."),
    (r"apache", r"2\.4\.29",       "CVE-2017-15715", "high", 8.1,
     "Apache HTTP Server filenames bypass.",
     "Upgrade Apache to latest version."),

    # nginx
    (r"nginx", r"1\.(1[0-6]|[0-9])\.", "CVE-2021-23017", "high", 7.7,
     "nginx DNS resolver off-by-one heap write.",
     "Upgrade nginx to 1.21.0+ or 1.20.1+."),

    # OpenSSH
    (r"openssh", r"[0-7]\.",       "CVE-2023-38408", "high", 7.5,
     "OpenSSH pre-authentication vulnerability.",
     "Upgrade OpenSSH to 9.3p2+."),
    (r"openssh", r"8\.[0-7]",     "CVE-2023-38408", "high", 7.5,
     "OpenSSH agent forwarding vulnerability.",
     "Upgrade OpenSSH to 9.3p2+."),

    # MySQL
    (r"mysql", r"5\.7\.",          "CVE-2020-14812", "medium", 4.9,
     "MySQL Server optimizer vulnerability.",
     "Upgrade MySQL to latest patch level."),
    (r"mysql", r"8\.0\.[0-2][0-8]", "CVE-2023-21977", "medium", 4.9,
     "MySQL Server optimizer vulnerability.",
     "Upgrade MySQL to 8.0.33+."),

    # PostgreSQL
    (r"postgresql", r"1[0-3]\.",   "CVE-2023-2454", "high", 7.2,
     "PostgreSQL privilege escalation via schema permissions.",
     "Upgrade PostgreSQL to latest patch."),

    # Redis
    (r"redis", r"[0-5]\.",         "CVE-2022-0543", "critical", 10.0,
     "Redis Lua sandbox escape — remote code execution.",
     "Upgrade Redis to 6.2.7+, 7.0.0+."),
    (r"redis", r"6\.[0-1]\.",     "CVE-2022-0543", "critical", 10.0,
     "Redis Lua sandbox escape — remote code execution.",
     "Upgrade Redis to 6.2.7+, 7.0.0+."),

    # Elasticsearch
    (r"elasticsearch", r"[0-6]\.", "CVE-2015-1427", "critical", 9.8,
     "Elasticsearch Groovy scripting RCE.",
     "Upgrade Elasticsearch to 7.x+."),
    (r"elasticsearch", r"7\.[0-9]\.", "CVE-2021-22145", "medium", 6.5,
     "Elasticsearch information disclosure.",
     "Upgrade Elasticsearch to latest."),

    # MongoDB
    (r"mongodb", r"[0-3]\.",       "CVE-2017-2665", "critical", 9.8,
     "MongoDB unauthenticated access (default config).",
     "Enable authentication. Upgrade MongoDB."),

    # ProFTPD
    (r"proftpd", r"1\.3\.[0-5]",  "CVE-2019-12815", "critical", 9.8,
     "ProFTPD arbitrary file copy.",
     "Upgrade ProFTPD to 1.3.6+."),

    # vsftpd
    (r"vsftpd", r"2\.3\.4",       "CVE-2011-2523", "critical", 9.8,
     "vsftpd backdoor command execution.",
     "Replace with clean vsftpd binary."),

    # Microsoft IIS
    (r"iis", r"[0-7]\.",          "CVE-2017-7269", "critical", 9.8,
     "IIS WebDAV buffer overflow RCE.",
     "Upgrade IIS. Disable WebDAV if not needed."),

    # Tomcat
    (r"tomcat", r"[0-8]\.",       "CVE-2020-1938", "critical", 9.8,
     "Apache Tomcat AJP Ghostcat file read/inclusion.",
     "Upgrade Tomcat. Disable AJP connector if not needed."),
    (r"tomcat", r"9\.0\.[0-3][0-5]", "CVE-2020-1938", "critical", 9.8,
     "Apache Tomcat AJP Ghostcat.",
     "Upgrade to Tomcat 9.0.31+."),

    # Jenkins
    (r"jenkins", r"2\.[0-2]",     "CVE-2019-1003000", "critical", 9.8,
     "Jenkins RCE via Groovy sandbox bypass.",
     "Upgrade Jenkins to latest LTS."),

    # Docker
    (r"docker", r"1[89]\.",       "CVE-2019-5736", "critical", 8.6,
     "Docker runc container escape.",
     "Upgrade Docker to 18.09.2+."),
]


# ═══════════════════════════════════════════════════════════════════════
#  Default Network Credentials
# ═══════════════════════════════════════════════════════════════════════

NETWORK_DEFAULT_CREDS = [
    # (port, service, description)
    (6379, "redis", "Redis default — no authentication required"),
    (27017, "mongodb", "MongoDB default — no authentication required"),
    (9200, "elasticsearch", "Elasticsearch default — no authentication"),
    (2375, "docker", "Docker API default — unauthenticated"),
    (2379, "etcd", "etcd default — unauthenticated"),
    (8500, "consul", "Consul default — no ACL"),
    (11211, "memcached", "Memcached default — no authentication"),
    (5984, "couchdb", "CouchDB default — admin party mode"),
]


def run_network_tests(
    service_map: Dict[str, dict],
    workdir: str,
    scan_id: str = "",
) -> int:
    """
    Run network-level tests against the service map.
    Returns total findings.
    """
    banner("NETWORK TESTING", "CVE match · Default creds · Banner analysis")

    db    = FindingsDB()
    total = 0

    total += _match_cves(service_map, scan_id, db)
    total += _check_default_network_creds(service_map, scan_id, db)

    status(f"Network tests complete: {total} findings", "ok")
    return total


# ═══════════════════════════════════════════════════════════════════════
#  CVE Matching
# ═══════════════════════════════════════════════════════════════════════

def _match_cves(service_map: dict, scan_id: str, db: FindingsDB) -> int:
    """Match discovered services against known CVE patterns."""
    status("CVE matching against service banners...", "run")
    count = 0

    for host, info in service_map.items():
        for port_info in info.get("ports", []):
            product = (port_info.get("product", "") + " " +
                       port_info.get("service", "")).lower()
            version = port_info.get("version", "")
            banner_str  = port_info.get("banner", "").lower()
            portnum = port_info.get("port", 0)

            full_str = f"{product} {version} {banner_str}"

            for prod_re, ver_re, cve, sev, cvss, desc, remed in KNOWN_CVES:
                if (re.search(prod_re, full_str, re.IGNORECASE) and
                    re.search(ver_re, version)):

                    finding = {
                        "scan_id":     scan_id,
                        "title":       f"{cve} — {product.strip()} {version} ({host}:{portnum})",
                        "template_id": f"pentest-cve-{cve.lower()}",
                        "cve_id":      cve,
                        "severity":    sev,
                        "cvss_score":  cvss,
                        "category":    "cve",
                        "owasp_web":   "A06:2021",
                        "mitre_technique": "T1190",
                        "host":        host,
                        "url":         f"{host}:{portnum}",
                        "description": desc,
                        "evidence":    f"Service: {product.strip()} {version}\nPort: {portnum}\nBanner: {banner_str[:200]}",
                        "impact":      f"Known vulnerability ({cve}) in running service version.",
                        "remediation": remed,
                        "confidence":  85,
                    }
                    fid = db.add_finding(finding)
                    if fid:
                        count += 1
                        notify_finding(finding)
                        status(f"{sev.upper()}: {cve} — {host}:{portnum}", "finding")

    status(f"CVE match: {count} findings", "ok" if not count else "warn")
    return count


# ═══════════════════════════════════════════════════════════════════════
#  Default Network Credentials
# ═══════════════════════════════════════════════════════════════════════

def _check_default_network_creds(service_map: dict, scan_id: str,
                                  db: FindingsDB) -> int:
    """Check if network services are running without authentication."""
    status("Default network credential check...", "run")
    count = 0

    for host, info in service_map.items():
        open_ports = [p.get("port") for p in info.get("ports", [])]

        for port, service, desc in NETWORK_DEFAULT_CREDS:
            if port in open_ports:
                # The port is open — flag as potential no-auth service
                finding = {
                    "scan_id":     scan_id,
                    "title":       f"Unauthenticated {service.upper()} — {host}:{port}",
                    "template_id": f"pentest-noauth-{service}",
                    "severity":    "critical",
                    "cvss_score":  9.8,
                    "category":    "auth",
                    "owasp_web":   "A07:2021",
                    "mitre_technique": "T1078",
                    "host":        host,
                    "url":         f"{host}:{port}",
                    "description": f"{desc}. Port {port} ({service}) is accessible and likely has no authentication.",
                    "evidence":    f"Port {port} ({service}) open on {host}.\nDefault configuration typically has no auth.",
                    "impact":      f"Full access to {service} data and administration without credentials.",
                    "remediation": f"Enable authentication on {service}. Restrict port {port} to trusted IPs via firewall.",
                    "confidence":  70,  # lower — needs active verification
                }
                fid = db.add_finding(finding)
                if fid:
                    count += 1
                    notify_finding(finding)
                    status(f"CRITICAL: Unauthenticated {service} — {host}:{port}", "finding")

    status(f"Network creds: {count} findings", "ok" if not count else "warn")
    return count
