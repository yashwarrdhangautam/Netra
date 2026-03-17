"""
recon/ports.py
Port scanning via naabu (fast) + nmap -sV (deep).
Builds service map for pentest engine target selection.
"""

import json
import xml.etree.ElementTree as ET
from pathlib import Path

from netra.core.config import CONFIG
from netra.core.utils  import run_cmd, status, tool_exists, write_targets_file
from netra.core.database import FindingsDB


def scan_ports(
    targets_file: str,
    workdir: str,
    scan_id: str = "",
) -> str:
    """
    Phase 1: naabu fast port scan
    Phase 2: nmap -sV on discovered open ports

    Returns path to service_map.json
    """
    workdir   = Path(workdir)
    recon_dir = workdir / "recon"
    recon_dir.mkdir(exist_ok=True)

    naabu_out  = str(recon_dir / "naabu.txt")
    nmap_xml   = str(recon_dir / "nmap.xml")
    svc_map    = str(recon_dir / "service_map.json")

    # ── Phase 1: naabu fast scan ─────────────────────────────────────
    if tool_exists("naabu"):
        status("Fast port scan (naabu)...", "run")
        run_cmd(
            [
                "naabu",
                "-l", targets_file,
                "-o", naabu_out,
                "-top-ports", "1000",
                "-silent",
                "-timeout", CONFIG.get("timeout", "10"),
                "-rate", CONFIG.get("rate_limit", "100"),
                "-threads", CONFIG.get("threads", "10"),
            ],
            silent=False, timeout=600
        )
    else:
        status("naabu not found, using nmap for port scan", "warn")

    # ── Phase 2: nmap service detection ──────────────────────────────
    if tool_exists("nmap"):
        status("Service detection (nmap -sV)...", "run")

        # Legacy mode: use -sT (slower but doesn't require root / less disruptive)
        scan_type = "-sT" if CONFIG.get("legacy_mode") == "true" else "-sS"

        nmap_cmd = [
            "nmap",
            scan_type,
            "-sV",
            "-O",                          # OS detection
            "--version-intensity", "5",
            "-iL", targets_file,
            "-oX", nmap_xml,               # XML output
            "--open",                      # only open ports
            "--host-timeout", "300s",
            "-T3",                         # timing (3=normal)
        ]

        if Path(naabu_out).exists():
            # Use naabu-discovered ports instead of scanning all
            open_ports = _parse_naabu_ports(naabu_out)
            if open_ports:
                port_str = ",".join(map(str, sorted(set(open_ports))))
                nmap_cmd.extend(["-p", port_str])
        else:
            nmap_cmd.extend(["--top-ports", "1000"])

        run_cmd(nmap_cmd, silent=False, timeout=1800)

    # ── Parse nmap XML into service map ──────────────────────────────
    services = {}
    if Path(nmap_xml).exists():
        services = _parse_nmap_xml(nmap_xml, scan_id)

    Path(svc_map).write_text(json.dumps(services, indent=2))
    status(f"Service map: {len(services)} hosts, "
           f"{sum(len(v.get('ports',[])) for v in services.values())} open ports",
           "ok")

    # Check for interesting exposed services
    _flag_exposed_services(services, scan_id)

    return svc_map


def _parse_naabu_ports(path: str) -> list:
    ports = []
    for line in Path(path).read_text().splitlines():
        if ":" in line:
            try:
                ports.append(int(line.strip().split(":")[1]))
            except (ValueError, IndexError):
                pass
    return ports


def _parse_nmap_xml(xml_path: str, scan_id: str) -> dict:
    services = {}
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()

        for host in root.findall(".//host"):
            # Get IP/hostname
            addr_el   = host.find(".//address[@addrtype='ipv4']")
            if addr_el is None:
                addr_el = host.find(".//address")
            ip = addr_el.get("addr", "") if addr_el is not None else ""

            hostname_el = host.find(".//hostname")
            hostname    = hostname_el.get("name", "") if hostname_el is not None else ""

            key = hostname or ip
            if not key:
                continue

            # OS detection
            os_el = host.find(".//osmatch")
            os_guess = os_el.get("name", "") if os_el is not None else ""

            open_ports = []
            for port in host.findall(".//port"):
                state_el = port.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue

                svc_el  = port.find("service")
                portnum = int(port.get("portid", 0))
                proto   = port.get("protocol", "tcp")
                service = svc_el.get("name", "")    if svc_el is not None else ""
                product = svc_el.get("product", "") if svc_el is not None else ""
                version = svc_el.get("version", "") if svc_el is not None else ""
                extra   = svc_el.get("extrainfo", "") if svc_el is not None else ""

                open_ports.append({
                    "port":     portnum,
                    "proto":    proto,
                    "service":  service,
                    "product":  product,
                    "version":  version,
                    "extra":    extra,
                    "banner":   f"{product} {version} {extra}".strip(),
                })

            services[key] = {
                "ip":       ip,
                "hostname": hostname,
                "os":       os_guess,
                "ports":    open_ports,
            }

    except Exception as e:
        status(f"nmap XML parse error: {e}", "warn")

    return services


DANGEROUS_PORTS = {
    21:    ("ftp",              "medium"),
    22:    ("ssh",              "low"),
    23:    ("telnet",           "critical"),
    25:    ("smtp",             "medium"),
    445:   ("smb",              "critical"),
    1433:  ("mssql",            "critical"),
    1521:  ("oracle",           "critical"),
    2375:  ("docker-api",       "critical"),
    2376:  ("docker-api-tls",   "high"),
    2379:  ("etcd",             "critical"),
    3306:  ("mysql",            "critical"),
    3389:  ("rdp",              "high"),
    4444:  ("metasploit",       "critical"),
    5432:  ("postgresql",       "critical"),
    5900:  ("vnc",              "critical"),
    6379:  ("redis",            "critical"),
    7001:  ("weblogic",         "critical"),
    8080:  ("http-alt",         "medium"),
    8443:  ("https-alt",        "medium"),
    9200:  ("elasticsearch",    "critical"),
    11211: ("memcached",        "critical"),
    27017: ("mongodb",          "critical"),
    50000: ("jenkins-agent",    "high"),
}


def _flag_exposed_services(services: dict, scan_id: str) -> None:
    """Check service map for dangerous exposed ports and add findings."""
    from netra.core.notify import notify_finding
    db = FindingsDB()

    for host, info in services.items():
        for port_info in info.get("ports", []):
            portnum = port_info.get("port")
            if portnum in DANGEROUS_PORTS:
                svc_name, sev = DANGEROUS_PORTS[portnum]
                banner_str = port_info.get("banner", "")

                finding = {
                    "scan_id":     scan_id,
                    "title":       f"Exposed {svc_name.upper()} Service — port {portnum}",
                    "template_id": f"exposed-{svc_name}",
                    "severity":    sev,
                    "cvss_score":  9.8 if sev == "critical" else 7.5 if sev == "high" else 5.3,
                    "category":    "misconfig",
                    "host":        host,
                    "url":         f"{host}:{portnum}",
                    "owasp_web":   "A05:2021",
                    "mitre_technique": "T1190",
                    "description": f"{svc_name.upper()} service on port {portnum} is accessible from the internet.",
                    "evidence":    f"Service banner: {banner_str}" if banner_str else f"Port {portnum} open",
                    "impact":      f"Exposed {svc_name} allows direct attack on the service. Default credentials, known CVEs, or data exfiltration.",
                    "remediation": f"Restrict port {portnum} to trusted IPs only via firewall rules. Never expose {svc_name} directly to the internet.",
                    "confidence":  98,
                }
                fid = db.add_finding(finding)
                if fid:
                    notify_finding(finding)
                    status(f"{sev.upper()}: Exposed {svc_name} on {host}:{portnum}", "finding")


def load_service_map(workdir: str) -> dict:
    """Load service map for use by other modules."""
    svc_file = Path(workdir) / "recon" / "service_map.json"
    if svc_file.exists():
        try:
            return json.loads(svc_file.read_text())
        except Exception:
            return {}
    return {}
