"""SSRF Protection utilities for validating scan targets.

Prevents Server-Side Request Forgery attacks by blocking:
- Private IP addresses (RFC 1918)
- Loopback addresses
- Link-local addresses
- Cloud metadata endpoints (AWS, GCP, Azure)
- Internal hostnames
"""
import ipaddress
import socket
from urllib.parse import urlparse
from typing import Literal

import structlog

logger = structlog.get_logger()


# Cloud metadata endpoints that should never be scanned
CLOUD_METADATA_ENDPOINTS = {
    # AWS
    "169.254.169.254",
    "169.254.170.2",  # AWS ECS
    "169.254.169.253",  # AWS EKS
    # GCP
    "169.254.169.254",
    "metadata.google.internal",
    # Azure
    "169.254.169.254",
    "168.63.129.16",  # Azure DNS
    # DigitalOcean
    "169.254.169.254",
    # Kubernetes
    "kubernetes.default.svc",
}

# Private IP ranges (RFC 1918)
PRIVATE_IP_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),  # Loopback
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),  # Carrier-grade NAT
    ipaddress.ip_network("192.0.0.0/24"),  # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),  # Documentation (TEST-NET-1)
    ipaddress.ip_network("198.18.0.0/15"),  # Network Interconnect Devices
    ipaddress.ip_network("198.51.100.0/24"),  # Documentation (TEST-NET-2)
    ipaddress.ip_network("203.0.113.0/24"),  # Documentation (TEST-NET-3)
    ipaddress.ip_network("224.0.0.0/4"),  # Multicast
    ipaddress.ip_network("240.0.0.0/4"),  # Reserved
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local
]


class SSRFProtectionError(Exception):
    """Exception raised when SSRF protection validation fails."""

    def __init__(self, message: str, violation_type: str):
        self.message = message
        self.violation_type = violation_type
        super().__init__(self.message)


class SSRFProtection:
    """SSRF Protection validator for scan targets."""

    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """Check if an IP address is private/internal.

        Args:
            ip: IP address string

        Returns:
            True if IP is private/internal
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Check if it's a private address
            if ip_obj.is_private:
                return True
            
            # Check if it's a loopback address
            if ip_obj.is_loopback:
                return True
            
            # Check if it's a link-local address
            if ip_obj.is_link_local:
                return True
            
            # Check against explicit private ranges
            for network in PRIVATE_IP_RANGES:
                if ip_obj in network:
                    return True
            
            # Check cloud metadata endpoints
            if str(ip_obj) in CLOUD_METADATA_ENDPOINTS:
                return True
            
            return False
            
        except ValueError:
            # Invalid IP address
            return True

    @staticmethod
    def is_blocked_hostname(hostname: str) -> bool:
        """Check if a hostname is blocked.

        Args:
            hostname: Hostname to check

        Returns:
            True if hostname is blocked
        """
        hostname_lower = hostname.lower()
        
        # Check cloud metadata endpoints
        if hostname_lower in CLOUD_METADATA_ENDPOINTS:
            return True
        
        # Check for internal hostnames
        internal_suffixes = [
            ".internal",
            ".local",
            ".lan",
            ".private",
            ".corp",
            ".intra",
        ]
        
        for suffix in internal_suffixes:
            if hostname_lower.endswith(suffix):
                return True
        
        return False

    @staticmethod
    def resolve_and_validate(hostname: str) -> tuple[bool, list[str]]:
        """Resolve hostname and validate all IPs.

        Args:
            hostname: Hostname to resolve and validate

        Returns:
            Tuple of (is_valid, list_of_ips)

        Raises:
            SSRFProtectionError: If validation fails
        """
        try:
            # Get all IP addresses for the hostname
            addr_info = socket.getaddrinfo(hostname, None, socket.AF_INET)
            ips = list(set([info[4][0] for info in addr_info]))
            
            # Validate each IP
            for ip in ips:
                if SSRFProtection.is_private_ip(ip):
                    raise SSRFProtectionError(
                        f"Target resolves to private/internal IP: {ip}",
                        "private_ip"
                    )
            
            return True, ips
            
        except socket.gaierror as e:
            raise SSRFProtectionError(
                f"Failed to resolve hostname: {hostname}",
                "resolution_failed"
            )
        except socket.herror as e:
            raise SSRFProtectionError(
                f"DNS error for hostname: {hostname}",
                "dns_error"
            )

    @staticmethod
    def validate_url(url: str) -> tuple[bool, str]:
        """Validate a URL for SSRF vulnerabilities.

        Args:
            url: URL to validate

        Returns:
            Tuple of (is_valid, normalized_url)

        Raises:
            SSRFProtectionError: If validation fails
        """
        try:
            parsed = urlparse(url)
            
            # Check scheme
            if parsed.scheme not in ["http", "https"]:
                raise SSRFProtectionError(
                    f"Invalid scheme: {parsed.scheme}. Only http/https allowed.",
                    "invalid_scheme"
                )
            
            # Check if hostname exists
            if not parsed.hostname:
                raise SSRFProtectionError(
                    "Missing hostname in URL",
                    "missing_hostname"
                )
            
            hostname = parsed.hostname
            
            # Check for blocked hostnames
            if SSRFProtection.is_blocked_hostname(hostname):
                raise SSRFProtectionError(
                    f"Blocked hostname: {hostname}",
                    "blocked_hostname"
                )
            
            # Check if hostname is an IP address
            try:
                if SSRFProtection.is_private_ip(hostname):
                    raise SSRFProtectionError(
                        f"Private/internal IP address: {hostname}",
                        "private_ip"
                    )
            except ValueError:
                # Not an IP, continue with hostname validation
                pass
            
            # Resolve and validate hostname
            SSRFProtection.resolve_and_validate(hostname)
            
            # Reconstruct normalized URL
            normalized = f"{parsed.scheme}://{hostname}"
            if parsed.port:
                normalized += f":{parsed.port}"
            if parsed.path:
                normalized += parsed.path
            if parsed.query:
                normalized += f"?{parsed.query}"
            
            return True, normalized
            
        except SSRFProtectionError:
            raise
        except Exception as e:
            raise SSRFProtectionError(
                f"URL validation failed: {str(e)}",
                "validation_error"
            )

    @staticmethod
    def validate_domain(domain: str) -> tuple[bool, str]:
        """Validate a domain name for SSRF vulnerabilities.

        Args:
            domain: Domain name to validate

        Returns:
            Tuple of (is_valid, domain)

        Raises:
            SSRFProtectionError: If validation fails
        """
        # Remove protocol if present
        domain = domain.replace("http://", "").replace("https://", "")
        domain = domain.split("/")[0].split(":")[0]
        
        # Check for blocked hostnames
        if SSRFProtection.is_blocked_hostname(domain):
            raise SSRFProtectionError(
                f"Blocked domain: {domain}",
                "blocked_domain"
            )
        
        # Check if it's an IP address
        try:
            if SSRFProtection.is_private_ip(domain):
                raise SSRFProtectionError(
                    f"Private/internal IP address: {domain}",
                    "private_ip"
                )
        except ValueError:
            # Not an IP, continue with domain validation
            pass
        
        # Resolve and validate
        SSRFProtection.resolve_and_validate(domain)
        
        return True, domain

    @staticmethod
    def validate_ip(ip: str) -> tuple[bool, str]:
        """Validate an IP address for scanning.

        Args:
            ip: IP address to validate

        Returns:
            Tuple of (is_valid, ip)

        Raises:
            SSRFProtectionError: If validation fails
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            if SSRFProtection.is_private_ip(ip):
                raise SSRFProtectionError(
                    f"Cannot scan private/internal IP: {ip}",
                    "private_ip"
                )
            
            return True, ip
            
        except ValueError:
            raise SSRFProtectionError(
                f"Invalid IP address format: {ip}",
                "invalid_ip_format"
            )

    @staticmethod
    def validate_ip_range(cidr: str) -> tuple[bool, str]:
        """Validate an IP range (CIDR notation) for scanning.

        Args:
            cidr: IP range in CIDR notation (e.g., "10.0.0.0/8")

        Returns:
            Tuple of (is_valid, cidr)

        Raises:
            SSRFProtectionError: If validation fails
        """
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            
            # Check if the network is private
            first_ip = str(network.network_address)
            if SSRFProtection.is_private_ip(first_ip):
                raise SSRFProtectionError(
                    f"Cannot scan private IP range: {cidr}",
                    "private_ip_range"
                )
            
            # Check if range is too large (prevent accidental large scans)
            max_hosts = 65536  # /16
            if network.num_addresses > max_hosts:
                raise SSRFProtectionError(
                    f"IP range too large: {cidr} ({network.num_addresses} hosts). "
                    f"Maximum allowed: /16 ({max_hosts} hosts)",
                    "range_too_large"
                )
            
            return True, cidr
            
        except ValueError:
            raise SSRFProtectionError(
                f"Invalid CIDR notation: {cidr}",
                "invalid_cidr"
            )

    @staticmethod
    def validate_target(value: str, target_type: str) -> tuple[bool, str, list[str]]:
        """Validate a scan target based on its type.

        Args:
            value: Target value
            target_type: Target type (domain, ip, ip_range, url)

        Returns:
            Tuple of (is_valid, normalized_value, resolved_ips)

        Raises:
            SSRFProtectionError: If validation fails
        """
        resolved_ips = []
        
        if target_type == "url":
            is_valid, normalized = SSRFProtection.validate_url(value)
            # Extract hostname for resolution
            parsed = urlparse(normalized)
            if parsed.hostname:
                _, resolved_ips = SSRFProtection.resolve_and_validate(parsed.hostname)
            return is_valid, normalized, resolved_ips
            
        elif target_type == "domain":
            is_valid, normalized = SSRFProtection.validate_domain(value)
            _, resolved_ips = SSRFProtection.resolve_and_validate(normalized)
            return is_valid, normalized, resolved_ips
            
        elif target_type == "ip":
            is_valid, normalized = SSRFProtection.validate_ip(value)
            return is_valid, normalized, [normalized]
            
        elif target_type == "ip_range":
            is_valid, normalized = SSRFProtection.validate_ip_range(value)
            return is_valid, normalized, []
            
        else:
            raise SSRFProtectionError(
                f"Unknown target type: {target_type}",
                "unknown_target_type"
            )


def validate_scan_target(value: str, target_type: str) -> dict:
    """Convenience function to validate a scan target.

    Args:
        value: Target value
        target_type: Target type

    Returns:
        Validation result dictionary

    Raises:
        SSRFProtectionError: If validation fails
    """
    try:
        is_valid, normalized, resolved_ips = SSRFProtection.validate_target(
            value, target_type
        )
        
        logger.info(
            "ssrf_validation_passed",
            target_type=target_type,
            normalized=normalized,
            resolved_ips=resolved_ips,
        )
        
        return {
            "valid": True,
            "normalized": normalized,
            "resolved_ips": resolved_ips,
            "message": "Target validated successfully",
        }
        
    except SSRFProtectionError as e:
        logger.warning(
            "ssrf_validation_failed",
            target_type=target_type,
            value=value,
            violation_type=e.violation_type,
            error=e.message,
        )
        
        return {
            "valid": False,
            "error": e.message,
            "violation_type": e.violation_type,
        }
