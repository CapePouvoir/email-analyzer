"""
Email Forensic Analyzer - Headers Analysis Module
Analyzes email headers for SPF, DKIM, DMARC, IP reputation, etc.

Author: Randra Timothy RAZAFINDRABE (CapePouvoir / D3adinsid3)
"""

import re
import socket
from dataclasses import dataclass, field
from typing import Optional, Dict, List
from email.utils import parseaddr


@dataclass
class HeaderAnalysis:
    """Results of header analysis."""
    
    # Basic info
    from_address: Optional[str] = None
    from_domain: Optional[str] = None
    to_addresses: List[str] = field(default_factory=list)
    subject: Optional[str] = None
    date: Optional[str] = None
    
    # IP and server info
    source_ip: Optional[str] = None
    received_from: List[str] = field(default_factory=list)
    received_by: List[str] = field(default_factory=list)
    
    # Authentication results
    spf_result: Optional[str] = None
    spf_domain: Optional[str] = None
    dkim_result: Optional[str] = None
    dkim_domain: Optional[str] = None
    dmarc_result: Optional[str] = None
    dmarc_policy: Optional[str] = None
    
    # Security flags
    is_spf_pass: bool = False
    is_dkim_pass: bool = False
    is_dmarc_pass: bool = False
    is_suspicious: bool = False
    
    # Warnings
    warnings: List[str] = field(default_factory=list)
    
    # Raw headers
    raw_headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class IPReputation:
    """IP reputation analysis results."""
    ip: str
    is_private: bool = False
    is_reserved: bool = False
    is_tor: bool = False
    is_known_malicious: bool = False
    country: Optional[str] = None
    asn: Optional[str] = None
    reputation_source: str = "local"


def extract_headers_from_eml(eml_content: str) -> Dict[str, str]:
    """
    Extract headers from raw EML content.
    
    Args:
        eml_content: Raw EML file content
        
    Returns:
        Dictionary of headers (lowercase keys)
    """
    headers = {}
    lines = eml_content.split('\n')
    
    for line in lines:
        if not line.strip() or line.strip() == '--':
            break  # End of headers
        
        if ': ' in line:
            key, value = line.split(': ', 1)
            headers[key.lower()] = value.strip()
    
    return headers


def analyse_headers(eml_content: str) -> HeaderAnalysis:
    """
    Perform comprehensive header analysis on EML content.
    
    Args:
        eml_content: Raw EML file content
        
    Returns:
        HeaderAnalysis object with all results
    """
    analysis = HeaderAnalysis()
    headers = extract_headers_from_eml(eml_content)
    analysis.raw_headers = headers
    
    # Extract basic information
    analysis.from_address, analysis.from_domain = _parse_from(headers)
    analysis.to_addresses = _parse_to(headers)
    analysis.subject = headers.get('subject')
    analysis.date = headers.get('date')
    
    # Extract IP and received chain
    analysis.source_ip, analysis.received_from, analysis.received_by = _extract_ip_info(headers)
    
    # Analyze authentication headers
    analysis.spf_result, analysis.spf_domain, analysis.is_spf_pass = _analyse_spf(headers)
    analysis.dkim_result, analysis.dkim_domain, analysis.is_dkim_pass = _analyse_dkim(headers)
    analysis.dmarc_result, analysis.dmarc_policy, analysis.is_dmarc_pass = _analyse_dmarc(headers)
    
    # Check for suspicious patterns
    analysis.warnings = _check_suspicious_patterns(headers, analysis)
    analysis.is_suspicious = len(analysis.warnings) > 0
    
    return analysis


def _parse_from(headers: Dict[str, str]) -> tuple:
    """Parse From header and extract domain."""
    from_header = headers.get('from', '')
    if not from_header:
        return None, None
    
    # Parse email address
    name, address = parseaddr(from_header)
    if not address:
        return from_header, None
    
    # Extract domain
    domain = address.split('@')[-1] if '@' in address else None
    
    return address, domain


def _parse_to(headers: Dict[str, str]) -> List[str]:
    """Parse To header and return list of addresses."""
    to_header = headers.get('to', '')
    if not to_header:
        return []
    
    # Simple parsing (could be improved)
    addresses = [addr.strip() for addr in to_header.split(',')]
    return [addr for addr in addresses if addr]


def _extract_ip_info(headers: Dict[str, str]) -> tuple:
    """Extract source IP and received chain from headers."""
    source_ip = None
    received_from = []
    received_by = []
    
    # Look for Received headers
    for key, value in headers.items():
        if key.startswith('received'):
            # Extract IP from received header
            ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', value)
            if ip_match:
                ip = ip_match.group(1)
                if _is_valid_ip(ip):
                    if not source_ip:
                        source_ip = ip
                    
            # Extract from/by info
            from_match = re.search(r'from\s+([^\s;]+)', value, re.IGNORECASE)
            by_match = re.search(r'by\s+([^\s;]+)', value, re.IGNORECASE)
            
            if from_match:
                received_from.append(from_match.group(1))
            if by_match:
                received_by.append(by_match.group(1))
    
    # Try to get IP from X-Originating-IP
    if not source_ip:
        source_ip = headers.get('x-originating-ip')
    
    # Try to get IP from X-Forwarded-For
    if not source_ip:
        forwarded_for = headers.get('x-forwarded-for', '')
        if forwarded_for:
            ips = [ip.strip() for ip in forwarded_for.split(',')]
            for ip in ips:
                if _is_valid_ip(ip):
                    source_ip = ip
                    break
    
    return source_ip, received_from, received_by


def _is_valid_ip(ip: str) -> bool:
    """Check if IP address is valid."""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def _analyse_spf(headers: Dict[str, str]) -> tuple:
    """Analyze SPF authentication result."""
    spf_result = headers.get('received-spf', '')
    spf_domain = None
    is_pass = False
    
    if 'pass' in spf_result.lower():
        is_pass = True
    
    # Extract domain from SPF header
    spf_match = re.search(r'client-ip=(\S+)', spf_result)
    if spf_match:
        spf_domain = spf_match.group(1)
    
    return spf_result, spf_domain, is_pass


def _analyse_dkim(headers: Dict[str, str]) -> tuple:
    """Analyze DKIM authentication result."""
    dkim_result = headers.get('dkim-signature', '')
    dkim_domain = None
    is_pass = False
    
    # Look for DKIM result in Authentication-Results
    auth_results = headers.get('authentication-results', '')
    if 'dkim=pass' in auth_results.lower():
        is_pass = True
    
    # Extract domain from DKIM-Signature
    dkim_match = re.search(r'd=([^;\s]+)', dkim_result)
    if dkim_match:
        dkim_domain = dkim_match.group(1)
    
    return dkim_result, dkim_domain, is_pass


def _analyse_dmarc(headers: Dict[str, str]) -> tuple:
    """Analyze DMARC authentication result."""
    dmarc_result = None
    dmarc_policy = None
    is_pass = False
    
    # Look for DMARC result in Authentication-Results
    auth_results = headers.get('authentication-results', '')
    if 'dmarc=pass' in auth_results.lower():
        is_pass = True
        dmarc_result = 'pass'
    elif 'dmarc=fail' in auth_results.lower():
        dmarc_result = 'fail'
    elif 'dmarc=none' in auth_results.lower():
        dmarc_result = 'none'
    
    # Extract policy from DMARC header
    dmarc_header = headers.get('dmarc-policy', '')
    if 'p=' in dmarc_header:
        policy_match = re.search(r'p=([^;\s]+)', dmarc_header)
        if policy_match:
            dmarc_policy = policy_match.group(1)
    
    return dmarc_result, dmarc_policy, is_pass


def _check_suspicious_patterns(headers: Dict[str, str], analysis: HeaderAnalysis) -> List[str]:
    """Check for suspicious patterns in headers."""
    warnings = []
    
    # Check for mismatched domains
    if analysis.from_domain and analysis.received_from:
        for received in analysis.received_from:
            if received != analysis.from_domain:
                warnings.append(
                    f"Domain mismatch: From domain '{analysis.from_domain}' "
                    f"!= Received from '{received}'"
                )
    
    # Check for suspicious headers
    suspicious_headers = [
        'x-phish', 'x-malware', 'x-virus', 'x-spam',
        'x-priority: high', 'urgent'
    ]
    
    for header_key, header_value in headers.items():
        header_lower = header_key.lower() + ': ' + header_value.lower()
        for suspicious in suspicious_headers:
            if suspicious in header_lower:
                warnings.append(f"Suspicious header detected: {header_key}")
                break
    
    # Check SPF/DKIM/DMARC failures
    if not analysis.is_spf_pass:
        warnings.append("SPF authentication failed or missing")
    if not analysis.is_dkim_pass:
        warnings.append("DKIM authentication failed or missing")
    if not analysis.is_dmarc_pass:
        warnings.append("DMARC policy not enforced")
    
    # Check for known malicious IPs (placeholder - could be extended with a database)
    if analysis.source_ip:
        # This is a placeholder - in production, you'd use a threat intelligence feed
        known_malicious_ips = [
            # Add known malicious IPs here
        ]
        if analysis.source_ip in known_malicious_ips:
            warnings.append(f"Known malicious IP: {analysis.source_ip}")
    
    return warnings


def analyse_ip_reputation(ip: str) -> IPReputation:
    """
    Analyze IP reputation (local analysis only - no external API calls).
    
    Args:
        ip: IP address to analyze
        
    Returns:
        IPReputation object
    """
    reputation = IPReputation(ip=ip)
    
    # Check if private IP
    if _is_private_ip(ip):
        reputation.is_private = True
        reputation.reputation_source = "local_db"
        return reputation
    
    # Check if reserved IP
    if _is_reserved_ip(ip):
        reputation.is_reserved = True
        reputation.reputation_source = "local_db"
        return reputation
    
    # In a production environment, you would:
    # 1. Query local threat intelligence database
    # 2. Check against known malicious IP lists
    # 3. Optionally call external APIs (if configured)
    
    # For now, just mark as unknown
    reputation.reputation_source = "local_db"
    return reputation


def _is_private_ip(ip: str) -> bool:
    """Check if IP is in private ranges."""
    private_ranges = [
        ('10.0.0.0', '10.255.255.255'),
        ('172.16.0.0', '172.31.255.255'),
        ('192.168.0.0', '192.168.255.255'),
        ('127.0.0.0', '127.255.255.255'),
        ('169.254.0.0', '169.254.255.255'),
    ]
    
    try:
        ip_int = _ip_to_int(ip)
        for start, end in private_ranges:
            if _ip_to_int(start) <= ip_int <= _ip_to_int(end):
                return True
    except:
        pass
    
    return False


def _is_reserved_ip(ip: str) -> bool:
    """Check if IP is in reserved ranges."""
    reserved_ranges = [
        ('0.0.0.0', '0.255.255.255'),
        ('100.64.0.0', '100.127.255.255'),
        ('192.0.0.0', '192.0.0.255'),
        ('192.0.2.0', '192.0.2.255'),
        ('192.88.99.0', '192.88.99.255'),
        ('198.18.0.0', '198.19.255.255'),
        ('198.51.100.0', '198.51.100.255'),
        ('203.0.113.0', '203.0.113.255'),
        ('224.0.0.0', '255.255.255.255'),
    ]
    
    try:
        ip_int = _ip_to_int(ip)
        for start, end in reserved_ranges:
            if _ip_to_int(start) <= ip_int <= _ip_to_int(end):
                return True
    except:
        pass
    
    return False


def _ip_to_int(ip: str) -> int:
    """Convert IP address to integer."""
    parts = list(map(int, ip.split('.')))
    return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
