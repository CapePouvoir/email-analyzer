"""
Email Forensic Analyzer - Links Analysis Module
Extracts, analyzes, and checks URLs from email content.

Author: Randra Timothy RAZAFINDRABE (CapePouvoir / D3adinsid3)
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
from urllib.parse import urlparse, urlunparse
import requests


@dataclass
class LinkInfo:
    """Information about a single link."""
    original_url: str
    normalized_url: str = ""
    domain: str = ""
    path: str = ""
    query: str = ""
    fragment: str = ""
    is_https: bool = False
    is_http: bool = False
    is_relative: bool = False
    is_shortened: bool = False
    is_suspicious: bool = False
    shortener_service: Optional[str] = None
    final_url: Optional[str] = None  # After following redirects
    status_code: Optional[int] = None
    warnings: List[str] = field(default_factory=list)


@dataclass
class LinkAnalysis:
    """Results of link analysis."""
    links: List[LinkInfo] = field(default_factory=list)
    total_links: int = 0
    https_count: int = 0
    http_count: int = 0
    shortened_count: int = 0
    suspicious_count: int = 0
    unique_domains: Set[str] = field(default_factory=set)
    suspicious_domains: List[str] = field(default_factory=list)


# Known URL shorteners
URL_SHORTENERS = [
    'bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 't.co', 'is.gd',
    'buff.ly', 'adf.ly', 'j.mp', 'bc.vc', 'twitthis.com', 'u.to',
    'j.mp', 'bc.vc', 'twitthis.com', 'u.to', 'tinylink.io', 'shorturl.at',
    'rebrand.ly', 'doiop.com', 's2r.co', 'clicky.me', 'soo.gd',
    'shorte.st', 'go2cut.com', 'bc.vc', 'x.co', 'tr.im', 'ptiturl.com',
    'bimim.com', 'duckduckgo.com', 's.id', 'scrnch.me', 'filoops.info',
    'viralurl.com', 'cutt.us', 'u2can.co', 'short.to', 'linktini.com'
]

# Known suspicious domains (can be extended)
SUSPICIOUS_DOMAINS = [
    # Phishing domains
    'paypal-verify.com', 'apple-id-verify.com', 'bankofamerica-secure.com',
    'microsoft-support.com', 'google-accounts.com', 'facebook-login.com',
    
    # Malware domains
    'malicious-site.evil', 'bad-actor.com', 'evil-corp.net',
    
    # Add more as needed
]

# Suspicious keywords in URLs
SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'account', 'secure', 'update', 'password',
    'bank', 'paypal', 'creditcard', 'social-security', 'irs',
    'confirm', 'suspicious', 'alert', 'urgent', 'action-required',
    'click-here', 'download', 'free', 'winner', 'prize',
    'admin', 'webmail', 'portal', 'session', 'token'
]


def analyse_links(eml_content: str, follow_redirects: bool = False) -> LinkAnalysis:
    """
    Extract and analyze all links from EML content.
    
    Args:
        eml_content: Raw EML file content
        follow_redirects: Whether to follow redirects to get final URL
        
    Returns:
        LinkAnalysis object with all results
    """
    analysis = LinkAnalysis()
    
    # Extract all URLs from content
    urls = _extract_urls_from_eml(eml_content)
    
    for url in urls:
        link_info = _analyse_link(url, follow_redirects)
        analysis.links.append(link_info)
        
        # Update counters
        analysis.total_links += 1
        if link_info.is_https:
            analysis.https_count += 1
        if link_info.is_http:
            analysis.http_count += 1
        if link_info.is_shortened:
            analysis.shortened_count += 1
        if link_info.is_suspicious:
            analysis.suspicious_count += 1
        
        # Track domains
        if link_info.domain:
            analysis.unique_domains.add(link_info.domain)
            if link_info.is_suspicious:
                analysis.suspicious_domains.append(link_info.domain)
    
    return analysis


def _extract_urls_from_eml(eml_content: str) -> List[str]:
    """
    Extract all URLs from EML content.
    
    Args:
        eml_content: Raw EML file content
        
    Returns:
        List of URLs found
    """
    urls = []
    
    # URL pattern - matches most URLs
    url_pattern = re.compile(
        r'(?:(?:https?|ftp|file)://|www\.|ftp\.)'  # Protocol
        r'(?:\S+(?::\S*)?@)?'  # User:pass
        r'(?:'
        r'(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+'  # Subdomain
        r'(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # TLD
        r'localhost|'  # localhost
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # IP
        r'\S+'  # Anything else
        r')'
        r'(?::\d+)?'  # Port
        r'(?:/?|[/?]\S+)'  # Path
        r'(?:\?\S*)?'  # Query
        r'(?:#\S*)?',  # Fragment
        re.IGNORECASE
    )
    
    # Find all URLs
    matches = url_pattern.findall(eml_content)
    urls.extend(matches)
    
    # Also look for URLs in HTML href attributes
    href_pattern = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
    matches = href_pattern.findall(eml_content)
    urls.extend(matches)
    
    # Also look for URLs in HTML src attributes
    src_pattern = re.compile(r'src=["\']([^"\']+)["\']', re.IGNORECASE)
    matches = src_pattern.findall(eml_content)
    urls.extend(matches)
    
    # Deduplicate while preserving order
    seen = set()
    unique_urls = []
    for url in urls:
        # Normalize URL for deduplication
        normalized = _normalize_url(url)
        if normalized not in seen:
            seen.add(normalized)
            unique_urls.append(url)
    
    return unique_urls


def _analyse_link(url: str, follow_redirects: bool = False) -> LinkInfo:
    """
    Analyze a single URL.
    
    Args:
        url: URL to analyze
        follow_redirects: Whether to follow redirects
        
    Returns:
        LinkInfo object
    """
    info = LinkInfo(original_url=url)
    
    # Normalize URL
    info.normalized_url = _normalize_url(url)
    
    # Parse URL
    parsed = urlparse(url)
    
    # Set basic info
    info.domain = parsed.netloc.lower() if parsed.netloc else ''
    info.path = parsed.path
    info.query = parsed.query
    info.fragment = parsed.fragment
    
    # Check protocol
    scheme = parsed.scheme.lower()
    if scheme == 'https':
        info.is_https = True
    elif scheme == 'http':
        info.is_http = True
    elif not scheme or scheme in ['', '//']:
        info.is_relative = True
        # Try to make it absolute
        info.normalized_url = f"https://{url}" if not url.startswith('/') else f"https://{parsed.netloc}{url}"
        parsed = urlparse(info.normalized_url)
        info.domain = parsed.netloc.lower()
        info.path = parsed.path
    
    # Check if shortened
    info.is_shortened, info.shortener_service = _is_shortened_url(parsed.netloc)
    
    # Follow redirects if requested
    if follow_redirects and info.is_shortened:
        try:
            final_url = _follow_redirects(url)
            if final_url:
                info.final_url = final_url
                final_parsed = urlparse(final_url)
                info.domain = final_parsed.netloc.lower()
        except:
            pass
    
    # Check if suspicious
    info.is_suspicious = _is_suspicious_url(url, parsed, info)
    
    # Generate warnings
    info.warnings = _generate_warnings(url, parsed, info)
    
    return info


def _normalize_url(url: str) -> str:
    """
    Normalize URL by:
    - Removing fragment
    - Lowercasing domain
    - Adding https:// if missing
    """
    parsed = urlparse(url)
    
    # Remove fragment
    parsed = parsed._replace(fragment='')
    
    # Lowercase domain
    if parsed.netloc:
        parsed = parsed._replace(netloc=parsed.netloc.lower())
    
    # Add scheme if missing
    if not parsed.scheme:
        parsed = parsed._replace(scheme='https')
    
    return urlunparse(parsed)


def _is_shortened_url(domain: str) -> tuple:
    """
    Check if URL is from a known URL shortener.
    
    Returns:
        Tuple of (is_shortened, shortener_service)
    """
    domain_lower = domain.lower()
    
    for shortener in URL_SHORTENERS:
        if shortener in domain_lower or domain_lower.endswith(shortener):
            return True, shortener
    
    return False, None


def _is_suspicious_url(url: str, parsed: urlparse, info: LinkInfo) -> bool:
    """Check if URL is suspicious."""
    domain = parsed.netloc.lower()
    
    # Check if in known suspicious domains
    if domain in SUSPICIOUS_DOMAINS:
        return True
    
    # Check for suspicious keywords in domain
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in domain:
            return True
    
    # Check for suspicious keywords in path
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in parsed.path.lower():
            return True
    
    # Check if using HTTP (not HTTPS)
    if info.is_http and not info.is_https:
        return True
    
    # Check if shortened
    if info.is_shortened:
        return True
    
    # Check for IP addresses in URL
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
        return True
    
    # Check for unusual TLDs
    unusual_tlds = ['.gq', '.tk', '.ml', '.cf', '.ga', '.xyz', '.top', '.gdn', '.men']
    for tld in unusual_tlds:
        if domain.endswith(tld):
            return True
    
    return False


def _generate_warnings(url: str, parsed: urlparse, info: LinkInfo) -> List[str]:
    """Generate warnings for the link."""
    warnings = []
    domain = parsed.netloc.lower()
    
    # Warning for HTTP
    if info.is_http and not info.is_https:
        warnings.append(f"⚠️ Insecure protocol: {url}")
    
    # Warning for shortened URL
    if info.is_shortened:
        warnings.append(f"⚠️ Shortened URL: {url} (service: {info.shortener_service})")
        if info.final_url:
            warnings.append(f"   → Resolves to: {info.final_url}")
    
    # Warning for known suspicious domain
    if domain in SUSPICIOUS_DOMAINS:
        warnings.append(f"⚠️ Known suspicious domain: {domain}")
    
    # Warning for IP in URL
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
        warnings.append(f"⚠️ IP address in URL: {url}")
    
    # Warning for unusual TLD
    unusual_tlds = ['.gq', '.tk', '.ml', '.cf', '.ga', '.xyz', '.top', '.gdn', '.men']
    for tld in unusual_tlds:
        if domain.endswith(tld):
            warnings.append(f"⚠️ Unusual TLD: {tld}")
            break
    
    # Warning for suspicious keywords
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in domain:
            warnings.append(f"⚠️ Suspicious keyword in domain: {keyword}")
            break
    
    return warnings


def _follow_redirects(url: str, max_redirects: int = 5) -> Optional[str]:
    """
    Follow redirects to get final URL.
    
    Args:
        url: Starting URL
        max_redirects: Maximum number of redirects to follow
        
    Returns:
        Final URL after all redirects, or None if error
    """
    try:
        # Disable SSL verification for internal use (can be enabled in production)
        response = requests.head(
            url,
            allow_redirects=True,
            timeout=10,
            verify=False,
            headers={'User-Agent': 'EmailForensicAnalyzer/1.0'}
        )
        return response.url
    except:
        return None
