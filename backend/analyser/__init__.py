"""
Email Forensic Analyzer - Analyser Module
Main package for email forensic analysis.

Author: Randra Timothy RAZAFINDRABE (CapePouvoir / D3adinsid3)
"""

from backend.analyser.headers import analyse_headers, HeaderAnalysis, analyse_ip_reputation, IPReputation
from backend.analyser.attachments import analyse_attachments, AttachmentAnalysis, AttachmentInfo
from backend.analyser.links import analyse_links, LinkAnalysis, LinkInfo
from backend.analyser.report import ReportGenerator, Report

__all__ = [
    # Headers
    'analyse_headers', 'HeaderAnalysis', 'analyse_ip_reputation', 'IPReputation',
    # Attachments
    'analyse_attachments', 'AttachmentAnalysis', 'AttachmentInfo',
    # Links
    'analyse_links', 'LinkAnalysis', 'LinkInfo',
    # Report
    'ReportGenerator', 'Report'
]
