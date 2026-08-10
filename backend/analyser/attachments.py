"""
Email Forensic Analyzer - Attachments Analysis Module
Extracts, analyzes, and generates hashes for email attachments.

Author: Randra Timothy RAZAFINDRABE (CapePouvoir / D3adinsid3)
"""

import hashlib
import base64
import mimetypes
import magic
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Tuple
from pathlib import Path
import re


@dataclass
class AttachmentInfo:
    """Information about a single attachment."""
    filename: str
    content_type: str
    size: int
    file_extension: str
    is_executable: bool = False
    is_suspicious: bool = False
    hash_sha256: Optional[str] = None
    hash_md5: Optional[str] = None
    magic_type: Optional[str] = None
    magic_description: Optional[str] = None
    base64_preview: Optional[str] = None  # First 100 bytes in base64 for preview
    warnings: List[str] = field(default_factory=list)


@dataclass
class AttachmentAnalysis:
    """Results of attachment analysis."""
    attachments: List[AttachmentInfo] = field(default_factory=list)
    total_size: int = 0
    has_attachments: bool = False
    suspicious_count: int = 0
    executable_count: int = 0
    total_virustotal_links: List[Tuple[str, str]] = field(default_factory=list)  # (filename, VT link)


# List of suspicious file extensions
SUSPICIOUS_EXTENSIONS = [
    '.exe', '.dll', '.bat', '.cmd', '.ps1', '.psm1', '.vbs', '.vbe',
    '.js', '.jse', '.ws', '.wsf', '.wsc', '.wsh', '.psc1', '.psc2',
    '.msi', '.msp', '.mst', '.cpl', '.scr', '.reg', '.lnk', '.pif',
    '.com', '.cab', '.inf', '.hta', '.msh', '.msh1', '.msh2', '.msh1xml',
    '.msh2xml', '.mshxml', '.scf', '.url', '.jar', '.class',
    '.app', '.apk', '.ipa', '.dmg', '.iso', '.img', '.bin', '.dat',
    '.sys', '.drv', '.ocx', '.bpl', '.dll'
]

# List of document extensions that can contain macros
DOCUMENT_EXTENSIONS = [
    '.doc', '.docm', '.docx', '.dot', '.dotm', '.dotx',
    '.xls', '.xlsx', '.xlsm', '.xlsb', '.xlt', '.xltm', '.xltx',
    '.ppt', '.pptx', '.pptm', '.pps', '.ppsm', '.ppsx', '.pot', '.potm', '.potx',
    '.rtf', '.pdf', '.pages', '.numbers', '.keynote'
]

# Maximum size for base64 preview (in bytes)
MAX_PREVIEW_SIZE = 100


def analyse_attachments(eml_content: str, upload_dir: Optional[Path] = None) -> AttachmentAnalysis:
    """
    Analyze all attachments in an EML file.
    
    Args:
        eml_content: Raw EML file content
        upload_dir: Optional directory to save attachments
        
    Returns:
        AttachmentAnalysis object with all results
    """
    analysis = AttachmentAnalysis()
    
    # Extract attachments from EML
    attachments_data = _extract_attachments_from_eml(eml_content)
    
    for filename, content, content_type in attachments_data:
        # Create attachment info
        attachment = _analyse_attachment(filename, content, content_type)
        analysis.attachments.append(attachment)
        analysis.total_size += attachment.size
        
        if attachment.is_suspicious:
            analysis.suspicious_count += 1
        if attachment.is_executable:
            analysis.executable_count += 1
        
        # Generate VirusTotal link (for manual checking)
        if attachment.hash_sha256:
            vt_link = f"https://www.virustotal.com/gui/search/{attachment.hash_sha256}"
            analysis.total_virustotal_links.append((attachment.filename, vt_link))
        
        # Save attachment if upload_dir is provided
        if upload_dir and content:
            _save_attachment(upload_dir, filename, content)
    
    analysis.has_attachments = len(analysis.attachments) > 0
    return analysis


def _extract_attachments_from_eml(eml_content: str) -> List[Tuple[str, bytes, str]]:
    """
    Extract attachments from raw EML content.
    
    Args:
        eml_content: Raw EML file content
        
    Returns:
        List of tuples: (filename, content, content_type)
    """
    attachments = []
    
    try:
        # Use mail-parser library if available
        from mailparser import parse_from_string
        mail = parse_from_string(eml_content)
        
        # Get all attachments
        for attachment in mail.attachments:
            filename = attachment.filename or f"unnamed_{len(attachments)}"
            content = attachment.payload
            content_type = attachment.content_type or "application/octet-stream"
            attachments.append((filename, content, content_type))
    
    except ImportError:
        # Fallback to manual parsing if mail-parser is not available
        attachments = _manual_extract_attachments(eml_content)
    
    return attachments


def _manual_extract_attachments(eml_content: str) -> List[Tuple[str, bytes, str]]:
    """
    Manual extraction of attachments from EML (fallback method).
    """
    attachments = []
    
    # Split by boundary
    content_type = _get_content_type(eml_content)
    if not content_type or 'boundary=' not in content_type.lower():
        return attachments
    
    # Extract boundary
    boundary_match = re.search(r'boundary="?([^";\s]+)"?', content_type, re.IGNORECASE)
    if not boundary_match:
        boundary_match = re.search(r'boundary=([^;\s]+)', content_type, re.IGNORECASE)
    
    if not boundary_match:
        return attachments
    
    boundary = boundary_match.group(1)
    
    # Split by boundary
    parts = re.split(r'--' + re.escape(boundary) + r'--?', eml_content)
    
    for part in parts:
        if not part.strip() or part.strip() == '--':
            continue
        
        filename, content, content_type = _parse_attachment_part(part)
        if filename and content:
            attachments.append((filename, content, content_type))
    
    return attachments


def _get_content_type(eml_content: str) -> Optional[str]:
    """Get Content-Type header from EML."""
    for line in eml_content.split('\n'):
        if line.lower().startswith('content-type:'):
            return line.split(':', 1)[1].strip()
    return None


def _parse_attachment_part(part: str) -> Tuple[Optional[str], Optional[bytes], str]:
    """Parse a single attachment part from EML."""
    filename = None
    content_type = "application/octet-stream"
    content = None
    
    lines = part.split('\n')
    in_headers = True
    headers = {}
    body_lines = []
    
    for line in lines:
        if in_headers:
            if not line.strip():
                in_headers = False
                continue
            if ': ' in line:
                key, value = line.split(': ', 1)
                headers[key.lower()] = value.strip()
        else:
            body_lines.append(line)
    
    # Extract filename
    content_disposition = headers.get('content-disposition', '')
    filename_match = re.search(r'filename="?([^";\s]+)"?', content_disposition, re.IGNORECASE)
    if filename_match:
        filename = filename_match.group(1)
    elif 'filename' in headers:
        filename = headers['filename']
    
    # Extract content type
    if 'content-type' in headers:
        content_type = headers['content-type']
    
    # Extract content
    body = '\n'.join(body_lines)
    if body.strip():
        try:
            content = base64.b64decode(body)
        except:
            try:
                content = body.encode('utf-8')
            except:
                content = None
    
    return filename, content, content_type


def _analyse_attachment(filename: str, content: bytes, content_type: str) -> AttachmentInfo:
    """
    Analyze a single attachment.
    
    Args:
        filename: Attachment filename
        content: Attachment content as bytes
        content_type: MIME type of the attachment
        
    Returns:
        AttachmentInfo object
    """
    info = AttachmentInfo(
        filename=filename,
        content_type=content_type,
        size=len(content) if content else 0,
        file_extension=Path(filename).suffix.lower() if filename else ''
    )
    
    # Detect actual file type using magic
    if content:
        try:
            # Use python-magic for better detection
            magic_result = magic.from_buffer(content, mime=True)
            info.magic_type = magic_result
            info.magic_description = magic.from_buffer(content)
        except:
            pass
    
    # Check if executable
    info.is_executable = _is_executable(filename, content_type, info.file_extension)
    
    # Check if suspicious
    info.is_suspicious = _is_suspicious(filename, content_type, info.file_extension)
    
    # Generate hashes
    if content:
        info.hash_sha256 = _generate_sha256(content)
        info.hash_md5 = _generate_md5(content)
        
        # Generate base64 preview (first 100 bytes)
        preview = content[:MAX_PREVIEW_SIZE]
        try:
            info.base64_preview = base64.b64encode(preview).decode('utf-8')
        except:
            pass
    
    # Add warnings
    info.warnings = _generate_warnings(filename, content_type, info)
    
    return info


def _is_executable(filename: str, content_type: str, extension: str) -> bool:
    """Check if file is executable."""
    # Check extension
    if extension.lower() in [ext.lower() for ext in SUSPICIOUS_EXTENSIONS]:
        return True
    
    # Check content type
    executable_types = [
        'application/x-msdownload',
        'application/x-dosexec',
        'application/x-exe',
        'application/x-winexe',
        'application/x-msi',
        'application/java-archive',
        'application/x-java-applet',
        'application/x-sh',
        'application/x-bat',
        'application/x-python',
        'application/x-perl',
        'application/x-ruby',
    ]
    
    if content_type.lower() in executable_types:
        return True
    
    # Check magic type
    if 'executable' in content_type.lower() or 'script' in content_type.lower():
        return True
    
    return False


def _is_suspicious(filename: str, content_type: str, extension: str) -> bool:
    """Check if file is suspicious."""
    # Executables are always suspicious
    if _is_executable(filename, content_type, extension):
        return True
    
    # Check for double extensions
    if _has_double_extension(filename):
        return True
    
    # Check for mismatched extension and content type
    if _has_mismatched_extension(content_type, extension):
        return True
    
    return False


def _has_double_extension(filename: str) -> bool:
    """Check if filename has double extension (e.g., file.pdf.exe)."""
    parts = filename.lower().split('.')
    if len(parts) >= 3:
        # Check if last two parts are suspicious
        for ext in SUSPICIOUS_EXTENSIONS:
            if parts[-1] == ext[1:] or parts[-2] + '.' + parts[-1] == ext[1:]:
                return True
    return False


def _has_mismatched_extension(content_type: str, extension: str) -> bool:
    """Check if content type doesn't match file extension."""
    # Common mismatches
    mismatches = {
        '.pdf': ['application/x-dosexec', 'application/x-msdownload'],
        '.doc': ['application/x-dosexec', 'application/x-msdownload'],
        '.xls': ['application/x-dosexec', 'application/x-msdownload'],
        '.jpg': ['application/x-dosexec', 'application/x-msdownload'],
        '.png': ['application/x-dosexec', 'application/x-msdownload'],
    }
    
    if extension in mismatches:
        if content_type.lower() in mismatches[extension]:
            return True
    
    return False


def _generate_warnings(filename: str, content_type: str, info: AttachmentInfo) -> List[str]:
    """Generate warnings for the attachment."""
    warnings = []
    
    # Warning for executable files
    if info.is_executable:
        warnings.append(f"⚠️ Executable file detected: {filename}")
    
    # Warning for double extension
    if _has_double_extension(filename):
        warnings.append(f"⚠️ Double extension detected: {filename}")
    
    # Warning for mismatched extension
    if _has_mismatched_extension(content_type, info.file_extension):
        warnings.append(f"⚠️ Content type mismatch: {filename} ({content_type} vs {info.file_extension})")
    
    # Warning for large files
    if info.size > 10 * 1024 * 1024:  # > 10MB
        warnings.append(f"⚠️ Large attachment: {filename} ({info.size / 1024 / 1024:.1f} MB)")
    
    # Warning for macro-enabled documents
    if info.file_extension in [ext for ext in DOCUMENT_EXTENSIONS]:
        warnings.append(f"⚠️ Document with potential macros: {filename}")
    
    return warnings


def _generate_sha256(content: bytes) -> str:
    """Generate SHA256 hash of content."""
    return hashlib.sha256(content).hexdigest()


def _generate_md5(content: bytes) -> str:
    """Generate MD5 hash of content."""
    return hashlib.md5(content).hexdigest()


def _save_attachment(upload_dir: Path, filename: str, content: bytes) -> Optional[Path]:
    """
    Save attachment to upload directory.
    
    Args:
        upload_dir: Directory to save attachment
        filename: Attachment filename
        content: Attachment content
        
    Returns:
        Path to saved file, or None if failed
    """
    try:
        # Sanitize filename
        safe_filename = _sanitize_filename(filename)
        
        # Create upload directory if it doesn't exist
        upload_dir.mkdir(parents=True, exist_ok=True)
        
        # Save file
        filepath = upload_dir / safe_filename
        
        # Avoid overwriting
        counter = 1
        while filepath.exists():
            name, ext = safe_filename.rsplit('.', 1) if '.' in safe_filename else (safe_filename, '')
            new_filename = f"{name}_{counter}" + (f".{ext}" if ext else "")
            filepath = upload_dir / new_filename
            counter += 1
        
        filepath.write_bytes(content)
        return filepath
    
    except Exception as e:
        print(f"Error saving attachment {filename}: {e}")
        return None


def _sanitize_filename(filename: str) -> str:
    """Sanitize filename to remove dangerous characters."""
    # Remove path information
    filename = Path(filename).name
    
    # Remove or replace dangerous characters
    dangerous_chars = ['<', '>', ':', '"', '/', '\\', '|', '?', '*']
    for char in dangerous_chars:
        filename = filename.replace(char, '_')
    
    # Limit length
    if len(filename) > 255:
        ext = Path(filename).suffix
        name = filename[:255 - len(ext)] if ext else filename[:255]
        filename = name + ext
    
    return filename
