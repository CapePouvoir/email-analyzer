"""
Email Forensic Analyzer - FastAPI Backend
Main application entry point

Author: Randra Timothy RAZAFINDRABE (CapePouvoir / D3adinsid3)
"""

from fastapi import FastAPI, UploadFile, File, HTTPException, Request, Form
from fastapi.responses import HTMLResponse, FileResponse, PlainTextResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path
import uvicorn
import logging
import aiofiles
import os

from backend.config import get_settings
from backend.analyser import (
    analyse_headers, analyse_attachments, analyse_links,
    HeaderAnalysis, AttachmentAnalysis, LinkAnalysis,
    ReportGenerator
)
from backend.ollama_client import OllamaClient

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Email Forensic Analyzer",
    description="Plateforme d'analyse automatisée d'emails (.eml) pour SOC - Développé par Randra Timothy RAZAFINDRABE",
    version="0.1.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# Load settings
settings = get_settings()

# Setup templates and static files
BASE_DIR = Path(__file__).parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "frontend" / "templates"))
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "frontend" / "static")), name="static")

# Initialize Ollama client
ollama_client = OllamaClient()

# Initialize report generator
report_generator = ReportGenerator()


# Helper function to convert AttachmentInfo to dict
from backend.analyser.attachments import AttachmentInfo
from backend.analyser.links import LinkInfo

def attachment_to_dict(attachment: AttachmentInfo) -> dict:
    """Convert AttachmentInfo to dictionary."""
    return {
        'filename': attachment.filename,
        'content_type': attachment.content_type,
        'size': attachment.size,
        'file_extension': attachment.file_extension,
        'is_executable': attachment.is_executable,
        'is_suspicious': attachment.is_suspicious,
        'hash_sha256': attachment.hash_sha256,
        'hash_md5': attachment.hash_md5,
        'magic_type': attachment.magic_type,
        'magic_description': attachment.magic_description,
        'warnings': attachment.warnings
    }


def link_to_dict(link: LinkInfo) -> dict:
    """Convert LinkInfo to dictionary."""
    return {
        'original_url': link.original_url,
        'normalized_url': link.normalized_url,
        'domain': link.domain,
        'path': link.path,
        'query': link.query,
        'fragment': link.fragment,
        'is_https': link.is_https,
        'is_http': link.is_http,
        'is_relative': link.is_relative,
        'is_shortened': link.is_shortened,
        'is_suspicious': link.is_suspicious,
        'shortener_service': link.shortener_service,
        'final_url': link.final_url,
        'warnings': link.warnings
    }


def header_to_dict(header: HeaderAnalysis) -> dict:
    """Convert HeaderAnalysis to dictionary."""
    return {
        'from_address': header.from_address,
        'from_domain': header.from_domain,
        'to_addresses': header.to_addresses,
        'subject': header.subject,
        'date': header.date,
        'source_ip': header.source_ip,
        'received_from': header.received_from,
        'received_by': header.received_by,
        'spf_result': header.spf_result,
        'spf_domain': header.spf_domain,
        'dkim_result': header.dkim_result,
        'dkim_domain': header.dkim_domain,
        'dmarc_result': header.dmarc_result,
        'dmarc_policy': header.dmarc_policy,
        'is_spf_pass': header.is_spf_pass,
        'is_dkim_pass': header.is_dkim_pass,
        'is_dmarc_pass': header.is_dmarc_pass,
        'is_suspicious': header.is_suspicious,
        'warnings': header.warnings,
        'raw_headers': header.raw_headers
    }


# ============================================================================
# Routes
# ============================================================================

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    """Main page with drag & drop interface."""
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/health", tags=["health"])
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "version": "0.1.0",
        "ollama_url": settings.OLLAMA_URL,
        "ollama_model": settings.OLLAMA_MODEL,
    }


@app.post("/api/upload", tags=["analysis"])
async def upload_email(
    file: UploadFile = File(...),
    context: Optional[str] = Form(None)
):
    """
    Upload and analyze an email file (.eml).
    
    This endpoint accepts a .eml file and optional user context, 
    then returns a comprehensive analysis report.
    
    The analysis includes:
    - Header analysis (SPF, DKIM, DMARC, IP reputation)
    - Attachment analysis (hashes, file types, suspicious files)
    - Link analysis (URLs, domains, shortened links)
    - LLM-based contextual analysis (via Ollama) with optional user context
    - Markdown report generation
    """
    # Check file extension
    if not file.filename.lower().endswith('.eml'):
        raise HTTPException(
            status_code=400,
            detail="Only .eml files are accepted"
        )
    
    # Check file size
    file_size = len(await file.read())
    if file_size > settings.max_file_size_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum size: {settings.MAX_FILE_SIZE_MB}MB"
        )
    
    # Reset file pointer after reading
    file.file.seek(0)
    
    # Read file content
    eml_content = await file.read()
    eml_content_str = eml_content.decode('utf-8', errors='replace')
    
    # Log custom context if provided
    if context:
        logger.info(f"User provided context: {context[:100]}...")
    
    logger.info(f"Analyzing file: {file.filename} ({len(eml_content)} bytes)")
    
    try:
        # Step 1: Analyze headers
        logger.info(f"Analyzing headers for {file.filename}")
        header_analysis = analyse_headers(eml_content_str)
        logger.info(f"Headers analysis complete: from={header_analysis.from_address}, subject={header_analysis.subject}")
        
        # Step 2: Analyze attachments
        upload_dir = settings.UPLOAD_DIR
        logger.info(f"Analyzing attachments for {file.filename}")
        attachment_analysis = analyse_attachments(eml_content_str, upload_dir)
        logger.info(f"Attachments analysis complete: {len(attachment_analysis.attachments)} attachments found")
        
        # Step 3: Analyze links
        logger.info(f"Analyzing links for {file.filename}")
        link_analysis = analyse_links(eml_content_str, follow_redirects=False)
        logger.info(f"Links analysis complete: {link_analysis.total_links} links found")
        
        # Step 4: Analyze with Ollama (if available)
        ollama_analysis = None
        if ollama_client.check_health():
            try:
                logger.info(f"Running Ollama analysis for {file.filename}")
                ollama_analysis = ollama_client.analyze_email(
                    headers=header_to_dict(header_analysis),
                    attachments=[attachment_to_dict(a) for a in attachment_analysis.attachments],
                    links=[link_to_dict(l) for l in link_analysis.links],
                    email_content=eml_content_str,
                    custom_context=context
                )
                logger.info(f"Ollama analysis complete for {file.filename}")
            except Exception as e:
                logger.warning(f"Ollama analysis failed for {file.filename}: {e}")
                ollama_analysis = {
                    'verdict': 'Ollama non disponible',
                    'context_analysis': str(e),
                    'recommendations': [],
                    'confidence': 0.0
                }
        else:
            logger.warning(f"Ollama not available for {file.filename}")
            ollama_analysis = {
                'verdict': 'Ollama non disponible',
                'context_analysis': 'Le service Ollama n\'est pas démarré. Démarrez-le avec: ollama serve',
                'recommendations': [],
                'confidence': 0.0
            }
        
        # Step 5: Generate report
        logger.info(f"Generating report for {file.filename}")
        report = report_generator.generate(
            eml_content=eml_content_str,
            header_analysis=header_analysis,
            attachment_analysis=attachment_analysis,
            link_analysis=link_analysis,
            ollama_analysis=ollama_analysis,
            template='full'
        )
        
        # Prepare response
        response_data = {
            "status": "analyzed",
            "filename": file.filename,
            "size": len(eml_content),
            "report": {
                "markdown": report.markdown,
                "severity": report.severity,
                "score": report.score,
                "filename": report.filename,
                "hash": report.hash_sha256,
                "date": report.analysis_date.isoformat()
            },
            "analysis": {
                "headers": header_to_dict(header_analysis),
                "attachments": [attachment_to_dict(a) for a in attachment_analysis.attachments],
                "links": [link_to_dict(l) for l in link_analysis.links],
                "ollama": ollama_analysis
            },
            "virustotal_links": attachment_analysis.total_virustotal_links
        }
        
        logger.info(f"Analysis complete for {file.filename}")
        return response_data
        
    except Exception as e:
        logger.error(f"Analysis failed for {file.filename}: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {str(e)}"
        )


# ============================================================================
# Admin Routes
# ============================================================================

@app.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request):
    """Admin interface (password protected)."""
    # TODO: Implement admin auth
    return templates.TemplateResponse("admin.html", {"request": request})


@app.get("/api/report/{report_hash}", tags=["analysis"])
async def get_report(report_hash: str):
    """
    Get a specific report by its hash.
    
    Returns the Markdown report content.
    """
    # In a real implementation, we would store reports in a database
    # For now, return a 404
    raise HTTPException(
        status_code=404,
        detail="Report storage not yet implemented. Reports are generated on-the-fly."
    )


@app.get("/api/health/ollama", tags=["health"])
async def ollama_health():
    """Check Ollama service health."""
    is_healthy = ollama_client.check_health()
    models = ollama_client.list_models()
    
    return {
        "status": "healthy" if is_healthy else "unhealthy",
        "ollama_running": is_healthy,
        "available_models": models or [],
        "current_model": settings.OLLAMA_MODEL
    }


@app.get("/api/health", tags=["health"])
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "version": "0.1.0",
        "author": "Randra Timothy RAZAFINDRABE (CapePouvoir / D3adinsid3)",
        "ollama_url": settings.OLLAMA_URL,
        "ollama_model": settings.OLLAMA_MODEL,
        "upload_dir": str(settings.UPLOAD_DIR),
        "max_file_size_mb": settings.MAX_FILE_SIZE_MB
    }


# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == "__main__":
    uvicorn.run(
        "backend.app:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=True,
        log_level="info",
    )
