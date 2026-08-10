"""
Email Forensic Analyzer - FastAPI Backend
Main application entry point
"""

from fastapi import FastAPI, UploadFile, File, HTTPException, Request
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path
import uvicorn
import logging

from backend.config import get_settings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Email Forensic Analyzer",
    description="Plateforme d'analyse automatisée d'emails (.eml) pour SOC",
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
async def upload_email(file: UploadFile = File(...)):
    """
    Upload and analyze an email file (.eml).
    
    This endpoint accepts a .eml file and returns an analysis report.
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
    
    # TODO: Implement full analysis here
    # For now, return a placeholder response
    logger.info(f"Received file: {file.filename} ({file_size} bytes)")
    
    return {
        "status": "received",
        "filename": file.filename,
        "size": file_size,
        "message": "Analysis pipeline will be implemented next. For now, file is accepted.",
        "next_steps": [
            "Parse .eml file",
            "Extract headers and attachments",
            "Generate SHA256 hashes",
            "Call Ollama for contextual analysis",
            "Generate Markdown report"
        ]
    }


# ============================================================================
# Admin Routes
# ============================================================================

@app.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request):
    """Admin interface (password protected)."""
    # TODO: Implement admin auth
    return templates.TemplateResponse("admin.html", {"request": request})


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
