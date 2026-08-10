"""
Configuration management for Email Forensic Analyzer
Loads environment variables from .env file
"""

import os
from pathlib import Path
from typing import Optional
from pydantic_settings import BaseSettings
from pydantic import Field, field_validator


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # Ollama Configuration
    OLLAMA_URL: str = Field(
        default="http://localhost:11434",
        description="URL of the Ollama API server"
    )
    OLLAMA_MODEL: str = Field(
        default="mistral",
        description="Ollama model to use for analysis (e.g., mistral, deepseek, llama3)"
    )
    OLLAMA_TIMEOUT: int = Field(
        default=120,
        description="Timeout for Ollama API requests in seconds"
    )
    
    # Storage Configuration
    UPLOAD_DIR: Path = Field(
        default=Path("./data/uploads"),
        description="Directory to store uploaded .eml files"
    )
    CLEANUP_DAYS: int = Field(
        default=7,
        description="Number of days before automatic cleanup of uploaded files"
    )
    
    # Server Configuration
    HOST: str = Field(
        default="0.0.0.0",
        description="Host for the FastAPI server"
    )
    PORT: int = Field(
        default=8000,
        description="Port for the FastAPI server"
    )
    
    # Admin Authentication
    ADMIN_PASSWORD: Optional[str] = Field(
        default=None,
        description="Password for admin interface. Leave empty to disable admin auth."
    )
    
    # Analysis Options
    MAX_FILE_SIZE_MB: int = Field(
        default=50,
        description="Maximum file size for uploads in MB"
    )
    BLOCKED_EXTENSIONS: str = Field(
        default=".exe,.bat,.sh,.js,.vbs,.ps1,.jar,.msi",
        description="Comma-separated list of blocked file extensions"
    )
    
    # VirusTotal (Optional)
    VIRUSTOTAL_API_KEY: Optional[str] = Field(
        default=None,
        description="VirusTotal API key for automatic hash checking. Leave empty to disable."
    )
    
    @field_validator('UPLOAD_DIR', mode='before')
    @classmethod
    def validate_upload_dir(cls, v):
        """Convert string to Path and ensure directory exists."""
        path = Path(v)
        path.mkdir(parents=True, exist_ok=True)
        return path
    
    @property
    def blocked_extensions_list(self) -> list[str]:
        """Return blocked extensions as a list."""
        return [ext.strip().lower() for ext in self.BLOCKED_EXTENSIONS.split(",") if ext.strip()]
    
    @property
    def max_file_size_bytes(self) -> int:
        """Return max file size in bytes."""
        return self.MAX_FILE_SIZE_MB * 1024 * 1024
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"


# Global settings instance
settings = Settings()


def get_settings() -> Settings:
    """Get the global settings instance."""
    return settings
