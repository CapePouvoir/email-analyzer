"""
Email Forensic Analyzer - Cleanup Utilities
Handles automatic cleanup of old uploaded files.

Author: Randra Timothy RAZAFINDRABE (CapePouvoir / D3adinsid3)
"""

import os
import time
from pathlib import Path
from typing import List, Optional
from datetime import datetime, timedelta
import logging

from backend.config import get_settings

logger = logging.getLogger(__name__)


def get_old_files(upload_dir: Path, days: int) -> List[Path]:
    """
    Get list of files older than specified days.
    
    Args:
        upload_dir: Directory to scan
        days: Number of days to keep files (files older than this will be listed)
    
    Returns:
        List of Path objects for old files
    """
    old_files = []
    cutoff_time = datetime.now() - timedelta(days=days)
    
    if not upload_dir.exists():
        logger.warning(f"Upload directory does not exist: {upload_dir}")
        return old_files
    
    for file_path in upload_dir.iterdir():
        if file_path.is_file():
            try:
                # Get modification time
                mtime = datetime.fromtimestamp(file_path.stat().st_mtime)
                if mtime < cutoff_time:
                    old_files.append(file_path)
            except Exception as e:
                logger.warning(f"Error checking file {file_path}: {e}")
    
    return old_files


def cleanup_old_files(upload_dir: Path, days: int, dry_run: bool = False) -> dict:
    """
    Clean up files older than specified days.
    
    Args:
        upload_dir: Directory to clean
        days: Number of days to keep files
        dry_run: If True, only report what would be deleted without actually deleting
    
    Returns:
        Dictionary with cleanup results:
        {
            'total_files': int,
            'deleted_files': int,
            'deleted_list': List[str],
            'space_freed_bytes': int,
            'dry_run': bool
        }
    """
    settings = get_settings()
    
    # Ensure upload directory exists
    upload_dir = Path(upload_dir)
    
    old_files = get_old_files(upload_dir, days)
    
    deleted_list = []
    space_freed = 0
    
    for file_path in old_files:
        try:
            file_size = file_path.stat().st_size
            if not dry_run:
                file_path.unlink()
                logger.info(f"Deleted old file: {file_path} ({file_size} bytes)")
            deleted_list.append(str(file_path))
            space_freed += file_size
        except Exception as e:
            logger.error(f"Error deleting file {file_path}: {e}")
    
    return {
        'total_files': len(old_files),
        'deleted_files': len(deleted_list),
        'deleted_list': deleted_list,
        'space_freed_bytes': space_freed,
        'space_freed_mb': round(space_freed / (1024 * 1024), 2),
        'dry_run': dry_run
    }


def cleanup_uploads() -> dict:
    """
    Clean up old uploads based on configuration.
    
    Uses CLEANUP_DAYS from settings.
    
    Returns:
        Dictionary with cleanup results
    """
    settings = get_settings()
    upload_dir = settings.UPLOAD_DIR
    cleanup_days = settings.CLEANUP_DAYS
    
    logger.info(f"Starting cleanup of files older than {cleanup_days} days in {upload_dir}")
    
    return cleanup_old_files(upload_dir, cleanup_days)


def cleanup_uploads_dry_run() -> dict:
    """
    Perform a dry run of cleanup to see what would be deleted.
    
    Returns:
        Dictionary with cleanup results (dry_run=True)
    """
    settings = get_settings()
    upload_dir = settings.UPLOAD_DIR
    cleanup_days = settings.CLEANUP_DAYS
    
    logger.info(f"Dry run: checking files older than {cleanup_days} days in {upload_dir}")
    
    return cleanup_old_files(upload_dir, cleanup_days, dry_run=True)


def get_upload_stats() -> dict:
    """
    Get statistics about uploaded files.
    
    Returns:
        Dictionary with upload statistics:
        {
            'total_files': int,
            'total_size_bytes': int,
            'total_size_mb': float,
            'oldest_file_days': int,
            'newest_file_days': int
        }
    """
    settings = get_settings()
    upload_dir = settings.UPLOAD_DIR
    
    if not upload_dir.exists():
        return {
            'total_files': 0,
            'total_size_bytes': 0,
            'total_size_mb': 0.0,
            'oldest_file_days': 0,
            'newest_file_days': 0
        }
    
    files = [f for f in upload_dir.iterdir() if f.is_file()]
    total_size = sum(f.stat().st_size for f in files)
    
    now = datetime.now()
    file_ages = []
    for f in files:
        try:
            mtime = datetime.fromtimestamp(f.stat().st_mtime)
            age_days = (now - mtime).days
            file_ages.append(age_days)
        except:
            pass
    
    return {
        'total_files': len(files),
        'total_size_bytes': total_size,
        'total_size_mb': round(total_size / (1024 * 1024), 2),
        'oldest_file_days': max(file_ages) if file_ages else 0,
        'newest_file_days': min(file_ages) if file_ages else 0
    }


def schedule_cleanup():
    """
    Schedule automatic cleanup (to be called periodically).
    
    This function should be called:
    - At application startup (to clean old files)
    - Periodically (via a background task or cron job)
    
    Returns:
        Dictionary with cleanup results
    """
    settings = get_settings()
    logger.info(f"Running scheduled cleanup (keep files for {settings.CLEANUP_DAYS} days)")
    return cleanup_uploads()
