"""
Email Forensic Analyzer - System Utilities
Handles system information detection (RAM, etc.) for model selection.

Author: Randra Timothy RAZAFINDRABE (CapePouvoir / D3adinsid3)
"""

import os
import psutil
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# Minimum RAM requirements for models (in GB)
MODEL_RAM_REQUIREMENTS: Dict[str, int] = {
    'phi3': 4,            # Lightweight model
    'mistral': 8,        # Balanced model
    'llama3': 8,         # Alternative to Mistral
    'deepseek': 16,      # Powerful model, requires more RAM
    'deepseek-coder': 8, # Smaller variant, similar to mistral in size
}

# Model priority order (preferred models when RAM is sufficient)
MODEL_PRIORITY: list[str] = ['deepseek', 'deepseek-coder', 'mistral', 'llama3', 'phi3']


def get_available_ram_gb() -> float:
    """
    Get available RAM in GB.
    
    Returns:
        Available RAM in gigabytes
    """
    try:
        # Get total available memory
        available_bytes = psutil.virtual_memory().available
        available_gb = available_bytes / (1024 ** 3)
        logger.info(f"Available RAM: {available_gb:.2f} GB")
        return available_gb
    except Exception as e:
        logger.warning(f"Could not detect available RAM: {e}")
        # Fallback: try to read from /proc/meminfo on Linux
        try:
            if os.path.exists('/proc/meminfo'):
                with open('/proc/meminfo', 'r') as f:
                    for line in f:
                        if line.startswith('MemAvailable:'):
                            # Extract value in kB and convert to GB
                            available_kb = int(line.split()[1])
                            available_gb = available_kb / (1024 ** 2)
                            logger.info(f"Available RAM (fallback): {available_gb:.2f} GB")
                            return available_gb
        except Exception as e2:
            logger.warning(f"Fallback RAM detection also failed: {e2}")
        
        # Default to 8 GB if detection fails (conservative choice)
        logger.warning("Using default RAM value of 8 GB")
        return 8.0


def get_total_ram_gb() -> float:
    """
    Get total RAM in GB.
    
    Returns:
        Total RAM in gigabytes
    """
    try:
        total_bytes = psutil.virtual_memory().total
        total_gb = total_bytes / (1024 ** 3)
        logger.info(f"Total RAM: {total_gb:.2f} GB")
        return total_gb
    except Exception as e:
        logger.warning(f"Could not detect total RAM: {e}")
        return 8.0


def normalize_model_name(model_name: str) -> str:
    """
    Normalize model name by removing tag/version suffix.
    
    Examples:
        deepseek-coder:latest -> deepseek-coder
        mistral:latest -> mistral
        llama3:7b -> llama3
    
    Args:
        model_name: Full model name from Ollama
    
    Returns:
        Normalized model name (base name without tag)
    """
    # Remove everything after : (tag) or - (variant)
    # Keep the base name
    base_name = model_name.split(':')[0].split('-')[0].lower()
    return base_name


def get_model_base_name(model_name: str) -> str:
    """
    Get the base name of a model, handling various naming conventions.
    
    Args:
        model_name: Model name (could be mistral, mistral:latest, deepseek-coder:latest, etc.)
    
    Returns:
        Base model name
    """
    # Remove tag (everything after :)
    name_without_tag = model_name.split(':')[0]
    
    # For models like deepseek-coder, keep as deepseek-coder
    # For models like mistral, use mistral
    # Map known variants to their base
    model_mapping = {
        'deepseek': 'deepseek',
        'mistral': 'mistral',
        'llama3': 'llama3',
        'phi3': 'phi3',
    }
    
    base = name_without_tag.lower()
    # Only map if there's a mapping, otherwise keep the original name
    return model_mapping.get(base, base)


def select_model_based_on_ram(
    available_models: list[str],
    available_ram_gb: Optional[float] = None,
    preferred_model: Optional[str] = None,
    use_total_ram: bool = True
) -> str:
    """
    Select the best model based on available RAM and available models.
    
    Args:
        available_models: List of models available in Ollama (e.g., ['mistral:latest', 'deepseek-coder:latest'])
        available_ram_gb: Available RAM in GB (auto-detected if None)
        preferred_model: Optional model to prefer (from .env, e.g., 'mistral', 'deepseek', 'deepseek-coder')
        use_total_ram: If True, use total RAM for selection. If False, use available RAM.
    
    Returns:
        Selected model name (full name as returned by Ollama, e.g., 'mistral:latest')
    """
    # Detect RAM if not provided - use total RAM for selection
    if available_ram_gb is None:
        if use_total_ram:
            available_ram_gb = get_total_ram_gb()
        else:
            available_ram_gb = get_available_ram_gb()
    
    ram_type = "total" if use_total_ram else "available"
    logger.info(f"Selecting model with {available_ram_gb:.2f} GB RAM {ram_type}")
    
    # Normalize preferred model name - also map it to base name
    if preferred_model:
        preferred_base = get_model_base_name(preferred_model.lower())
    else:
        preferred_base = None
    
    # Check if preferred model is available
    if preferred_base:
        for ollama_model in available_models:
            ollama_base = get_model_base_name(ollama_model)
            if ollama_base == preferred_base:
                required_ram = MODEL_RAM_REQUIREMENTS.get(ollama_base, 8)
                if available_ram_gb >= required_ram:
                    logger.info(f"Using preferred model: {ollama_model} (base: {ollama_base}, requires {required_ram} GB, have {available_ram_gb:.2f} GB)")
                    return ollama_model
                else:
                    logger.warning(
                        f"Preferred model {ollama_model} (base: {ollama_base}) requires {required_ram} GB "
                        f"but only {available_ram_gb:.2f} GB {ram_type}. Falling back to auto-selection."
                    )
                    break  # Found but not enough RAM, stop looking
        else:
            # Preferred model not found in available models
            logger.warning(
                f"Preferred model (base: {preferred_base}) not available. "
                f"Available models: {available_models}. Falling back to auto-selection."
            )
    
    # Auto-select based on priority and RAM requirements
    # Try each priority model and find a matching available model
    for base_model in MODEL_PRIORITY:
        required_ram = MODEL_RAM_REQUIREMENTS.get(base_model, 8)
        if available_ram_gb < required_ram:
            continue  # Not enough RAM for this model
        
        # Find an available model that matches this base
        for ollama_model in available_models:
            ollama_base = get_model_base_name(ollama_model)
            if ollama_base == base_model:
                logger.info(f"Auto-selected model: {ollama_model} (base: {base_model}, requires {required_ram} GB, have {available_ram_gb:.2f} GB)")
                return ollama_model
    
    # Fallback: return first available model
    if available_models:
        fallback_model = available_models[0]
        fallback_base = get_model_base_name(fallback_model)
        fallback_ram = MODEL_RAM_REQUIREMENTS.get(fallback_base, 8)
        logger.warning(f"No ideal model found. Falling back to: {fallback_model} (base: {fallback_base}, requires {fallback_ram} GB)")
        return fallback_model
    
    # Absolute fallback
    logger.warning("No models available. Using default: mistral:latest")
    return "mistral:latest"


def get_model_ram_requirement(model_name: str) -> int:
    """
    Get the minimum RAM requirement for a specific model.
    
    Args:
        model_name: Name of the model
    
    Returns:
        Minimum RAM in GB (defaults to 8 if unknown)
    """
    return MODEL_RAM_REQUIREMENTS.get(model_name.lower(), 8)


def check_ollama_available() -> bool:
    """
    Check if Ollama is installed and running.
    
    Returns:
        True if Ollama is available, False otherwise
    """
    try:
        import requests
        response = requests.get("http://127.0.0.1:11434/api/tags", timeout=5)
        return response.status_code == 200
    except Exception:
        return False
