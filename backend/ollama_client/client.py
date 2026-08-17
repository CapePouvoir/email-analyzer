"""
Email Forensic Analyzer - Ollama Client Module
Handles communication with local Ollama API for LLM analysis.

Author: Randra Timothy RAZAFINDRABE (CapePouvoir / D3adinsid3)
"""

import json
import requests
from typing import Optional, Dict, Any, List
from pathlib import Path
import logging

from backend.config import get_settings
from backend.utils.system import (
    select_model_based_on_ram, 
    get_available_ram_gb,
    get_model_ram_requirement
)

logger = logging.getLogger(__name__)


class OllamaClient:
    """Client for interacting with Ollama API."""
    
    def __init__(self, auto_select_model: bool = True):
        """
        Initialize Ollama client.
        
        Args:
            auto_select_model: If True, automatically select the best model
                             based on available RAM and available models.
                             If False, use the model from settings.
        """
        self.settings = get_settings()
        self.base_url = self.settings.OLLAMA_URL.rstrip('/')
        # Force localhost to 127.0.0.1 to avoid DNS resolution issues
        if self.base_url == 'http://localhost:11434':
            self.base_url = 'http://127.0.0.1:11434'
        self.timeout = self.settings.OLLAMA_TIMEOUT
        
        # Store preferred model from settings
        self.preferred_model = self.settings.OLLAMA_MODEL
        
        # Auto-select model based on RAM if requested
        if auto_select_model:
            self.model = self._auto_select_model()
        else:
            # If not auto-selecting, try to match the preferred model with available models
            self.model = self._match_model_name(self.preferred_model)
        
        logger.info(f"Ollama client initialized with model: {self.model}")
    
    def _match_model_name(self, model_name: str) -> str:
        """
        Match a model name with available models in Ollama.
        
        Args:
            model_name: Preferred model name (e.g., 'mistral', 'deepseek')
        
        Returns:
            Full model name as available in Ollama (e.g., 'mistral:latest')
        """
        from backend.utils.system import get_model_base_name
        
        available_models = self.list_models()
        if not available_models:
            return model_name
        
        # Try to find a model with matching base name
        preferred_base = get_model_base_name(model_name)
        for ollama_model in available_models:
            if get_model_base_name(ollama_model) == preferred_base:
                return ollama_model
        
        # If no match, return the original name
        return model_name
    
    def _auto_select_model(self) -> str:
        """
        Automatically select the best model based on available RAM and models.
        
        Returns:
            Selected model name (full name as returned by Ollama)
        """
        # Get available models from Ollama
        available_models = self.list_models()
        
        if not available_models:
            logger.warning("No models available in Ollama. Using preferred model from settings.")
            return self._match_model_name(self.preferred_model)
        
        logger.info(f"Available Ollama models: {available_models}")
        
        # Detect total RAM for model selection
        from backend.utils.system import get_total_ram_gb
        total_ram_gb = get_total_ram_gb()
        logger.info(f"Total RAM: {total_ram_gb:.2f} GB")
        
        # Select model based on RAM and priority
        selected_model = select_model_based_on_ram(
            available_models=available_models,
            available_ram_gb=total_ram_gb,
            preferred_model=self.preferred_model,
            use_total_ram=True
        )
        
        # Check if the selected model requires more RAM than available (use available RAM for warning)
        available_ram_gb = get_available_ram_gb()
        required_ram = get_model_ram_requirement(selected_model)
        if available_ram_gb < required_ram:
            logger.warning(
                f"Selected model {selected_model} requires {required_ram} GB "
                f"but only {available_ram_gb:.2f} GB currently available. "
                f"Consider closing other applications."
            )
        
        return selected_model
    
    def reselect_model(self) -> str:
        """
        Re-select the model based on current conditions.
        
        Returns:
            Newly selected model name
        """
        old_model = self.model
        self.model = self._auto_select_model()
        if old_model != self.model:
            logger.info(f"Model changed from {old_model} to {self.model}")
        return self.model
    
    def set_model(self, model_name: str) -> None:
        """
        Manually set the model to use.
        
        Args:
            model_name: Name of the model to use
        """
        self.model = model_name
        logger.info(f"Model manually set to: {model_name}")
    
    def get_available_models_info(self) -> Dict[str, Any]:
        """
        Get information about available models and their RAM requirements.
        
        Returns:
            Dictionary with model information
        """
        from backend.utils.system import get_total_ram_gb, get_available_ram_gb
        
        available_models = self.list_models() or []
        
        models_info = {}
        for model in available_models:
            models_info[model] = {
                'available': True,
                'ram_requirement_gb': get_model_ram_requirement(model),
                'selected': model == self.model
            }
        
        # Add models from requirements that are not available
        for model, ram_req in [('phi3', 4), ('mistral', 8), ('llama3', 8), ('deepseek', 16)]:
            if model not in models_info:
                models_info[model] = {
                    'available': False,
                    'ram_requirement_gb': ram_req,
                    'selected': False
                }
        
        return {
            'current_model': self.model,
            'preferred_model': self.preferred_model,
            'total_ram_gb': get_total_ram_gb(),
            'available_ram_gb': get_available_ram_gb(),
            'models': models_info
        }
    
    def generate(
        self,
        prompt: str,
        system: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 2048,
        stream: bool = False
    ) -> Optional[Dict[str, Any]]:
        """
        Generate text using Ollama.
        
        Args:
            prompt: The user prompt
            system: Optional system prompt
            temperature: Creativity level (0-1)
            max_tokens: Maximum tokens to generate
            stream: Whether to stream the response
            
        Returns:
            Response dictionary or None if error
        """
        url = f"{self.base_url}/api/generate"
        
        payload = {
            'model': self.model,
            'prompt': prompt,
            'temperature': temperature,
            'max_tokens': max_tokens,
            'stream': stream,
        }
        
        if system:
            payload['system'] = system
        
        try:
            response = requests.post(
                url,
                json=payload,
                timeout=self.timeout
            )
            response.raise_for_status()
            return response.json()
        
        except requests.exceptions.RequestException as e:
            logger.error(f"Ollama API error: {e}")
            return None
    
    def analyze_email(
        self,
        headers: Dict[str, Any],
        attachments: List[Dict[str, Any]],
        links: List[Dict[str, Any]],
        email_content: Optional[str] = None,
        custom_context: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Analyze email content using Ollama LLM.
        
        Args:
            headers: Header analysis results
            attachments: Attachment analysis results
            links: Link analysis results
            email_content: Optional raw email content
            custom_context: Optional user-provided context for better analysis
            
        Returns:
            Analysis results from LLM
        """
        # Build context for LLM
        context = self._build_context(headers, attachments, links, email_content)
        
        # Add custom context if provided
        if custom_context:
            context += f"\n\n=== CONTEXTE UTILISATEUR ==="
            context += f"\n{custom_context}"
        
        # System prompt for email analysis
        system_prompt = """Tu es un expert en cybersécurité spécialisé dans l'analyse forensique d'emails.
Ton rôle est d'analyser les emails suspects pour détecter les attaques de phishing, malware, et autres menaces.

Analyse les informations fournies et réponds avec :
1. Un verdict clair (Bénin, Suspect, Malveillant)
2. Une analyse contextuelle détaillée
3. Des recommandations actionnables

Sois précis, technique, et basé sur les faits. Réponds en français."""

        # User prompt
        user_prompt = f"""Analyse cet email avec les informations suivantes :

{context}

Fournis ton analyse au format JSON avec les champs :
- verdict (string): "Bénin", "Suspect", ou "Malveillant"
- context_analysis (string): Analyse détaillée du contexte
- recommendations (list): Liste de recommandations
- confidence (float): Niveau de confiance (0.0 - 1.0)"""

        # Call Ollama
        response = self.generate(
            prompt=user_prompt,
            system=system_prompt,
            temperature=0.3,  # Lower temperature for more deterministic results
            max_tokens=4096
        )
        
        if not response:
            return {
                'verdict': 'Error',
                'context_analysis': 'Impossible de contacter Ollama. Vérifiez que le service est démarré.',
                'recommendations': [],
                'confidence': 0.0
            }
        
        # Parse response
        try:
            # Try to parse as JSON (if LLM returned JSON)
            if 'response' in response:
                text = response['response']
                
                # Try to extract JSON from text
                try:
                    # Look for JSON in the response
                    start = text.find('{')
                    end = text.rfind('}') + 1
                    if start >= 0 and end > start:
                        json_str = text[start:end]
                        return json.loads(json_str)
                except:
                    pass
                
                # If not JSON, return structured response
                return {
                    'verdict': 'Analyse manuelle requise',
                    'context_analysis': text,
                    'recommendations': [],
                    'confidence': 0.5
                }
        
        except Exception as e:
            logger.error(f"Error parsing Ollama response: {e}")
            return {
                'verdict': 'Error',
                'context_analysis': f'Erreur lors du parsing: {str(e)}',
                'recommendations': [],
                'confidence': 0.0
            }
    
    def _build_context(
        self,
        headers: Dict[str, Any],
        attachments: List[Dict[str, Any]],
        links: List[Dict[str, Any]],
        email_content: Optional[str]
    ) -> str:
        """Build context string for LLM analysis."""
        context_parts = []
        
        # Headers context
        context_parts.append("=== HEADERS ===")
        context_parts.append(f"Expéditeur: {headers.get('from_address', 'Inconnu')}")
        context_parts.append(f"Sujet: {headers.get('subject', 'Inconnu')}")
        context_parts.append(f"IP Source: {headers.get('source_ip', 'Inconnu')}")
        context_parts.append(f"SPF: {'PASS' if headers.get('is_spf_pass') else 'FAIL'}")
        context_parts.append(f"DKIM: {'PASS' if headers.get('is_dkim_pass') else 'FAIL'}")
        context_parts.append(f"DMARC: {'PASS' if headers.get('is_dmarc_pass') else 'FAIL'}")
        
        if headers.get('warnings'):
            context_parts.append(f"Avertissements headers: {', '.join(headers.get('warnings', []))}")
        
        # Attachments context
        context_parts.append("\n=== PIÈCES JOINTES ===")
        if attachments:
            for i, attachment in enumerate(attachments, 1):
                context_parts.append(f"{i}. {attachment.get('filename', 'Inconnu')}")
                context_parts.append(f"   Type: {attachment.get('content_type', 'Inconnu')}")
                context_parts.append(f"   Taille: {attachment.get('size', 0)} octets")
                context_parts.append(f"   Hash SHA256: {attachment.get('hash_sha256', 'N/A')}")
                context_parts.append(f"   Suspect: {'Oui' if attachment.get('is_suspicious') else 'Non'}")
                if attachment.get('warnings'):
                    context_parts.append(f"   Avertissements: {', '.join(attachment.get('warnings', []))}")
        else:
            context_parts.append("Aucune pièce jointe")
        
        # Links context
        context_parts.append("\n=== LIENS ===")
        if links:
            for i, link in enumerate(links, 1):
                context_parts.append(f"{i}. {link.get('original_url', 'Inconnu')}")
                context_parts.append(f"   Domaine: {link.get('domain', 'Inconnu')}")
                context_parts.append(f"   HTTPS: {'Oui' if link.get('is_https') else 'Non'}")
                context_parts.append(f"   Raccourci: {'Oui' if link.get('is_shortened') else 'Non'}")
                context_parts.append(f"   Suspect: {'Oui' if link.get('is_suspicious') else 'Non'}")
                if link.get('warnings'):
                    context_parts.append(f"   Avertissements: {', '.join(link.get('warnings', []))}")
        else:
            context_parts.append("Aucun lien")
        
        # Email content preview (if available)
        if email_content:
            context_parts.append("\n=== CONTENU (EXTRAIT) ===")
            preview = email_content[:1000]  # First 1000 characters
            context_parts.append(preview)
        
        return "\n".join(context_parts)
    
    def check_health(self) -> bool:
        """Check if Ollama is running and accessible."""
        try:
            url = f"{self.base_url}/api/tags"
            response = requests.get(url, timeout=5)
            return response.status_code == 200
        except:
            return False
    
    def list_models(self) -> Optional[List[str]]:
        """List available models in Ollama."""
        try:
            url = f"{self.base_url}/api/tags"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
            return [model['name'] for model in data.get('models', [])]
        except Exception as e:
            logger.error(f"Error listing models: {e}")
            return None
    
    def pull_model(self, model_name: str) -> bool:
        """Pull a model from Ollama repository."""
        try:
            url = f"{self.base_url}/api/pull"
            payload = {'name': model_name}
            response = requests.post(url, json=payload, timeout=300)  # 5 min timeout
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Error pulling model {model_name}: {e}")
            return False
