#!/usr/bin/env python3
"""
Email Forensic Analyzer - Interactive Installation Script

This script guides the user through the installation process:
- Checks system requirements
- Detects available RAM
- Lists available Ollama models
- Allows interactive model selection
- Generates .env configuration file

Author: Randra Timothy RAZAFINDRABE (CapePouvoir / D3adinsid3)
"""

import os
import sys
import subprocess
import json
import requests
from pathlib import Path
from typing import Optional, List, Dict

# Add backend to path for imports
BASE_DIR = Path(__file__).parent
sys.path.insert(0, str(BASE_DIR))

try:
    from backend.utils.system import (
        get_total_ram_gb, 
        get_available_ram_gb,
        MODEL_RAM_REQUIREMENTS,
        MODEL_PRIORITY,
        get_model_base_name
    )
    USE_SYSTEM_MODULE = True
except ImportError:
    USE_SYSTEM_MODULE = False
    # Fallback definitions
    MODEL_RAM_REQUIREMENTS = {
        'phi3': 4,
        'mistral': 8,
        'llama3': 8,
        'deepseek': 16,
    }
    MODEL_PRIORITY = ['deepseek', 'mistral', 'llama3', 'phi3']


# ANSI color codes
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def print_header(text: str) -> None:
    """Print a header with color."""
    print(f"\n{Colors.HEADER}{Colors.BOLD}{text}{Colors.ENDC}")


def print_success(text: str) -> None:
    """Print a success message."""
    print(f"{Colors.OKGREEN}✓ {text}{Colors.ENDC}")


def print_warning(text: str) -> None:
    """Print a warning message."""
    print(f"{Colors.WARNING}⚠ {text}{Colors.ENDC}")


def print_error(text: str) -> None:
    """Print an error message."""
    print(f"{Colors.FAIL}✗ {text}{Colors.ENDC}")


def print_info(text: str) -> None:
    """Print an info message."""
    print(f"{Colors.OKBLUE}ℹ {text}{Colors.ENDC}")


def print_step(number: int, text: str) -> None:
    """Print a step number."""
    print(f"\n{Colors.BOLD}[Étape {number}] {text}{Colors.ENDC}")


def clear_screen() -> None:
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')


def check_python_version() -> bool:
    """Check if Python 3.10+ is installed."""
    print_step(1, "Vérification de Python")
    version = sys.version_info
    print(f"Python {version.major}.{version.minor}.{version.micro} détecté")
    
    if version >= (3, 10):
        print_success("Version de Python compatible (3.10+)")
        return True
    else:
        print_error("Python 3.10 ou supérieur est requis")
        return False


def check_pip_package(package: str) -> bool:
    """Check if a pip package is installed."""
    try:
        import importlib
        importlib.import_module(package)
        return True
    except ImportError:
        return False


def check_ollama_installed() -> bool:
    """Check if Ollama is installed."""
    print_step(2, "Vérification d'Ollama")
    
    # Check if ollama command exists
    try:
        result = subprocess.run(['which', 'ollama'], capture_output=True, text=True)
        if result.returncode == 0:
            print_success("Ollama est installé")
            return True
    except FileNotFoundError:
        pass
    
    print_error("Ollama n'est pas installé")
    print_info("Pour installer Ollama, exécutez :")
    print_info("  curl -fsSL https://ollama.com/install.sh | sh")
    return False


def check_ollama_running() -> bool:
    """Check if Ollama service is running."""
    try:
        response = requests.get("http://127.0.0.1:11434/api/tags", timeout=5)
        if response.status_code == 200:
            print_success("Ollama est démarré")
            return True
    except Exception:
        pass
    
    print_warning("Ollama n'est pas démarré")
    print_info("Pour démarrer Ollama, exécutez :")
    print_info("  ollama serve")
    
    # Try to start it automatically
    try:
        print_info("Tentative de démarrage automatique...")
        subprocess.Popen(['ollama', 'serve'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        import time
        time.sleep(3)
        
        response = requests.get("http://127.0.0.1:11434/api/tags", timeout=5)
        if response.status_code == 200:
            print_success("Ollama a été démarré avec succès !")
            return True
    except Exception:
        pass
    
    return False


def get_ollama_models() -> List[str]:
    """Get list of available Ollama models."""
    try:
        response = requests.get("http://127.0.0.1:11434/api/tags", timeout=10)
        if response.status_code == 200:
            data = response.json()
            return [model['name'] for model in data.get('models', [])]
    except Exception as e:
        print_warning(f"Impossible de récupérer les modèles Ollama: {e}")
    return []


def detect_ram() -> Dict[str, float]:
    """Detect total and available RAM."""
    print_step(3, "Détection de la mémoire (RAM)")
    
    total_ram = 0.0
    available_ram = 0.0
    
    try:
        import psutil
        total_ram = psutil.virtual_memory().total / (1024 ** 3)
        available_ram = psutil.virtual_memory().available / (1024 ** 3)
    except ImportError:
        # Fallback to /proc/meminfo on Linux
        try:
            with open('/proc/meminfo', 'r') as f:
                for line in f:
                    if line.startswith('MemTotal:'):
                        total_ram = int(line.split()[1]) / (1024 ** 2)
                    elif line.startswith('MemAvailable:'):
                        available_ram = int(line.split()[1]) / (1024 ** 2)
        except:
            pass
    
    if total_ram > 0:
        print(f"RAM totale: {total_ram:.2f} GB")
        print(f"RAM disponible: {available_ram:.2f} GB")
    else:
        print_warning("Impossible de détecter la RAM. Utilisation de 8 GB par défaut.")
        total_ram = 8.0
        available_ram = 8.0
    
    return {
        'total': total_ram,
        'available': available_ram
    }


def get_recommended_model(ram_info: Dict[str, float], available_models: List[str]) -> str:
    """Get the recommended model based on RAM and available models."""
    total_ram = ram_info['total']
    
    # Try preferred models in priority order
    for model in MODEL_PRIORITY:
        required_ram = MODEL_RAM_REQUIREMENTS.get(model, 8)
        if total_ram >= required_ram:
            # Check if this model (or a variant) is available
            for ollama_model in available_models:
                if get_model_base_name(ollama_model) == model:
                    return ollama_model
    
    # Fallback: return first available model
    return available_models[0] if available_models else "mistral:latest"


def select_model_interactive(ram_info: Dict[str, float], available_models: List[str]) -> str:
    """
    Interactive model selection menu.
    
    Returns:
        Selected model name
    """
    print_step(4, "Sélection du modèle LLM")
    
    total_ram = ram_info['total']
    available_ram = ram_info['available']
    
    # Show RAM info
    print(f"\n{MODEL_RAM_REQUIREMENTS}")
    print(f"\n{Colors.BOLD}Modèles disponibles dans Ollama:{Colors.ENDC}")
    for i, model in enumerate(available_models, 1):
        base = get_model_base_name(model)
        required = MODEL_RAM_REQUIREMENTS.get(base, 8)
        status = "✓" if total_ram >= required else "✗"
        print(f"  {i}. {model:25s} (nécessite {required} GB RAM) {status}")
    
    # Get recommendation
    recommended = get_recommended_model(ram_info, available_models)
    print(f"\n{Colors.OKGREEN}Recommandation: {recommended} (basé sur {total_ram:.2f} GB RAM){Colors.ENDC}")
    
    # Menu options
    print(f"\n{Colors.BOLD}Options:{Colors.ENDC}")
    print("  A. Utiliser la recommandation automatique")
    print("  M. Choisir manuellement")
    print("  Q. Quitter")
    
    while True:
        choice = input(f"\n{Colors.BOLD}Votre choix (A/M/Q): {Colors.ENDC}").strip().upper()
        
        if choice == 'Q':
            sys.exit(0)
        elif choice == 'A':
            print_success(f"Modèle sélectionné: {recommended}")
            return recommended
        elif choice == 'M':
            # Manual selection
            print(f"\n{Colors.BOLD}Sélection manuelle:{Colors.ENDC}")
            print("Entrez le numéro du modèle ou son nom exact")
            
            for i, model in enumerate(available_models, 1):
                base = get_model_base_name(model)
                required = MODEL_RAM_REQUIREMENTS.get(base, 8)
                print(f"  {i}. {model}")
            
            print("  0. Retour")
            
            while True:
                selection = input(f"\n{Colors.BOLD}Votre choix: {Colors.ENDC}").strip()
                
                if selection == '0':
                    break
                
                try:
                    # Try as number
                    idx = int(selection) - 1
                    if 0 <= idx < len(available_models):
                        selected = available_models[idx]
                        base = get_model_base_name(selected)
                        required = MODEL_RAM_REQUIREMENTS.get(base, 8)
                        
                        if total_ram >= required:
                            print_success(f"Modèle sélectionné: {selected}")
                            return selected
                        else:
                            print_error(f"Ce modèle nécessite {required} GB RAM, mais vous n'en avez que {total_ram:.2f} GB")
                            print_warning("La sélection est possible mais peut échouer au démarrage")
                            confirm = input(f"Continuer quand même ? (O/N): ").strip().upper()
                            if confirm == 'O':
                                return selected
                    else:
                        print_error("Numéro invalide")
                except ValueError:
                    # Try as model name
                    if selection in available_models:
                        selected = selection
                        base = get_model_base_name(selected)
                        required = MODEL_RAM_REQUIREMENTS.get(base, 8)
                        
                        if total_ram >= required:
                            print_success(f"Modèle sélectionné: {selected}")
                            return selected
                        else:
                            print_error(f"Ce modèle nécessite {required} GB RAM, mais vous n'en avez que {total_ram:.2f} GB")
                            confirm = input(f"Continuer quand même ? (O/N): ").strip().upper()
                            if confirm == 'O':
                                return selected
                    else:
                        print_error(f"Modèle '{selection}' non trouvé")
        else:
            print_error("Choix invalide. Veuillez entrer A, M ou Q.")


def install_python_dependencies() -> bool:
    """Install Python dependencies."""
    print_step(5, "Installation des dépendances Python")
    
    requirements_file = BASE_DIR / "backend" / "requirements.txt"
    
    if not requirements_file.exists():
        print_error(f"Fichier {requirements_file} introuvable")
        return False
    
    print_info(f"Installation des dépendances depuis {requirements_file}...")
    
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "-r", str(requirements_file), "--break-system-packages"],
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            print_success("Dépendances installées avec succès")
            return True
        else:
            print_warning("Certaines dépendances n'ont pas pu être installées:")
            print(result.stderr)
            return False
    except Exception as e:
        print_error(f"Erreur lors de l'installation: {e}")
        return False


def generate_env_file(model: str) -> bool:
    """Generate .env configuration file."""
    print_step(6, "Génération du fichier .env")
    
    env_path = BASE_DIR / ".env"
    env_example_path = BASE_DIR / ".env.example"
    
    # Read example file if exists
    if env_example_path.exists():
        with open(env_example_path, 'r') as f:
            env_content = f.read()
    else:
        # Default template
        env_content = """# Email Forensic Analyzer - Configuration
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=mistral
OLLAMA_TIMEOUT=120
UPLOAD_DIR=./data/uploads
CLEANUP_DAYS=7
HOST=0.0.0.0
PORT=8000
ADMIN_PASSWORD=changeme
MAX_FILE_SIZE_MB=50
BLOCKED_EXTENSIONS=.exe,.bat,.sh,.js,.vbs,.ps1,.jar,.msi
"""
    
    # Update OLLAMA_MODEL
    # Extract base name from model (remove :latest or other tags)
    base_model = model.split(':')[0]
    env_content = env_content.replace(
        "OLLAMA_MODEL=mistral",
        f"OLLAMA_MODEL={base_model}"
    )
    
    # Write .env file
    try:
        with open(env_path, 'w') as f:
            f.write(env_content)
        print_success(f"Fichier .env généré avec modèle: {base_model}")
        print_info(f"Fichier: {env_path}")
        return True
    except Exception as e:
        print_error(f"Impossible d'écrire le fichier .env: {e}")
        return False


def print_summary(model: str, ram_info: Dict[str, float], available_models: List[str]) -> None:
    """Print installation summary."""
    clear_screen()
    print_header("✅ Installation terminée !")
    
    print(f"\n{Colors.BOLD}Configuration:{Colors.ENDC}")
    print(f"  Modèle LLM sélectionné: {model}")
    base = get_model_base_name(model)
    required = MODEL_RAM_REQUIREMENTS.get(base, 8)
    print(f"  RAM totale: {ram_info['total']:.2f} GB")
    print(f"  RAM requise pour {base}: {required} GB")
    
    print(f"\n{Colors.BOLD}Modèles disponibles:{Colors.ENDC}")
    for m in available_models:
        print(f"  - {m}")
    
    print(f"\n{Colors.BOLD}Prochaines étapes:{Colors.ENDC}")
    print("  1. Démarrez le backend:")
    print(f"     cd {BASE_DIR}")
    print("     uvicorn backend.app:app --reload --host 0.0.0.0 --port 8000")
    print("\n  2. Accédez à l'application:")
    print("     http://localhost:8000")
    print("\n  3. Pour analyser un email:")
    print("     - Glissez-déposez un fichier .eml dans l'interface")
    print("     - Ou utilisez l'API: POST /api/upload")
    
    print(f"\n{Colors.BOLD}Fichier de configuration:{Colors.ENDC}")
    print(f"  {BASE_DIR / '.env'}")
    print_info("Vous pouvez modifier ce fichier pour ajuster la configuration")


def main() -> None:
    """Main installation routine."""
    clear_screen()
    print_header("Email Forensic Analyzer - Installation Interactive")
    print_info("Ce script vous guide pas à pas dans l'installation")
    
    # Step 1: Check Python
    if not check_python_version():
        print_error("Veuillez installer Python 3.10+ et relancez ce script")
        sys.exit(1)
    
    # Step 2: Check Ollama
    if not check_ollama_installed():
        print_error("Veuillez installer Ollama avant de continuer")
        sys.exit(1)
    
    # Step 3: Start Ollama if needed
    if not check_ollama_running():
        print_warning("Ollama n'est pas démarré. Certaines fonctionnalités peuvent être limitées.")
        proceed = input("Voulez-vous continuer quand même ? (O/N): ").strip().upper()
        if proceed != 'O':
            sys.exit(0)
    
    # Step 4: Detect RAM
    ram_info = detect_ram()
    
    # Step 5: Get available models
    available_models = get_ollama_models()
    
    if not available_models:
        print_warning("Aucun modèle Ollama trouvé. Vous devrez en télécharger un plus tard.")
        print_info("Pour télécharger un modèle: ollama pull mistral")
        # Use default
        selected_model = "mistral"
    else:
        # Interactive selection
        selected_model = select_model_interactive(ram_info, available_models)
    
    # Step 6: Install dependencies
    install_python_dependencies()
    
    # Step 7: Generate .env
    generate_env_file(selected_model)
    
    # Step 8: Summary
    print_summary(selected_model, ram_info, available_models)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInstallation annulée par l'utilisateur")
        sys.exit(0)
    except Exception as e:
        print_error(f"Erreur inattendue: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
