# Email Forensic Analyzer

> **Plateforme d'analyse automatisée d'emails (.eml) pour SOC**
> *POC pour amélioration de la qualité de vie en SOC et prévention des galères imprévues*

---

## 📌 Contexte
Projet proposé dans le cadre d'une alternance en cybersécurité (Analyste SOC N1/N2).
L'objectif est de fournir une plateforme interne permettant aux clients d'upload des emails suspects (format `.eml`) pour une analyse automatisée suivant les méthodes de *Digital Forensic*.

**Fonctionnalités clés** :
- Drag & Drop de fichiers `.eml`
- Analyse forensique automatique (headers, SPF/DKIM/DMARC, liens, pièces jointes)
- **Hash SHA256 des pièces jointes** (pour vérification manuelle sur VirusTotal)
- Génération de **rapport Markdown** complet
- Utilisation de **LLM auto-hébergés** (Ollama : Mistral/DeepSeek)
- **100% offline** (pas d'envoi de données sur internet, sauf option VirusTotal désactivable)

---

## 🏗️ Architecture

```
Client (Navigateur) → [Frontend: HTML/JS] → [Backend: FastAPI]
                                       ↓
                                 [Parse .eml]
                                       ↓
                          [Analyse Forensique]
                                       ├── Headers (SPF/DKIM/DMARC)
                                       ├── Liens/URLs
                                       ├── Pièces jointes → Hash SHA256
                                       └── Réputation IP (locale)
                                       ↓
                          [Ollama: Mistral/DeepSeek]
                                       ↓
                          [Rapport Markdown]
                                       ↓
                          [Storage: /data/uploads/]
```

---

## 🚀 Déploiement Rapide

### 1. Prérequis
- **OS** : Linux (testé sur Ubuntu/Debian, compatible Proxmox)
- **Python** : 3.10+
- **Ollama** : [Installation officielle](https://ollama.com/)
- **Ressources** : 12Go RAM (recommandé)

### 2. Installation

#### Clone le dépôt
```bash
git clone https://github.com/CapePouvoir/email-analyzer.git
cd email-analyzer
```

#### Installe les dépendances
```bash
# Crée un environnement virtuel (optionnel mais recommandé)
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# .venv\Scripts\activate   # Windows

# Installe les dépendances Python
pip install -r backend/requirements.txt
```

#### Configure Ollama
```bash
# Installe Ollama (si pas déjà fait)
curl -fsSL https://ollama.com/install.sh | sh

# Télécharge un modèle (ex: Mistral)
ollama pull mistral
# ou
ollama pull deepseek
```

#### Configure l'application
```bash
# Copie le fichier d'exemple
cp .env.example .env

# Édite .env avec tes paramètres
nano .env  # ou utilise ton éditeur préféré
```

### 3. Lance le service

#### Mode développement
```bash
cd backend
uvicorn app:app --reload --host 0.0.0.0 --port 8000
```
> Accède à l'application : [http://localhost:8000](http://localhost:8000)

#### Mode production (avec systemd)
```bash
# Copie le service systemd
cp deploy/email-analyzer.service /etc/systemd/system/

# Active et démarre le service
sudo systemctl daemon-reload
sudo systemctl enable email-analyzer
sudo systemctl start email-analyzer

# Vérifie les logs
sudo journalctl -u email-analyzer -f
```
> Accède à l'application : [http://<IP_DU_SERVEUR>:8000](http://<IP_DU_SERVEUR>:8000)

---

## 📂 Structure du Projet

```
email-analyzer/
├── backend/                  # Backend FastAPI
│   ├── app.py               # Point d'entrée de l'API
│   ├── config.py            # Gestion de la configuration (.env)
│   ├── requirements.txt     # Dépendances Python
│   ├── analyser/            # Modules d'analyse forensique
│   │   ├── __init__.py
│   │   ├── headers.py        # Analyse des headers (SPF/DKIM/DMARC)
│   │   ├── attachments.py   # Gestion des pièces jointes (hash, type)
│   │   ├── links.py          # Analyse des liens/URLs
│   │   └── report.py         # Génération du rapport Markdown
│   └── ollama_client.py     # Client pour Ollama (configurable)
├── frontend/                # Frontend (HTML/JS)
│   ├── static/              # CSS/JS/Images
│   └── templates/           # Templates HTML (Jinja2)
│       └── index.html       # Page principale (Drag & Drop)
├── deploy/                  # Scripts de déploiement
│   └── email-analyzer.service  # Service systemd
├── data/                   # Données locales
│   └── uploads/             # Stockage des .eml (nettoyage après 7j)
├── .env.example             # Template de configuration
├── .gitignore               # Fichiers exclus de Git
└── README.md                # Ce fichier
```

---

## 🔧 Configuration

### Variables d'environnement (`.env`)

| Variable | Description | Valeur par défaut | Obligatoire |
|----------|-------------|-------------------|-------------|
| `OLLAMA_URL` | URL de l'API Ollama | `http://localhost:11434` | ✅ |
| `OLLAMA_MODEL` | Modèle à utiliser (Mistral/DeepSeek) | `mistral` | ✅ |
| `UPLOAD_DIR` | Dossier de stockage des uploads | `./data/uploads` | ❌ |
| `CLEANUP_DAYS` | Jours avant nettoyage auto | `7` | ❌ |
| `ADMIN_PASSWORD` | Mot de passe pour l'interface admin | `changeme` | ❌ |
| `HOST` | Hôte de l'API | `0.0.0.0` | ❌ |
| `PORT` | Port de l'API | `8000` | ❌ |

**Exemple de `.env`** :
```ini
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=mistral
UPLOAD_DIR=./data/uploads
CLEANUP_DAYS=7
ADMIN_PASSWORD=MonMotDePasseAdmin2024
HOST=0.0.0.0
PORT=8000
```

---

## 🔍 Fonctionnalités d'Analyse

### 1. Analyse des Headers
- **SPF** : Vérification de la validité
- **DKIM** : Statut de la signature
- **DMARC** : Politique de traitement
- **IP Source** : Réputation (via listes locales)
- **From/To** : Cohérence des domaines

### 2. Analyse du Contenu
- Détection de mots-clés suspects (phishing, urgence, etc.)
- Analyse des URLs (domaines suspects, raccourcisseurs)
- Vérification des pièces jointes (extensions dangereuses)

### 3. Pièces Jointes
- **Hash SHA256** : Pour vérification sur [VirusTotal](https://www.virustotal.com/)
- **Type MIME** : Détection des fichiers malveillants courants
- **Taille** : Alerte si > 10Mo (configurable)

### 4. Rapport Markdown
Le rapport généré contient :
```markdown
# 🔍 Rapport d'Analyse Forensique

## 📧 Informations Générales
- **Fichier** : `suspicious_email.eml`
- **Date d'analyse** : 2026-08-10 14:30:00
- **Taille** : 2.4 Ko

## ✅ Résultat Global
**Verdict** : ⚠️ **SUSPECT** (Score : 85/100)

## 🔎 Analyse Technique
### Headers
| Champ | Valeur | Statut |
|-------|--------|--------|
| SPF | `pass` | ✅ |
| DKIM | `fail` | ❌ |
| DMARC | `none` | ⚠️ |
| IP Source | 192.168.1.100 | 🔍 |

### Pièces Jointes (1)
| Nom | Type | Taille | Hash SHA256 | VirusTotal |
|-----|------|-------|-------------|------------|
| invoice.pdf | application/pdf | 1.2 Mo | `a1b2c3...` | [Vérifier](https://www.virustotal.com/gui/search/a1b2c3...) |

### Liens (3)
1. `https://example.com/login` → ✅ Legitime
2. `https://bit.ly/3xYz` → ⚠️ Raccourcisseur (à vérifier)
3. `https://malicious-site.evil` → ❌ Domaine connu malveillant

## 🧠 Analyse Contextuelle (LLM)
> Le mail présente plusieurs indicateurs de phishing :
> - Le domaine de l'expéditeur (`support@amazon-security.com`) ne correspond pas au domaine officiel d'Amazon.
> - Le lien `bit.ly/3xYz` pointe vers une URL suspecte masquée.
> - La pièce jointe `invoice.pdf` a un hash connu dans certaines bases de données de malware (à vérifier manuellement sur VirusTotal).
> 
> **Recommandation** : Bloquer l'IP source et informer l'utilisateur final.

## 🛡️ Recommandations
- [ ] Bloquer l'IP `192.168.1.100`
- [ ] Bloquer le domaine `malicious-site.evil`
- [ ] Vérifier manuellement la pièce jointe sur VirusTotal
- [ ] Sensibiliser l'utilisateur aux attaques de phishing
```

---

## 🔐 Sécurité & Confidentialité

- **100% Auto-hébergé** : Aucune donnée n'est envoyée sur internet (sauf option VirusTotal désactivable).
- **LLM Local** : Ollama tourne en local, pas de fuite de données vers des API externes.
- **Nettoyage Automatique** : Les fichiers uploadés sont supprimés après 7 jours.
- **Pas d'authentification utilisateur** : Accès libre pour simplifier l'utilisation en interne.
- **Authentification Admin** : Route `/admin` protégée par mot de passe (configurable).

---

## 🤝 Contribution

Ce projet est développé dans le cadre d'une alternance en cybersécurité.

- **Auteur** : [CapePouvoir](https://github.com/CapePouvoir)
- **Licence** : MIT (à confirmer selon politique entreprise)

---

## 📜 Changelog

| Version | Date | Modifications |
|---------|------|---------------|
| 0.1.0 | 2026-08-10 | Version initiale (POC) |
