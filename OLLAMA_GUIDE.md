# Guide d'utilisation d'Ollama avec Email Forensic Analyzer

## 🚀 Configuration d'Ollama avec DeepSeek

### 1. Installer Ollama

#### Sur Linux/macOS :
```bash
curl -fsSL https://ollama.com/install.sh | sh
```

#### Sur Windows (WSL2) :
```bash
# Installer WSL2 puis :
curl -fsSL https://ollama.com/install.sh | sh
```

### 2. Démarrer le service Ollama

```bash
ollama serve
```

Ce commande démarre le serveur Ollama en arrière-plan sur `http://localhost:11434`.

### 3. Télécharger le modèle DeepSeek

```bash
ollama pull deepseek
```

> ⚠️ **Note** : DeepSeek est un modèle plus puissant que Mistral mais nécessite plus de RAM (16-24 Go recommandés).

Pour vérifier les modèles disponibles :
```bash
ollama list
```

### 4. Configurer l'application

Éditer le fichier `.env` à la racine du projet :

```bash
cd email-analyzer
cp .env.example .env
nano .env
```

Configurer les variables Ollama :
```ini
# --- Ollama (LLM Local) ---
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=deepseek  # ou mistral, llama3, etc.
OLLAMA_TIMEOUT=180    # Timeout plus long pour DeepSeek
```

> 💡 **Astuce** : Vous pouvez changer de modèle à tout moment en modifiant `OLLAMA_MODEL` dans `.env`.

## 📝 Utiliser le contexte personnalisé

L'application permet d'ajouter du **contexte personnalisé** pour améliorer l'analyse LLM.

### Comment ça marche ?

1. **Sans contexte** : Le LLM analyse uniquement les données extraites de l'email (headers, pièces jointes, liens)
2. **Avec contexte** : Vous fournissez des informations supplémentaires que le LLM prend en compte pour une analyse plus précise

### Exemples de contexte utile :

```
- Cet email provient de notre fournisseur habituel Acme Corp
- Nous attendions une facture de leur part cette semaine
- Le domaine @acme.com est dans notre liste blanche
- Notre entreprise a récemment subi des attaques de phishing ciblant les factures
- L'expéditeur est un nouveau contact, pas encore vérifié
```

### Interface utilisateur :

1. Glissez-déposez un fichier `.eml` ou cliquez pour sélectionner
2. Un champ de texte apparaît : **"Contexte supplémentaire (optionnel)"**
3. Entrez vos informations contextuelles (max 2000 caractères)
4. Cliquez sur **"Analyser avec contexte"**
5. Le rapport généré inclura l'analyse LLM enrichie avec votre contexte

## 🎯 Bonnes pratiques

### Pour DeepSeek :
- **RAM recommandée** : 16 Go minimum (24 Go pour de meilleures performances)
- **GPU** : Si disponible, Ollama l'utilisera automatiquement
- **Premier téléchargement** : Le modèle pèse ~4-8 Go selon la version

### Pour le contexte :
- ✅ **À inclure** :
  - Relations avec l'expéditeur
  - Contexte métier (factures attendues, projets en cours)
  - Comportements inhabituels récents
  - Politiques internes de sécurité
  
- ❌ **À éviter** :
  - Informations sensibles ou confidentielles
  - Données personnelles (RGPD)
  - Instructions contradictoires

### Modèles recommandés :

| Modèle | Taille | RAM requise | Cas d'usage |
|--------|-------|-------------|-------------|
| `mistral` | ~4 Go | 8 Go | Bon équilibre vitesse/qualité |
| `deepseek` | ~7 Go | 16 Go | Analyse approfondie, meilleure compréhension |
| `llama3` | ~4 Go | 8 Go | Alternative à Mistral |
| `phi3` | ~2 Go | 4 Go | Léger, pour machines limitées |

## 🐛 Dépannage

### "Ollama non disponible"
- Vérifiez que le service est démarré : `ollama serve`
- Vérifiez le port : `curl http://localhost:11434/api/tags`
- Vérifiez que le modèle est téléchargé : `ollama list`

### Erreur de mémoire
- Réduisez la taille du modèle : utilisez `mistral` ou `phi3`
- Fermez d'autres applications gourmandes en RAM
- Utilisez `--no-gpu` si vous avez des problèmes GPU

### L'analyse est lente
- Augmentez le timeout dans `.env` : `OLLAMA_TIMEOUT=300`
- Essayez un modèle plus léger
- Vérifiez que votre machine a assez de ressources

## 📊 Exemple de rapport avec DeepSeek

Avec contexte personnalisé, le rapport inclura :

```markdown
## 🧠 Analyse Contextuelle (LLM - Ollama)

### Verdict : Suspect
**Confiance** : 87.5%

### Analyse du contexte
> En tenant compte de votre contexte (fournisseur habituel, facture attendue), 
> l'email présente néanmoins plusieurs indicateurs préoccupants :
> 
> 1. Le domaine `golincalspan.com` ressemble à `golincal.com` mais avec une faute
> 2. Les headers SPF/DKIM sont en échec malgré la relation légitime
> 3. La pièce jointe PDF contient des macros (détecté par l'analyse statique)
> 
> **Recommandation** : Contacter Acme Corp par téléphone pour vérifier l'authenticité
> avant d'ouvrir la pièce jointe.

### Recommandations supplémentaires
- Vérifier le domaine exact avec Acme Corp
- Analyser le PDF dans un environnement sandbox
- Sensibiliser l'équipe aux attaques par usurpation de domaine
```

## 🔧 Configuration avancée

### Changer de modèle à la volée

Vous pouvez modifier le modèle sans redémarrer l'application :

```bash
# Télécharger un nouveau modèle
ollama pull llama3

# Mettre à jour la configuration
sed -i 's/OLLAMA_MODEL=.*/OLLAMA_MODEL=llama3/' .env

# Redémarrer le backend
# (ou simplement attendre, la config est rechargée automatiquement)
```

### Utiliser plusieurs modèles

Ollama permet d'avoir plusieurs modèles téléchargés :

```bash
ollama pull mistral
ollama pull deepseek
ollama pull llama3

# Changer dans .env
OLLAMA_MODEL=deepseek  # ou mistral, llama3
```

### Monitorer Ollama

```bash
# Voir les modèles téléchargés
ollama list

# Voir les logs
journalctl -u ollama -f

# Vérifier l'utilisation GPU
nvidia-smi  # si vous avez NVIDIA GPU
```

## 📚 Références

- [Ollama Documentation](https://github.com/jmorganca/ollama)
- [DeepSeek Model](https://github.com/deepseek-ai/DeepSeek)
- [Mistral AI](https://mistral.ai/)
