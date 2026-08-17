#!/usr/bin/env python3
"""Test script for DeepSeek analysis with custom context."""

import sys
sys.path.insert(0, '.')

from backend.analyser import analyse_headers, analyse_attachments, analyse_links
from backend.analyser.report import ReportGenerator
from backend.ollama_client import OllamaClient
from backend.config import get_settings

# Path to the email file
email_path = '/home/d3adinsid3/Téléchargements/sampleLNS.eml'

print("="*80)
print("TEST AVEC DEEPSEEK-CODER + CONTEXTE PERSONNALISÉ")
print("="*80)
print()

# Lire le fichier .eml
with open(email_path, 'r', encoding='utf-8', errors='replace') as f:
    eml_content = f.read()

print(f"📧 Email chargé: {email_path}")
print(f"   Taille: {len(eml_content)} bytes")
print()

# Analyser les headers
print("🔍 Analyse des headers...")
header_analysis = analyse_headers(eml_content)
print(f"   ✓ Expéditeur: {header_analysis.from_address}")
print(f"   ✓ Sujet: {header_analysis.subject}")
print(f"   ✓ IP Source: {header_analysis.source_ip}")
print()

# Analyser les attachments
settings = get_settings()
print("📎 Analyse des pièces jointes...")
attachment_analysis = analyse_attachments(eml_content, settings.UPLOAD_DIR)
print(f"   ✓ {len(attachment_analysis.attachments)} pièce(s) jointe(s) trouvée(s)")
for i, att in enumerate(attachment_analysis.attachments, 1):
    print(f"      {i}. {att.filename} ({att.size} octets)")
print()

# Analyser les links
print("🔗 Analyse des liens...")
link_analysis = analyse_links(eml_content, follow_redirects=False)
print(f"   ✓ {link_analysis.total_links} lien(s) trouvé(s)")
print()

# Analyser avec DeepSeek + contexte personnalisé
print("🧠 Analyse avec DeepSeek-Coder + Contexte...")
ollama_client = OllamaClient()

# Contexte personnalisé pour améliorer l'analyse
custom_context = """
Contexte utilisateur:
- Cet email provient d'un partenaire connu (LNS)
- La facture CLT816-26-00479 est attendue
- Le domaine golincalspan.com semble être une faute de frappe sur golincal.com
- Notre entreprise a récemment subi des attaques de phishing par usurpation de domaine
- Nous voulons vérifier si cet email est légitime ou malveillant
"""

print(f"   Contexte fourni: {len(custom_context)} caractères")
print()

if ollama_client.check_health():
    print("   ✓ Ollama est disponible")
    models = ollama_client.list_models()
    print(f"   ✓ Modèles disponibles: {models}")
    
    print("   ⏳ Analyse en cours avec DeepSeek-Coder...")
    ollama_analysis = ollama_client.analyze_email(
        headers={
            'from_address': header_analysis.from_address,
            'from_domain': header_analysis.from_domain,
            'to_addresses': header_analysis.to_addresses,
            'subject': header_analysis.subject,
            'date': header_analysis.date,
            'source_ip': header_analysis.source_ip,
            'is_spf_pass': header_analysis.is_spf_pass,
            'is_dkim_pass': header_analysis.is_dkim_pass,
            'is_dmarc_pass': header_analysis.is_dmarc_pass,
            'is_suspicious': header_analysis.is_suspicious,
            'warnings': header_analysis.warnings,
        },
        attachments=[{
            'filename': a.filename,
            'content_type': a.content_type,
            'size': a.size,
            'is_suspicious': a.is_suspicious,
            'hash_sha256': a.hash_sha256,
            'warnings': a.warnings
        } for a in attachment_analysis.attachments],
        links=[{
            'original_url': l.original_url,
            'domain': l.domain,
            'is_https': l.is_https,
            'is_suspicious': l.is_suspicious,
            'warnings': l.warnings
        } for l in link_analysis.links],
        email_content=eml_content[:2000],
        custom_context=custom_context
    )
    
    print()
    print("   ✅ Analyse DeepSeek terminée!")
    print(f"   Verdict: {ollama_analysis.get('verdict')}")
    print(f"   Confiance: {ollama_analysis.get('confidence', 0) * 100:.1f}%")
    print()
    print("   Analyse contextuelle:")
    print(f"   {ollama_analysis.get('context_analysis', '')[:500]}...")
    print()
    if ollama_analysis.get('recommendations'):
        print("   Recommandations:")
        for i, rec in enumerate(ollama_analysis['recommendations'], 1):
            print(f"      {i}. {rec}")
else:
    print("   ❌ Ollama n'est pas disponible")
    ollama_analysis = None

# Générer le rapport
print("\n📄 Génération du rapport...")
report_generator = ReportGenerator()
report = report_generator.generate(
    eml_content=eml_content,
    header_analysis=header_analysis,
    attachment_analysis=attachment_analysis,
    link_analysis=link_analysis,
    ollama_analysis=ollama_analysis if ollama_analysis else {
        'verdict': 'Test sans Ollama',
        'context_analysis': 'Ollama non disponible',
        'recommendations': [],
        'confidence': 0.0
    },
    template='full'
)

print(f"   ✓ Rapport généré!")
print(f"   Severity: {report.severity}")
print(f"   Score: {report.score}/100")
print()

# Sauvegarder le rapport
report_filename = f"/tmp/email_analysis_deepseek_{report.hash_sha256[:8]}.md"
with open(report_filename, 'w', encoding='utf-8') as f:
    f.write(report.markdown)

print(f"   💾 Rapport sauvegardé: {report_filename}")
print()

# Afficher la section Ollama du rapport
print("="*80)
print("SECTION OLLAMA DU RAPPORT:")
print("="*80)

# Extraire la section Ollama du markdown
if "## 🧠 Analyse Contextuelle" in report.markdown:
    start = report.markdown.find("## 🧠 Analyse Contextuelle")
    end = report.markdown.find("## 🛡️ Recommandations")
    if end == -1:
        end = len(report.markdown)
    ollama_section = report.markdown[start:end]
    print(ollama_section)
else:
    print("Section Ollama non trouvée dans le rapport")

print("="*80)
