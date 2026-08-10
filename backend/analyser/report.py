"""
Email Forensic Analyzer - Report Generation Module
Generates comprehensive Markdown reports from analysis results.

Author: Randra Timothy RAZAFINDRABE (CapePouvoir / D3adinsid3)
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime
import hashlib

from backend.analyser.headers import HeaderAnalysis
from backend.analyser.attachments import AttachmentAnalysis, AttachmentInfo
from backend.analyser.links import LinkAnalysis, LinkInfo


@dataclass
class Report:
    """Complete analysis report."""
    markdown: str
    filename: str
    hash_sha256: str
    analysis_date: datetime
    severity: str  # low, medium, high, critical
    score: int  # 0-100


class ReportGenerator:
    """Generates Markdown reports from analysis results."""
    
    def __init__(self):
        self.templates = {
            'full': self._generate_full_report,
            'summary': self._generate_summary_report,
            'technical': self._generate_technical_report,
        }
    
    def generate(
        self,
        eml_content: str,
        header_analysis: HeaderAnalysis,
        attachment_analysis: AttachmentAnalysis,
        link_analysis: LinkAnalysis,
        ollama_analysis: Optional[Dict[str, Any]] = None,
        template: str = 'full'
    ) -> Report:
        """
        Generate a report using the specified template.
        
        Args:
            eml_content: Raw EML content
            header_analysis: Results from header analysis
            attachment_analysis: Results from attachment analysis
            link_analysis: Results from link analysis
            ollama_analysis: Results from Ollama LLM analysis
            template: Report template to use ('full', 'summary', 'technical')
            
        Returns:
            Report object with Markdown content
        """
        # Calculate severity and score
        severity, score = self._calculate_severity(
            header_analysis, attachment_analysis, link_analysis, ollama_analysis
        )
        
        # Generate report content
        markdown = self.templates.get(template, self._generate_full_report)(
            eml_content, header_analysis, attachment_analysis, 
            link_analysis, ollama_analysis, severity, score
        )
        
        # Generate filename and hash
        filename = self._generate_filename(header_analysis)
        hash_sha256 = hashlib.sha256(eml_content.encode('utf-8')).hexdigest()
        
        return Report(
            markdown=markdown,
            filename=filename,
            hash_sha256=hash_sha256,
            analysis_date=datetime.now(),
            severity=severity,
            score=score
        )
    
    def _generate_full_report(
        self,
        eml_content: str,
        header_analysis: HeaderAnalysis,
        attachment_analysis: AttachmentAnalysis,
        link_analysis: LinkAnalysis,
        ollama_analysis: Optional[Dict[str, Any]],
        severity: str,
        score: int
    ) -> str:
        """Generate a comprehensive full report."""
        
        # Build report sections
        sections = []
        
        # Header
        sections.append(self._generate_header(header_analysis, severity, score))
        
        # General information
        sections.append(self._generate_general_info(header_analysis))
        
        # Global verdict
        sections.append(self._generate_verdict(severity, score))
        
        # Technical analysis - Headers
        sections.append(self._generate_headers_section(header_analysis))
        
        # Technical analysis - Attachments
        if attachment_analysis.has_attachments:
            sections.append(self._generate_attachments_section(attachment_analysis))
        
        # Technical analysis - Links
        if link_analysis.total_links > 0:
            sections.append(self._generate_links_section(link_analysis))
        
        # LLM analysis
        if ollama_analysis:
            sections.append(self._generate_ollama_section(ollama_analysis))
        
        # Recommendations
        sections.append(self._generate_recommendations(
            header_analysis, attachment_analysis, link_analysis, severity
        ))
        
        # Join all sections
        return '\n\n'.join(sections)
    
    def _generate_header(
        self, 
        header_analysis: HeaderAnalysis,
        severity: str,
        score: int
    ) -> str:
        """Generate report header."""
        severity_emoji = self._get_severity_emoji(severity)
        
        return f"""# 🔍 Rapport d'Analyse Forensique

## {severity_emoji} Verdict: {severity.upper()} (Score: {score}/100)

**Analyste** : Randra Timothy RAZAFINDRABE (CapePouvoir / D3adinsid3)  
**Date** : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Type** : Analyse automatisée d'email (.eml)

---"""
    
    def _generate_general_info(self, header_analysis: HeaderAnalysis) -> str:
        """Generate general information section."""
        from_addr = header_analysis.from_address or "Inconnu"
        to_addrs = ", ".join(header_analysis.to_addresses) if header_analysis.to_addresses else "Inconnu"
        subject = header_analysis.subject or "Aucun sujet"
        date = header_analysis.date or "Inconnu"
        
        return f"""## 📧 Informations Générales

| Propriété | Valeur |
|----------|--------|
| **Expéditeur** | `{from_addr}` |
| **Destinataires** | `{to_addrs}` |
| **Sujet** | `{subject}` |
| **Date** | `{date}` |
| **IP Source** | `{header_analysis.source_ip or 'Inconnu'}` |
"""
    
    def _generate_verdict(self, severity: str, score: int) -> str:
        """Generate global verdict section."""
        severity_emoji = self._get_severity_emoji(severity)
        severity_color = self._get_severity_color(severity)
        
        verdict_text = self._get_verdict_text(severity, score)
        
        return f"""## ✅ Résultat Global

{severity_emoji} **Verdict** : <span style="color:{severity_color};font-weight:bold;">{severity.upper()}</span>  
**Score de menace** : `{score}/100`  

> {verdict_text}
"""
    
    def _generate_headers_section(self, header_analysis: HeaderAnalysis) -> str:
        """Generate headers analysis section."""
        spf_status = "✅ PASS" if header_analysis.is_spf_pass else "❌ FAIL"
        dkim_status = "✅ PASS" if header_analysis.is_dkim_pass else "❌ FAIL"
        dmarc_status = "✅ PASS" if header_analysis.is_dmarc_pass else "⚠️ NONE"
        
        warnings = "\n".join([f"- {w}" for w in header_analysis.warnings])
        
        return f"""## 🔎 Analyse Technique - Headers

### Protocoles d'Authentification

| Protocole | Statut | Domaine |
|-----------|--------|---------|
| **SPF** | {spf_status} | {header_analysis.spf_domain or 'N/A'} |
| **DKIM** | {dkim_status} | {header_analysis.dkim_domain or 'N/A'} |
| **DMARC** | {dmarc_status} | {header_analysis.dmarc_policy or 'N/A'} |

### Avertissements
{warnings if warnings else "Aucun avertissement détecté."}
"""
    
    def _generate_attachments_section(self, attachment_analysis: AttachmentAnalysis) -> str:
        """Generate attachments analysis section."""
        rows = []
        for attachment in attachment_analysis.attachments:
            vt_link = ""
            for filename, link in attachment_analysis.total_virustotal_links:
                if filename == attachment.filename:
                    vt_link = f"[Vérifier]({link})"
                    break
            
            row = f"| {attachment.filename} | {attachment.content_type} | {self._format_size(attachment.size)} | `{attachment.hash_sha256 or 'N/A'}` | {vt_link} |"
            rows.append(row)
        
        attachments_table = "\n".join(rows)
        
        warnings = "\n".join([f"- {w}" for a in attachment_analysis.attachments for w in a.warnings])
        
        return f"""## 📎 Analyse des Pièces Jointes ({len(attachment_analysis.attachments)})

### Liste des pièces jointes

| Nom | Type | Taille | Hash SHA256 | VirusTotal |
|-----|------|-------|-------------|------------|
{attachments_table}

### Statistiques
- **Total** : {len(attachment_analysis.attachments)} pièce(s) jointe(s)
- **Taille totale** : {self._format_size(attachment_analysis.total_size)}
- **Fichiers suspects** : {attachment_analysis.suspicious_count}
- **Fichiers exécutables** : {attachment_analysis.executable_count}

### Avertissements
{warnings if warnings else "Aucun avertissement détecté."}

> ⚠️ **Pour vérifier manuellement sur VirusTotal** : Copiez le hash SHA256 et collez-le sur [https://www.virustotal.com](https://www.virustotal.com)
"""
    
    def _generate_links_section(self, link_analysis: LinkAnalysis) -> str:
        """Generate links analysis section."""
        rows = []
        for link in link_analysis.links:
            status = "✅ Sécurisé" if not link.is_suspicious else "⚠️ Suspect"
            row = f"| [{link.original_url}]({link.original_url}) | {link.domain} | {status} | {', '.join(link.warnings) or 'Aucun'} |"
            rows.append(row)
        
        links_table = "\n".join(rows)
        
        return f"""## 🔗 Analyse des Liens ({link_analysis.total_links})

### Liste des liens

| URL | Domaine | Statut | Avertissements |
|-----|---------|--------|---------------|
{links_table}

### Statistiques
- **Total** : {link_analysis.total_links} lien(s)
- **HTTPS** : {link_analysis.https_count}
- **HTTP** : {link_analysis.http_count}
- **Liens raccourcis** : {link_analysis.shortened_count}
- **Liens suspects** : {link_analysis.suspicious_count}
- **Domaines uniques** : {len(link_analysis.unique_domains)}

### Domaines suspects
{', '.join(link_analysis.suspicious_domains) if link_analysis.suspicious_domains else "Aucun"}
"""
    
    def _generate_ollama_section(self, ollama_analysis: Dict[str, Any]) -> str:
        """Generate Ollama LLM analysis section."""
        context = ollama_analysis.get('context_analysis', '')
        recommendations = ollama_analysis.get('recommendations', [])
        verdict = ollama_analysis.get('verdict', '')
        
        recommendations_list = "\n".join([f"- {r}" for r in recommendations])
        
        return f"""## 🧠 Analyse Contextuelle (LLM - Ollama)

### Verdict
> {verdict}

### Analyse du contexte
> {context}

### Recommandations
{recommendations_list if recommendations_list else "Aucune recommandation supplémentaire."}
"""
    
    def _generate_recommendations(
        self,
        header_analysis: HeaderAnalysis,
        attachment_analysis: AttachmentAnalysis,
        link_analysis: LinkAnalysis,
        severity: str
    ) -> str:
        """Generate recommendations section."""
        recommendations = []
        
        # Header-based recommendations
        if not header_analysis.is_spf_pass:
            recommendations.append("Bloquer ou investiguer l'IP source (SPF non validé)")
        if not header_analysis.is_dkim_pass:
            recommendations.append("Vérifier l'intégrité du message (DKIM non validé)")
        if not header_analysis.is_dmarc_pass:
            recommendations.append("Configurer ou renforcer la politique DMARC")
        
        # Attachment-based recommendations
        if attachment_analysis.suspicious_count > 0:
            recommendations.append(f"Analyser manuellement les {attachment_analysis.suspicious_count} pièce(s) jointe(s) suspecte(s)")
        if attachment_analysis.executable_count > 0:
            recommendations.append(f"Bloquer immédiatement les {attachment_analysis.executable_count} fichier(s) exécutable(s) détecté(s)")
        
        # Link-based recommendations
        if link_analysis.http_count > 0:
            recommendations.append(f"Éviter de cliquer sur les {link_analysis.http_count} lien(s) HTTP non sécurisé(s)")
        if link_analysis.shortened_count > 0:
            recommendations.append(f"Développer les {link_analysis.shortened_count} lien(s) raccourci(s) avant de cliquer")
        if link_analysis.suspicious_count > 0:
            recommendations.append(f"Bloquer les domaines des {link_analysis.suspicious_count} lien(s) suspect(s)")
        
        # Severity-based recommendations
        if severity == 'critical':
            recommendations.append("ESCALADER vers le N2/N3 SOC immédiatement")
            recommendations.append("Isoler l'équipement concerné")
        elif severity == 'high':
            recommendations.append("Investigation approfondie recommandée")
            recommendations.append("Surveillance renforcée des indicateurs")
        elif severity == 'medium':
            recommendations.append("Analyse complémentaire suggérée")
        
        recommendations_list = "\n".join([f"- [ ] {r}" for r in recommendations])
        
        return f"""## 🛡️ Recommandations

{recommendations_list if recommendations_list else "Aucune recommandation spécifique."}

---

*Ce rapport a été généré automatiquement par **Email Forensic Analyzer**.*
*Développé par Randra Timothy RAZAFINDRABE (CapePouvoir / D3adinsid3).*
"""
    
    def _generate_summary_report(
        self,
        eml_content: str,
        header_analysis: HeaderAnalysis,
        attachment_analysis: AttachmentAnalysis,
        link_analysis: LinkAnalysis,
        ollama_analysis: Optional[Dict[str, Any]],
        severity: str,
        score: int
    ) -> str:
        """Generate a concise summary report."""
        # This would be a shorter version - implement as needed
        return self._generate_full_report(
            eml_content, header_analysis, attachment_analysis,
            link_analysis, ollama_analysis, severity, score
        )
    
    def _generate_technical_report(
        self,
        eml_content: str,
        header_analysis: HeaderAnalysis,
        attachment_analysis: AttachmentAnalysis,
        link_analysis: LinkAnalysis,
        ollama_analysis: Optional[Dict[str, Any]],
        severity: str,
        score: int
    ) -> str:
        """Generate a technical-focused report."""
        # This would focus more on technical details - implement as needed
        return self._generate_full_report(
            eml_content, header_analysis, attachment_analysis,
            link_analysis, ollama_analysis, severity, score
        )
    
    def _calculate_severity(
        self,
        header_analysis: HeaderAnalysis,
        attachment_analysis: AttachmentAnalysis,
        link_analysis: LinkAnalysis,
        ollama_analysis: Optional[Dict[str, Any]]
    ) -> tuple:
        """Calculate severity and score based on analysis results."""
        score = 0
        
        # Header analysis (max 40 points)
        if not header_analysis.is_spf_pass:
            score += 15
        if not header_analysis.is_dkim_pass:
            score += 15
        if not header_analysis.is_dmarc_pass:
            score += 10
        if header_analysis.is_suspicious:
            score += 10
        
        # Attachment analysis (max 40 points)
        score += attachment_analysis.suspicious_count * 10
        score += attachment_analysis.executable_count * 15
        
        # Link analysis (max 20 points)
        score += link_analysis.http_count * 2
        score += link_analysis.shortened_count * 5
        score += link_analysis.suspicious_count * 10
        
        # Clamp score to 0-100
        score = max(0, min(100, score))
        
        # Determine severity
        if score >= 80:
            severity = "critical"
        elif score >= 60:
            severity = "high"
        elif score >= 40:
            severity = "medium"
        elif score >= 20:
            severity = "low"
        else:
            severity = "benign"
        
        return severity, score
    
    def _generate_filename(self, header_analysis: HeaderAnalysis) -> str:
        """Generate a filename for the report."""
        from_addr = header_analysis.from_address or "unknown"
        date = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Sanitize filename
        safe_from = "".join(c if c.isalnum() or c in ['.', '_', '-'] else '_' for c in from_addr)
        
        return f"report_{safe_from}_{date}.md"
    
    def _format_size(self, size: int) -> str:
        """Format file size in human-readable format."""
        for unit in ['octets', 'Ko', 'Mo', 'Go']:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} To"
    
    def _get_severity_emoji(self, severity: str) -> str:
        """Get emoji for severity level."""
        emojis = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🟢',
            'benign': '✅'
        }
        return emojis.get(severity, '⚠️')
    
    def _get_severity_color(self, severity: str) -> str:
        """Get color for severity level."""
        colors = {
            'critical': '#dc2626',
            'high': '#ea580c',
            'medium': '#f59e0b',
            'low': '#10b981',
            'benign': '#059669'
        }
        return colors.get(severity, '#64748b')
    
    def _get_verdict_text(self, severity: str, score: int) -> str:
        """Get verdict text based on severity and score."""
        if severity == 'critical':
            return f"Cet email présente des **indicateurs forts de malveillance** (score: {score}/100). Une action immédiate est requise."
        elif severity == 'high':
            return f"Cet email est **suspect** avec des indicateurs significatifs (score: {score}/100). Une investigation approfondie est recommandée."
        elif severity == 'medium':
            return f"Cet email présente **des éléments à vérifier** (score: {score}/100). Une analyse complémentaire est suggérée."
        elif severity == 'low':
            return f"Cet email semble **globalement sûr** mais avec quelques éléments mineurs à vérifier (score: {score}/100)."
        else:
            return f"Cet email est **bénin** (score: {score}/100). Aucun risque détecté."
