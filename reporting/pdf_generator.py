"""
LatticeGuard - Post-Quantum Cryptography Assessment Tool
Copyright (c) 2026 Waqas Khalid Obeidy
"""

"""
PDF Compliance Report Generator
Generates professional PDF reports with NIST/CNSA compliance mapping for PQC assessment findings.
"""
import sqlite3
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional
from collections import Counter

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image, HRFlowable
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT


class PDFReportGenerator:
    """
    Generates PDF compliance reports from PQC assessment findings.
    Includes executive summary, detailed findings, and NIST/CNSA mapping.
    """
    
    # Risk level colors
    RISK_COLORS = {
        "critical": colors.Color(0.8, 0.1, 0.1),  # Dark red
        "high": colors.Color(0.9, 0.3, 0.2),      # Red-orange
        "medium": colors.Color(0.95, 0.6, 0.1),   # Orange
        "low": colors.Color(0.2, 0.6, 0.2),       # Green
        "info": colors.Color(0.3, 0.5, 0.7),      # Blue
    }
    
    # NIST/CNSA compliance mapping
    COMPLIANCE_MAPPING = {
        "RSA": {
            "nist": "NIST SP 800-208: Recommendation for Key-Establishment Schemes",
            "cnsa": "CNSA 2.0: RSA deprecated by 2030, removed by 2035",
            "action": "Migrate to ML-KEM (CRYSTALS-Kyber) for encryption, ML-DSA for signing"
        },
        "ECDSA": {
            "nist": "NIST SP 800-186: Recommendations for Discrete Logarithm Cryptography",
            "cnsa": "CNSA 2.0: ECDSA deprecated by 2030, removed by 2035",
            "action": "Migrate to ML-DSA (CRYSTALS-Dilithium) or SLH-DSA (SPHINCS+)"
        },
        "DSA": {
            "nist": "NIST SP 800-186: DSA constraints",
            "cnsa": "CNSA 2.0: DSA deprecated immediately",
            "action": "Migrate to ML-DSA (CRYSTALS-Dilithium)"
        },
        "DH": {
            "nist": "NIST SP 800-56A: DH Key Agreement",
            "cnsa": "CNSA 2.0: DH deprecated by 2030",
            "action": "Migrate to ML-KEM for key establishment"
        },
        "AES": {
            "nist": "NIST SP 800-38A: Block Cipher Modes",
            "cnsa": "CNSA 2.0: AES-256 recommended (quantum-resistant)",
            "action": "Use AES-256 with GCM mode. No migration needed."
        },
        "SHA-256": {
            "nist": "NIST SP 800-185: SHA-3 Standard",
            "cnsa": "CNSA 2.0: SHA-384+ recommended for long-term security",
            "action": "Consider SHA-384 or SHA3-256 for quantum margin"
        },
        "MD5": {
            "nist": "NIST SP 800-131A: MD5 prohibited",
            "cnsa": "CNSA 2.0: MD5 prohibited",
            "action": "Immediate migration to SHA-256 or stronger"
        },
        "SHA-1": {
            "nist": "NIST SP 800-131A: SHA-1 deprecated",
            "cnsa": "CNSA 2.0: SHA-1 prohibited",
            "action": "Immediate migration to SHA-256 or stronger"
        },
    }
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.styles = getSampleStyleSheet()
        self._init_custom_styles()
    
    def _init_custom_styles(self):
        """Initialize custom paragraph styles."""
        self.styles.add(ParagraphStyle(
            name='ReportTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.Color(0.1, 0.2, 0.4)
        ))
        
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            spaceBefore=20,
            spaceAfter=10,
            textColor=colors.Color(0.2, 0.3, 0.5)
        ))
        
        self.styles.add(ParagraphStyle(
            name='SubSection',
            parent=self.styles['Heading3'],
            fontSize=12,
            spaceBefore=15,
            spaceAfter=8,
        ))
        
        self.styles.add(ParagraphStyle(
            name='CustomBody',
            parent=self.styles['Normal'],
            fontSize=10,
            spaceAfter=8,
        ))
        
        self.styles.add(ParagraphStyle(
            name='Critical',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=self.RISK_COLORS['critical'],
            fontName='Helvetica-Bold'
        ))
    
    def generate(self, run_id: str, output_path: str) -> str:
        """Generate PDF report for a specific scan run."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Fetch data from database
        findings = self._fetch_findings(run_id)
        scan_info = self._fetch_scan_info(run_id)
        
        # Build document
        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=letter,
            rightMargin=0.75*inch,
            leftMargin=0.75*inch,
            topMargin=0.75*inch,
            bottomMargin=0.75*inch
        )
        
        story = []
        
        # Title page
        story.extend(self._build_title_page(run_id, scan_info, findings))
        story.append(PageBreak())
        
        # Executive summary
        story.extend(self._build_executive_summary(findings))
        story.append(Spacer(1, 0.3*inch))
        
        # Risk summary table
        story.extend(self._build_risk_summary(findings))
        story.append(PageBreak())
        
        # Detailed findings
        story.extend(self._build_detailed_findings(findings))
        story.append(PageBreak())
        
        # Compliance matrix
        story.extend(self._build_compliance_matrix(findings))
        story.append(PageBreak())
        
        # Remediation roadmap
        story.extend(self._build_remediation_roadmap(findings))
        
        # Build PDF
        doc.build(story)
        
        return str(output_path)
    
    def _fetch_findings(self, run_id: str) -> List[Dict]:
        """Fetch findings from database."""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            
            c.execute("""
                SELECT * FROM inventory 
                WHERE run_id = ? 
                ORDER BY is_pqc_vulnerable DESC, category
            """, (run_id,))
            
            rows = c.fetchall()
            conn.close()
            
            return [dict(row) for row in rows]
        except Exception as e:
            return []
    
    def _fetch_scan_info(self, run_id: str) -> Dict:
        """Fetch scan metadata."""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            
            c.execute("""
                SELECT COUNT(*) as finding_count,
                       COUNT(CASE WHEN is_pqc_vulnerable = 1 THEN 1 END) as vulnerable_count
                FROM inventory WHERE run_id = ?
            """, (run_id,))
            
            row = c.fetchone()
            conn.close()
            
            return dict(row) if row else {}
        except:
            return {}
    
    def _build_title_page(self, run_id: str, scan_info: Dict, findings: List[Dict]) -> List:
        """Build title page elements."""
        elements = []
        
        elements.append(Spacer(1, 1.5*inch))
        elements.append(Paragraph("Post-Quantum Cryptography", self.styles['ReportTitle']))
        elements.append(Paragraph("Assessment Report", self.styles['ReportTitle']))
        elements.append(Spacer(1, 0.5*inch))
        
        elements.append(HRFlowable(
            width="80%", thickness=2, 
            color=colors.Color(0.2, 0.3, 0.5),
            spaceBefore=10, spaceAfter=20
        ))
        
        # Report metadata
        meta_data = [
            ["Report ID:", run_id],
            ["Generated:", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
            ["Total Findings:", str(len(findings))],
            ["Vulnerable Items:", str(sum(1 for f in findings if f.get('is_pqc_vulnerable')))],
        ]
        
        meta_table = Table(meta_data, colWidths=[2*inch, 4*inch])
        meta_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        elements.append(meta_table)
        
        elements.append(Spacer(1, 1*inch))
        
        # Compliance frameworks
        elements.append(Paragraph(
            "<b>Compliance Frameworks Referenced:</b>",
            self.styles['CustomBody']
        ))
        elements.append(Paragraph(
            "• NIST SP 800-208: Recommendation for Stateful Hash-Based Signature Schemes<br/>"
            "• NIST SP 800-186: Recommendations for Discrete Logarithm Cryptography<br/>"
            "• NSA CNSA 2.0: Commercial National Security Algorithm Suite 2.0<br/>"
            "• NIST FIPS 203/204/205: Post-Quantum Cryptography Standards",
            self.styles['CustomBody']
        ))
        
        return elements
    
    def _build_executive_summary(self, findings: List[Dict]) -> List:
        """Build executive summary section."""
        elements = []
        
        elements.append(Paragraph("Executive Summary", self.styles['SectionHeader']))
        
        # Count vulnerabilities by category
        vulnerable = [f for f in findings if f.get('is_pqc_vulnerable')]
        categories = Counter(f.get('category', 'unknown') for f in vulnerable)
        
        if not findings:
            elements.append(Paragraph(
                "No cryptographic assets were identified in this scan.",
                self.styles['CustomBody']
            ))
            return elements
        
        vuln_pct = len(vulnerable) / len(findings) * 100 if findings else 0
        
        summary_text = f"""
        This assessment identified <b>{len(findings)}</b> cryptographic assets across the scanned codebase 
        and infrastructure. Of these, <b>{len(vulnerable)} ({vuln_pct:.0f}%)</b> are considered vulnerable 
        to future quantum computer attacks using Shor's algorithm or Grover's algorithm.
        """
        elements.append(Paragraph(summary_text, self.styles['CustomBody']))
        
        if vuln_pct > 50:
            elements.append(Paragraph(
                "⚠️ CRITICAL: More than half of cryptographic assets require migration to post-quantum algorithms.",
                self.styles['Critical']
            ))
        
        # Category breakdown
        if categories:
            elements.append(Paragraph("Vulnerable Assets by Category:", self.styles['SubSection']))
            cat_data = [["Category", "Count", "Percentage"]]
            for cat, count in categories.most_common():
                pct = count / len(vulnerable) * 100
                cat_data.append([cat.title(), str(count), f"{pct:.1f}%"])
            
            cat_table = Table(cat_data, colWidths=[2.5*inch, 1*inch, 1.5*inch])
            cat_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.Color(0.2, 0.3, 0.5)),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.Color(0.95, 0.95, 0.95)]),
            ]))
            elements.append(cat_table)
        
        return elements
    
    def _build_risk_summary(self, findings: List[Dict]) -> List:
        """Build risk summary table."""
        elements = []
        
        elements.append(Paragraph("Risk Distribution", self.styles['SectionHeader']))
        
        # Count by algorithm
        algorithms = Counter()
        for f in findings:
            algo = f.get('algorithm') or 'Unknown'
            # Extract base algorithm name
            base_algo = algo.split('-')[0].split('_')[0].upper()
            if f.get('is_pqc_vulnerable'):
                algorithms[base_algo] += 1
        
        if algorithms:
            algo_data = [["Algorithm", "Vulnerable Instances", "Risk Level", "CNSA 2.0 Timeline"]]
            
            timelines = {
                "RSA": "Deprecated 2030, Removed 2035",
                "ECDSA": "Deprecated 2030, Removed 2035",
                "DSA": "Deprecated immediately",
                "DH": "Deprecated 2030",
                "MD5": "Prohibited now",
                "SHA": "SHA-1 prohibited, SHA-256+ OK",
            }
            
            for algo, count in algorithms.most_common(10):
                risk = "High" if algo in ["RSA", "ECDSA", "DSA", "DH"] else "Medium"
                timeline = timelines.get(algo, "Review required")
                algo_data.append([algo, str(count), risk, timeline])
            
            algo_table = Table(algo_data, colWidths=[1.5*inch, 1.5*inch, 1*inch, 2.5*inch])
            algo_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.Color(0.2, 0.3, 0.5)),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('ALIGN', (1, 0), (2, -1), 'CENTER'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.Color(0.95, 0.95, 0.95)]),
            ]))
            elements.append(algo_table)
        
        return elements
    
    def _build_detailed_findings(self, findings: List[Dict]) -> List:
        """Build detailed findings section."""
        elements = []
        
        elements.append(Paragraph("Detailed Findings", self.styles['SectionHeader']))
        
        if not findings:
            elements.append(Paragraph("No findings to display.", self.styles['CustomBody']))
            return elements
        
        # Build findings table
        table_data = [["#", "Name", "Algorithm", "Category", "Vulnerable", "Path"]]
        
        for i, f in enumerate(findings[:50], 1):  # Limit to 50 for PDF size
            name = f.get('name', 'Unknown')[:30]
            algo = f.get('algorithm', 'N/A')[:15]
            cat = f.get('category', 'N/A')[:12]
            vuln = "Yes" if f.get('is_pqc_vulnerable') else "No"
            path = f.get('path', 'N/A')
            # Truncate path to show file name
            path_short = Path(path).name if path != 'N/A' else 'N/A'
            
            table_data.append([str(i), name, algo, cat, vuln, path_short[:20]])
        
        findings_table = Table(
            table_data, 
            colWidths=[0.4*inch, 1.8*inch, 1.2*inch, 1*inch, 0.7*inch, 1.4*inch]
        )
        findings_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.Color(0.2, 0.3, 0.5)),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('ALIGN', (0, 0), (0, -1), 'CENTER'),
            ('ALIGN', (4, 0), (4, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.Color(0.95, 0.95, 0.95)]),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        elements.append(findings_table)
        
        if len(findings) > 50:
            elements.append(Paragraph(
                f"<i>Showing 50 of {len(findings)} findings. See JSON export for complete data.</i>",
                self.styles['CustomBody']
            ))
        
        return elements
    
    def _build_compliance_matrix(self, findings: List[Dict]) -> List:
        """Build NIST/CNSA compliance matrix."""
        elements = []
        
        elements.append(Paragraph("Compliance Matrix", self.styles['SectionHeader']))
        elements.append(Paragraph(
            "The following table maps identified algorithms to relevant NIST and CNSA 2.0 guidance:",
            self.styles['CustomBody']
        ))
        
        # Find unique algorithms in findings
        found_algos = set()
        for f in findings:
            algo = f.get('algorithm', '')
            if algo:
                base = algo.split('-')[0].split('_')[0].upper()
                found_algos.add(base)
        
        # Build compliance table
        table_data = [["Algorithm", "NIST Reference", "CNSA 2.0 Timeline", "Required Action"]]
        
        for algo in sorted(found_algos):
            if algo in self.COMPLIANCE_MAPPING:
                mapping = self.COMPLIANCE_MAPPING[algo]
                nist = mapping['nist'][:40] + "..." if len(mapping['nist']) > 40 else mapping['nist']
                cnsa = mapping['cnsa'].split(':')[1].strip() if ':' in mapping['cnsa'] else mapping['cnsa']
                action = mapping['action'][:50] + "..." if len(mapping['action']) > 50 else mapping['action']
                table_data.append([algo, nist, cnsa, action])
        
        if len(table_data) > 1:
            comp_table = Table(table_data, colWidths=[1*inch, 2*inch, 1.5*inch, 2*inch])
            comp_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.Color(0.15, 0.25, 0.4)),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.Color(0.95, 0.95, 0.95)]),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            elements.append(comp_table)
        else:
            elements.append(Paragraph("No algorithm-specific compliance guidance applicable.", self.styles['BodyText']))
        
        return elements
    
    def _build_remediation_roadmap(self, findings: List[Dict]) -> List:
        """Build remediation roadmap section."""
        elements = []
        
        elements.append(Paragraph("Remediation Roadmap", self.styles['SectionHeader']))
        
        elements.append(Paragraph(
            "<b>Phase 1: Immediate Actions (0-6 months)</b>",
            self.styles['SubSection']
        ))
        elements.append(Paragraph(
            "• Inventory all cryptographic assets using this assessment<br/>"
            "• Eliminate deprecated algorithms (MD5, SHA-1, 3DES)<br/>"
            "• Upgrade to TLS 1.3 where possible<br/>"
            "• Document key rotation schedules",
            self.styles['BodyText']
        ))
        
        elements.append(Paragraph(
            "<b>Phase 2: Preparation (6-18 months)</b>",
            self.styles['SubSection']
        ))
        elements.append(Paragraph(
            "• Implement crypto-agility patterns in new development<br/>"
            "• Test hybrid PQC algorithms in non-production environments<br/>"
            "• Update key management systems for larger key sizes<br/>"
            "• Train development teams on PQC migration",
            self.styles['BodyText']
        ))
        
        elements.append(Paragraph(
            "<b>Phase 3: Migration (18-36 months)</b>",
            self.styles['SubSection']
        ))
        elements.append(Paragraph(
            "• Deploy hybrid certificates (classical + PQC)<br/>"
            "• Migrate RSA/ECDSA to ML-DSA (CRYSTALS-Dilithium)<br/>"
            "• Migrate key exchange to ML-KEM (CRYSTALS-Kyber)<br/>"
            "• Validate performance and interoperability",
            self.styles['BodyText']
        ))
        
        elements.append(Paragraph(
            "<b>Phase 4: Full Transition (36+ months)</b>",
            self.styles['SubSection']
        ))
        elements.append(Paragraph(
            "• Remove classical algorithm fallbacks<br/>"
            "• Achieve full CNSA 2.0 compliance<br/>"
            "• Continuous monitoring for cryptographic drift",
            self.styles['BodyText']
        ))
        
        return elements
