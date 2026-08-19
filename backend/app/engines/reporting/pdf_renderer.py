"""
backend/app/engines/reporting/pdf_renderer.py
----------------------------------------------
M4 PDF Report Generator for NetSleuth-AI.
Generates structured, presentation-quality forensic PDF reports using ReportLab Platypus.

Structure:
  1. Cover / Header (with compact metadata table & 8-char UUIDs)
  2. Executive Summary (3-5 sentence auto-generated prose paragraph)
  3. Key Findings Table (with color-coded severity badges & auto-population)
  4. IOC Table (deduplicated with occurrence counts & footnote flags)
  5. Grouped Timeline (session/flow-grouped, distinct capture vs pipeline times, collapsed extractions)
  6. Appendix (full raw UUID mappings, page-broken, small font size, MITRE, Evidence Integrity, Attack Chain, AI Narrative)
"""

from __future__ import annotations

import html
import io
import re
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

# ReportLab Platypus & Layout Imports
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.shared.contract_validation import ContractValidator

# =============================================================================
# COLOR PALETTE DEFINITIONS
# =============================================================================
NAVY_PRIMARY = colors.HexColor("#0F172A")    # Dark Slate/Navy for main title banners
NAVY_HEADER = colors.HexColor("#1E293B")     # Section headers
NAVY_SUBHEADER = colors.HexColor("#334155")  # Table column headers / accents
BLUE_ACCENT = colors.HexColor("#2563EB")     # Brand accent blue
TEXT_PRIMARY = colors.HexColor("#0F172A")    # Primary body text
TEXT_SECONDARY = colors.HexColor("#475569")  # Subtitle / secondary text
TEXT_MUTED = colors.HexColor("#64748B")      # Muted labels / footnotes
BG_LIGHT_ROW = colors.HexColor("#F8FAFC")    # Table alternating row light
BG_WHITE = colors.HexColor("#FFFFFF")        # Pure white
BORDER_COLOR = colors.HexColor("#CBD5E1")    # Subtle table grid border
BORDER_SUBTLE = colors.HexColor("#E2E8F0")   # Soft divider

# Severity Palette (Backgrounds and Foregrounds)
SEV_COLORS: Dict[str, Tuple[colors.Color, colors.Color, str]] = {
    "CRITICAL": (colors.HexColor("#FEE2E2"), colors.HexColor("#991B1B"), "CRITICAL"),
    "HIGH": (colors.HexColor("#FFEDD5"), colors.HexColor("#9A3412"), "HIGH"),
    "MEDIUM": (colors.HexColor("#FEF3C7"), colors.HexColor("#92400E"), "MEDIUM"),
    "LOW": (colors.HexColor("#F1F5F9"), colors.HexColor("#475569"), "LOW"),
    "INFORMATIONAL": (colors.HexColor("#DBEAFE"), colors.HexColor("#1E40AF"), "INFO"),
    "INFO": (colors.HexColor("#DBEAFE"), colors.HexColor("#1E40AF"), "INFO"),
}


# =============================================================================
# DETERMINISTIC NUMBERED CANVAS FOR RUNNING HEADERS & FOOTERS
# =============================================================================
class NumberedCanvas(canvas.Canvas):
    """Two-pass deterministic canvas to compute and render 'Page X of Y' footers."""

    _invariant = 1

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._saved_page_states: List[Any] = []

    def showPage(self) -> None:
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self) -> None:
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()

        # Enforce deterministic metadata timestamp and signature ID
        if hasattr(self, "_doc") and self._doc:
            self._doc.info.creationDate = "D:20260101000000+00'00'"
            self._doc.info.modDate = "D:20260101000000+00'00'"
            self._doc._ID = b"\n[<00000000000000000000000000000000><00000000000000000000000000000000>]\n"

        super().save()

    def draw_page_decorations(self, total_pages: int) -> None:
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(TEXT_MUTED)

        # Running Footer
        footer_text = f"NetSleuth-AI Forensic Investigation Report  |  Page {self._pageNumber} of {total_pages}  |  CONFIDENTIAL"
        self.drawRightString(letter[0] - 0.6 * inch, 0.4 * inch, footer_text)

        # Subtle bottom line
        self.setStrokeColor(BORDER_SUBTLE)
        self.setLineWidth(0.5)
        self.line(0.6 * inch, 0.52 * inch, letter[0] - 0.6 * inch, 0.52 * inch)

        self.restoreState()


# =============================================================================
# PDF REPORT RENDERER CLASS
# =============================================================================
class PDFReportRenderer:
    """
    M4 PDF Report Generator.
    Produces formatted, executive-ready forensic investigation PDF reports.
    """

    def __init__(self, validator: Optional[ContractValidator] = None) -> None:
        self.validator = validator or ContractValidator()
        self.page_width, self.page_height = letter
        self.margin = 0.6 * inch
        self.content_width = self.page_width - (2 * self.margin)

    # -------------------------------------------------------------------------
    # Helper & Version Detection Methods
    # -------------------------------------------------------------------------
    def _detect_report_version(self, report: Dict[str, Any]) -> str:
        schema_version = report.get("schema_version")
        if schema_version == "report-v1":
            return "report-v1.json"
        elif schema_version == "report-v1.1":
            return "report-v1.1.json"
        elif schema_version == "report-v1.2":
            return "report-v1.2.json"
        elif schema_version == "report-v1.3":
            return "report-v1.3.json"
        else:
            raise ValueError(f"Unsupported or unknown report schema_version '{schema_version}'.")

    def _truncate_id(self, val: Any, length: int = 8) -> str:
        if not val:
            return "UNKNOWN"
        s = str(val).strip()
        if s.startswith("CASE-") or s.startswith("REP-") or s.startswith("ACQ-"):
            prefix, _, rest = s.partition("-")
            return f"{prefix}-{rest[:length]}"
        return s[:length]

    def _clean_str(self, val: Any, default: str = "N/A") -> str:
        if val is None:
            return default
        s = str(val).strip()
        if s in ("", "-", "None", "null", "N/A"):
            return default
        return s

    def _format_timestamp(self, ts_str: Any) -> str:
        if not ts_str:
            return "N/A"
        try:
            cleaned = str(ts_str).replace("Z", "+00:00")
            dt = datetime.fromisoformat(cleaned)
            return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            return str(ts_str)

    def _create_styles(self) -> Dict[str, ParagraphStyle]:
        styles = getSampleStyleSheet()
        custom: Dict[str, ParagraphStyle] = {}

        custom["DocTitle"] = ParagraphStyle(
            "DocTitle",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=15,
            leading=18,
            textColor=colors.white,
            alignment=TA_LEFT,
        )
        custom["DocSubtitle"] = ParagraphStyle(
            "DocSubtitle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor("#E2E8F0"),
            alignment=TA_LEFT,
        )
        custom["SectionHeader"] = ParagraphStyle(
            "SectionHeader",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=9.5,
            leading=12,
            textColor=colors.white,
            alignment=TA_LEFT,
        )
        custom["Body"] = ParagraphStyle(
            "Body",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=8,
            leading=11.5,
            textColor=TEXT_PRIMARY,
            alignment=TA_JUSTIFY,
        )
        custom["TableHeader"] = ParagraphStyle(
            "TableHeader",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=7.5,
            leading=9.5,
            textColor=colors.white,
            alignment=TA_LEFT,
        )
        custom["TableHeaderCenter"] = ParagraphStyle(
            "TableHeaderCenter",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=7.5,
            leading=9.5,
            textColor=colors.white,
            alignment=TA_CENTER,
        )
        custom["TableCell"] = ParagraphStyle(
            "TableCell",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=7,
            leading=9.5,
            textColor=TEXT_PRIMARY,
            alignment=TA_LEFT,
        )
        custom["TableCellBold"] = ParagraphStyle(
            "TableCellBold",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=7,
            leading=9.5,
            textColor=TEXT_PRIMARY,
            alignment=TA_LEFT,
        )
        custom["TableCellCenter"] = ParagraphStyle(
            "TableCellCenter",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=7,
            leading=9.5,
            textColor=TEXT_PRIMARY,
            alignment=TA_CENTER,
        )
        custom["TableCellMono"] = ParagraphStyle(
            "TableCellMono",
            parent=styles["Normal"],
            fontName="Courier",
            fontSize=6.5,
            leading=8.5,
            textColor=TEXT_PRIMARY,
            alignment=TA_LEFT,
        )
        custom["BadgeText"] = ParagraphStyle(
            "BadgeText",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=6.5,
            leading=7.5,
            alignment=TA_CENTER,
        )
        custom["Footnote"] = ParagraphStyle(
            "Footnote",
            parent=styles["Normal"],
            fontName="Helvetica-Oblique",
            fontSize=6.5,
            leading=8.5,
            textColor=TEXT_MUTED,
        )
        custom["AppendixMono"] = ParagraphStyle(
            "AppendixMono",
            parent=styles["Normal"],
            fontName="Courier",
            fontSize=6,
            leading=7.5,
            textColor=TEXT_SECONDARY,
        )
        custom["AppendixLabel"] = ParagraphStyle(
            "AppendixLabel",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=6.5,
            leading=8,
            textColor=TEXT_PRIMARY,
        )

        return custom

    # -------------------------------------------------------------------------
    # UI Component Generators
    # -------------------------------------------------------------------------
    def _render_section_banner(self, title: str, styles: Dict[str, ParagraphStyle]) -> Table:
        t = Table([[title.upper()]], colWidths=[self.content_width])
        t.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), NAVY_HEADER),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9.5),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ])
        )
        return t

    def _render_severity_cell(self, severity_str: str, styles: Dict[str, ParagraphStyle]) -> Table:
        sev_key = self._clean_str(severity_str, "MEDIUM").upper()
        if sev_key in SEV_COLORS:
            bg_col, fg_col, label = SEV_COLORS[sev_key]
        else:
            bg_col, fg_col, label = SEV_COLORS["MEDIUM"]

        badge_table = Table([[label]], colWidths=[55])
        badge_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), bg_col),
                ("TEXTCOLOR", (0, 0), (-1, -1), fg_col),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 6.5),
                ("TOPPADDING", (0, 0), (-1, -1), 1.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5),
                ("LEFTPADDING", (0, 0), (-1, -1), 2),
                ("RIGHTPADDING", (0, 0), (-1, -1), 2),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ])
        )
        return badge_table

    # -------------------------------------------------------------------------
    # Section 1: Cover / Header & Metadata
    # -------------------------------------------------------------------------
    def _build_header_section(
        self, report: Dict[str, Any], styles: Dict[str, ParagraphStyle]
    ) -> List[Any]:
        story: List[Any] = []

        report_id = report.get("report_id", "N/A")
        case_id = report.get("case_id", "N/A")
        generated_at = self._format_timestamp(report.get("generated_at"))
        gen_ver = report.get("generator_version", "v1.3")

        summary = report.get("summary", {})
        case_title = str(summary.get("case_title") or report.get("title") or "Forensic Investigation")
        case_status = str(summary.get("case_status", "OPEN")).upper()

        total_findings = summary.get("total_findings", len(report.get("findings", [])))
        total_events = summary.get("total_timeline_events", len(report.get("timeline", [])))
        verified_ev = summary.get("verified_evidence_count", 0)
        total_ev = summary.get("total_evidence_references", len(report.get("evidence_integrity", [])))

        # Header Title Banner
        header_table = Table(
            [
                ["NETSLEUTH-AI FORENSIC REPORT"],
                [f"Case: {case_title}  |  Status: {case_status}  |  Generated: {generated_at}"],
            ],
            colWidths=[self.content_width],
        )
        header_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), NAVY_PRIMARY),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 14),
                ("TEXTCOLOR", (0, 1), (-1, 1), colors.HexColor("#E2E8F0")),
                ("FONTNAME", (0, 1), (-1, 1), "Helvetica"),
                ("FONTSIZE", (0, 1), (-1, 1), 8.5),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ])
        )
        story.append(header_table)
        story.append(Spacer(1, 5))

        # Compact Metadata Table (truncated UUIDs in header)
        meta_data = [
            [
                Paragraph("<b>Report ID (8-char)</b>", styles["TableHeader"]),
                Paragraph("<b>Case ID (8-char)</b>", styles["TableHeader"]),
                Paragraph("<b>Engine Version</b>", styles["TableHeader"]),
                Paragraph("<b>Findings</b>", styles["TableHeaderCenter"]),
                Paragraph("<b>Timeline Events</b>", styles["TableHeaderCenter"]),
                Paragraph("<b>Evidence Verified</b>", styles["TableHeaderCenter"]),
            ],
            [
                Paragraph(f"<code>{html.escape(self._truncate_id(report_id))}...</code>", styles["TableCellMono"]),
                Paragraph(f"<code>{html.escape(self._truncate_id(case_id))}...</code>", styles["TableCellMono"]),
                Paragraph(html.escape(str(gen_ver)), styles["TableCell"]),
                Paragraph(str(total_findings), styles["TableCellCenter"]),
                Paragraph(str(total_events), styles["TableCellCenter"]),
                Paragraph(f"{verified_ev}/{total_ev} Verified", styles["TableCellCenter"]),
            ],
        ]

        col_w = self.content_width / 6.0
        meta_table = Table(meta_data, colWidths=[col_w] * 6)
        meta_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), NAVY_SUBHEADER),
                ("BACKGROUND", (0, 1), (-1, 1), BG_LIGHT_ROW),
                ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
                ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ])
        )
        story.append(meta_table)
        story.append(Spacer(1, 6))

        return story

    # -------------------------------------------------------------------------
    # Section 2: Executive Summary (3-5 Sentence Auto-Generated Prose)
    # -------------------------------------------------------------------------
    def _build_executive_summary_section(
        self, report: Dict[str, Any], styles: Dict[str, ParagraphStyle]
    ) -> List[Any]:
        story: List[Any] = []
        story.append(self._render_section_banner("1. Executive Summary", styles))
        story.append(Spacer(1, 3))

        findings = report.get("findings", [])
        timeline = report.get("timeline", [])
        entities = report.get("entities", [])
        summary_meta = report.get("summary", {})
        assessment = report.get("assessment", {})
        llm_enrichment = report.get("llm_enrichment", {})

        case_title = summary_meta.get("case_title") or report.get("title") or "Network Observation"

        # 1. Identify distinct IOCs (Domains / IPs)
        domains = [e.get("value") for e in entities if e.get("entity_type") in ("DOMAIN", "domain") and e.get("value")]
        ips = [e.get("value") for e in entities if e.get("entity_type") in ("IP", "ip", "IPV4", "IPV6") and e.get("value")]
        top_iocs = list(dict.fromkeys(domains + ips))[:3]
        ioc_str = ", ".join([f"<code>{html.escape(str(i))}</code>" for i in top_iocs]) if top_iocs else "identified network communication channels"

        # 2. Extract Time Window
        timestamps = [t.get("timestamp") for t in timeline if t.get("timestamp")]
        if timestamps:
            first_seen = self._format_timestamp(min(timestamps))
            last_seen = self._format_timestamp(max(timestamps))
            time_window_str = f"between {first_seen} and {last_seen}"
        else:
            time_window_str = "during the monitored packet capture period"

        # 3. Detect Activity Pattern
        activity_classes = set()
        for f in findings:
            ac = f.get("finding_type") or f.get("title") or ""
            activity_classes.add(ac.upper())

        pattern_desc = "anomalous communications and behavioral deviations"
        if any("C2" in ac or "MALWARE" in ac for ac in activity_classes):
            pattern_desc = "periodic external command-and-control (C2) beaconing and suspicious callback channels"
        elif any("DNS" in ac or "TUNNEL" in ac for ac in activity_classes):
            pattern_desc = "high-frequency DNS anomalous queries consistent with DNS tunneling and unauthorized resolution"
        elif any("SCAN" in ac or "RECON" in ac for ac in activity_classes):
            pattern_desc = "systematic multi-endpoint network reconnaissance and port exploration"
        elif any("EXFIL" in ac for ac in activity_classes):
            pattern_desc = "elevated outbound data transmission consistent with staging and exfiltration patterns"
        elif any("WEB" in ac or "HTTP" in ac for ac in activity_classes):
            pattern_desc = "unusual HTTP/HTTPS transaction payloads and suspicious user-agent characteristics"

        # Build 3-5 Sentence Prose
        sentences: List[str] = []

        total_f = len(findings)
        total_e = len(timeline)
        sentences.append(
            f"NetSleuth-AI automated forensic analysis examined case <b>{html.escape(str(case_title))}</b>, "
            f"identifying <b>{total_f}</b> correlated security finding(s) and <b>{total_e}</b> protocol event(s) {time_window_str}."
        )

        sentences.append(
            f"The primary activity centered on network interactions involving {ioc_str}, indicating targeted protocol utilization."
        )

        sentences.append(
            f"Observed behavioral signatures closely match forensic patterns of <b>{pattern_desc}</b> across monitored network segments."
        )

        verified_count = summary_meta.get("verified_evidence_count", 0)
        total_ev = summary_meta.get("total_evidence_references", len(report.get("evidence_integrity", [])))
        if total_ev > 0:
            sentences.append(
                f"Evidence integrity auditing verified {verified_count} of {total_ev} artifact records under strict SHA-256 cryptographic chain-of-custody protocols."
            )
        else:
            sentences.append(
                "All associated flow and protocol events were cataloged, deduplicated, and attributed to corresponding analytical findings."
            )

        if llm_enrichment and llm_enrichment.get("summary"):
            llm_text = html.escape(str(llm_enrichment.get("summary", "")).strip())
            sentences.append(f"AI Assistant Synthesis: {llm_text}")
        elif assessment and assessment.get("summary"):
            ass_text = html.escape(str(assessment.get("summary", "")).strip())
            sentences.append(f"Correlated Assessment: {ass_text}")

        prose = " ".join(sentences)
        p_table = Table([[Paragraph(prose, styles["Body"])]], colWidths=[self.content_width])
        p_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), BG_LIGHT_ROW),
                ("BOX", (0, 0), (-1, -1), 0.5, BORDER_SUBTLE),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ])
        )
        story.append(p_table)
        story.append(Spacer(1, 6))

        return story

    # -------------------------------------------------------------------------
    # Section 3: Key Findings Table
    # -------------------------------------------------------------------------
    def _build_findings_section(
        self, report: Dict[str, Any], styles: Dict[str, ParagraphStyle]
    ) -> List[Any]:
        story: List[Any] = []
        story.append(self._render_section_banner("2. Key Findings", styles))
        story.append(Spacer(1, 3))

        findings = report.get("findings", [])
        timeline = report.get("timeline", [])

        timeline_by_id = {t.get("event_id"): t for t in timeline if t.get("event_id")}

        table_rows = [
            [
                Paragraph("<b>Detection Type</b>", styles["TableHeader"]),
                Paragraph("<b>Severity</b>", styles["TableHeaderCenter"]),
                Paragraph("<b>Description & Correlated Evidence</b>", styles["TableHeader"]),
            ]
        ]

        if not findings:
            table_rows.append([
                Paragraph("Baseline Telemetry", styles["TableCellBold"]),
                self._render_severity_cell("LOW", styles),
                Paragraph("No malicious or anomalous findings were identified during the observation period.", styles["TableCell"]),
            ])
        else:
            for idx, f in enumerate(findings):
                f_type = f.get("finding_type") or f.get("title")
                if not f_type or f_type in ("-", "None", "null", "N/A"):
                    linked_types = [
                        timeline_by_id[eid].get("event_type")
                        for eid in f.get("evidence_references", [])
                        if eid in timeline_by_id and timeline_by_id[eid].get("event_type")
                    ]
                    f_type = linked_types[0] if linked_types else "CORRELATED_ANOMALY"

                f_type_str = html.escape(str(f_type).replace("_", " ").title())

                severity = f.get("severity")
                if not severity or severity in ("-", "None", "null", "N/A"):
                    confidence = float(f.get("confidence", 0.7))
                    severity = "HIGH" if confidence >= 0.8 else ("MEDIUM" if confidence >= 0.5 else "LOW")
                severity_badge = self._render_severity_cell(str(severity), styles)

                desc = f.get("description")
                if not desc or desc in ("-", "None", "null", "N/A"):
                    desc = f.get("title") or f"Forensic detection linked to {len(f.get('evidence_references', []))} evidence artifact(s)."

                ev_refs = f.get("evidence_references", [])
                ev_str = f" <font color='{TEXT_MUTED.hexval()}'>[Evidence: {', '.join([self._truncate_id(r) for r in ev_refs[:4]])}]</font>" if ev_refs else ""
                full_desc = f"{html.escape(str(desc))}{ev_str}"

                table_rows.append([
                    Paragraph(f"<b>{f_type_str}</b>", styles["TableCell"]),
                    severity_badge,
                    Paragraph(full_desc, styles["TableCell"]),
                ])

        col_widths = [105, 65, self.content_width - 170]
        findings_table = Table(table_rows, colWidths=col_widths)
        findings_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), NAVY_SUBHEADER),
                ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ])
        )

        for i in range(1, len(table_rows)):
            bg = BG_LIGHT_ROW if i % 2 == 1 else BG_WHITE
            findings_table.setStyle(TableStyle([("BACKGROUND", (0, i), (-1, i), bg)]))

        story.append(findings_table)
        story.append(Spacer(1, 6))
        return story

    # -------------------------------------------------------------------------
    # Section 4: IOC Table (Deduplicated with Footnotes)
    # -------------------------------------------------------------------------
    def _build_ioc_section(
        self, report: Dict[str, Any], styles: Dict[str, ParagraphStyle]
    ) -> List[Any]:
        story: List[Any] = []
        story.append(self._render_section_banner("3. Indicators of Compromise (Deduplicated)", styles))
        story.append(Spacer(1, 3))

        entities = report.get("entities", [])
        timeline = report.get("timeline", [])
        evidence_integrity = report.get("evidence_integrity", [])

        # Collect and count all IOC entries
        ioc_counts: Counter[Tuple[str, str]] = Counter()

        for ent in entities:
            e_type = (ent.get("entity_type") or "ENTITY").upper()
            e_val = ent.get("value")
            if e_val and e_val not in ("-", "None", "null"):
                ioc_counts[(e_type, str(e_val))] += 1

        for ev in evidence_integrity:
            ev_hash = ev.get("calculated_hash") or ev.get("expected_hash")
            if ev_hash and len(ev_hash) >= 16:
                ioc_counts[("SHA-256 HASH", str(ev_hash))] += 1

        for t in timeline:
            desc = t.get("description", "")
            for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", desc):
                ioc_counts[("IP ADDRESS", ip)] += 1

        if not ioc_counts:
            ioc_counts[("DOMAIN", "N/A — No external domain extractions")] = 1

        table_rows = [
            [
                Paragraph("<b>IOC Type</b>", styles["TableHeader"]),
                Paragraph("<b>Indicator Value</b>", styles["TableHeader"]),
                Paragraph("<b>Occurrences</b>", styles["TableHeaderCenter"]),
            ]
        ]

        footnotes: List[str] = []
        fn_counter = 1

        sorted_iocs = sorted(ioc_counts.items(), key=lambda x: (-x[1], x[0][0], x[0][1]))

        for idx, ((i_type, i_val), count) in enumerate(sorted_iocs[:15]):
            display_val = i_val
            if len(i_val) > 48:
                display_val = f"{i_val[:45]}... [{fn_counter}]"
                footnotes.append(f"[{fn_counter}] Full Value: {i_val}")
                fn_counter += 1

            type_label = html.escape(i_type.replace("_", " ").title())
            val_p = Paragraph(f"<code>{html.escape(display_val)}</code>", styles["TableCellMono"])
            count_p = Paragraph(str(count), styles["TableCellCenter"])

            table_rows.append([
                Paragraph(type_label, styles["TableCell"]),
                val_p,
                count_p,
            ])

        col_widths = [105, self.content_width - 160, 55]
        ioc_table = Table(table_rows, colWidths=col_widths)
        ioc_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), NAVY_SUBHEADER),
                ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ])
        )

        for i in range(1, len(table_rows)):
            bg = BG_LIGHT_ROW if i % 2 == 1 else BG_WHITE
            ioc_table.setStyle(TableStyle([("BACKGROUND", (0, i), (-1, i), bg)]))

        story.append(ioc_table)

        if footnotes:
            story.append(Spacer(1, 2))
            for fn in footnotes:
                story.append(Paragraph(html.escape(fn), styles["Footnote"]))

        story.append(Spacer(1, 6))
        return story

    # -------------------------------------------------------------------------
    # Section 5: Grouped Timeline (Flow/Session Grouping + Distinct Timestamps)
    # -------------------------------------------------------------------------
    def _build_timeline_section(
        self, report: Dict[str, Any], styles: Dict[str, ParagraphStyle]
    ) -> List[Any]:
        story: List[Any] = []
        story.append(self._render_section_banner("4. Correlated Forensic Timeline (Grouped Flows)", styles))
        story.append(Spacer(1, 3))

        timeline = report.get("timeline", [])
        pipeline_generated_at = self._format_timestamp(report.get("generated_at"))

        if not timeline:
            empty_table = Table(
                [[Paragraph("No chronological timeline events were recorded for this case.", styles["TableCell"])]],
                colWidths=[self.content_width],
            )
            empty_table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), BG_LIGHT_ROW),
                    ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
                    ("PADDING", (0, 0), (-1, -1), 5),
                ])
            )
            story.append(empty_table)
            story.append(Spacer(1, 6))
            return story

        # 1. Collapse duplicate extraction events into summary rows to avoid timeline clutter
        collapsed_events: List[Dict[str, Any]] = []
        extraction_counts: Counter[str] = Counter()
        first_extraction_event: Dict[str, Dict[str, Any]] = {}

        for event in sorted(timeline, key=lambda e: e.get("timestamp") or ""):
            desc = event.get("description", "") or event.get("title", "")
            if "artifact extracted from stream" in desc.lower() or "extracted: file artifact" in desc.lower():
                match = re.search(r"(?:USER_AGENT|DOMAIN|URI|IP)\s*\([^)]+\)", desc)
                key = match.group(0) if match else desc[:40]
                extraction_counts[key] += 1
                if key not in first_extraction_event:
                    first_extraction_event[key] = event
            else:
                collapsed_events.append(event)

        for key, count in extraction_counts.items():
            base_ev = first_extraction_event[key]
            ev_copy = deepcopy(base_ev)
            if count > 1:
                ev_copy["title"] = f"Aggregated Artifact Extractions ({count}x)"
                ev_copy["description"] = f"Collapsed {count} occurrences of stream extraction: {key}"
            collapsed_events.append(ev_copy)

        sorted_events = sorted(collapsed_events, key=lambda e: e.get("timestamp") or "")

        # 2. Group events into sessions/flows (by event_type or 6-item chunks)
        groups: List[List[Dict[str, Any]]] = []
        current_group: List[Dict[str, Any]] = []
        last_proto: Optional[str] = None

        for event in sorted_events:
            proto = event.get("event_type") or "FLOW"
            if last_proto is None or proto == last_proto or len(current_group) < 5:
                current_group.append(event)
                last_proto = proto
            else:
                groups.append(current_group)
                current_group = [event]
                last_proto = proto
        if current_group:
            groups.append(current_group)

        for g_idx, grp in enumerate(groups[:6]):
            t_stamps = [e.get("timestamp") for e in grp if e.get("timestamp")]
            start_t = self._format_timestamp(min(t_stamps)) if t_stamps else "N/A"
            end_t = self._format_timestamp(max(t_stamps)) if t_stamps else "N/A"
            proto_label = grp[0].get("event_type") or "NETWORK"

            group_header_text = (
                f"<b>Session Flow {g_idx + 1}: {html.escape(proto_label.upper())}</b> &nbsp;|&nbsp; "
                f"Capture Window: {start_t} &rarr; {end_t} &nbsp;|&nbsp; Events: {len(grp)}"
            )
            gh_p = Paragraph(group_header_text, styles["DocSubtitle"])
            gh_table = Table([[gh_p]], colWidths=[self.content_width])
            gh_table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), NAVY_SUBHEADER),
                    ("TOPPADDING", (0, 0), (-1, -1), 2),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                    ("LEFTPADDING", (0, 0), (-1, -1), 5),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ])
            )

            g_rows = [
                [
                    Paragraph("<b>Network Timestamp (Capture)</b>", styles["TableHeader"]),
                    Paragraph("<b>Event Identifier & Title</b>", styles["TableHeader"]),
                    Paragraph("<b>Details & Associated Entities</b>", styles["TableHeader"]),
                ]
            ]

            for e_idx, e in enumerate(grp):
                ts = self._format_timestamp(e.get("timestamp"))
                title = e.get("title") or e.get("event_id") or f"Event {e_idx + 1}"
                desc = e.get("description") or "Observed packet interaction."

                e_id_short = self._truncate_id(e.get("event_id"))
                entities_list = e.get("entity_ids", [])
                ent_str = f"<br/><font color='{TEXT_MUTED.hexval()}'>Entities: {', '.join([self._truncate_id(ent) for ent in entities_list[:3]])}</font>" if entities_list else ""

                cell_time = Paragraph(f"<code>{html.escape(ts)}</code>", styles["TableCellMono"])
                cell_event = Paragraph(f"<b>[{html.escape(e_id_short)}]</b> {html.escape(str(title))}", styles["TableCell"])
                cell_desc = Paragraph(f"{html.escape(str(desc))}{ent_str}", styles["TableCell"])

                g_rows.append([
                    cell_time,
                    cell_event,
                    cell_desc,
                ])

            col_widths = [105, 135, self.content_width - 240]
            events_table = Table(g_rows, colWidths=col_widths)
            events_table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#475569")),
                    ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ])
            )

            for i in range(1, len(g_rows)):
                bg = BG_LIGHT_ROW if i % 2 == 1 else BG_WHITE
                events_table.setStyle(TableStyle([("BACKGROUND", (0, i), (-1, i), bg)]))

            proc_note = Paragraph(
                f"&bull; <i>Pipeline Processing: Analyzed by NetSleuth M1-M3 engines at {pipeline_generated_at}</i>",
                styles["Footnote"],
            )

            story.append(KeepTogether([gh_table, events_table, Spacer(1, 1), proc_note]))
            story.append(Spacer(1, 5))

        return story

    # -------------------------------------------------------------------------
    # Section 6: Appendix (Full Raw UUIDs Mapped, Smallest Font Size)
    # -------------------------------------------------------------------------
    def _build_appendix_section(
        self, report: Dict[str, Any], styles: Dict[str, ParagraphStyle]
    ) -> List[Any]:
        story: List[Any] = []
        story.append(PageBreak())  # Strictly page-broken from main report
        story.append(self._render_section_banner("5. Appendix: Forensic Identifiers & Evidence Custody", styles))
        story.append(Spacer(1, 3))

        intro_p = Paragraph(
            "This appendix contains complete, untruncated cryptographic UUIDs and entity mapping tables for formal evidentiary reference.",
            styles["Footnote"],
        )
        story.append(intro_p)
        story.append(Spacer(1, 3))

        # 1. Full Raw UUID Mappings Table
        uuid_rows = [
            [
                Paragraph("<b>Forensic Record Label</b>", styles["TableHeader"]),
                Paragraph("<b>Full Raw Cryptographic UUID / Hash Reference</b>", styles["TableHeader"]),
            ]
        ]

        # Case & Report Root IDs
        uuid_rows.append([
            Paragraph("Report Identifier", styles["AppendixLabel"]),
            Paragraph(f"<code>{html.escape(str(report.get('report_id', 'N/A')))}</code>", styles["AppendixMono"]),
        ])
        uuid_rows.append([
            Paragraph("Case Identifier", styles["AppendixLabel"]),
            Paragraph(f"<code>{html.escape(str(report.get('case_id', 'N/A')))}</code>", styles["AppendixMono"]),
        ])

        # Finding IDs
        for idx, f in enumerate(report.get("findings", [])):
            fid = f.get("finding_id", "N/A")
            ftitle = f.get("title") or f"Finding {idx + 1}"
            uuid_rows.append([
                Paragraph(f"Finding: {html.escape(str(ftitle)[:30])}", styles["AppendixLabel"]),
                Paragraph(f"<code>{html.escape(str(fid))}</code>", styles["AppendixMono"]),
            ])

        # Timeline Event IDs
        for idx, t in enumerate(report.get("timeline", [])):
            eid = t.get("event_id", "N/A")
            etitle = t.get("title") or f"Event {idx + 1}"
            uuid_rows.append([
                Paragraph(f"Timeline: {html.escape(str(etitle)[:30])}", styles["AppendixLabel"]),
                Paragraph(f"<code>{html.escape(str(eid))}</code>", styles["AppendixMono"]),
            ])

        # Entity IDs
        for idx, ent in enumerate(report.get("entities", [])):
            ent_id = ent.get("entity_id", "N/A")
            eval_str = ent.get("value") or f"Entity {idx + 1}"
            uuid_rows.append([
                Paragraph(f"Entity: {html.escape(str(eval_str)[:30])}", styles["AppendixLabel"]),
                Paragraph(f"<code>{html.escape(str(ent_id))}</code>", styles["AppendixMono"]),
            ])

        # Relationship IDs
        for idx, rel in enumerate(report.get("relationships", [])):
            rel_id = rel.get("relationship_id", "N/A")
            rel_type = rel.get("relationship_type", "RELATIONSHIP")
            s_id = rel.get("source_entity_id", "N/A")
            t_id = rel.get("target_entity_id", "N/A")
            uuid_rows.append([
                Paragraph(f"Rel: {html.escape(str(rel_type))}", styles["AppendixLabel"]),
                Paragraph(f"<code>{html.escape(str(rel_id))} ({html.escape(str(s_id))} -> {html.escape(str(t_id))})</code>", styles["AppendixMono"]),
            ])

        # Provenance
        prov = report.get("provenance")
        if prov:
            col_id = prov.get("collector_id", "N/A")
            env_id = prov.get("environment", "N/A")
            uuid_rows.append([
                Paragraph("Provenance Collector", styles["AppendixLabel"]),
                Paragraph(f"<code>{html.escape(str(col_id))} (Env: {html.escape(str(env_id))})</code>", styles["AppendixMono"]),
            ])

        col_w1 = 135
        col_w2 = self.content_width - col_w1
        uuid_table = Table(uuid_rows, colWidths=[col_w1, col_w2])
        uuid_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), NAVY_SUBHEADER),
                ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
                ("TOPPADDING", (0, 0), (-1, -1), 1.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ])
        )

        for i in range(1, len(uuid_rows)):
            bg = BG_LIGHT_ROW if i % 2 == 1 else BG_WHITE
            uuid_table.setStyle(TableStyle([("BACKGROUND", (0, i), (-1, i), bg)]))

        story.append(uuid_table)
        story.append(Spacer(1, 6))

        # Evidence Integrity Records & Chain of Custody
        evidence_integrity = report.get("evidence_integrity", [])
        if evidence_integrity:
            story.append(self._render_section_banner("--- EVIDENCE INTEGRITY & CHAIN OF CUSTODY ---", styles))
            story.append(Spacer(1, 2))
            ev_rows = [
                [
                    Paragraph("<b>Evidence ID</b>", styles["TableHeader"]),
                    Paragraph("<b>Type</b>", styles["TableHeader"]),
                    Paragraph("<b>Custodian & Chain of Custody</b>", styles["TableHeader"]),
                    Paragraph("<b>Verification Status</b>", styles["TableHeaderCenter"]),
                ]
            ]
            for ev in evidence_integrity:
                ev_id = ev.get("evidence_id", "N/A")
                ev_type = ev.get("evidence_type", "N/A")
                ev_stat = ev.get("verification_status", "UNVERIFIED")
                custody_list = ev.get("chain_of_custody", [])
                cust_lines = []
                for c in custody_list:
                    c_id = c.get("custodian_id", "N/A")
                    c_act = c.get("action", "action")
                    cust_lines.append(f"{c_id} ({c_act})")
                cust_str = ", ".join(cust_lines) if cust_lines else "N/A"

                ev_rows.append([
                    Paragraph(f"<code>{html.escape(str(ev_id))}</code>", styles["TableCellMono"]),
                    Paragraph(html.escape(str(ev_type)), styles["TableCell"]),
                    Paragraph(html.escape(cust_str), styles["TableCell"]),
                    Paragraph(f"<b>{html.escape(str(ev_stat))}</b>", styles["TableCellCenter"]),
                ])

            ev_table = Table(ev_rows, colWidths=[110, 75, self.content_width - 255, 70])
            ev_table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), NAVY_SUBHEADER),
                    ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
                    ("TOPPADDING", (0, 0), (-1, -1), 1.5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ])
            )
            for i in range(1, len(ev_rows)):
                bg = BG_LIGHT_ROW if i % 2 == 1 else BG_WHITE
                ev_table.setStyle(TableStyle([("BACKGROUND", (0, i), (-1, i), bg)]))
            story.append(ev_table)
            story.append(Spacer(1, 6))

        # Assessment Facts & Hypotheses
        assessment = report.get("assessment")
        if assessment:
            story.append(self._render_section_banner("--- ASSESSMENT ---", styles))
            story.append(Spacer(1, 2))
            ass_summary = assessment.get("summary", "N/A")
            ass_rows = [
                [Paragraph("<b>Assessment Summary</b>", styles["TableHeader"])],
                [Paragraph(html.escape(str(ass_summary)), styles["TableCell"])],
            ]
            for f_item in assessment.get("facts", []):
                f_stmt = f_item.get("statement", "")
                f_id = f_item.get("fact_id", "")
                ass_rows.append([Paragraph(f"<b>Fact [{html.escape(str(f_id))}]:</b> {html.escape(str(f_stmt))}", styles["TableCell"])])

            ass_table = Table(ass_rows, colWidths=[self.content_width])
            ass_table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), NAVY_SUBHEADER),
                    ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
                    ("TOPPADDING", (0, 0), (-1, -1), 1.5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ])
            )
            story.append(ass_table)
            story.append(Spacer(1, 4))

            hypotheses = assessment.get("hypotheses", [])
            if hypotheses:
                story.append(self._render_section_banner("--- INVESTIGATION HYPOTHESES ---", styles))
                story.append(Spacer(1, 2))
                hyp_rows = [[Paragraph("<b>Hypothesis ID</b>", styles["TableHeader"]), Paragraph("<b>Statement & Status</b>", styles["TableHeader"])]]
                for h_item in hypotheses:
                    h_stmt = h_item.get("statement", "")
                    h_type = h_item.get("hypothesis_type", "")
                    h_id = h_item.get("hypothesis_id", "")
                    h_stat = h_item.get("status", "")
                    hyp_rows.append([
                        Paragraph(f"<code>{html.escape(str(h_id))}</code>", styles["TableCellMono"]),
                        Paragraph(f"[{html.escape(str(h_type))} - {html.escape(str(h_stat))}] {html.escape(str(h_stmt))}", styles["TableCell"]),
                    ])
                h_table = Table(hyp_rows, colWidths=[105, self.content_width - 105])
                h_table.setStyle(
                    TableStyle([
                        ("BACKGROUND", (0, 0), (-1, 0), NAVY_SUBHEADER),
                        ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
                        ("TOPPADDING", (0, 0), (-1, -1), 1.5),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5),
                        ("LEFTPADDING", (0, 0), (-1, -1), 4),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                    ])
                )
                for i in range(1, len(hyp_rows)):
                    bg = BG_LIGHT_ROW if i % 2 == 1 else BG_WHITE
                    h_table.setStyle(TableStyle([("BACKGROUND", (0, i), (-1, i), bg)]))
                story.append(h_table)
                story.append(Spacer(1, 4))

            h_vals = assessment.get("hypothesis_validations", [])
            if h_vals or "hypothesis_validations" in assessment:
                story.append(self._render_section_banner("--- HYPOTHESIS VALIDATION ---", styles))
                story.append(Spacer(1, 2))
                hv_rows = [[Paragraph("<b>Validation ID</b>", styles["TableHeader"]), Paragraph("<b>Status & Missing Evidence</b>", styles["TableHeader"])]]
                for hv in h_vals:
                    hv_id = hv.get("validation_id", "N/A")
                    hv_stat = hv.get("validation_status", "N/A")
                    hv_miss = ", ".join(hv.get("missing_evidence", [])) or "None"
                    hv_rows.append([
                        Paragraph(f"<code>{html.escape(str(hv_id))}</code>", styles["TableCellMono"]),
                        Paragraph(f"Status: {html.escape(str(hv_stat))} | Missing: {html.escape(str(hv_miss))}", styles["TableCell"]),
                    ])
                if len(hv_rows) == 1:
                    hv_rows.append([Paragraph("None", styles["TableCell"]), Paragraph("No hypothesis validations recorded.", styles["TableCell"])])
                hv_table = Table(hv_rows, colWidths=[105, self.content_width - 105])
                hv_table.setStyle(
                    TableStyle([
                        ("BACKGROUND", (0, 0), (-1, 0), NAVY_SUBHEADER),
                        ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
                        ("TOPPADDING", (0, 0), (-1, -1), 1.5),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5),
                        ("LEFTPADDING", (0, 0), (-1, -1), 4),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                    ])
                )
                for i in range(1, len(hv_rows)):
                    bg = BG_LIGHT_ROW if i % 2 == 1 else BG_WHITE
                    hv_table.setStyle(TableStyle([("BACKGROUND", (0, i), (-1, i), bg)]))
                story.append(hv_table)
                story.append(Spacer(1, 4))

            r_causes = assessment.get("root_causes", [])
            if r_causes or "root_causes" in assessment:
                story.append(self._render_section_banner("--- ROOT CAUSE ANALYSIS ---", styles))
                story.append(Spacer(1, 2))
                rc_rows = [[Paragraph("<b>Root Cause ID</b>", styles["TableHeader"]), Paragraph("<b>Statement & Status</b>", styles["TableHeader"])]]
                for rc in r_causes:
                    rc_id = rc.get("root_cause_id", "N/A")
                    rc_stmt = rc.get("statement", "")
                    rc_stat = rc.get("status", "N/A")
                    rc_rows.append([
                        Paragraph(f"<code>{html.escape(str(rc_id))}</code>", styles["TableCellMono"]),
                        Paragraph(f"[{html.escape(str(rc_stat))}] {html.escape(str(rc_stmt))}", styles["TableCell"]),
                    ])
                if len(rc_rows) == 1:
                    rc_rows.append([Paragraph("None", styles["TableCell"]), Paragraph("No root causes recorded.", styles["TableCell"])])
                rc_table = Table(rc_rows, colWidths=[105, self.content_width - 105])
                rc_table.setStyle(
                    TableStyle([
                        ("BACKGROUND", (0, 0), (-1, 0), NAVY_SUBHEADER),
                        ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
                        ("TOPPADDING", (0, 0), (-1, -1), 1.5),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5),
                        ("LEFTPADDING", (0, 0), (-1, -1), 4),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                    ])
                )
                for i in range(1, len(rc_rows)):
                    bg = BG_LIGHT_ROW if i % 2 == 1 else BG_WHITE
                    rc_table.setStyle(TableStyle([("BACKGROUND", (0, i), (-1, i), bg)]))
                story.append(rc_table)
                story.append(Spacer(1, 4))

            impacts = assessment.get("impacts", []) or assessment.get("impact_assessments", [])
            if impacts or "impacts" in assessment or "impact_assessments" in assessment:
                story.append(self._render_section_banner("--- IMPACT ASSESSMENT ---", styles))
                story.append(Spacer(1, 2))
                imp_rows = [[Paragraph("<b>Impact ID</b>", styles["TableHeader"]), Paragraph("<b>Statement & Status</b>", styles["TableHeader"])]]
                for imp in impacts:
                    imp_id = imp.get("impact_id", "N/A")
                    imp_stmt = imp.get("statement", "")
                    imp_stat = imp.get("status", "N/A")
                    imp_rows.append([
                        Paragraph(f"<code>{html.escape(str(imp_id))}</code>", styles["TableCellMono"]),
                        Paragraph(f"[{html.escape(str(imp_stat))}] {html.escape(str(imp_stmt))}", styles["TableCell"]),
                    ])
                if len(imp_rows) == 1:
                    imp_rows.append([Paragraph("None", styles["TableCell"]), Paragraph("No impact assessments recorded.", styles["TableCell"])])
                imp_table = Table(imp_rows, colWidths=[105, self.content_width - 105])
                imp_table.setStyle(
                    TableStyle([
                        ("BACKGROUND", (0, 0), (-1, 0), NAVY_SUBHEADER),
                        ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
                        ("TOPPADDING", (0, 0), (-1, -1), 1.5),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5),
                        ("LEFTPADDING", (0, 0), (-1, -1), 4),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                    ])
                )
                for i in range(1, len(imp_rows)):
                    bg = BG_LIGHT_ROW if i % 2 == 1 else BG_WHITE
                    imp_table.setStyle(TableStyle([("BACKGROUND", (0, i), (-1, i), bg)]))
                story.append(imp_table)
                story.append(Spacer(1, 6))

        # MITRE ATT&CK Mappings if present in report
        if "mitre_mappings" in report:
            mitre_mappings = report.get("mitre_mappings")
            story.append(self._render_section_banner("MITRE ATT&CK MAPPINGS", styles))
            story.append(Spacer(1, 2))
            if mitre_mappings:
                mitre_rows = [
                    [
                        Paragraph("<b>Technique</b>", styles["TableHeader"]),
                        Paragraph("<b>Tactic & Behavior</b>", styles["TableHeader"]),
                        Paragraph("<b>Status & Confidence</b>", styles["TableHeader"]),
                        Paragraph("<b>Rationale & Analytics</b>", styles["TableHeader"]),
                    ]
                ]
                for m in mitre_mappings:
                    tech_str = f"{m.get('technique_id', 'N/A')}: {m.get('technique_name', '')}"
                    tac_str = f"{m.get('tactic_id', '')} - {m.get('tactic_name', '')}<br/>Behavior: {m.get('behavior_id', '')}"
                    stat_str = f"Status: {m.get('mapping_status', 'SUPPORTED')}<br/>Confidence: {m.get('mapping_confidence', 1.0)}"
                    rat_str = f"{m.get('rationale', '')}<br/>Findings: {', '.join(m.get('source_finding_ids', []))}<br/>Evidence: {', '.join(m.get('evidence_ids', []))}<br/>Channels: {', '.join(m.get('channels', []))}<br/>Strategies: {', '.join(m.get('detection_strategy_ids', []))}<br/>Analytics: {', '.join(m.get('analytic_ids', []))}<br/>Components: {', '.join(m.get('data_component_ids', []))}<br/>First: {m.get('first_seen', '')}<br/>Last: {m.get('last_seen', '')}"

                    mitre_rows.append([
                        Paragraph(f"<code>{html.escape(tech_str)}</code>", styles["TableCellMono"]),
                        Paragraph(html.escape(tac_str), styles["TableCell"]),
                        Paragraph(html.escape(stat_str), styles["TableCell"]),
                        Paragraph(html.escape(rat_str), styles["TableCell"]),
                    ])

                mitre_table = Table(mitre_rows, colWidths=[105, 105, 80, self.content_width - 290])
                mitre_table.setStyle(
                    TableStyle([
                        ("BACKGROUND", (0, 0), (-1, 0), NAVY_SUBHEADER),
                        ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
                        ("TOPPADDING", (0, 0), (-1, -1), 1.5),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5),
                        ("LEFTPADDING", (0, 0), (-1, -1), 4),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ])
                )
                for i in range(1, len(mitre_rows)):
                    bg = BG_LIGHT_ROW if i % 2 == 1 else BG_WHITE
                    mitre_table.setStyle(TableStyle([("BACKGROUND", (0, i), (-1, i), bg)]))
                story.append(mitre_table)
            else:
                story.append(Table([["No MITRE ATT&CK mappings recorded."]], colWidths=[self.content_width]))
            story.append(Spacer(1, 6))

        # MITRE Provenance if present
        if "mitre_provenance" in report and report.get("mitre_provenance"):
            m_prov = report.get("mitre_provenance")
            story.append(self._render_section_banner("MITRE PROVENANCE", styles))
            story.append(Spacer(1, 2))
            m_rows = [
                [Paragraph("<b>Property</b>", styles["TableHeader"]), Paragraph("<b>Value</b>", styles["TableHeader"])],
                [Paragraph("Framework", styles["TableCellBold"]), Paragraph(html.escape(str(m_prov.get("framework", "N/A"))), styles["TableCell"])],
                [Paragraph("Domain", styles["TableCellBold"]), Paragraph(html.escape(str(m_prov.get("domain", "N/A"))), styles["TableCell"])],
                [Paragraph("Version", styles["TableCellBold"]), Paragraph(html.escape(str(m_prov.get("version", "N/A"))), styles["TableCell"])],
                [Paragraph("Knowledge Profile ID", styles["TableCellBold"]), Paragraph(html.escape(str(m_prov.get("knowledge_profile_id", "N/A"))), styles["TableCell"])],
            ]
            m_table = Table(m_rows, colWidths=[130, self.content_width - 130])
            m_table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), NAVY_SUBHEADER),
                    ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
                    ("TOPPADDING", (0, 0), (-1, -1), 1.5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ])
            )
            for i in range(1, len(m_rows)):
                bg = BG_LIGHT_ROW if i % 2 == 1 else BG_WHITE
                m_table.setStyle(TableStyle([("BACKGROUND", (0, i), (-1, i), bg)]))
            story.append(m_table)
            story.append(Spacer(1, 6))

        # Attack Chain if present
        if "attack_chain" in report and report.get("attack_chain") is not None:
            ac = report.get("attack_chain", {})
            story.append(self._render_section_banner("ATTACK CHAIN", styles))
            story.append(Spacer(1, 2))
            ac_stat = ac.get("status", "N/A")
            stages = ac.get("stages", [])
            story.append(Paragraph(f"<b>Status:</b> {html.escape(str(ac_stat))}", styles["TableCell"]))
            story.append(Spacer(1, 2))
            if stages:
                ac_rows = [
                    [
                        Paragraph("<b>Stage ID</b>", styles["TableHeader"]),
                        Paragraph("<b>Stage Name</b>", styles["TableHeader"]),
                        Paragraph("<b>Timestamp</b>", styles["TableHeader"]),
                        Paragraph("<b>Findings & Events</b>", styles["TableHeader"]),
                    ]
                ]
                for stg in stages:
                    s_id = stg.get("stage_id", "N/A")
                    s_name = stg.get("name", "N/A")
                    s_time = self._format_timestamp(stg.get("timestamp"))
                    f_ids = ", ".join(stg.get("finding_ids", [])) or "None"
                    e_ids = ", ".join(stg.get("event_ids", [])) or "None"
                    ac_rows.append([
                        Paragraph(f"<code>{html.escape(str(s_id))}</code>", styles["TableCellMono"]),
                        Paragraph(html.escape(str(s_name)), styles["TableCell"]),
                        Paragraph(html.escape(str(s_time)), styles["TableCell"]),
                        Paragraph(f"Findings: {html.escape(f_ids)}<br/>Events: {html.escape(e_ids)}", styles["TableCell"]),
                    ])
                ac_table = Table(ac_rows, colWidths=[75, 105, 105, self.content_width - 285])
                ac_table.setStyle(
                    TableStyle([
                        ("BACKGROUND", (0, 0), (-1, 0), NAVY_SUBHEADER),
                        ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
                        ("TOPPADDING", (0, 0), (-1, -1), 1.5),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5),
                        ("LEFTPADDING", (0, 0), (-1, -1), 4),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ])
                )
                for i in range(1, len(ac_rows)):
                    bg = BG_LIGHT_ROW if i % 2 == 1 else BG_WHITE
                    ac_table.setStyle(TableStyle([("BACKGROUND", (0, i), (-1, i), bg)]))
                story.append(ac_table)
            else:
                story.append(Table([["No attack chain stages recorded."]], colWidths=[self.content_width]))
            story.append(Spacer(1, 6))

        # AI-Assisted Narrative (LLM Enrichment) if present
        if "llm_enrichment" in report and report.get("llm_enrichment") is not None:
            llm = report.get("llm_enrichment", {})
            story.append(self._render_section_banner("--- AI-ASSISTED NARRATIVE ---", styles))
            story.append(Spacer(1, 2))
            llm_stat = llm.get("status", "N/A")
            llm_summary = llm.get("summary", "")
            llm_expl = llm.get("explanation", "")
            llm_limits = llm.get("limitations", "")

            llm_rows = [
                [Paragraph("<b>Status</b>", styles["TableHeader"]), Paragraph(html.escape(str(llm_stat)), styles["TableHeader"])],
            ]
            if llm_summary:
                llm_rows.append([Paragraph("Summary", styles["TableCellBold"]), Paragraph(html.escape(str(llm_summary)), styles["TableCell"])])
            if llm_expl:
                llm_rows.append([Paragraph("Explanation", styles["TableCellBold"]), Paragraph(html.escape(str(llm_expl)), styles["TableCell"])])
            if llm_limits:
                llm_rows.append([Paragraph("Limitations", styles["TableCellBold"]), Paragraph(html.escape(str(llm_limits)), styles["TableCell"])])

            for m_item in llm.get("mitre_explanations", []):
                t_id = m_item.get("technique_id", "")
                t_nm = m_item.get("technique_name", "")
                t_ex = m_item.get("explanation", "")
                llm_rows.append([Paragraph(f"MITRE [{html.escape(str(t_id))}]", styles["TableCellBold"]), Paragraph(f"<b>{html.escape(str(t_nm))}:</b> {html.escape(str(t_ex))}", styles["TableCell"])])

            for q, a in llm.get("investigator_answers", {}).items():
                llm_rows.append([Paragraph(f"Q: {html.escape(str(q))}", styles["TableCellBold"]), Paragraph(f"A: {html.escape(str(a))}", styles["TableCell"])])

            llm_table = Table(llm_rows, colWidths=[110, self.content_width - 110])
            llm_table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), NAVY_SUBHEADER),
                    ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
                    ("TOPPADDING", (0, 0), (-1, -1), 1.5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ])
            )
            for i in range(1, len(llm_rows)):
                bg = BG_LIGHT_ROW if i % 2 == 1 else BG_WHITE
                llm_table.setStyle(TableStyle([("BACKGROUND", (0, i), (-1, i), bg)]))
            story.append(llm_table)

        return story

    # -------------------------------------------------------------------------
    # Main Render & Generation Methods
    # -------------------------------------------------------------------------
    def render(self, report: Dict[str, Any]) -> bytes:
        """
        Renders a contract-valid Report V1/V1.1/V1.2/V1.3 dictionary into a single PDF document.

        :param report: Dict adhering to NetSleuth Report contracts.
        :return: Binary PDF bytes (%PDF-1.4).
        """
        if not isinstance(report, dict):
            raise ValueError("Report input must be a dictionary.")

        # 1. Input immutability
        report_data = deepcopy(report)

        # 2. Version-aware Contract validation
        schema_file = self._detect_report_version(report_data)
        if self.validator:
            self.validator.validate(schema_file, report_data)

        # 3. Setup document template with 0.6in margins
        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf,
            pagesize=letter,
            leftMargin=self.margin,
            rightMargin=self.margin,
            topMargin=self.margin,
            bottomMargin=self.margin,
            pageCompression=0,  # Uncompressed streams for high compatibility & text searchability
            invariant=1,        # Enforce deterministic rendering output
        )

        styles = self._create_styles()
        story: List[Any] = []

        # Section 1: Header / Cover
        story.extend(self._build_header_section(report_data, styles))

        # Section 2: Executive Summary
        story.extend(self._build_executive_summary_section(report_data, styles))

        # Section 3: Key Findings Table
        story.extend(self._build_findings_section(report_data, styles))

        # Section 4: IOC Table (Deduplicated)
        story.extend(self._build_ioc_section(report_data, styles))

        # Section 5: Grouped Timeline
        story.extend(self._build_timeline_section(report_data, styles))

        # Section 6: Appendix
        story.extend(self._build_appendix_section(report_data, styles))

        # Build Document
        doc.build(story, canvasmaker=NumberedCanvas)
        return buf.getvalue()

    def generate_pdf(
        self, report: Dict[str, Any], output_path: Optional[Union[str, Path]] = None
    ) -> bytes:
        """
        Generates PDF and optionally saves it to output_path.

        :param report: Case or Report dictionary.
        :param output_path: Optional destination file path.
        :return: Binary PDF bytes.
        """
        pdf_bytes = self.render(report)
        if output_path:
            out = Path(output_path)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(pdf_bytes)
        return pdf_bytes


# =============================================================================
# TOP-LEVEL FUNCTION INTERFACE
# =============================================================================
def generate_pdf_report(
    case_or_report_data: Dict[str, Any],
    output_path: Optional[Union[str, Path]] = None,
    validator: Optional[ContractValidator] = None,
) -> bytes:
    """
    Convenience function to generate a formatted PDF report from case/report JSON.

    :param case_or_report_data: Case dictionary or Report dictionary.
    :param output_path: Optional file path to write the PDF to.
    :param validator: Optional ContractValidator instance.
    :return: Binary PDF bytes.
    """
    renderer = PDFReportRenderer(validator=validator)
    return renderer.generate_pdf(case_or_report_data, output_path=output_path)
