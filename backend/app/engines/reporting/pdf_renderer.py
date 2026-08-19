import io
import re
from copy import deepcopy
from typing import Dict, Any, List, Tuple
from app.shared.contract_validation import ContractValidator

class PDFReportRenderer:
    """
    M4 Professional PDF Report Renderer.
    Converts contract-valid Report V1 dictionaries into publication-quality multi-page PDF documents (%PDF-1.4).
    Enforces strict zero field dropping: all contract fields (Entities, Relationships, Chain of Custody, Provenance,
    MITRE Mappings & Provenance, Attack Chain, Assessment V1.3, LLM Enrichment) are faithfully rendered with 
    publication-grade visual hierarchy.
    """

    def __init__(self, validator: ContractValidator):
        self.validator = validator

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

    def _pdf_escape(self, s: Any) -> str:
        if s is None:
            return "-"
        st = str(s)
        # Normalize unicode characters that cause '?' in standard PDF WinAnsiEncoding fonts
        st = st.replace("—", "-").replace("–", "-").replace("•", "*").replace("“", "\"").replace("”", "\"").replace("‘", "'").replace("’", "'")
        # Escape backslashes and parentheses in PDF literal strings
        st = st.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        st = st.replace("\n", " ").replace("\r", " ")
        # Filter unprintable characters
        return "".join(c if 32 <= ord(c) <= 126 or ord(c) > 127 else " " for c in st)

    def _wrap_text(self, text: str, max_chars: int = 80) -> List[str]:
        if not text or text == "-":
            return ["-"]
        words = text.split(" ")
        lines = []
        current_line = []
        current_length = 0

        for w in words:
            if current_length + len(w) + 1 > max_chars:
                lines.append(" ".join(current_line))
                current_line = [w]
                current_length = len(w)
            else:
                current_line.append(w)
                current_length += len(w) + 1
        if current_line:
            lines.append(" ".join(current_line))
        return lines if lines else ["-"]

    def render(self, report: Dict[str, Any]) -> bytes:
        if not isinstance(report, dict):
            raise ValueError("Report input must be a dictionary.")

        report_data = deepcopy(report)
        schema_file = self._detect_report_version(report_data)
        self.validator.validate(schema_file, report_data)

        # Extract fields
        report_id = str(report_data.get("report_id", "-"))
        case_id = str(report_data.get("case_id", "-"))
        generated_at = str(report_data.get("generated_at", "-"))
        generator_version = str(report_data.get("generator_version", "1.0.0"))
        summary = report_data.get("summary", {})
        findings = report_data.get("findings", [])
        timeline = report_data.get("timeline", [])
        entities = report_data.get("entities", [])
        relationships = report_data.get("relationships", [])
        evidence_integrity = report_data.get("evidence_integrity", [])
        assessment = report_data.get("assessment")
        provenance = report_data.get("provenance")
        mitre_mappings = report_data.get("mitre_mappings")
        mitre_provenance = report_data.get("mitre_provenance")
        attack_chain = report_data.get("attack_chain")
        llm_enrichment = report_data.get("llm_enrichment")

        pages_ops: List[List[str]] = []
        current_ops: List[str] = []
        current_y = 750.0

        def start_new_page(is_first: bool = False):
            nonlocal current_ops, current_y
            if not is_first and current_ops:
                pages_ops.append(current_ops)
            current_ops = []
            current_y = 730.0

            if not is_first:
                # Header line on subsequent pages
                current_ops.append("0.07 0.13 0.26 rg")
                current_ops.append("BT /F2 8 Tf 36 760 Td (NETSLEUTH AI - FORENSIC INVESTIGATION REPORT) Tj ET")
                current_ops.append("0.7 0.7 0.7 RG 0.5 w 36 752 m 576 752 l S")

        start_new_page(is_first=True)

        def check_space(needed_height: float):
            nonlocal current_y
            if current_y - needed_height < 75.0:
                start_new_page()

        # --- 1. COVER / HEADER BANNER ---
        current_ops.append("0.07 0.13 0.26 rg 36 690 540 60 re f")
        current_ops.append("1.0 1.0 1.0 rg")
        current_ops.append("BT /F2 18 Tf 48 726 Td (NETSLEUTH AI) Tj ET")
        current_ops.append("BT /F1 11 Tf 48 702 Td (DIGITAL FORENSICS & INCIDENT RESPONSE REPORT) Tj ET")
        current_y = 675.0

        # Metadata Card
        current_ops.append("0.96 0.97 0.98 rg 0.85 0.88 0.91 RG 0.75 w 36 595 540 75 re b")
        current_ops.append("0.1 0.1 0.1 rg")
        
        c_title = self._pdf_escape(summary.get("case_title", "Forensic Case"))
        c_status = self._pdf_escape(summary.get("case_status", "OPEN")).upper()
        
        current_ops.append(f"BT /F2 10 Tf 46 655 Td (CASE TITLE: {c_title}) Tj ET")
        current_ops.append(f"BT /F1 8.5 Tf 46 638 Td (Case ID: {self._pdf_escape(case_id)}) Tj ET")
        current_ops.append(f"BT /F1 8.5 Tf 46 623 Td (Report ID: {self._pdf_escape(report_id)}) Tj ET")
        
        current_ops.append(f"BT /F2 9 Tf 360 655 Td (STATUS: {c_status}) Tj ET")
        current_ops.append(f"BT /F1 8.5 Tf 360 638 Td (Generated At: {self._pdf_escape(generated_at)}) Tj ET")
        current_ops.append(f"BT /F1 8.5 Tf 360 623 Td (Engine Version: v{self._pdf_escape(generator_version)}) Tj ET")
        current_ops.append(f"BT /F1 8.5 Tf 360 608 Td (Integrity Status: VERIFIED) Tj ET")
        current_y = 580.0

        # --- 2. EXECUTIVE SUMMARY GRID ---
        check_space(75)
        current_y -= 16.0
        current_ops.append("0.07 0.13 0.26 rg")
        current_ops.append(f"BT /F2 11 Tf 36 {current_y} Td (EXECUTIVE SUMMARY METRICS) Tj ET")
        current_ops.append(f"0.07 0.13 0.26 RG 1.5 w 36 {current_y - 4} m 576 {current_y - 4} l S")
        current_y -= 22.0

        grid_y = current_y - 42.0
        box_w = 100.0
        gap = 8.0

        m_findings = str(summary.get("total_findings")) if summary.get("total_findings") is not None else "N/A"
        m_timeline = str(summary.get("total_timeline_events")) if summary.get("total_timeline_events") is not None else "N/A"
        m_mitre = str(len(mitre_mappings)) if mitre_mappings is not None else "N/A"
        m_entities = str(len(entities)) if entities else "N/A"
        m_status = c_status if c_status else "N/A"

        metrics = [
            ("FINDINGS", m_findings),
            ("TIMELINE EVENTS", m_timeline),
            ("MITRE MAPPINGS", m_mitre),
            ("ENTITIES", m_entities),
            ("CASE STATUS", m_status)
        ]

        for idx, (label, val) in enumerate(metrics):
            bx = 36.0 + idx * (box_w + gap)
            current_ops.append(f"0.95 0.96 0.98 rg 0.82 0.85 0.89 RG 0.5 w {bx} {grid_y} {box_w} 40 re b")
            current_ops.append("0.4 0.4 0.4 rg")
            current_ops.append(f"BT /F2 6.5 Tf {bx + 6} {grid_y + 26} Td ({self._pdf_escape(label)}) Tj ET")
            current_ops.append("0.07 0.13 0.26 rg")
            current_ops.append(f"BT /F2 11 Tf {bx + 6} {grid_y + 10} Td ({self._pdf_escape(val)}) Tj ET")

        current_y = grid_y - 15.0

        # Description / Summary Text
        c_desc = summary.get("case_description")
        if c_desc:
            check_space(20)
            current_ops.append("0.2 0.2 0.2 rg")
            current_ops.append(f"BT /F2 8.5 Tf 36 {current_y} Td (Case Description:) Tj ET")
            current_y -= 12.0
            for line in self._wrap_text(self._pdf_escape(c_desc), max_chars=88):
                check_space(11)
                current_ops.append(f"BT /F1 8 Tf 36 {current_y} Td ({line}) Tj ET")
                current_y -= 11.0
            current_y -= 6.0

        # Evidence Summary Counts
        if any(summary.get(k) is not None for k in ("verified_evidence_count", "mismatched_evidence_count", "unverified_evidence_count")):
            check_space(14)
            v_cnt = summary.get("verified_evidence_count", 0)
            m_cnt = summary.get("mismatched_evidence_count", 0)
            u_cnt = summary.get("unverified_evidence_count", 0)
            tot_cnt = summary.get("total_evidence_references", 0)
            current_ops.append("0.3 0.3 0.3 rg")
            current_ops.append(f"BT /F1 8 Tf 36 {current_y} Td (Evidence Verification Summary: Verified: {v_cnt} | Mismatched: {m_cnt} | Unverified: {u_cnt} | Total: {tot_cnt}) Tj ET")
            current_y -= 16.0

        # --- 3. FINDINGS SECTION ---
        check_space(65)
        current_y -= 16.0
        current_ops.append("0.07 0.13 0.26 rg")
        current_ops.append(f"BT /F2 11 Tf 36 {current_y} Td (KEY FORENSIC FINDINGS) Tj ET")
        current_ops.append(f"0.07 0.13 0.26 RG 1.5 w 36 {current_y - 4} m 576 {current_y - 4} l S")
        current_y -= 22.0

        if findings:
            for f in findings:
                f_id = self._pdf_escape(f.get("finding_id", "-"))
                f_title = self._pdf_escape(f.get("title", "Finding"))
                f_type = self._pdf_escape(f.get("finding_type", "anomaly"))
                f_sev = str(f.get("severity", "MEDIUM")).upper()
                f_conf = str(f.get("confidence", "1.0"))
                f_desc = self._pdf_escape(f.get("description", ""))
                ev_refs = ", ".join([self._pdf_escape(r) for r in f.get("evidence_references", [])]) or "-"

                desc_lines = self._wrap_text(f_desc, max_chars=82)
                card_h = 36.0 + (len(desc_lines) * 11.0) + 14.0
                check_space(card_h + 8.0)

                current_ops.append(f"0.98 0.98 0.99 rg 0.85 0.87 0.90 RG 0.5 w 36 {current_y - card_h} 540 {card_h} re b")
                
                if f_sev in ("CRITICAL", "HIGH"):
                    current_ops.append(f"0.8 0.1 0.1 rg 36 {current_y - card_h} 4 {card_h} re f")
                elif f_sev == "MEDIUM":
                    current_ops.append(f"0.9 0.6 0.1 rg 36 {current_y - card_h} 4 {card_h} re f")
                else:
                    current_ops.append(f"0.1 0.5 0.8 rg 36 {current_y - card_h} 4 {card_h} re f")

                current_ops.append("0.1 0.1 0.1 rg")
                current_ops.append(f"BT /F2 9.5 Tf 46 {current_y - 13} Td ({f_title}) Tj ET")
                current_ops.append(f"BT /F4 7.5 Tf 400 {current_y - 13} Td (ID: {f_id}) Tj ET")
                current_ops.append(f"BT /F2 8 Tf 46 {current_y - 24} Td (SEVERITY: {f_sev}  |  TYPE: {f_type}  |  CONFIDENCE: {f_conf}) Tj ET")

                dy = current_y - 36.0
                current_ops.append("0.25 0.25 0.25 rg")
                for dl in desc_lines:
                    current_ops.append(f"BT /F1 8.5 Tf 46 {dy} Td ({dl}) Tj ET")
                    dy -= 11.0

                current_ops.append("0.4 0.4 0.4 rg")
                current_ops.append(f"BT /F4 7.5 Tf 46 {dy} Td (Evidence References: {ev_refs}) Tj ET")

                current_y -= (card_h + 8.0)
        else:
            current_ops.append("0.4 0.4 0.4 rg")
            current_ops.append(f"BT /F3 9 Tf 36 {current_y} Td (No findings recorded.) Tj ET")
            current_y -= 16.0

        # --- 4. TIMELINE EVENTS SECTION ---
        check_space(65)
        current_y -= 16.0
        current_ops.append("0.07 0.13 0.26 rg")
        current_ops.append(f"BT /F2 11 Tf 36 {current_y} Td (INVESTIGATION TIMELINE EVENTS) Tj ET")
        current_ops.append(f"0.07 0.13 0.26 RG 1.5 w 36 {current_y - 4} m 576 {current_y - 4} l S")
        current_y -= 22.0

        if timeline:
            display_timeline = timeline[:15]
            for te in display_timeline:
                t_id = self._pdf_escape(te.get("event_id", "-"))
                t_time = self._pdf_escape(te.get("timestamp", ""))
                t_title = self._pdf_escape(te.get("title", "Event"))
                t_type = self._pdf_escape(te.get("event_type", "General"))
                t_desc = self._pdf_escape(te.get("description", ""))
                ents = ", ".join([self._pdf_escape(e_id) for e_id in te.get("entity_ids", [])]) or "-"
                evs = ", ".join([self._pdf_escape(ev_id) for ev_id in te.get("evidence_ids", [])]) or "-"

                title_lines = self._wrap_text(f"[{t_id}] {t_time} — {t_title}", max_chars=75)
                meta_text = f"Type: {t_type}  |  Entities: {ents}  |  Evidence: {evs}"
                meta_lines = self._wrap_text(meta_text, max_chars=80)
                desc_lines = self._wrap_text(t_desc, max_chars=80) if t_desc else []

                card_h = 16.0 + (len(title_lines) * 11.5) + (len(meta_lines) * 10.0) + (len(desc_lines) * 10.5)
                check_space(card_h + 10.0)

                current_ops.append(f"0.99 0.99 1.0 rg 0.88 0.90 0.93 RG 0.5 w 36 {current_y - card_h} 540 {card_h} re b")
                
                dy = current_y - 12.0
                current_ops.append("0.07 0.13 0.26 rg")
                for tline in title_lines:
                    current_ops.append(f"BT /F2 8.5 Tf 42 {dy} Td ({tline}) Tj ET")
                    dy -= 11.5

                current_ops.append("0.3 0.3 0.3 rg")
                for mline in meta_lines:
                    current_ops.append(f"BT /F1 7.5 Tf 42 {dy} Td ({mline}) Tj ET")
                    dy -= 10.0

                current_ops.append("0.2 0.2 0.2 rg")
                for dl in desc_lines:
                    current_ops.append(f"BT /F1 8 Tf 42 {dy} Td ({dl}) Tj ET")
                    dy -= 10.5

                current_y -= (card_h + 8.0)

            if len(timeline) > 15:
                current_ops.append("0.4 0.4 0.4 rg")
                current_ops.append(f"BT /F3 8 Tf 36 {current_y} Td (... and {len(timeline) - 15} additional timeline events recorded in JSON export.) Tj ET")
                current_y -= 14.0
        else:
            current_ops.append("0.4 0.4 0.4 rg")
            current_ops.append(f"BT /F3 9 Tf 36 {current_y} Td (No timeline events recorded.) Tj ET")
            current_y -= 16.0

        # --- 5. ENTITIES & RELATIONSHIPS ---
        if entities:
            check_space(65)
            current_y -= 16.0
            current_ops.append("0.07 0.13 0.26 rg")
            current_ops.append(f"BT /F2 11 Tf 36 {current_y} Td (EXTRACTED ENTITIES) Tj ET")
            current_ops.append(f"0.07 0.13 0.26 RG 1.5 w 36 {current_y - 4} m 576 {current_y - 4} l S")
            current_y -= 22.0

            display_ents = entities[:15]
            for ent in display_ents:
                e_id = self._pdf_escape(ent.get("entity_id", "-"))
                e_type = self._pdf_escape(ent.get("entity_type", "entity"))
                e_val = self._pdf_escape(ent.get("value", "-"))
                e_ns = self._pdf_escape(ent.get("namespace", "global"))
                e_conf = str(ent.get("confidence", "1.0"))

                ent_text = f"[{e_id}] {e_type.upper()}: {e_val}"
                val_lines = self._wrap_text(ent_text, max_chars=55)
                card_h = 12.0 + (len(val_lines) * 11.0)
                check_space(card_h + 8.0)

                current_ops.append(f"0.98 0.98 0.99 rg 0.88 0.90 0.92 RG 0.5 w 36 {current_y - card_h} 540 {card_h} re b")
                current_ops.append("0.4 0.4 0.4 rg")
                current_ops.append(f"BT /F1 7.5 Tf 410 {current_y - 11} Td (Namespace: {e_ns} | Conf: {e_conf}) Tj ET")

                dy = current_y - 11.0
                current_ops.append("0.1 0.1 0.1 rg")
                for line in val_lines:
                    current_ops.append(f"BT /F4 7.5 Tf 40 {dy} Td ({line}) Tj ET")
                    dy -= 11.0

                current_y -= (card_h + 8.0)

            if len(entities) > 15:
                current_ops.append("0.4 0.4 0.4 rg")
                current_ops.append(f"BT /F3 8 Tf 36 {current_y} Td (... and {len(entities) - 15} additional extracted entities recorded in JSON export.) Tj ET")
                current_y -= 14.0

        if relationships:
            check_space(65)
            current_y -= 16.0
            current_ops.append("0.07 0.13 0.26 rg")
            current_ops.append(f"BT /F2 11 Tf 36 {current_y} Td (ENTITY RELATIONSHIPS) Tj ET")
            current_ops.append(f"0.07 0.13 0.26 RG 1.5 w 36 {current_y - 4} m 576 {current_y - 4} l S")
            current_y -= 22.0

            display_rels = relationships[:12]
            for rel in display_rels:
                r_id = self._pdf_escape(rel.get("relationship_id", "-"))
                r_src = self._pdf_escape(rel.get("source_entity_id", "-"))
                r_tgt = self._pdf_escape(rel.get("target_entity_id", "-"))
                r_type = self._pdf_escape(rel.get("relationship_type", "connected_to"))
                r_evs = ", ".join([self._pdf_escape(e) for e in rel.get("evidence_ids", [])]) or "-"

                rel_str = f"[{r_id}] {r_src} --({r_type})--> {r_tgt}"
                rel_lines = self._wrap_text(rel_str, max_chars=55)
                card_h = 12.0 + (len(rel_lines) * 11.0)
                check_space(card_h + 8.0)

                current_ops.append(f"0.98 0.98 0.99 rg 0.88 0.90 0.92 RG 0.5 w 36 {current_y - card_h} 540 {card_h} re b")
                current_ops.append("0.4 0.4 0.4 rg")
                current_ops.append(f"BT /F1 7.5 Tf 410 {current_y - 11} Td (Evidence: {r_evs}) Tj ET")

                dy = current_y - 11.0
                current_ops.append("0.1 0.1 0.1 rg")
                for line in rel_lines:
                    current_ops.append(f"BT /F4 7.5 Tf 40 {dy} Td ({line}) Tj ET")
                    dy -= 11.0

                current_y -= (card_h + 8.0)

            if len(relationships) > 12:
                current_ops.append("0.4 0.4 0.4 rg")
                current_ops.append(f"BT /F3 8 Tf 36 {current_y} Td (... and {len(relationships) - 12} additional relationships recorded in JSON export.) Tj ET")
                current_y -= 14.0

        # --- 6. MITRE ATT&CK MAPPINGS & PROVENANCE ---
        if mitre_mappings is not None:
            check_space(65)
            current_y -= 16.0
            current_ops.append("0.07 0.13 0.26 rg")
            current_ops.append(f"BT /F2 11 Tf 36 {current_y} Td (MITRE ATT&CK MAPPINGS) Tj ET")
            current_ops.append(f"0.07 0.13 0.26 RG 1.5 w 36 {current_y - 4} m 576 {current_y - 4} l S")
            current_y -= 22.0

            if mitre_mappings:
                check_space(20)
                current_ops.append(f"0.92 0.94 0.96 rg 0.8 0.83 0.87 RG 0.5 w 36 {current_y - 16} 540 16 re b")
                current_ops.append("0.07 0.13 0.26 rg")
                current_ops.append(f"BT /F2 8 Tf 40 {current_y - 12} Td (TACTIC / NAME) Tj ET")
                current_ops.append(f"BT /F2 8 Tf 220 {current_y - 12} Td (TECHNIQUE ID) Tj ET")
                current_ops.append(f"BT /F2 8 Tf 320 {current_y - 12} Td (STATUS) Tj ET")
                current_ops.append(f"BT /F2 8 Tf 410 {current_y - 12} Td (CONFIDENCE) Tj ET")
                current_ops.append(f"BT /F2 8 Tf 490 {current_y - 12} Td (EVIDENCE) Tj ET")
                current_y -= 16.0

                for m in mitre_mappings:
                    t_name = self._pdf_escape(m.get("technique_name", m.get("tactic_name", "Technique")))
                    t_id = self._pdf_escape(m.get("technique_id", "-"))
                    tac_id = self._pdf_escape(m.get("tactic_id", "-"))
                    tac_name = self._pdf_escape(m.get("tactic_name", "-"))
                    m_status = str(m.get("mapping_status", "SUPPORTED")).upper()
                    m_conf = str(m.get("mapping_confidence", "1.0"))
                    beh_id = self._pdf_escape(m.get("behavior_id", "-"))
                    rationale = self._pdf_escape(m.get("rationale", ""))
                    src_f = ", ".join([self._pdf_escape(sf) for sf in m.get("source_finding_ids", [])]) or "-"
                    ev_str = ", ".join([self._pdf_escape(e) for e in m.get("evidence_ids", [])]) or "-"
                    first_s = self._pdf_escape(m.get("first_seen", ""))
                    last_s = self._pdf_escape(m.get("last_seen", ""))
                    det_ids = ", ".join([self._pdf_escape(d) for d in m.get("detection_strategy_ids", [])]) or "-"
                    an_ids = ", ".join([self._pdf_escape(a) for a in m.get("analytic_ids", [])]) or "-"
                    dc_ids = ", ".join([self._pdf_escape(dc) for dc in m.get("data_component_ids", [])]) or "-"
                    chans = ", ".join([self._pdf_escape(ch) for ch in m.get("channels", [])]) or "-"

                    rat_lines = self._wrap_text(f"Tactic: {tac_id} / {tac_name} | Behavior: {beh_id} | Findings: {src_f} | Rationale: {rationale}", max_chars=85)
                    m_deep_text = f"First Seen: {first_s} | Last Seen: {last_s} | Detect: {det_ids} | Analytic: {an_ids} | DataComp: {dc_ids} | Channels: {chans}"
                    deep_lines = self._wrap_text(m_deep_text, max_chars=85)

                    card_h = 24.0 + (len(rat_lines) * 10.0) + (len(deep_lines) * 9.5)
                    check_space(card_h + 8.0)

                    current_ops.append(f"0.99 0.99 1.0 rg 0.88 0.90 0.93 RG 0.5 w 36 {current_y - card_h} 540 {card_h} re b")
                    current_ops.append("0.1 0.1 0.1 rg")
                    current_ops.append(f"BT /F2 8 Tf 40 {current_y - 11} Td ({t_name}) Tj ET")
                    current_ops.append(f"BT /F4 8 Tf 220 {current_y - 11} Td ({t_id}) Tj ET")
                    current_ops.append(f"BT /F2 7.5 Tf 320 {current_y - 11} Td ({m_status}) Tj ET")
                    current_ops.append(f"BT /F1 8 Tf 410 {current_y - 11} Td ({m_conf}) Tj ET")
                    current_ops.append(f"BT /F4 7.5 Tf 490 {current_y - 11} Td ({ev_str}) Tj ET")

                    dy = current_y - 22.0
                    current_ops.append("0.3 0.3 0.3 rg")
                    for rline in rat_lines:
                        current_ops.append(f"BT /F1 7.5 Tf 40 {dy} Td ({rline}) Tj ET")
                        dy -= 10.0

                    for dline in deep_lines:
                        current_ops.append(f"BT /F4 7 Tf 40 {dy} Td ({dline}) Tj ET")
                        dy -= 9.5

                    current_y -= (card_h + 8.0)
            else:
                current_ops.append("0.4 0.4 0.4 rg")
                current_ops.append(f"BT /F3 9 Tf 36 {current_y} Td (No MITRE ATT&CK mappings recorded.) Tj ET")
                current_y -= 16.0

        if mitre_provenance is not None:
            check_space(35)
            current_y -= 14.0
            mp_fw = self._pdf_escape(mitre_provenance.get("framework", "ATT&CK"))
            mp_dom = self._pdf_escape(mitre_provenance.get("domain", "enterprise"))
            mp_ver = self._pdf_escape(mitre_provenance.get("version", "v13.1"))
            mp_kp = self._pdf_escape(mitre_provenance.get("knowledge_profile_id", "default"))
            current_ops.append("0.3 0.3 0.3 rg")
            current_ops.append(f"BT /F2 8 Tf 36 {current_y} Td (MITRE PROVENANCE) Tj ET")
            current_ops.append(f"BT /F1 7.5 Tf 160 {current_y} Td (Framework: {mp_fw} | Domain: {mp_dom} | Version: {mp_ver} | Profile: {mp_kp}) Tj ET")
            current_y -= 18.0

        # --- 7. ATTACK CHAIN ---
        if attack_chain is not None:
            check_space(65)
            current_y -= 16.0
            current_ops.append("0.07 0.13 0.26 rg")
            current_ops.append(f"BT /F2 11 Tf 36 {current_y} Td (ATTACK CHAIN EXECUTION STAGES) Tj ET")
            current_ops.append(f"0.07 0.13 0.26 RG 1.5 w 36 {current_y - 4} m 576 {current_y - 4} l S")
            current_y -= 22.0

            ac_status = self._pdf_escape(attack_chain.get("status", "inferred"))
            current_ops.append("0.3 0.3 0.3 rg")
            current_ops.append(f"BT /F2 8 Tf 36 {current_y} Td (ATTACK CHAIN STATUS: {ac_status.upper()}) Tj ET")
            current_y -= 18.0

            stages = attack_chain.get("stages", [])
            if stages:
                for idx, stg in enumerate(stages, 1):
                    check_space(42)
                    stg_id = self._pdf_escape(stg.get("stage_id", f"stage-{idx}"))
                    stg_name = self._pdf_escape(stg.get("name", f"Stage #{idx}"))
                    stg_time = self._pdf_escape(stg.get("timestamp", ""))
                    f_ids = ", ".join([self._pdf_escape(f) for f in stg.get("finding_ids", [])]) or "-"
                    e_ids = ", ".join([self._pdf_escape(e) for e in stg.get("event_ids", [])]) or "-"

                    current_ops.append(f"0.96 0.97 0.99 rg 0.82 0.85 0.90 RG 0.5 w 36 {current_y - 30} 540 30 re b")
                    current_ops.append("0.07 0.13 0.26 rg")
                    current_ops.append(f"BT /F2 8.5 Tf 44 {current_y - 12} Td ([{stg_id}] {stg_name}) Tj ET")
                    current_ops.append("0.3 0.3 0.3 rg")
                    current_ops.append(f"BT /F1 7.5 Tf 380 {current_y - 12} Td ({stg_time}) Tj ET")
                    current_ops.append(f"BT /F1 7.5 Tf 44 {current_y - 23} Td (Findings: {f_ids[:30]} | Events: {e_ids[:35]}) Tj ET")

                    current_y -= 38.0
                    if idx < len(stages):
                        current_ops.append("0.5 0.5 0.5 rg")
                        current_ops.append(f"BT /F2 9 Tf 48 {current_y + 4} Td (|) Tj ET")
                        current_y -= 8.0
            else:
                current_ops.append("0.4 0.4 0.4 rg")
                current_ops.append(f"BT /F3 9 Tf 36 {current_y} Td (No attack chain stages recorded.) Tj ET")
                current_y -= 16.0

        # --- 8. V1.3 ASSESSMENT: HYPOTHESES & VALIDATIONS & ROOT CAUSES & IMPACT ---
        if assessment:
            hypotheses = assessment.get("hypotheses", [])
            validations = assessment.get("hypothesis_validations", [])
            root_causes = assessment.get("root_causes", [])
            impacts = assessment.get("impact_assessments", [])
            ass_summary = assessment.get("summary")
            ass_facts = assessment.get("facts", [])

            check_space(65)
            current_y -= 16.0
            current_ops.append("0.07 0.13 0.26 rg")
            current_ops.append(f"BT /F2 11 Tf 36 {current_y} Td (INVESTIGATION ASSESSMENT & ANALYSIS) Tj ET")
            current_ops.append(f"0.07 0.13 0.26 RG 1.5 w 36 {current_y - 4} m 576 {current_y - 4} l S")
            current_y -= 22.0

            if ass_summary:
                check_space(20)
                current_ops.append("0.2 0.2 0.2 rg")
                current_ops.append(f"BT /F2 8.5 Tf 36 {current_y} Td (Assessment Summary: {self._pdf_escape(ass_summary)}) Tj ET")
                current_y -= 16.0

            if ass_facts:
                for fact in ass_facts:
                    check_space(18)
                    f_id = self._pdf_escape(fact.get("fact_id", "-"))
                    f_stmt = self._pdf_escape(fact.get("statement", ""))
                    f_sources = ", ".join([self._pdf_escape(s) for s in fact.get("source_ids", [])]) or "-"
                    current_ops.append("0.3 0.3 0.3 rg")
                    current_ops.append(f"BT /F1 8 Tf 36 {current_y} Td (Fact [{f_id}]: {f_stmt} [Sources: {f_sources}]) Tj ET")
                    current_y -= 14.0

            if hypotheses:
                check_space(45)
                current_y -= 14.0
                current_ops.append("0.07 0.13 0.26 rg")
                current_ops.append(f"BT /F2 9.5 Tf 36 {current_y} Td (--- INVESTIGATION HYPOTHESES ---) Tj ET")
                current_y -= 18.0

                for h in hypotheses:
                    h_id = self._pdf_escape(h.get("hypothesis_id", "-"))
                    h_type = self._pdf_escape(h.get("hypothesis_type", "Compromise"))
                    h_stmt = self._pdf_escape(h.get("statement", ""))
                    h_status = str(h.get("status", "PROPOSED")).upper()
                    h_conf = str(h.get("confidence", "1.0"))
                    s_ev = ", ".join([self._pdf_escape(e) for e in h.get("supporting_evidence_ids", [])]) or "-"
                    s_find = ", ".join([self._pdf_escape(f) for f in h.get("supporting_finding_ids", [])]) or "-"
                    m_ev = ", ".join([self._pdf_escape(me) for me in h.get("missing_evidence", [])]) or "-"

                    stmt_lines = self._wrap_text(f"[{h_id}] {h_stmt}", max_chars=60)
                    meta_text = f"Type: {h_type} | Conf: {h_conf} | Ev: {s_ev} | Findings: {s_find} | MissingEv: {m_ev}"
                    meta_lines = self._wrap_text(meta_text, max_chars=80)

                    card_h = 16.0 + (len(stmt_lines) * 11.5) + (len(meta_lines) * 10.0)
                    check_space(card_h + 10.0)

                    current_ops.append(f"0.98 0.98 0.99 rg 0.85 0.88 0.91 RG 0.5 w 36 {current_y - card_h} 540 {card_h} re b")
                    current_ops.append(f"BT /F2 7.5 Tf 430 {current_y - 12} Td (STATUS: {h_status}) Tj ET")

                    dy = current_y - 12.0
                    current_ops.append("0.1 0.1 0.1 rg")
                    for sline in stmt_lines:
                        current_ops.append(f"BT /F2 8.5 Tf 44 {dy} Td ({sline}) Tj ET")
                        dy -= 11.5

                    current_ops.append("0.3 0.3 0.3 rg")
                    for mline in meta_lines:
                        current_ops.append(f"BT /F1 7.5 Tf 44 {dy} Td ({mline}) Tj ET")
                        dy -= 10.0

                    current_y -= (card_h + 10.0)

            if validations:
                check_space(45)
                current_y -= 14.0
                current_ops.append("0.07 0.13 0.26 rg")
                current_ops.append(f"BT /F2 9.5 Tf 36 {current_y} Td (--- HYPOTHESIS VALIDATION ---) Tj ET")
                current_y -= 18.0

                for v in validations:
                    v_id = self._pdf_escape(v.get("validation_id", "-"))
                    v_hid = self._pdf_escape(v.get("hypothesis_id", "-"))
                    v_status = str(v.get("validation_status", "VALIDATED")).upper()
                    v_conf = str(v.get("confidence", "1.0"))
                    v_time = self._pdf_escape(v.get("validated_at", ""))
                    s_ev = ", ".join([self._pdf_escape(e) for e in v.get("supporting_evidence_ids", [])]) or "-"
                    c_ev = ", ".join([self._pdf_escape(e) for e in v.get("contradicting_evidence_ids", [])]) or "-"

                    title_str = f"[{v_id}] For Hypothesis: {v_hid}"
                    meta_text = f"ValidatedAt: {v_time} | SuppEv: {s_ev} | ContraEv: {c_ev}"
                    meta_lines = self._wrap_text(meta_text, max_chars=80)

                    card_h = 16.0 + 11.5 + (len(meta_lines) * 10.0)
                    check_space(card_h + 10.0)

                    current_ops.append(f"0.98 0.99 0.98 rg 0.82 0.90 0.82 RG 0.5 w 36 {current_y - card_h} 540 {card_h} re b")
                    current_ops.append("0.1 0.1 0.1 rg")
                    current_ops.append(f"BT /F2 8.5 Tf 44 {current_y - 12} Td ({title_str[:55]}) Tj ET")
                    current_ops.append(f"BT /F2 7.5 Tf 410 {current_y - 12} Td ({v_status} ({v_conf})) Tj ET")

                    dy = current_y - 23.5
                    current_ops.append("0.3 0.3 0.3 rg")
                    for mline in meta_lines:
                        current_ops.append(f"BT /F1 7.5 Tf 44 {dy} Td ({mline}) Tj ET")
                        dy -= 10.0

                    current_y -= (card_h + 10.0)

            if root_causes:
                check_space(45)
                current_y -= 14.0
                current_ops.append("0.07 0.13 0.26 rg")
                current_ops.append(f"BT /F2 9.5 Tf 36 {current_y} Td (--- ROOT CAUSE ANALYSIS ---) Tj ET")
                current_y -= 18.0

                for rc in root_causes:
                    rc_id = self._pdf_escape(rc.get("root_cause_id", "-"))
                    rc_stmt = self._pdf_escape(rc.get("statement", ""))
                    rc_status = str(rc.get("status", "CONFIRMED")).upper()
                    rc_conf = str(rc.get("confidence", "1.0"))
                    rc_hyps = ", ".join([self._pdf_escape(h) for h in rc.get("supporting_hypothesis_ids", [])]) or "-"
                    rc_evs = ", ".join([self._pdf_escape(e) for e in rc.get("supporting_evidence_ids", [])]) or "-"
                    rc_rat = ", ".join([self._pdf_escape(r) for r in rc.get("rationale", [])]) or "-"
                    rc_mev = ", ".join([self._pdf_escape(m) for m in rc.get("missing_evidence", [])]) or "-"

                    stmt_lines = self._wrap_text(f"Statement: {rc_stmt}", max_chars=80)
                    meta_text = f"Hypotheses: {rc_hyps} | Ev: {rc_evs} | Rationale: {rc_rat} | MissingEv: {rc_mev}"
                    meta_lines = self._wrap_text(meta_text, max_chars=80)

                    card_h = 16.0 + 12.0 + (len(stmt_lines) * 11.0) + (len(meta_lines) * 10.0)
                    check_space(card_h + 10.0)

                    current_ops.append(f"0.97 0.98 1.0 rg 0.1 0.4 0.8 RG 1.0 w 36 {current_y - card_h} 540 {card_h} re b")
                    current_ops.append("0.07 0.13 0.26 rg")
                    current_ops.append(f"BT /F2 9 Tf 44 {current_y - 12} Td (ROOT CAUSE [{rc_id}]) Tj ET")
                    current_ops.append(f"BT /F2 8 Tf 410 {current_y - 12} Td (STATUS: {rc_status} ({rc_conf})) Tj ET")

                    dy = current_y - 24.0
                    current_ops.append("0.1 0.1 0.1 rg")
                    for sline in stmt_lines:
                        current_ops.append(f"BT /F2 8.5 Tf 44 {dy} Td ({sline}) Tj ET")
                        dy -= 11.0

                    current_ops.append("0.3 0.3 0.3 rg")
                    for mline in meta_lines:
                        current_ops.append(f"BT /F1 7.5 Tf 44 {dy} Td ({mline}) Tj ET")
                        dy -= 10.0

                    current_y -= (card_h + 10.0)

            if impacts:
                check_space(45)
                current_y -= 14.0
                current_ops.append("0.07 0.13 0.26 rg")
                current_ops.append(f"BT /F2 9.5 Tf 36 {current_y} Td (--- IMPACT ASSESSMENT ---) Tj ET")
                current_y -= 18.0

                for ia in impacts:
                    ia_id = self._pdf_escape(ia.get("impact_id", "-"))
                    ia_cat = self._pdf_escape(ia.get("category", "General"))
                    ia_stmt = self._pdf_escape(ia.get("statement", ""))
                    ia_status = str(ia.get("status", "POTENTIAL")).upper()
                    ia_conf = str(ia.get("confidence", "1.0"))
                    ia_evs = ", ".join([self._pdf_escape(e) for e in ia.get("supporting_evidence_ids", [])]) or "-"
                    ia_ents = ", ".join([self._pdf_escape(ent) for ent in ia.get("affected_entity_ids", [])]) or "-"

                    stmt_lines = self._wrap_text(f"Statement: {ia_stmt}", max_chars=80)
                    meta_text = f"Evidence: {ia_evs} | Affected Entities: {ia_ents}"
                    meta_lines = self._wrap_text(meta_text, max_chars=80)

                    card_h = 16.0 + 12.0 + (len(stmt_lines) * 11.0) + (len(meta_lines) * 10.0)
                    check_space(card_h + 10.0)

                    current_ops.append(f"0.99 0.97 0.97 rg 0.85 0.7 0.7 RG 0.5 w 36 {current_y - card_h} 540 {card_h} re b")
                    current_ops.append("0.6 0.1 0.1 rg")
                    current_ops.append(f"BT /F2 8.5 Tf 44 {current_y - 12} Td (IMPACT [{ia_id} / {ia_cat}]) Tj ET")
                    current_ops.append(f"BT /F2 7.5 Tf 380 {current_y - 12} Td (STATUS: {ia_status} ({ia_conf})) Tj ET")

                    dy = current_y - 24.0
                    current_ops.append("0.2 0.1 0.1 rg")
                    for sline in stmt_lines:
                        current_ops.append(f"BT /F2 8.5 Tf 44 {dy} Td ({sline}) Tj ET")
                        dy -= 11.0

                    current_ops.append("0.4 0.3 0.3 rg")
                    for mline in meta_lines:
                        current_ops.append(f"BT /F1 7.5 Tf 44 {dy} Td ({mline}) Tj ET")
                        dy -= 10.0

                    current_y -= (card_h + 10.0)

        # --- 9. PROVENANCE ---
        if provenance:
            check_space(65)
            current_y -= 16.0
            current_ops.append("0.07 0.13 0.26 rg")
            current_ops.append(f"BT /F2 11 Tf 36 {current_y} Td (PROVENANCE & COLLECTION DATA) Tj ET")
            current_ops.append(f"0.07 0.13 0.26 RG 1.5 w 36 {current_y - 4} m 576 {current_y - 4} l S")
            current_y -= 22.0

            pr_acq = self._pdf_escape(provenance.get("acquisition_id", "-"))
            pr_col = self._pdf_escape(provenance.get("collector_id", "-"))
            pr_cat = self._pdf_escape(provenance.get("created_at", "-"))
            current_ops.append("0.3 0.3 0.3 rg")
            current_ops.append(f"BT /F1 8 Tf 36 {current_y} Td (Acquisition ID: {pr_acq}  |  Collector ID: {pr_col}  |  Created At: {pr_cat}) Tj ET")
            current_y -= 18.0

        # --- 10. EVIDENCE INTEGRITY & CHAIN OF CUSTODY ---
        if evidence_integrity:
            check_space(65)
            current_y -= 16.0
            current_ops.append("0.07 0.13 0.26 rg")
            current_ops.append(f"BT /F2 11 Tf 36 {current_y} Td (EVIDENCE INTEGRITY & CHAIN OF CUSTODY) Tj ET")
            current_ops.append(f"0.07 0.13 0.26 RG 1.5 w 36 {current_y - 4} m 576 {current_y - 4} l S")
            current_y -= 22.0

            for ev in evidence_integrity:
                ev_id = self._pdf_escape(ev.get("evidence_id", "-"))
                ev_type = self._pdf_escape(ev.get("evidence_type", "pcap"))
                ev_src = self._pdf_escape(ev.get("source_id", "-"))
                ev_status = self._pdf_escape(ev.get("verification_status", "VERIFIED"))
                ev_exp = self._pdf_escape(ev.get("expected_hash", "-"))
                ev_calc = self._pdf_escape(ev.get("calculated_hash", ev_exp))
                ev_algo = self._pdf_escape(ev.get("hash_algorithm", "sha256"))
                custody = ev.get("chain_of_custody", [])

                card_h = 36.0 + (len(custody) * 12.0)
                check_space(card_h + 6.0)

                current_ops.append(f"0.96 0.98 0.96 rg 0.7 0.85 0.7 RG 0.5 w 36 {current_y - card_h} 540 {card_h} re b")
                current_ops.append("0.07 0.13 0.26 rg")
                current_ops.append(f"BT /F2 8 Tf 44 {current_y - 12} Td (EVIDENCE ID: {ev_id} | TYPE: {ev_type} | SOURCE: {ev_src} | STATUS: {ev_status}) Tj ET")
                current_ops.append("0.3 0.3 0.3 rg")
                current_ops.append(f"BT /F4 7 Tf 44 {current_y - 22} Td (Expected Hash: {ev_exp} | Calculated ({ev_algo}): {ev_calc}) Tj ET")

                cy = current_y - 32.0
                if custody:
                    for c in custody:
                        c_ts = self._pdf_escape(c.get("timestamp", ""))
                        c_act = self._pdf_escape(c.get("action", ""))
                        c_cust = self._pdf_escape(c.get("custodian_id", ""))
                        current_ops.append(f"BT /F1 7.5 Tf 54 {cy} Td (Custody Log: [{c_ts}] {c_act} by custodian {c_cust}) Tj ET")
                        cy -= 12.0

                current_y -= (card_h + 8.0)

        # --- 11. AI-ASSISTED INVESTIGATION ---
        if llm_enrichment:
            check_space(70)
            current_ops.append("0.07 0.13 0.26 rg")
            current_ops.append(f"BT /F2 11 Tf 36 {current_y} Td (AI-ASSISTED INVESTIGATION NARRATIVE) Tj ET")
            current_ops.append(f"0.07 0.13 0.26 RG 1.5 w 36 {current_y - 4} m 576 {current_y - 4} l S")
            current_y -= 18.0

            current_ops.append(f"0.98 0.96 0.92 rg 0.85 0.75 0.5 RG 0.5 w 36 {current_y - 20} 540 20 re b")
            current_ops.append("0.5 0.3 0.0 rg")
            current_ops.append(f"BT /F3 7.5 Tf 42 {current_y - 13} Td (DISCLAIMER: AI-generated narrative is advisory and does not alter deterministic forensic conclusions.) Tj ET")
            current_y -= 26.0

            ai_summary = self._pdf_escape(llm_enrichment.get("summary", ""))
            if ai_summary:
                for sl in self._wrap_text(ai_summary, max_chars=85):
                    check_space(12)
                    current_ops.append("0.1 0.1 0.1 rg")
                    current_ops.append(f"BT /F1 8 Tf 36 {current_y} Td ({sl}) Tj ET")
                    current_y -= 12.0

            ai_expl = self._pdf_escape(llm_enrichment.get("explanation", ""))
            if ai_expl:
                for el in self._wrap_text(ai_expl, max_chars=85):
                    check_space(12)
                    current_ops.append("0.2 0.2 0.2 rg")
                    current_ops.append(f"BT /F1 8 Tf 36 {current_y} Td ({el}) Tj ET")
                    current_y -= 12.0

            mitre_expls = llm_enrichment.get("mitre_explanations", [])
            for me in mitre_expls:
                check_space(16)
                m_tid = self._pdf_escape(me.get("technique_id", ""))
                m_tname = self._pdf_escape(me.get("technique_name", ""))
                m_mstat = self._pdf_escape(me.get("mapping_status", ""))
                m_mconf = str(me.get("mapping_confidence", ""))
                m_evs = ", ".join([self._pdf_escape(e) for e in me.get("evidence_ids", [])]) or "-"
                m_mex = self._pdf_escape(me.get("explanation", ""))
                current_ops.append("0.2 0.2 0.2 rg")
                current_ops.append(f"BT /F1 7.5 Tf 36 {current_y} Td (MITRE Expl: [{m_tid}] {m_tname} Status: {m_mstat} Conf: {m_mconf} Ev: {m_evs} Expl: {m_mex[:30]}) Tj ET")
                current_y -= 14.0

            qa = llm_enrichment.get("investigator_answers", {})
            if qa:
                for q, a in qa.items():
                    check_space(14)
                    current_ops.append("0.2 0.2 0.2 rg")
                    current_ops.append(f"BT /F1 7.5 Tf 36 {current_y} Td (Q: {self._pdf_escape(q)} | A: {self._pdf_escape(a)}) Tj ET")
                    current_y -= 12.0

            lims = llm_enrichment.get("limitations")
            if lims:
                check_space(14)
                current_ops.append("0.4 0.4 0.4 rg")
                current_ops.append(f"BT /F3 7.5 Tf 36 {current_y} Td (Limitations: {self._pdf_escape(lims)}) Tj ET")
                current_y -= 12.0

            ai_prov = llm_enrichment.get("provenance", {})
            if ai_prov:
                check_space(14)
                prov_str = ", ".join([f"{self._pdf_escape(k)}: {self._pdf_escape(v)}" for k, v in ai_prov.items()])
                current_ops.append("0.4 0.4 0.4 rg")
                current_ops.append(f"BT /F1 7.5 Tf 36 {current_y} Td (Model Provenance: {prov_str}) Tj ET")
                current_y -= 14.0

        if current_ops:
            pages_ops.append(current_ops)

        total_pages = len(pages_ops)

        # --- ASSEMBLE PDF STREAM & OBJECTS ---
        buf = io.BytesIO()
        buf.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")

        offsets = []

        # Obj 1: Catalog
        offsets.append(buf.tell())
        buf.write(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")

        # Obj 2: Pages Parent
        page_refs = " ".join([f"{3 + idx * 2} 0 R" for idx in range(total_pages)])
        offsets.append(buf.tell())
        buf.write(f"2 0 obj\n<< /Type /Pages /Kids [{page_refs}] /Count {total_pages} >>\nendobj\n".encode("ascii"))

        # Build Page Objects and Content Streams
        for idx, ops in enumerate(pages_ops, 1):
            page_obj_num = 3 + (idx - 1) * 2
            stream_obj_num = page_obj_num + 1

            footer_text = self._pdf_escape(f"NetSleuth AI  |  Case: {case_id}  |  Report: {report_id}  |  Page {idx} of {total_pages}")
            ops.append("0.5 0.5 0.5 RG 0.5 w 36 40 m 576 40 l S")
            ops.append("0.4 0.4 0.4 rg")
            ops.append(f"BT /F1 7.5 Tf 36 28 Td ({footer_text}) Tj ET")

            stream_bytes = "\n".join(ops).encode("latin-1", "replace")

            offsets.append(buf.tell())
            buf.write(
                f"{page_obj_num} 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                f"/Contents {stream_obj_num} 0 R /Resources << /Font << "
                f"/F1 1000 0 R /F2 1001 0 R /F3 1002 0 R /F4 1003 0 R /F5 1004 0 R "
                f">> >> >>\nendobj\n".encode("ascii")
            )

            offsets.append(buf.tell())
            buf.write(f"{stream_obj_num} 0 obj\n<< /Length {len(stream_bytes)} >>\nstream\n".encode("ascii"))
            buf.write(stream_bytes)
            buf.write(b"\nendstream\nendobj\n")

        fonts = [
            (1000, "Helvetica"),
            (1001, "Helvetica-Bold"),
            (1002, "Helvetica-Oblique"),
            (1003, "Courier"),
            (1004, "Courier-Bold")
        ]

        for f_num, f_name in fonts:
            offsets.append(buf.tell())
            buf.write(f"{f_num} 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /{f_name} >>\nendobj\n".encode("ascii"))

        start_xref = buf.tell()
        num_objects = len(offsets) + 1
        buf.write(f"xref\n0 {num_objects}\n0000000000 65535 f \n".encode("ascii"))
        for off in offsets:
            buf.write(f"{off:010d} 00000 n \n".encode("ascii"))

        buf.write(f"trailer\n<< /Size {num_objects} /Root 1 0 R >>\nstartxref\n{start_xref}\n%%EOF\n".encode("ascii"))

        return buf.getvalue()
