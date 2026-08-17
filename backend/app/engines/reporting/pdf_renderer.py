import io
from copy import deepcopy
from typing import Dict, Any, List
from app.shared.contract_validation import ContractValidator

class PDFReportRenderer:
    """
    M4 PDF Report Renderer.
    Converts contract-valid Report V1 dictionaries into presentation-only PDF documents.
    Built using pure Python standard library to ensure 0 external dependencies.
    """

    def __init__(self, validator: ContractValidator):
        self.validator = validator

    def _pdf_escape(self, s: Any) -> str:
        if s is None:
            return "-"
        st = str(s)
        # Escape backslashes and parentheses in PDF literal strings
        st = st.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        st = st.replace("\n", " ").replace("\r", " ")
        # Filter unprintable characters
        return "".join(c if 32 <= ord(c) <= 126 or ord(c) > 127 else " " for c in st)

    def render(self, report: Dict[str, Any]) -> bytes:
        """
        Renders a contract-valid Report V1 dictionary as binary PDF bytes (%PDF-1.4).

        :param report: Dict adhering to docs/contracts/report-v1.json
        :return: Binary PDF document bytes.
        """
        if not isinstance(report, dict):
            raise ValueError("Report input must be a dictionary.")

        # 1. Input immutability
        report_data = deepcopy(report)

        # 2. Validate input payload against frozen report-v1.json schema
        self.validator.validate("report-v1.json", report_data)

        # Build PDF text lines
        lines: List[str] = []

        report_id = report_data.get("report_id")
        case_id = report_data.get("case_id")
        generated_at = report_data.get("generated_at")
        generator_version = report_data.get("generator_version")
        summary = report_data.get("summary", {})
        findings = report_data.get("findings", [])
        timeline = report_data.get("timeline", [])
        entities = report_data.get("entities", [])
        relationships = report_data.get("relationships", [])
        evidence_integrity = report_data.get("evidence_integrity", [])
        assessment = report_data.get("assessment")
        provenance = report_data.get("provenance")

        lines.append("NetSleuth-AI Forensic Investigation Report")
        lines.append("=" * 60)
        lines.append(f"Report ID:         {self._pdf_escape(report_id)}")
        lines.append(f"Case ID:           {self._pdf_escape(case_id)}")
        lines.append(f"Generated At:      {self._pdf_escape(generated_at)}")
        lines.append(f"Generator Version: {self._pdf_escape(generator_version)}")
        lines.append("")

        lines.append("--- CASE SUMMARY ---")
        lines.append(f"Title:         {self._pdf_escape(summary.get('case_title'))}")
        lines.append(f"Status:        {self._pdf_escape(summary.get('case_status'))}")
        lines.append(f"Description:   {self._pdf_escape(summary.get('case_description'))}")
        lines.append(f"Findings Count:{self._pdf_escape(summary.get('total_findings'))}")
        lines.append(f"Timeline Count:{self._pdf_escape(summary.get('total_timeline_events'))}")
        lines.append(f"Evidence Count:{self._pdf_escape(summary.get('total_evidence_references'))}")
        lines.append(f"Verified:      {self._pdf_escape(summary.get('verified_evidence_count'))}")
        lines.append(f"Mismatched:    {self._pdf_escape(summary.get('mismatched_evidence_count'))}")
        lines.append(f"Unverified:    {self._pdf_escape(summary.get('unverified_evidence_count'))}")
        lines.append("")

        lines.append("--- FINDINGS ---")
        if findings:
            for f in findings:
                lines.append(
                    f"[{self._pdf_escape(f.get('finding_id'))}] {self._pdf_escape(f.get('title'))} "
                    f"(Type: {self._pdf_escape(f.get('finding_type'))}, Severity: {self._pdf_escape(f.get('severity'))}, "
                    f"Confidence: {self._pdf_escape(f.get('confidence'))})"
                )
                lines.append(f"  Description: {self._pdf_escape(f.get('description'))}")
                ev_str = ", ".join([self._pdf_escape(ref) for ref in f.get("evidence_references", [])]) or "-"
                lines.append(f"  Evidence:    {ev_str}")
        else:
            lines.append("No findings recorded.")
        lines.append("")

        lines.append("--- TIMELINE EVENTS ---")
        if timeline:
            for te in timeline:
                ents = ", ".join([self._pdf_escape(e_id) for e_id in te.get("entity_ids", [])]) or "-"
                evs = ", ".join([self._pdf_escape(ev_id) for ev_id in te.get("evidence_ids", [])]) or "-"
                lines.append(
                    f"[{self._pdf_escape(te.get('event_id'))}] {self._pdf_escape(te.get('timestamp'))} - "
                    f"{self._pdf_escape(te.get('title'))} ({self._pdf_escape(te.get('event_type'))})"
                )
                lines.append(f"  Description: {self._pdf_escape(te.get('description'))}")
                lines.append(f"  Entities:    {ents}")
                lines.append(f"  Evidence:    {evs}")
        else:
            lines.append("No timeline events recorded.")
        lines.append("")

        lines.append("--- ENTITIES ---")
        if entities:
            for ent in entities:
                lines.append(
                    f"[{self._pdf_escape(ent.get('entity_id'))}] Type: {self._pdf_escape(ent.get('entity_type'))}, "
                    f"Value: {self._pdf_escape(ent.get('value'))}, Namespace: {self._pdf_escape(ent.get('namespace'))}, "
                    f"Confidence: {self._pdf_escape(ent.get('confidence'))}"
                )
        else:
            lines.append("No entities recorded.")
        lines.append("")

        lines.append("--- RELATIONSHIPS ---")
        if relationships:
            for rel in relationships:
                evs = ", ".join([self._pdf_escape(ev_id) for ev_id in rel.get("evidence_ids", [])]) or "-"
                lines.append(
                    f"[{self._pdf_escape(rel.get('relationship_id'))}] {self._pdf_escape(rel.get('source_entity_id'))} "
                    f"--({self._pdf_escape(rel.get('relationship_type'))})--> {self._pdf_escape(rel.get('target_entity_id'))} "
                    f"[Evidence: {evs}]"
                )
        else:
            lines.append("No relationships recorded.")
        lines.append("")

        lines.append("--- EVIDENCE INTEGRITY & CHAIN OF CUSTODY ---")
        if evidence_integrity:
            for ev in evidence_integrity:
                lines.append(
                    f"[{self._pdf_escape(ev.get('evidence_id'))}] Type: {self._pdf_escape(ev.get('evidence_type'))}, "
                    f"Status: {self._pdf_escape(ev.get('verification_status'))}, Source ID: {self._pdf_escape(ev.get('source_id'))}"
                )
                lines.append(f"  Expected Hash:   {self._pdf_escape(ev.get('expected_hash'))}")
                lines.append(f"  Calculated Hash: {self._pdf_escape(ev.get('calculated_hash'))}")
                lines.append(f"  Algorithm:       {self._pdf_escape(ev.get('hash_algorithm'))}")
                custody = ev.get("chain_of_custody", [])
                if custody:
                    lines.append("  Custody Log:")
                    for c in custody:
                        lines.append(
                            f"    - [{self._pdf_escape(c.get('timestamp'))}] {self._pdf_escape(c.get('action'))} "
                            f"by {self._pdf_escape(c.get('custodian_id'))}"
                        )
        else:
            lines.append("No evidence integrity records.")
        lines.append("")

        if assessment:
            lines.append("--- ASSESSMENT ---")
            lines.append(f"Summary: {self._pdf_escape(assessment.get('summary'))}")
            for fact in assessment.get("facts", []):
                s_ids = ", ".join([self._pdf_escape(s) for s in fact.get("source_ids", [])]) or "-"
                lines.append(
                    f"  Fact [{self._pdf_escape(fact.get('fact_id'))}]: {self._pdf_escape(fact.get('statement'))} "
                    f"(Sources: {s_ids})"
                )
            lines.append("")

        if provenance:
            lines.append("--- PROVENANCE ---")
            lines.append(f"Acquisition ID: {self._pdf_escape(provenance.get('acquisition_id'))}")
            lines.append(f"Collector ID:   {self._pdf_escape(provenance.get('collector_id'))}")
            lines.append(f"Created At:     {self._pdf_escape(provenance.get('created_at'))}")
            lines.append("")

        # Format stream commands for PDF object
        stream_cmds: List[str] = [
            "BT",
            "/F1 9 Tf",
            "12 TL",
            "36 750 Td"
        ]

        for l in lines:
            safe_text = self._pdf_escape(l)
            stream_cmds.append(f"({safe_text}) '")

        stream_cmds.append("ET")
        stream_data = "\n".join(stream_cmds).encode("latin-1", "replace")

        # Assemble PDF objects
        buf = io.BytesIO()
        buf.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")

        offsets = []

        # Obj 1: Catalog
        offsets.append(buf.tell())
        buf.write(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")

        # Obj 2: Pages
        offsets.append(buf.tell())
        buf.write(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")

        # Obj 3: Page
        offsets.append(buf.tell())
        buf.write(
            b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n"
        )

        # Obj 4: Contents Stream
        offsets.append(buf.tell())
        buf.write(f"4 0 obj\n<< /Length {len(stream_data)} >>\nstream\n".encode("ascii"))
        buf.write(stream_data)
        buf.write(b"\nendstream\nendobj\n")

        # Obj 5: Font F1
        offsets.append(buf.tell())
        buf.write(b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>\nendobj\n")

        # Xref Table
        start_xref = buf.tell()
        buf.write(f"xref\n0 6\n0000000000 65535 f \n".encode("ascii"))
        for off in offsets:
            buf.write(f"{off:010d} 00000 n \n".encode("ascii"))

        # Trailer
        buf.write(f"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{start_xref}\n%%EOF\n".encode("ascii"))

        return buf.getvalue()
