import json
from copy import deepcopy
from typing import Dict, Any, List
from app.shared.contract_validation import ContractValidator

class TextReportRenderer:
    """
    M4 Plain-Text Report Renderer.
    Converts contract-compliant Report V1 and Report V1.1 payloads into formatted plain-text reports.
    Provides deterministic presentation without code execution or schema mutation.
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
        else:
            raise ValueError(f"Unsupported or unknown report schema_version '{schema_version}'.")

    def render_text(self, report: Dict[str, Any]) -> str:
        """
        Renders a Report V1 or Report V1.1 dictionary payload into a structured, plain-text string report.

        :param report: Dict adhering to report-v1.json or report-v1.1.json
        :return: Plain-text string representation
        """
        if not isinstance(report, dict):
            raise ValueError("Report input must be a dictionary.")

        # 1. Input immutability
        report_data = deepcopy(report)

        # 2. Schema validation
        schema_file = self._detect_report_version(report_data)
        self.validator.validate(schema_file, report_data)

        # 3. Build text lines
        lines: List[str] = []

        # --- HEADER / REPORT IDENTITY ---
        lines.append("================================================================================")
        lines.append("                           NETSLEUTH-AI FORENSIC REPORT                         ")
        lines.append("================================================================================")
        lines.append(f"Report ID:         {report_data.get('report_id', '')}")
        lines.append(f"Case ID:           {report_data.get('case_id', '')}")
        lines.append(f"Schema Version:    {report_data.get('schema_version', '')}")
        lines.append(f"Generated At:      {report_data.get('generated_at', '')}")
        if report_data.get("generator_version"):
            lines.append(f"Generator Version: {report_data.get('generator_version')}")
        lines.append("")

        # --- SUMMARY ---
        summary = report_data.get("summary", {})
        lines.append("--------------------------------------------------------------------------------")
        lines.append("CASE SUMMARY")
        lines.append("--------------------------------------------------------------------------------")
        lines.append(f"Title:                      {summary.get('case_title', '')}")
        if summary.get("case_description") is not None:
            lines.append(f"Description:                {summary.get('case_description')}")
        lines.append(f"Status:                     {summary.get('case_status', '')}")
        lines.append(f"Total Findings:             {summary.get('total_findings', 0)}")
        lines.append(f"Total Timeline Events:      {summary.get('total_timeline_events', 0)}")
        lines.append(f"Total Evidence References:  {summary.get('total_evidence_references', 0)}")
        if summary.get("verified_evidence_count") is not None:
            lines.append(f"Verified Evidence Count:    {summary.get('verified_evidence_count')}")
        if summary.get("mismatched_evidence_count") is not None:
            lines.append(f"Mismatched Evidence Count:  {summary.get('mismatched_evidence_count')}")
        if summary.get("unverified_evidence_count") is not None:
            lines.append(f"Unverified Evidence Count:  {summary.get('unverified_evidence_count')}")
        lines.append("")

        # --- ASSESSMENT (if present) ---
        if "assessment" in report_data and report_data["assessment"] is not None:
            ass = report_data["assessment"]
            lines.append("--------------------------------------------------------------------------------")
            lines.append("ASSESSMENT")
            lines.append("--------------------------------------------------------------------------------")
            lines.append(f"Summary: {ass.get('summary', '')}")
            facts = ass.get("facts", [])
            if facts:
                lines.append("Facts:")
                for fact in facts:
                    fid = fact.get("fact_id", "")
                    stmt = fact.get("statement", "")
                    conf = fact.get("confidence")
                    conf_str = f" (Confidence: {conf})" if conf is not None else ""
                    sources = fact.get("source_ids", [])
                    src_str = f" [Sources: {', '.join(sources)}]" if sources else ""
                    lines.append(f"  - [{fid}] {stmt}{conf_str}{src_str}")
            lines.append("")

        # --- PROVENANCE (if present) ---
        if "provenance" in report_data and report_data["provenance"] is not None:
            prov = report_data["provenance"]
            lines.append("--------------------------------------------------------------------------------")
            lines.append("REPORT PROVENANCE")
            lines.append("--------------------------------------------------------------------------------")
            if prov.get("acquisition_id") is not None:
                lines.append(f"Acquisition ID: {prov.get('acquisition_id')}")
            if prov.get("collector_id") is not None:
                lines.append(f"Collector ID:   {prov.get('collector_id')}")
            if prov.get("created_at") is not None:
                lines.append(f"Created At:     {prov.get('created_at')}")
            lines.append("")

        # --- FINDINGS ---
        findings = report_data.get("findings", [])
        lines.append("--------------------------------------------------------------------------------")
        lines.append(f"FINDINGS ({len(findings)})")
        lines.append("--------------------------------------------------------------------------------")
        if not findings:
            lines.append("No findings reported.")
        for idx, f in enumerate(findings, 1):
            lines.append(f"[{idx}] Finding ID: {f.get('finding_id', '')}")
            lines.append(f"    Title:       {f.get('title', '')}")
            if f.get("finding_type") is not None:
                lines.append(f"    Type:        {f.get('finding_type')}")
            lines.append(f"    Severity:    {f.get('severity', '')}")
            lines.append(f"    Confidence:  {f.get('confidence', '')}")
            if f.get("description") is not None:
                lines.append(f"    Description: {f.get('description')}")
            ev_refs = f.get("evidence_references", [])
            if ev_refs:
                lines.append(f"    Evidence:    {', '.join(ev_refs)}")
            lines.append("")

        # --- TIMELINE ---
        timeline = report_data.get("timeline", [])
        lines.append("--------------------------------------------------------------------------------")
        lines.append(f"TIMELINE EVENTS ({len(timeline)})")
        lines.append("--------------------------------------------------------------------------------")
        if not timeline:
            lines.append("No timeline events reported.")
        for idx, te in enumerate(timeline, 1):
            lines.append(f"[{idx}] Event ID:    {te.get('event_id', '')}")
            lines.append(f"    Timestamp:   {te.get('timestamp', '')}")
            lines.append(f"    Title:       {te.get('title', '')}")
            if te.get("event_type") is not None:
                lines.append(f"    Event Type:  {te.get('event_type')}")
            if te.get("description") is not None:
                lines.append(f"    Description: {te.get('description')}")
            e_ids = te.get("entity_ids", [])
            if e_ids:
                lines.append(f"    Entities:    {', '.join(e_ids)}")
            ev_ids = te.get("evidence_ids", [])
            if ev_ids:
                lines.append(f"    Evidence:    {', '.join(ev_ids)}")
            lines.append("")

        # --- ENTITIES ---
        entities = report_data.get("entities", [])
        lines.append("--------------------------------------------------------------------------------")
        lines.append(f"ENTITIES ({len(entities)})")
        lines.append("--------------------------------------------------------------------------------")
        if not entities:
            lines.append("No entities reported.")
        for idx, e in enumerate(entities, 1):
            ns_str = f" (Namespace: {e.get('namespace')})" if e.get("namespace") is not None else ""
            conf_str = f" [Confidence: {e.get('confidence')}]" if e.get("confidence") is not None else ""
            lines.append(f"[{idx}] {e.get('entity_id', '')} | Type: {e.get('entity_type', '')} | Value: {e.get('value', '')}{ns_str}{conf_str}")
        lines.append("")

        # --- RELATIONSHIPS ---
        relationships = report_data.get("relationships", [])
        lines.append("--------------------------------------------------------------------------------")
        lines.append(f"RELATIONSHIPS ({len(relationships)})")
        lines.append("--------------------------------------------------------------------------------")
        if not relationships:
            lines.append("No relationships reported.")
        for idx, r in enumerate(relationships, 1):
            ev_ids = r.get("evidence_ids", [])
            ev_str = f" [Evidence: {', '.join(ev_ids)}]" if ev_ids else ""
            lines.append(f"[{idx}] {r.get('relationship_id', '')}: {r.get('source_entity_id', '')} --({r.get('relationship_type', '')})--> {r.get('target_entity_id', '')}{ev_str}")
        lines.append("")

        # --- EVIDENCE INTEGRITY ---
        evidence = report_data.get("evidence_integrity", [])
        lines.append("--------------------------------------------------------------------------------")
        lines.append(f"EVIDENCE INTEGRITY & CHAIN OF CUSTODY ({len(evidence)})")
        lines.append("--------------------------------------------------------------------------------")
        if not evidence:
            lines.append("No evidence integrity records reported.")
        for idx, ev in enumerate(evidence, 1):
            lines.append(f"[{idx}] Evidence ID:        {ev.get('evidence_id', '')}")
            lines.append(f"    Case ID:            {ev.get('case_id', '')}")
            lines.append(f"    Type:               {ev.get('evidence_type', '')}")
            if ev.get("source_id") is not None:
                lines.append(f"    Source ID:          {ev.get('source_id')}")
            lines.append(f"    Status:             {ev.get('verification_status', '')}")
            if ev.get("hash_algorithm") is not None:
                lines.append(f"    Hash Algorithm:     {ev.get('hash_algorithm')}")
            if ev.get("expected_hash") is not None:
                lines.append(f"    Expected Hash:      {ev.get('expected_hash')}")
            if ev.get("calculated_hash") is not None:
                lines.append(f"    Calculated Hash:    {ev.get('calculated_hash')}")
            if ev.get("verified_at") is not None:
                lines.append(f"    Verified At:        {ev.get('verified_at')}")
            if ev.get("collected_at") is not None:
                lines.append(f"    Collected At:       {ev.get('collected_at')}")
            if ev.get("ingested_at") is not None:
                lines.append(f"    Ingested At:        {ev.get('ingested_at')}")
            if ev.get("provenance") is not None:
                lines.append(f"    Provenance:         {json.dumps(ev.get('provenance'), sort_keys=True)}")

            custody = ev.get("chain_of_custody", [])
            if custody:
                lines.append("    Chain of Custody:")
                for c_idx, c in enumerate(custody, 1):
                    sig_str = f" (Signature: {c.get('signature')})" if c.get("signature") is not None else ""
                    lines.append(f"      - ({c_idx}) Custodian: {c.get('custodian_id', '')} | Action: {c.get('action', '')} | Timestamp: {c.get('timestamp', '')}{sig_str}")
            lines.append("")

        # --- V1.1 / V1.2 SPECIFIC SECTIONS: MITRE ATT&CK FINDINGS, PROVENANCE, ATTACK CHAIN ---
        if report_data.get("schema_version") in ("report-v1.1", "report-v1.2"):
            # MITRE PROVENANCE
            if "mitre_provenance" in report_data and report_data["mitre_provenance"] is not None:
                m_prov = report_data["mitre_provenance"]
                lines.append("--------------------------------------------------------------------------------")
                lines.append("MITRE ATT&CK PROVENANCE")
                lines.append("--------------------------------------------------------------------------------")
                lines.append(f"Framework:            {m_prov.get('framework', '')}")
                lines.append(f"Domain:               {m_prov.get('domain', '')}")
                lines.append(f"Version:              {m_prov.get('version', '')}")
                lines.append(f"Knowledge Profile ID: {m_prov.get('knowledge_profile_id', '')}")
                lines.append("")

            # MITRE MAPPINGS
            if "mitre_mappings" in report_data and report_data["mitre_mappings"] is not None:
                mappings = report_data["mitre_mappings"]
                lines.append("--------------------------------------------------------------------------------")
                lines.append(f"MITRE ATT&CK MAPPINGS ({len(mappings)})")
                lines.append("--------------------------------------------------------------------------------")
                if not mappings:
                    lines.append("No MITRE ATT&CK mappings reported.")
                for idx, m in enumerate(mappings, 1):
                    lines.append(f"[{idx}] Technique ID:     {m.get('technique_id', '')}")
                    lines.append(f"    Technique Name:   {m.get('technique_name', '')}")
                    if "tactic_id" in m and m["tactic_id"] is not None:
                        lines.append(f"    Tactic ID:        {m.get('tactic_id')}")
                    if "tactic_name" in m and m["tactic_name"] is not None:
                        lines.append(f"    Tactic Name:      {m.get('tactic_name')}")
                    if "behavior_id" in m and m["behavior_id"] is not None:
                        lines.append(f"    Behavior ID:      {m.get('behavior_id')}")
                    if "mapping_status" in m and m["mapping_status"] is not None:
                        lines.append(f"    Mapping Status:   {m.get('mapping_status')}")
                    if "mapping_confidence" in m and m["mapping_confidence"] is not None:
                        lines.append(f"    Confidence:       {m.get('mapping_confidence')}")
                    if "rationale" in m and m["rationale"] is not None:
                        lines.append(f"    Rationale:        {m.get('rationale')}")
                    if "source_finding_ids" in m and m["source_finding_ids"] is not None:
                        lines.append(f"    Source Findings:  {', '.join(m.get('source_finding_ids', []))}")
                    if "evidence_ids" in m and m["evidence_ids"] is not None:
                        lines.append(f"    Evidence IDs:     {', '.join(m.get('evidence_ids', []))}")
                    if "first_seen" in m and m["first_seen"] is not None:
                        lines.append(f"    First Seen:       {m.get('first_seen')}")
                    if "last_seen" in m and m["last_seen"] is not None:
                        lines.append(f"    Last Seen:        {m.get('last_seen')}")
                    if "detection_strategy_ids" in m and m["detection_strategy_ids"] is not None:
                        lines.append(f"    Detection Strat:  {', '.join(m.get('detection_strategy_ids', []))}")
                    if "analytic_ids" in m and m["analytic_ids"] is not None:
                        lines.append(f"    Analytic IDs:     {', '.join(m.get('analytic_ids', []))}")
                    if "data_component_ids" in m and m["data_component_ids"] is not None:
                        lines.append(f"    Data Components:  {', '.join(m.get('data_component_ids', []))}")
                    if "channels" in m and m["channels"] is not None:
                        lines.append(f"    Channels:         {', '.join(m.get('channels', []))}")
                    lines.append("")

            # ATTACK CHAIN
            if "attack_chain" in report_data and report_data["attack_chain"] is not None:
                ac = report_data["attack_chain"]
                lines.append("--------------------------------------------------------------------------------")
                lines.append("ATTACK CHAIN")
                lines.append("--------------------------------------------------------------------------------")
                lines.append(f"Status: {ac.get('status', 'none')}")
                stages = ac.get("stages", [])
                if stages:
                    lines.append("Stages:")
                    for s_idx, stg in enumerate(stages, 1):
                        lines.append(f"  [{s_idx}] Stage ID: {stg.get('stage_id', '')} | Name: {stg.get('name', '')}")
                        if "timestamp" in stg and stg["timestamp"] is not None:
                            lines.append(f"      Timestamp:   {stg.get('timestamp')}")
                        if "finding_ids" in stg and stg["finding_ids"] is not None:
                            lines.append(f"      Finding IDs: {', '.join(stg.get('finding_ids', []))}")
                        if "event_ids" in stg and stg["event_ids"] is not None:
                            lines.append(f"      Event IDs:   {', '.join(stg.get('event_ids', []))}")
                lines.append("")

        return "\n".join(lines)
