import html
from copy import deepcopy
from typing import Dict, Any, Optional, List
from app.shared.contract_validation import ContractValidator

class HTMLReportRenderer:
    """
    M4 HTML Report Renderer.
    Converts contract-valid Report V1 dictionaries into presentation-only, human-readable HTML documents.
    All dynamic strings are escaped to prevent XSS. Does NOT perform investigative inference or network calls.
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

    def render(self, report: Dict[str, Any]) -> str:
        """
        Renders a contract-valid Report V1 or Report V1.1 dictionary into a self-contained UTF-8 HTML document.

        :param report: Dict adhering to docs/contracts/report-v1.json or docs/contracts/report-v1.1.json
        :return: HTML document string.
        """
        if not isinstance(report, dict):
            raise ValueError("Report input must be a dictionary.")

        # 1. Input immutability
        report_data = deepcopy(report)

        # 2. Version-aware contract validation
        schema_file = self._detect_report_version(report_data)
        self.validator.validate(schema_file, report_data)

        # Helper for HTML escaping
        def e(val: Any) -> str:
            if val is None:
                return "-"
            if isinstance(val, (int, float)):
                return str(val)
            return html.escape(str(val))

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

        # HTML Head and Stylesheet
        css_style = """
        :root {
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-card: #1e293b;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent-blue: #38bdf8;
            --accent-green: #4ade80;
            --accent-red: #f87171;
            --accent-yellow: #facc15;
            --border-color: #334155;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            margin: 0;
            padding: 24px;
            line-height: 1.5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        header {
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 16px;
            margin-bottom: 24px;
        }
        h1 {
            color: var(--accent-blue);
            margin: 0 0 8px 0;
            font-size: 28px;
        }
        .meta-bar {
            display: flex;
            gap: 16px;
            color: var(--text-secondary);
            font-size: 14px;
            flex-wrap: wrap;
        }
        .meta-item strong {
            color: var(--text-primary);
        }
        section {
            background: var(--bg-secondary);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 24px;
            border: 1px solid var(--border-color);
        }
        h2 {
            font-size: 20px;
            color: var(--accent-blue);
            margin-top: 0;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 8px;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 16px;
        }
        .stat-card {
            background: rgba(15, 23, 42, 0.6);
            padding: 16px;
            border-radius: 6px;
            border: 1px solid var(--border-color);
            text-align: center;
        }
        .stat-number {
            font-size: 24px;
            font-weight: bold;
            color: var(--text-primary);
        }
        .stat-label {
            font-size: 12px;
            color: var(--text-secondary);
            text-transform: uppercase;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 12px;
            font-size: 14px;
        }
        th, td {
            padding: 10px 12px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }
        th {
            background-color: rgba(15, 23, 42, 0.8);
            color: var(--accent-blue);
            font-weight: 600;
        }
        tr:hover {
            background-color: rgba(51, 65, 85, 0.4);
        }
        .badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
        }
        .badge-critical, .badge-high, .badge-mismatch, .badge-tampered {
            background-color: rgba(248, 113, 113, 0.2);
            color: var(--accent-red);
            border: 1px solid var(--accent-red);
        }
        .badge-medium, .badge-unverified {
            background-color: rgba(250, 204, 21, 0.2);
            color: var(--accent-yellow);
            border: 1px solid var(--accent-yellow);
        }
        .badge-low, .badge-verified, .badge-informational {
            background-color: rgba(74, 222, 128, 0.2);
            color: var(--accent-green);
            border: 1px solid var(--accent-green);
        }
        .code-block {
            font-family: monospace;
            background: rgba(15, 23, 42, 0.8);
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 13px;
        }
        """

        # Header section
        html_out = [
            '<!DOCTYPE html>',
            '<html lang="en">',
            '<head>',
            '<meta charset="UTF-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1.0">',
            f'<title>NetSleuth AI Report - {e(report_data.get("report_id"))}</title>',
            f'<style>{css_style}</style>',
            '</head>',
            '<body>',
            '<div class="container">',
            '<header>',
            f'<h1>Forensic Investigation Report</h1>',
            '<div class="meta-bar">',
            f'<div class="meta-item">Report ID: <strong>{e(report_data.get("report_id"))}</strong></div>',
            f'<div class="meta-item">Case ID: <strong>{e(report_data.get("case_id"))}</strong></div>',
            f'<div class="meta-item">Generated: <strong>{e(report_data.get("generated_at"))}</strong></div>',
            f'<div class="meta-item">Generator Version: <strong>{e(report_data.get("generator_version"))}</strong></div>',
            '</div>',
            '</header>'
        ]

        # Case Summary Section
        html_out.extend([
            '<section>',
            '<h2>Case Summary</h2>',
            f'<p><strong>Title:</strong> {e(summary.get("case_title"))}</p>',
            f'<p><strong>Status:</strong> <span class="badge badge-informational">{e(summary.get("case_status"))}</span></p>',
            f'<p><strong>Description:</strong> {e(summary.get("case_description"))}</p>',
            '<div class="stats-grid">',
            f'<div class="stat-card"><div class="stat-number">{e(summary.get("total_findings"))}</div><div class="stat-label">Total Findings</div></div>',
            f'<div class="stat-card"><div class="stat-number">{e(summary.get("total_timeline_events"))}</div><div class="stat-label">Timeline Events</div></div>',
            f'<div class="stat-card"><div class="stat-number">{e(summary.get("total_evidence_references"))}</div><div class="stat-label">Evidence References</div></div>',
            f'<div class="stat-card"><div class="stat-number">{e(summary.get("verified_evidence_count"))}</div><div class="stat-label">Verified</div></div>',
            f'<div class="stat-card"><div class="stat-number">{e(summary.get("mismatched_evidence_count"))}</div><div class="stat-label">Mismatched</div></div>',
            f'<div class="stat-card"><div class="stat-number">{e(summary.get("unverified_evidence_count"))}</div><div class="stat-label">Unverified</div></div>',
            '</div>',
            '</section>'
        ])

        # Findings Section
        html_out.extend([
            '<section>',
            '<h2>Findings</h2>'
        ])
        if findings:
            html_out.extend([
                '<table>',
                '<thead><tr><th>ID</th><th>Title</th><th>Type</th><th>Severity</th><th>Confidence</th><th>Description</th><th>Evidence</th></tr></thead>',
                '<tbody>'
            ])
            for f in findings:
                sev = e(f.get("severity", "informational"))
                badge_class = f'badge-{sev}' if f.get("severity") in ("critical", "high", "medium", "low", "informational") else 'badge-informational'
                ev_refs = ", ".join([e(ref) for ref in f.get("evidence_references", [])]) or "-"
                html_out.append(
                    f'<tr>'
                    f'<td><span class="code-block">{e(f.get("finding_id"))}</span></td>'
                    f'<td>{e(f.get("title"))}</td>'
                    f'<td>{e(f.get("finding_type"))}</td>'
                    f'<td><span class="badge {badge_class}">{sev}</span></td>'
                    f'<td>{e(f.get("confidence"))}</td>'
                    f'<td>{e(f.get("description"))}</td>'
                    f'<td>{ev_refs}</td>'
                    f'</tr>'
                )
            html_out.append('</tbody></table>')
        else:
            html_out.append('<p>No findings recorded.</p>')
        html_out.append('</section>')

        # Timeline Section
        html_out.extend([
            '<section>',
            '<h2>Timeline Events</h2>'
        ])
        if timeline:
            html_out.extend([
                '<table>',
                '<thead><tr><th>ID</th><th>Timestamp</th><th>Title</th><th>Type</th><th>Description</th><th>Entities</th><th>Evidence</th></tr></thead>',
                '<tbody>'
            ])
            for te in timeline:
                ents = ", ".join([e(eid) for eid in te.get("entity_ids", [])]) or "-"
                evs = ", ".join([e(evid) for evid in te.get("evidence_ids", [])]) or "-"
                html_out.append(
                    f'<tr>'
                    f'<td><span class="code-block">{e(te.get("event_id"))}</span></td>'
                    f'<td>{e(te.get("timestamp"))}</td>'
                    f'<td>{e(te.get("title"))}</td>'
                    f'<td>{e(te.get("event_type"))}</td>'
                    f'<td>{e(te.get("description"))}</td>'
                    f'<td>{ents}</td>'
                    f'<td>{evs}</td>'
                    f'</tr>'
                )
            html_out.append('</tbody></table>')
        else:
            html_out.append('<p>No timeline events recorded.</p>')
        html_out.append('</section>')

        # Entities Section
        html_out.extend([
            '<section>',
            '<h2>Entities</h2>'
        ])
        if entities:
            html_out.extend([
                '<table>',
                '<thead><tr><th>ID</th><th>Type</th><th>Value</th><th>Namespace</th><th>Confidence</th><th>Label</th><th>Role</th></tr></thead>',
                '<tbody>'
            ])
            for ent in entities:
                html_out.append(
                    f'<tr>'
                    f'<td><span class="code-block">{e(ent.get("entity_id"))}</span></td>'
                    f'<td>{e(ent.get("entity_type"))}</td>'
                    f'<td>{e(ent.get("value"))}</td>'
                    f'<td>{e(ent.get("namespace"))}</td>'
                    f'<td>{e(ent.get("confidence"))}</td>'
                    f'<td>{e(ent.get("label"))}</td>'
                    f'<td>{e(ent.get("role"))}</td>'
                    f'</tr>'
                )
            html_out.append('</tbody></table>')
        else:
            html_out.append('<p>No entities recorded.</p>')
        html_out.append('</section>')

        # Relationships Section
        html_out.extend([
            '<section>',
            '<h2>Relationships</h2>'
        ])
        if relationships:
            html_out.extend([
                '<table>',
                '<thead><tr><th>ID</th><th>Source Entity</th><th>Target Entity</th><th>Type</th><th>Evidence IDs</th></tr></thead>',
                '<tbody>'
            ])
            for rel in relationships:
                evs = ", ".join([e(evid) for evid in rel.get("evidence_ids", [])]) or "-"
                html_out.append(
                    f'<tr>'
                    f'<td><span class="code-block">{e(rel.get("relationship_id"))}</span></td>'
                    f'<td>{e(rel.get("source_entity_id"))}</td>'
                    f'<td>{e(rel.get("target_entity_id"))}</td>'
                    f'<td>{e(rel.get("relationship_type"))}</td>'
                    f'<td>{evs}</td>'
                    f'</tr>'
                )
            html_out.append('</tbody></table>')
        else:
            html_out.append('<p>No relationships recorded.</p>')
        html_out.append('</section>')

        # Evidence Integrity & Chain of Custody Section
        html_out.extend([
            '<section>',
            '<h2>Evidence Integrity & Chain of Custody</h2>'
        ])
        if evidence_integrity:
            html_out.extend([
                '<table>',
                '<thead><tr><th>Evidence ID</th><th>Type</th><th>Source ID</th><th>Verification Status</th><th>Expected Hash</th><th>Calculated Hash</th><th>Algorithm</th><th>Custody Log</th></tr></thead>',
                '<tbody>'
            ])
            for ev in evidence_integrity:
                st = e(ev.get("verification_status", "unverified"))
                bclass = f'badge-{st}' if st in ("verified", "mismatch", "unverified", "tampered") else 'badge-unverified'

                # Render custody log list
                custody_entries = ev.get("chain_of_custody", [])
                custody_html = []
                for c in custody_entries:
                    custody_html.append(
                        f'<div>[{e(c.get("timestamp"))}] <strong>{e(c.get("action"))}</strong> by {e(c.get("custodian_id"))}</div>'
                    )
                custody_str = "".join(custody_html) if custody_html else "-"

                html_out.append(
                    f'<tr>'
                    f'<td><span class="code-block">{e(ev.get("evidence_id"))}</span></td>'
                    f'<td>{e(ev.get("evidence_type"))}</td>'
                    f'<td>{e(ev.get("source_id"))}</td>'
                    f'<td><span class="badge {bclass}">{st}</span></td>'
                    f'<td><span class="code-block">{e(ev.get("expected_hash"))}</span></td>'
                    f'<td><span class="code-block">{e(ev.get("calculated_hash"))}</span></td>'
                    f'<td>{e(ev.get("hash_algorithm"))}</td>'
                    f'<td>{custody_str}</td>'
                    f'</tr>'
                )
            html_out.append('</tbody></table>')
        else:
            html_out.append('<p>No evidence integrity records.</p>')
        html_out.append('</section>')

        # Assessment Section (if present)
        if assessment:
            html_out.extend([
                '<section>',
                '<h2>Assessment</h2>',
                f'<p>{e(assessment.get("summary"))}</p>'
            ])
            facts = assessment.get("facts", [])
            if facts:
                html_out.extend([
                    '<table>',
                    '<thead><tr><th>Fact ID</th><th>Statement</th><th>Confidence</th><th>Source IDs</th></tr></thead>',
                    '<tbody>'
                ])
                for f in facts:
                    s_ids = ", ".join([e(sid) for sid in f.get("source_ids", [])]) or "-"
                    html_out.append(
                        f'<tr>'
                        f'<td><span class="code-block">{e(f.get("fact_id"))}</span></td>'
                        f'<td>{e(f.get("statement"))}</td>'
                        f'<td>{e(f.get("confidence"))}</td>'
                        f'<td>{s_ids}</td>'
                        f'</tr>'
                    )
                html_out.append('</tbody></table>')
            html_out.append('</section>')

        # Provenance Section (if present)
        if provenance:
            html_out.extend([
                '<section>',
                '<h2>Provenance</h2>',
                f'<p><strong>Acquisition ID:</strong> {e(provenance.get("acquisition_id"))}</p>',
                f'<p><strong>Collector ID:</strong> {e(provenance.get("collector_id"))}</p>',
                f'<p><strong>Created At:</strong> {e(provenance.get("created_at"))}</p>',
                '</section>'
            ])

        # V1.1 MITRE ATT&CK Section (if present)
        if mitre_mappings is not None:
            html_out.extend([
                '<section>',
                '<h2>MITRE ATT&CK Findings</h2>'
            ])
            if mitre_mappings:
                html_out.extend([
                    '<table>',
                    '<thead><tr><th>Technique ID</th><th>Technique Name</th><th>Tactic ID</th><th>Tactic Name</th><th>Behavior ID</th><th>Status</th><th>Confidence</th><th>Rationale</th><th>Source Findings</th><th>Evidence IDs</th><th>First Seen</th><th>Last Seen</th><th>Detection Strategies</th><th>Analytics</th><th>Data Components</th><th>Channels</th></tr></thead>',
                    '<tbody>'
                ])
                for m in mitre_mappings:
                    src_f = ", ".join([e(sf) for sf in m.get("source_finding_ids", [])]) or "-"
                    ev_ids = ", ".join([e(ev) for ev in m.get("evidence_ids", [])]) or "-"
                    ds_ids = ", ".join([e(ds) for ds in m.get("detection_strategy_ids", [])]) or "-"
                    an_ids = ", ".join([e(an) for an in m.get("analytic_ids", [])]) or "-"
                    dc_ids = ", ".join([e(dc) for dc in m.get("data_component_ids", [])]) or "-"
                    ch_ids = ", ".join([e(ch) for ch in m.get("channels", [])]) or "-"
                    html_out.append(
                        f'<tr>'
                        f'<td><span class="code-block">{e(m.get("technique_id"))}</span></td>'
                        f'<td>{e(m.get("technique_name"))}</td>'
                        f'<td>{e(m.get("tactic_id"))}</td>'
                        f'<td>{e(m.get("tactic_name"))}</td>'
                        f'<td>{e(m.get("behavior_id"))}</td>'
                        f'<td>{e(m.get("mapping_status"))}</td>'
                        f'<td>{e(m.get("mapping_confidence"))}</td>'
                        f'<td>{e(m.get("rationale"))}</td>'
                        f'<td>{src_f}</td>'
                        f'<td>{ev_ids}</td>'
                        f'<td>{e(m.get("first_seen"))}</td>'
                        f'<td>{e(m.get("last_seen"))}</td>'
                        f'<td>{ds_ids}</td>'
                        f'<td>{an_ids}</td>'
                        f'<td>{dc_ids}</td>'
                        f'<td>{ch_ids}</td>'
                        f'</tr>'
                    )
                html_out.append('</tbody></table>')
            else:
                html_out.append('<p>No MITRE ATT&CK mappings recorded.</p>')
            html_out.append('</section>')

        # V1.1 MITRE Provenance Section (if present)
        if mitre_provenance is not None:
            html_out.extend([
                '<section>',
                '<h2>MITRE Provenance</h2>',
                f'<p><strong>Framework:</strong> {e(mitre_provenance.get("framework"))}</p>',
                f'<p><strong>Domain:</strong> {e(mitre_provenance.get("domain"))}</p>',
                f'<p><strong>Version:</strong> {e(mitre_provenance.get("version"))}</p>',
                f'<p><strong>Knowledge Profile ID:</strong> {e(mitre_provenance.get("knowledge_profile_id"))}</p>',
                '</section>'
            ])

        # V1.1 Attack Chain Section (if present)
        if attack_chain is not None:
            html_out.extend([
                '<section>',
                '<h2>Attack Chain</h2>',
                f'<p><strong>Status:</strong> <span class="badge badge-informational">{e(attack_chain.get("status"))}</span></p>'
            ])
            stages = attack_chain.get("stages", [])
            if stages:
                html_out.extend([
                    '<table>',
                    '<thead><tr><th>Stage ID</th><th>Stage Name</th><th>Timestamp</th><th>Finding IDs</th><th>Event IDs</th></tr></thead>',
                    '<tbody>'
                ])
                for stg in stages:
                    f_ids = ", ".join([e(fid) for fid in stg.get("finding_ids", [])]) or "-"
                    e_ids = ", ".join([e(eid) for eid in stg.get("event_ids", [])]) or "-"
                    html_out.append(
                        f'<tr>'
                        f'<td><span class="code-block">{e(stg.get("stage_id"))}</span></td>'
                        f'<td>{e(stg.get("name"))}</td>'
                        f'<td>{e(stg.get("timestamp"))}</td>'
                        f'<td>{f_ids}</td>'
                        f'<td>{e_ids}</td>'
                        f'</tr>'
                    )
                html_out.append('</tbody></table>')
            else:
                html_out.append('<p>No attack chain stages recorded.</p>')
            html_out.append('</section>')

        # V1.2 AI-Assisted Narrative Section (if present)
        if llm_enrichment is not None:
            html_out.extend([
                '<section>',
                '<h2>AI-Assisted Narrative</h2>',
                f'<p><strong>Status:</strong> <span class="badge badge-informational">{e(llm_enrichment.get("status"))}</span></p>'
            ])
            if llm_enrichment.get("summary"):
                html_out.extend([
                    '<h3>Summary</h3>',
                    f'<p>{e(llm_enrichment.get("summary"))}</p>'
                ])
            if llm_enrichment.get("explanation"):
                html_out.extend([
                    '<h3>Explanation</h3>',
                    f'<p>{e(llm_enrichment.get("explanation"))}</p>'
                ])
            
            mitre_expls = llm_enrichment.get("mitre_explanations", [])
            if mitre_expls:
                html_out.extend([
                    '<h3>MITRE Explanations</h3>',
                    '<table>',
                    '<thead><tr><th>Technique ID</th><th>Technique Name</th><th>Status</th><th>Confidence</th><th>Evidence IDs</th><th>Explanation</th></tr></thead>',
                    '<tbody>'
                ])
                for m in mitre_expls:
                    ev_ids = ", ".join([e(ev) for ev in m.get("evidence_ids", [])]) or "-"
                    html_out.append(
                        f'<tr>'
                        f'<td><span class="code-block">{e(m.get("technique_id"))}</span></td>'
                        f'<td>{e(m.get("technique_name"))}</td>'
                        f'<td>{e(m.get("mapping_status"))}</td>'
                        f'<td>{e(m.get("mapping_confidence"))}</td>'
                        f'<td>{ev_ids}</td>'
                        f'<td>{e(m.get("explanation"))}</td>'
                        f'</tr>'
                    )
                html_out.append('</tbody></table>')

            qa = llm_enrichment.get("investigator_answers", {})
            if qa:
                html_out.extend([
                    '<h3>Investigator Q&A</h3>',
                    '<ul>'
                ])
                for q, a in qa.items():
                    html_out.append(f'<li><strong>Q: {e(q)}</strong><br>A: {e(a)}</li>')
                html_out.append('</ul>')

            if llm_enrichment.get("limitations"):
                html_out.extend([
                    '<h3>Limitations</h3>',
                    f'<p>{e(llm_enrichment.get("limitations"))}</p>'
                ])
            
            prov = llm_enrichment.get("provenance", {})
            if prov:
                html_out.extend([
                    '<h3>Model Provenance</h3>',
                    '<ul>'
                ])
                for k, v in prov.items():
                    html_out.append(f'<li><strong>{e(k)}:</strong> {e(v)}</li>')
                html_out.append('</ul>')

            html_out.append('</section>')

        # Closing container & body
        html_out.extend([
            '</div>',
            '</body>',
            '</html>'
        ])

        return "\n".join(html_out)
