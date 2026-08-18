import hashlib
from typing import List, Dict, Set, Tuple
from datetime import datetime

from app.engines.correlation.domain.investigation import InvestigationContext
from app.engines.correlation.domain.input import M3InvestigationInput
from app.engines.correlation.domain.hypothesis import Hypothesis, HypothesisStatus

class HypothesisGenerator:
    def generate(self, ctx: InvestigationContext, m3_input: M3InvestigationInput) -> List[Hypothesis]:
        # Group findings by activity_class
        finding_index = {f.finding_id: f for f in m3_input.findings}
        
        # Mapping: activity_class -> list of finding IDs
        activity_groups: Dict[str, List[str]] = {}
        
        for f_ref in ctx.findings:
            finding = finding_index.get(f_ref.finding_id)
            if finding:
                ac = finding.activity_class
                if ac not in activity_groups:
                    activity_groups[ac] = []
                activity_groups[ac].append(finding.finding_id)
                
        hypotheses = []
        
        for activity_class, finding_ids in activity_groups.items():
            valid_ev_ids = set()
            has_dns_evidence = False
            has_http_evidence = False
            
            for fid in finding_ids:
                finding = finding_index[fid]
                ev_ids = []
                if hasattr(finding, "evidence_references"):
                    for ref in finding.evidence_references:
                        ev_ids.extend(getattr(ref, "flow_ids", []))
                        ev_ids.extend(getattr(ref, "event_ids", []))
                        ev_ids.extend(getattr(ref, "artifact_ids", []))
                
                for ev_id in ev_ids:
                    if ev_id in m3_input.evidence_index.flows or ev_id in m3_input.evidence_index.events or ev_id in m3_input.evidence_index.artifacts or ev_id in m3_input.evidence_index.findings:
                        valid_ev_ids.add(ev_id)
                        if ev_id in m3_input.evidence_index.events:
                            ev = m3_input.evidence_index.events[ev_id]
                            if getattr(ev, "protocol", None) == "dns":
                                has_dns_evidence = True
                            if getattr(ev, "protocol", None) == "http":
                                has_http_evidence = True

            if not valid_ev_ids:
                continue

            hyp_type = None
            statement = None
            reasons = []
            missing_evidence = []
            
            # Rule 1 - C2
            if activity_class == "C2_MALWARE_COMMUNICATION":
                statement = "Possible command-and-control communication"
                hyp_type = "C2_COMMUNICATION"
                reasons.append(f"Observed {len(finding_ids)} finding(s) of C2_MALWARE_COMMUNICATION with supporting evidence.")
                
            # Rule 2 - DNS
            elif activity_class == "DNS_ANOMALY_TUNNELING":
                if not has_dns_evidence:
                    continue
                statement = "Possible DNS-based command-and-control"
                hyp_type = "DNS_C2"
                reasons.append("Observed DNS_ANOMALY_TUNNELING findings corroborated by actual DNS evidence.")

            # Rule 3 - SCANNING
            elif activity_class == "SCANNING_RECONNAISSANCE":
                statement = "Possible network service reconnaissance"
                hyp_type = "NETWORK_RECONNAISSANCE"
                reasons.append("Observed SCANNING_RECONNAISSANCE findings with network evidence.")
                
            # Rule 4 - EXFILTRATION
            elif activity_class == "POSSIBLE_EXFILTRATION":
                statement = "Possible outbound data transfer consistent with exfiltration"
                hyp_type = "POTENTIAL_EXFILTRATION"
                reasons.append("Observed POSSIBLE_EXFILTRATION findings with network flow evidence.")
                missing_evidence.append("Endpoint process context or file-access telemetry is required for confirmation.")
                
            # Rule 5 - SUSPICIOUS WEB
            elif activity_class == "SUSPICIOUS_WEB_ACTIVITY":
                if not has_http_evidence:
                    continue
                statement = "Possible suspicious web-protocol activity"
                hyp_type = "SUSPICIOUS_WEB_ACTIVITY"
                reasons.append("Observed SUSPICIOUS_WEB_ACTIVITY findings corroborated by HTTP evidence.")

            if hyp_type and statement:
                supp_finding_ids = sorted(finding_ids)
                supp_ev_ids = sorted(list(valid_ev_ids))
                
                # Mitre Linkage
                related_mitre = set()
                if hasattr(ctx, "mitre_mappings") and ctx.mitre_mappings:
                    for m in ctx.mitre_mappings:
                        if getattr(m, "finding_id", None) in finding_ids:
                            related_mitre.add(m.technique_id)
                
                # Entity Linkage
                related_entities = set()
                timestamps = []
                for te in getattr(ctx, "timeline_events", []):
                    te_ev_ids = getattr(te, "evidence_ids", []) or []
                    if set(te_ev_ids).intersection(valid_ev_ids):
                        if getattr(te, "entity_ids", None):
                            related_entities.update(te.entity_ids)
                        if getattr(te, "timestamp", None):
                            timestamps.append(te.timestamp)
                
                if timestamps:
                    first_seen = min(timestamps)
                    last_seen = max(timestamps)
                else:
                    first_seen = None
                    last_seen = None
                    
                # Confidence Formula
                # Base confidence for having a correlated finding with evidence = 0.5
                # + 0.1 for having related timeline entities
                # + 0.1 for having a mapped MITRE technique
                # Cap at 0.7 for POTENTIAL status, to leave room for SUPPORTED
                confidence = 0.5
                if related_entities:
                    confidence += 0.1
                if related_mitre:
                    confidence += 0.1
                confidence = min(confidence, 0.7)
                
                # Deterministic ID Generation
                # Based on acquisition, hypothesis_type, and sorted finding/evidence
                hash_input = f"{m3_input.acquisition_id}|{hyp_type}|{','.join(supp_ev_ids)}|{','.join(supp_finding_ids)}"
                hyp_id = "HYP-" + hashlib.sha256(hash_input.encode('utf-8')).hexdigest()[:12]
                
                hyp = Hypothesis(
                    hypothesis_id=hyp_id,
                    statement=statement,
                    hypothesis_type=hyp_type,
                    status=HypothesisStatus.POTENTIAL,
                    confidence=confidence,
                    supporting_evidence_ids=supp_ev_ids,
                    supporting_finding_ids=supp_finding_ids,
                    related_entity_ids=sorted(list(related_entities)),
                    related_mitre_mapping_ids=sorted(list(related_mitre)),
                    supporting_reasons=reasons,
                    missing_evidence=missing_evidence,
                    first_seen=first_seen,
                    last_seen=last_seen
                )
                hypotheses.append(hyp)
                
        return sorted(hypotheses, key=lambda h: h.hypothesis_id)
