import hashlib
import ipaddress
from typing import List, Dict, Set
from datetime import datetime, timezone

from app.engines.correlation.domain.investigation import InvestigationContext
from app.engines.correlation.domain.input import M3InvestigationInput
from app.engines.correlation.domain.hypothesis import HypothesisValidation, ValidationStatus
from app.engines.correlation.domain.root_cause import RootCause, RootCauseStatus
from app.engines.correlation.domain.impact import ImpactAssessment, ImpactStatus

class ImpactAssessor:
    def _is_private_ip(self, ip_str: str) -> bool:
        try:
            return ipaddress.ip_address(ip_str).is_private
        except ValueError:
            return False

    def analyze(self, ctx: InvestigationContext, m3_input: M3InvestigationInput) -> List[ImpactAssessment]:
        impacts = []
        
        # Need hypothesis_validations to check contradictions for root causes
        vals_by_hyp = {v.hypothesis_id: v for v in getattr(ctx, "hypothesis_validations", [])}
        hyps_by_id = {h.hypothesis_id: h for h in getattr(ctx, "hypotheses", [])}

        for rc in getattr(ctx, "root_causes", []):
            if rc.status == RootCauseStatus.UNRESOLVED:
                continue
                
            # Get underlying hypothesis
            if not rc.supporting_hypothesis_ids:
                continue
                
            base_hyp_id = rc.supporting_hypothesis_ids[0]
            hyp = hyps_by_id.get(base_hyp_id)
            val = vals_by_hyp.get(base_hyp_id)
            
            if not hyp or not val:
                continue
                
            # Setup base properties
            category = ""
            statement = ""
            status = ImpactStatus.POTENTIAL
            missing_evidence = list(rc.missing_evidence) if rc.missing_evidence else []
            affected_entities = [] # Normally drawn from timeline_events in real scenarios
            
            # Use evidence from root cause
            supp_evidence_ids = list(rc.supporting_evidence_ids)
            contra_evidence_ids = list(val.contradicting_evidence_ids) if val else []

            # Rules
            if hyp.hypothesis_type == "C2_COMMUNICATION":
                category = "SYSTEM_COMPROMISE"
                statement = "Observed or inferred impact associated with persistent external command-and-control communication."
                
                # We do not claim confirmed host compromise from network traffic alone
                if rc.status == RootCauseStatus.SUPPORTED and len(supp_evidence_ids) > 2:
                    status = ImpactStatus.INFERRED
                else:
                    status = ImpactStatus.POTENTIAL

            elif hyp.hypothesis_type == "DNS_C2":
                category = "SYSTEM_COMPROMISE"
                statement = "Potential system impact associated with DNS-based command-and-control activity."
                status = ImpactStatus.POTENTIAL

            elif hyp.hypothesis_type == "NETWORK_RECONNAISSANCE":
                category = "LATERAL_MOVEMENT"
                statement = "Potential lateral movement indicated by cross-target internal scanning."
                
                # Only if internal-target evidence exists
                has_lateral_evidence = False
                private_targets = set()
                
                for ev_id in supp_evidence_ids:
                    flow = m3_input.evidence_index.flows.get(ev_id)
                    if flow:
                        flow_dict = flow if isinstance(flow, dict) else flow.model_dump()
                        dest = flow_dict.get("destination", {})
                        dest_ip = dest.get("ip") if isinstance(dest, dict) else ""
                        if dest_ip and self._is_private_ip(dest_ip):
                            private_targets.add(dest_ip)

                if len(private_targets) >= 2:
                    has_lateral_evidence = True
                    status = ImpactStatus.POTENTIAL
                else:
                    # Do not emit impact
                    continue

            elif hyp.hypothesis_type == "POTENTIAL_EXFILTRATION":
                category = "DATA_EXFILTRATION"
                statement = "Potential data exfiltration based on abnormal outbound transfer behavior."
                status = ImpactStatus.POTENTIAL
                missing_evidence.append("Process context unavailable")
                missing_evidence.append("File access telemetry unavailable")

            elif hyp.hypothesis_type == "SUSPICIOUS_WEB_ACTIVITY":
                # Do not automatically create impact unless supported explicitly
                continue
                
            else:
                continue

            # Contradiction handling
            if len(contra_evidence_ids) > 0:
                if status == ImpactStatus.OBSERVED:
                    status = ImpactStatus.INFERRED
                elif status == ImpactStatus.INFERRED:
                    status = ImpactStatus.POTENTIAL

            if not supp_evidence_ids:
                continue

            # Deterministic Confidence
            confidence = 0.30
            if rc.status == RootCauseStatus.SUPPORTED:
                confidence += 0.20
            
            confidence += 0.05 * min(len(supp_evidence_ids), 4)
            confidence -= 0.20 * len(contra_evidence_ids)
            confidence -= 0.10 * (1 if missing_evidence else 0)

            # Cap based on status
            if status == ImpactStatus.OBSERVED:
                confidence = min(confidence, 0.90)
            elif status == ImpactStatus.INFERRED:
                confidence = min(confidence, 0.75)
            elif status == ImpactStatus.POTENTIAL:
                confidence = min(confidence, 0.60)
            
            confidence = round(max(0.0, confidence), 2)

            # Deduplication ID
            support_ev_str = ",".join(sorted(supp_evidence_ids))
            entities_str = ",".join(sorted(affected_entities))
            
            hash_input = f"{m3_input.acquisition_id}|{category}|{statement}|{support_ev_str}|{entities_str}|{status.value}"
            imp_id = "IMP-" + hashlib.sha256(hash_input.encode('utf-8')).hexdigest()[:12]

            imp = ImpactAssessment(
                impact_id=imp_id,
                category=category,
                statement=statement,
                status=status,
                confidence=confidence,
                supporting_evidence_ids=sorted(list(supp_evidence_ids)),
                supporting_finding_ids=rc.supporting_finding_ids,
                affected_entity_ids=sorted(affected_entities),
                rationale="Deterministic rule mapping from validated root causes.",
                missing_evidence=list(set(missing_evidence))
            )
            
            impacts.append(imp)

        return impacts
