import hashlib
from typing import List, Dict, Set
from datetime import datetime, timezone

from app.engines.correlation.domain.investigation import InvestigationContext
from app.engines.correlation.domain.input import M3InvestigationInput
from app.engines.correlation.domain.hypothesis import Hypothesis, HypothesisValidation, ValidationStatus
from app.engines.correlation.domain.root_cause import RootCause, RootCauseStatus

class RootCauseAnalyzer:
    def analyze(self, ctx: InvestigationContext, m3_input: M3InvestigationInput) -> List[RootCause]:
        root_causes = []
        
        # We need both the hypotheses and their validations
        hyps_by_id = {h.hypothesis_id: h for h in getattr(ctx, "hypotheses", [])}
        
        for val in getattr(ctx, "hypothesis_validations", []):
            if val.validation_status == ValidationStatus.REJECTED:
                # Do not emit root cause for rejected hypotheses
                continue
                
            hyp = hyps_by_id.get(val.hypothesis_id)
            if not hyp:
                continue

            statement = ""
            status = RootCauseStatus.UNRESOLVED
            missing_evidence = list(val.missing_evidence) if val.missing_evidence else []
            
            # Causal Sufficiency Logic
            is_validated = (val.validation_status == ValidationStatus.VALIDATED)
            has_no_missing = (len(missing_evidence) == 0)
            has_no_contradiction = (len(val.contradicting_evidence_ids) == 0)
            strong_evidence = (len(val.supporting_evidence_ids) >= 2)
            
            causal_sufficiency_met = is_validated and has_no_missing and has_no_contradiction and strong_evidence
            
            # Base logic by type
            if hyp.hypothesis_type == "C2_COMMUNICATION":
                statement = "Underlying cause is consistent with persistent external command-and-control communication."
                if causal_sufficiency_met:
                    status = RootCauseStatus.SUPPORTED
                elif is_validated:
                    status = RootCauseStatus.PARTIALLY_SUPPORTED
                else:
                    status = RootCauseStatus.POTENTIAL

            elif hyp.hypothesis_type == "DNS_C2":
                statement = "Underlying activity is consistent with DNS-based command-and-control."
                if causal_sufficiency_met:
                    status = RootCauseStatus.SUPPORTED
                elif is_validated:
                    status = RootCauseStatus.PARTIALLY_SUPPORTED
                else:
                    status = RootCauseStatus.POTENTIAL

            elif hyp.hypothesis_type == "NETWORK_RECONNAISSANCE":
                statement = "Underlying activity is consistent with deliberate network service discovery/reconnaissance."
                if causal_sufficiency_met:
                    status = RootCauseStatus.SUPPORTED
                elif is_validated:
                    status = RootCauseStatus.PARTIALLY_SUPPORTED
                else:
                    status = RootCauseStatus.POTENTIAL

            elif hyp.hypothesis_type == "POTENTIAL_EXFILTRATION":
                statement = "Underlying activity is consistent with abnormal outbound data transfer consistent with possible exfiltration."
                # Network evidence alone is almost never causally sufficient for data theft
                missing_evidence.append("Process and endpoint telemetry required to confirm causal data theft.")
                if is_validated:
                    status = RootCauseStatus.PARTIALLY_SUPPORTED
                else:
                    status = RootCauseStatus.POTENTIAL

            elif hyp.hypothesis_type == "SUSPICIOUS_WEB_ACTIVITY":
                statement = "Underlying activity is consistent with suspicious web-protocol use."
                if causal_sufficiency_met:
                    status = RootCauseStatus.SUPPORTED
                elif is_validated:
                    status = RootCauseStatus.PARTIALLY_SUPPORTED
                else:
                    status = RootCauseStatus.POTENTIAL
                    
            else:
                statement = f"Underlying activity is consistent with {hyp.hypothesis_type}."
                status = RootCauseStatus.UNRESOLVED

            # If there's a strong contradiction but it wasn't rejected
            if len(val.contradicting_evidence_ids) > 0 and status in [RootCauseStatus.SUPPORTED, RootCauseStatus.PARTIALLY_SUPPORTED]:
                status = RootCauseStatus.POTENTIAL

            if not val.supporting_evidence_ids:
                status = RootCauseStatus.UNRESOLVED

            # Calculate deterministic confidence
            confidence = 0.40
            if val.validation_status == ValidationStatus.VALIDATED:
                confidence += 0.15
            
            confidence += 0.05 * min(len(val.supporting_evidence_ids), 4)
            confidence -= 0.15 * len(val.contradicting_evidence_ids)
            confidence -= 0.10 * (1 if missing_evidence else 0)

            # Caps based on status
            if status == RootCauseStatus.SUPPORTED:
                confidence = min(confidence, 0.90)
            elif status == RootCauseStatus.PARTIALLY_SUPPORTED:
                confidence = min(confidence, 0.75)
            elif status == RootCauseStatus.POTENTIAL:
                confidence = min(confidence, 0.60)
            elif status == RootCauseStatus.UNRESOLVED:
                confidence = min(confidence, 0.40)
            
            confidence = max(0.0, confidence)

            # Deterministic ID
            support_hyp_str = val.hypothesis_id
            support_ev_list = sorted(list(val.supporting_evidence_ids)) or sorted(list(hyp.supporting_evidence_ids))
            if not support_ev_list:
                # Must have at least 1 supporting evidence per V1.3 contract schema
                continue
            support_ev_str = ",".join(support_ev_list)
            hash_input = f"{m3_input.acquisition_id}|{statement}|{support_hyp_str}|{support_ev_str}|{status.value}"
            rc_id = "RC-" + hashlib.sha256(hash_input.encode('utf-8')).hexdigest()[:12]

            rc = RootCause(
                root_cause_id=rc_id,
                statement=statement,
                status=status,
                confidence=confidence,
                supporting_hypothesis_ids=[val.hypothesis_id],
                supporting_evidence_ids=support_ev_list,
                supporting_finding_ids=hyp.supporting_finding_ids,
                missing_evidence=list(set(missing_evidence))
            )
            
            root_causes.append(rc)

        return root_causes
