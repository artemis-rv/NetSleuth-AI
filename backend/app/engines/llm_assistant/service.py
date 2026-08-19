import uuid
import json
from typing import Dict, Any, Optional

from app.contracts.llm import LLMInvestigationContext
from app.engines.llm_assistant.models import (
    LLMInvestigationResponse, 
    LLMMitreExplanation, 
    LLMFindingExplanation,
    LLMHypothesisExplanation,
    LLMRootCauseExplanation,
    LLMImpactExplanation,
    LLMResponseStatus
)
from app.engines.llm_assistant.client import AbstractLLMClient, LLMConnectionError, LLMModelUnavailableError
from app.engines.llm_assistant.prompts import PromptBuilder

class GroundingError(Exception):
    pass

class LLMAssistantService:
    def __init__(self, client: AbstractLLMClient):
        self.client = client
        self.prompts = PromptBuilder()
        
    def _validate_groundedness(self, text: str, context: LLMInvestigationContext):
        lower_text = text.lower()
        if "known malicious" in lower_text:
            ctx_dump = context.model_dump_json().lower()
            if "known malicious" not in ctx_dump and "malicious" not in ctx_dump:
                raise GroundingError("Ungrounded claim detected: " + text)

    async def _execute_raw(self, prompt: str, context: LLMInvestigationContext) -> Dict[str, Any]:
        import inspect
        import re
        system_instruction = self.prompts.build_system_instruction()
        res = self.client.generate(prompt, system_instruction)
        if inspect.isawaitable(res):
            raw_output = await res
        else:
            raw_output = res
        
        if not raw_output or not isinstance(raw_output, str):
            return {"summary": "No output from language model.", "answer": "No output from language model.", "explanation": "No output from language model."}

        cleaned = raw_output.strip()
        if cleaned.startswith("```"):
            lines = cleaned.split("\n")
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            cleaned = "\n".join(lines).strip()
        
        try:
            return json.loads(cleaned, strict=False)
        except json.JSONDecodeError:
            match = re.search(r"\{.*\}", cleaned, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group(0), strict=False)
                except json.JSONDecodeError:
                    pass
            
            return {
                "summary": cleaned,
                "answer": cleaned,
                "explanation": cleaned,
            }

    async def generate_summary(self, context: LLMInvestigationContext) -> LLMInvestigationResponse:
        prompt = self.prompts.build_summary_prompt(context)
        req_id = str(uuid.uuid4())
        base_resp = LLMInvestigationResponse(
            request_id=req_id,
            case_id=context.case_id,
            provenance={"model": getattr(self.client, "model", "unknown")}
        )
        
        try:
            data = await self._execute_raw(prompt, context)
            summary = data.get("summary") or data.get("response") or data.get("answer") or str(data)
            self._validate_groundedness(summary, context)
            
            base_resp.summary = summary
            base_resp.status = LLMResponseStatus.SUCCESS
        except GroundingError:
            base_resp.status = LLMResponseStatus.LLM_UNGROUNDED
        except LLMModelUnavailableError:
            base_resp.status = LLMResponseStatus.LLM_MODEL_UNAVAILABLE
        except LLMConnectionError:
            base_resp.status = LLMResponseStatus.LLM_UNAVAILABLE
        except Exception:
            base_resp.status = LLMResponseStatus.LLM_INVALID_RESPONSE
            
        return base_resp

    async def generate_finding_explanation(self, context: LLMInvestigationContext, finding_id: str) -> LLMInvestigationResponse:
        prompt = self.prompts.build_finding_explanation_prompt(context, finding_id)
        req_id = str(uuid.uuid4())
        base_resp = LLMInvestigationResponse(
            request_id=req_id,
            case_id=context.case_id,
            provenance={"model": getattr(self.client, "model", "unknown")}
        )
        
        try:
            target_finding = next((f for f in context.findings if str(f.get("finding_id")) == str(finding_id)), None)
            if not target_finding:
                base_resp.status = LLMResponseStatus.LLM_INVALID_RESPONSE
                base_resp.explanation = f"Finding ID '{finding_id}' not found in authoritative M3 case context."
                return base_resp

            data = await self._execute_raw(prompt, context)
            explanation = data.get("explanation") or data.get("answer") or data.get("response") or str(data)
            self._validate_groundedness(explanation, context)
            
            exp_item = LLMFindingExplanation(
                finding_id=finding_id,
                explanation=explanation
            )
            base_resp.finding_explanations.append(exp_item)
            base_resp.explanation = explanation
            base_resp.status = LLMResponseStatus.SUCCESS
        except GroundingError:
            base_resp.status = LLMResponseStatus.LLM_UNGROUNDED
        except LLMModelUnavailableError:
            base_resp.status = LLMResponseStatus.LLM_MODEL_UNAVAILABLE
        except LLMConnectionError:
            base_resp.status = LLMResponseStatus.LLM_UNAVAILABLE
        except Exception:
            base_resp.status = LLMResponseStatus.LLM_INVALID_RESPONSE
            
        return base_resp

    async def generate_mitre_explanation(self, context: LLMInvestigationContext, technique_id: str) -> LLMInvestigationResponse:
        prompt = self.prompts.build_mitre_explanation_prompt(context, technique_id)
        req_id = str(uuid.uuid4())
        base_resp = LLMInvestigationResponse(
            request_id=req_id,
            case_id=context.case_id,
            provenance={"model": getattr(self.client, "model", "unknown")}
        )
        
        try:
            target_mapping = next((m for m in context.mitre_mappings if m.technique_id == technique_id), None)
            if not target_mapping:
                base_resp.status = LLMResponseStatus.LLM_INVALID_RESPONSE
                base_resp.explanation = f"MITRE Technique ID '{technique_id}' not found in authoritative M3 case context."
                return base_resp

            data = await self._execute_raw(prompt, context)
            explanation = data.get("explanation") or data.get("answer") or data.get("response") or str(data)
            self._validate_groundedness(explanation, context)
            
            mitre_exp = LLMMitreExplanation(
                technique_id=target_mapping.technique_id,
                technique_name=target_mapping.technique_name,
                mapping_status=target_mapping.mapping_status,
                mapping_confidence=target_mapping.mapping_confidence,
                evidence_ids=target_mapping.evidence_ids,
                explanation=explanation
            )
            base_resp.mitre_explanations.append(mitre_exp)
            base_resp.explanation = explanation
            base_resp.status = LLMResponseStatus.SUCCESS
            
        except GroundingError:
            base_resp.status = LLMResponseStatus.LLM_UNGROUNDED
        except LLMModelUnavailableError:
            base_resp.status = LLMResponseStatus.LLM_MODEL_UNAVAILABLE
        except LLMConnectionError:
            base_resp.status = LLMResponseStatus.LLM_UNAVAILABLE
        except Exception:
            base_resp.status = LLMResponseStatus.LLM_INVALID_RESPONSE
            
        return base_resp

    async def generate_hypothesis_explanation(self, context: LLMInvestigationContext, hypothesis_id: str) -> LLMInvestigationResponse:
        prompt = self.prompts.build_hypothesis_explanation_prompt(context, hypothesis_id)
        req_id = str(uuid.uuid4())
        base_resp = LLMInvestigationResponse(
            request_id=req_id,
            case_id=context.case_id,
            provenance={"model": getattr(self.client, "model", "unknown")}
        )
        
        try:
            target_h = next((h for h in context.hypotheses if str(h.hypothesis_id) == str(hypothesis_id)), None)
            if not target_h:
                base_resp.status = LLMResponseStatus.LLM_INVALID_RESPONSE
                base_resp.explanation = f"Hypothesis ID '{hypothesis_id}' not found in authoritative M3 case context."
                return base_resp

            data = await self._execute_raw(prompt, context)
            explanation = data.get("explanation") or data.get("answer") or str(data)
            self._validate_groundedness(explanation, context)
            
            exp = LLMHypothesisExplanation(hypothesis_id=hypothesis_id, explanation=explanation)
            base_resp.hypothesis_explanations.append(exp)
            base_resp.explanation = explanation
            base_resp.status = LLMResponseStatus.SUCCESS
        except GroundingError:
            base_resp.status = LLMResponseStatus.LLM_UNGROUNDED
        except LLMModelUnavailableError:
            base_resp.status = LLMResponseStatus.LLM_MODEL_UNAVAILABLE
        except LLMConnectionError:
            base_resp.status = LLMResponseStatus.LLM_UNAVAILABLE
        except Exception:
            base_resp.status = LLMResponseStatus.LLM_INVALID_RESPONSE
            
        return base_resp

    async def generate_root_cause_explanation(self, context: LLMInvestigationContext, root_cause_id: str) -> LLMInvestigationResponse:
        prompt = self.prompts.build_root_cause_explanation_prompt(context, root_cause_id)
        req_id = str(uuid.uuid4())
        base_resp = LLMInvestigationResponse(
            request_id=req_id,
            case_id=context.case_id,
            provenance={"model": getattr(self.client, "model", "unknown")}
        )
        
        try:
            target_rc = next((rc for rc in context.root_causes if str(rc.root_cause_id) == str(root_cause_id)), None)
            if not target_rc:
                base_resp.status = LLMResponseStatus.LLM_INVALID_RESPONSE
                base_resp.explanation = f"Root Cause ID '{root_cause_id}' not found in authoritative M3 case context."
                return base_resp

            data = await self._execute_raw(prompt, context)
            explanation = data.get("explanation") or data.get("answer") or str(data)
            self._validate_groundedness(explanation, context)
            
            exp = LLMRootCauseExplanation(root_cause_id=root_cause_id, explanation=explanation)
            base_resp.root_cause_explanations.append(exp)
            base_resp.explanation = explanation
            base_resp.status = LLMResponseStatus.SUCCESS
        except GroundingError:
            base_resp.status = LLMResponseStatus.LLM_UNGROUNDED
        except LLMModelUnavailableError:
            base_resp.status = LLMResponseStatus.LLM_MODEL_UNAVAILABLE
        except LLMConnectionError:
            base_resp.status = LLMResponseStatus.LLM_UNAVAILABLE
        except Exception:
            base_resp.status = LLMResponseStatus.LLM_INVALID_RESPONSE
            
        return base_resp

    async def generate_impact_explanation(self, context: LLMInvestigationContext, impact_id: str) -> LLMInvestigationResponse:
        prompt = self.prompts.build_impact_explanation_prompt(context, impact_id)
        req_id = str(uuid.uuid4())
        base_resp = LLMInvestigationResponse(
            request_id=req_id,
            case_id=context.case_id,
            provenance={"model": getattr(self.client, "model", "unknown")}
        )
        
        try:
            target_imp = next((imp for imp in context.impacts if str(imp.impact_id) == str(impact_id)), None)
            if not target_imp:
                base_resp.status = LLMResponseStatus.LLM_INVALID_RESPONSE
                base_resp.explanation = f"Impact ID '{impact_id}' not found in authoritative M3 case context."
                return base_resp

            data = await self._execute_raw(prompt, context)
            explanation = data.get("explanation") or data.get("answer") or str(data)
            self._validate_groundedness(explanation, context)
            
            exp = LLMImpactExplanation(impact_id=impact_id, explanation=explanation)
            base_resp.impact_explanations.append(exp)
            base_resp.explanation = explanation
            base_resp.status = LLMResponseStatus.SUCCESS
        except GroundingError:
            base_resp.status = LLMResponseStatus.LLM_UNGROUNDED
        except LLMModelUnavailableError:
            base_resp.status = LLMResponseStatus.LLM_MODEL_UNAVAILABLE
        except LLMConnectionError:
            base_resp.status = LLMResponseStatus.LLM_UNAVAILABLE
        except Exception:
            base_resp.status = LLMResponseStatus.LLM_INVALID_RESPONSE
            
        return base_resp

    async def generate_qa(self, context: LLMInvestigationContext, question: str) -> LLMInvestigationResponse:
        prompt = self.prompts.build_qa_prompt(context, question)
        req_id = str(uuid.uuid4())
        base_resp = LLMInvestigationResponse(
            request_id=req_id,
            case_id=context.case_id,
            provenance={"model": getattr(self.client, "model", "unknown")}
        )
        
        try:
            data = await self._execute_raw(prompt, context)
            answer = data.get("answer") or data.get("response") or data.get("summary") or data.get("explanation") or str(data)
            self._validate_groundedness(answer, context)
            
            base_resp.investigator_answers[question] = answer
            base_resp.explanation = answer
            base_resp.status = LLMResponseStatus.SUCCESS
        except GroundingError:
            base_resp.status = LLMResponseStatus.LLM_UNGROUNDED
        except LLMModelUnavailableError:
            base_resp.status = LLMResponseStatus.LLM_MODEL_UNAVAILABLE
        except LLMConnectionError:
            base_resp.status = LLMResponseStatus.LLM_UNAVAILABLE
        except Exception:
            base_resp.status = LLMResponseStatus.LLM_INVALID_RESPONSE
            
        return base_resp
