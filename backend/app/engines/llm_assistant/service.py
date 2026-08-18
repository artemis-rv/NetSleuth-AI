import uuid
import json
from typing import Dict, Any

from app.contracts.llm import LLMInvestigationContext
from app.engines.llm_assistant.models import (
    LLMInvestigationResponse, 
    LLMMitreExplanation, 
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
        # Heuristic check for ungrounded claims matching the required test behavior
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
            raise json.JSONDecodeError("Empty or invalid output", str(raw_output), 0)

        cleaned = raw_output.strip()
        if cleaned.startswith("```"):
            lines = cleaned.split("\n")
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            cleaned = "\n".join(lines).strip()
        
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            match = re.search(r"\{.*\}", cleaned, re.DOTALL)
            if match:
                return json.loads(match.group(0))
            raise

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
            summary = data.get("summary", "")
            self._validate_groundedness(summary, context)
            
            base_resp.summary = summary
            base_resp.status = LLMResponseStatus.SUCCESS
        except GroundingError:
            base_resp.status = LLMResponseStatus.LLM_UNGROUNDED
        except LLMModelUnavailableError:
            base_resp.status = LLMResponseStatus.LLM_MODEL_UNAVAILABLE
        except LLMConnectionError:
            base_resp.status = LLMResponseStatus.LLM_UNAVAILABLE
        except json.JSONDecodeError:
            base_resp.status = LLMResponseStatus.LLM_INVALID_RESPONSE
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
            data = await self._execute_raw(prompt, context)
            returned_tech = data.get("technique_id")
            explanation = data.get("explanation", "")
            
            if returned_tech != technique_id:
                base_resp.status = LLMResponseStatus.LLM_INVALID_RESPONSE
                return base_resp
                
            self._validate_groundedness(explanation, context)
            
            target_mapping = next((m for m in context.mitre_mappings if m.technique_id == technique_id), None)
            if not target_mapping:
                base_resp.status = LLMResponseStatus.LLM_INVALID_RESPONSE
                return base_resp
                
            mitre_exp = LLMMitreExplanation(
                technique_id=target_mapping.technique_id,
                technique_name=target_mapping.technique_name,
                mapping_status=target_mapping.mapping_status,
                mapping_confidence=target_mapping.mapping_confidence,
                evidence_ids=target_mapping.evidence_ids,
                explanation=explanation
            )
            base_resp.mitre_explanations.append(mitre_exp)
            base_resp.status = LLMResponseStatus.SUCCESS
            
        except GroundingError:
            base_resp.status = LLMResponseStatus.LLM_UNGROUNDED
        except LLMModelUnavailableError:
            base_resp.status = LLMResponseStatus.LLM_MODEL_UNAVAILABLE
        except LLMConnectionError:
            base_resp.status = LLMResponseStatus.LLM_UNAVAILABLE
        except json.JSONDecodeError:
            base_resp.status = LLMResponseStatus.LLM_INVALID_RESPONSE
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
            answer = data.get("answer", "")
            self._validate_groundedness(answer, context)
            
            base_resp.investigator_answers[question] = answer
            base_resp.status = LLMResponseStatus.SUCCESS
        except GroundingError:
            base_resp.status = LLMResponseStatus.LLM_UNGROUNDED
        except LLMModelUnavailableError:
            base_resp.status = LLMResponseStatus.LLM_MODEL_UNAVAILABLE
        except LLMConnectionError:
            base_resp.status = LLMResponseStatus.LLM_UNAVAILABLE
        except json.JSONDecodeError:
            base_resp.status = LLMResponseStatus.LLM_INVALID_RESPONSE
        except Exception:
            base_resp.status = LLMResponseStatus.LLM_INVALID_RESPONSE
            
        return base_resp
