import os
import httpx
from typing import Optional
from app.config import settings

class LLMClientError(Exception):
    pass

class LLMConnectionError(LLMClientError):
    pass

class LLMModelUnavailableError(LLMClientError):
    pass

class AbstractLLMClient:
    async def generate(self, prompt: str, system_instruction: str) -> str:
        raise NotImplementedError()

class OllamaClient(AbstractLLMClient):
    """
    Lightweight HTTP wrapper around a local Ollama instance.
    Defaults to OLLAMA_BASE_URL (http://localhost:11434) and OLLAMA_MODEL (qwen)
    """
    def __init__(self, base_url: Optional[str] = None, model: Optional[str] = None):
        self.base_url = base_url or settings.ollama_base_url
        self.model = model or settings.ollama_model
        
    async def generate(self, prompt: str, system_instruction: str) -> str:
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(
                    f"{self.base_url}/api/generate",
                    json={
                        "model": self.model,
                        "prompt": prompt,
                        "system": system_instruction,
                        "stream": False,
                        "format": "json"
                    }
                )
        except httpx.TimeoutException:
            raise LLMConnectionError("Ollama timeout")
        except httpx.RequestError:
            raise LLMConnectionError("Ollama unavailable")
            
        if resp.status_code == 404:
            raise LLMModelUnavailableError(f"Model {self.model} not found or Ollama unavailable at endpoint")
            
        if resp.status_code != 200:
            raise LLMConnectionError(f"Ollama returned {resp.status_code}: {resp.text}")
            
        data = resp.json()
        return data.get("response", "")
