import os
import requests
from typing import Optional

class LLMClientError(Exception):
    pass

class LLMConnectionError(LLMClientError):
    pass

class LLMModelUnavailableError(LLMClientError):
    pass

class AbstractLLMClient:
    def generate(self, prompt: str, system_instruction: str) -> str:
        raise NotImplementedError()

class OllamaClient(AbstractLLMClient):
    """
    Lightweight HTTP wrapper around a local Ollama instance.
    Defaults to OLLAMA_BASE_URL (http://localhost:11434) and OLLAMA_MODEL (qwen2.5)
    """
    def __init__(self, base_url: Optional[str] = None, model: Optional[str] = None):
        self.base_url = base_url or os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
        self.model = model or os.environ.get("OLLAMA_MODEL", "qwen")
        
    def generate(self, prompt: str, system_instruction: str) -> str:
        try:
            resp = requests.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "system": system_instruction,
                    "stream": False,
                    "format": "json"
                },
                timeout=30.0
            )
        except requests.exceptions.Timeout:
            raise LLMConnectionError("Ollama timeout")
        except requests.exceptions.ConnectionError:
            raise LLMConnectionError("Ollama unavailable")
            
        if resp.status_code == 404:
            raise LLMModelUnavailableError(f"Model {self.model} not found or Ollama unavailable at endpoint")
            
        if resp.status_code != 200:
            raise LLMConnectionError(f"Ollama returned {resp.status_code}: {resp.text}")
            
        data = resp.json()
        return data.get("response", "")
