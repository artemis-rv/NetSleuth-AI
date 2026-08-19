import os
import httpx
from typing import Optional, Dict, Any
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
    Defaults to OLLAMA_BASE_URL (http://localhost:11434) and OLLAMA_MODEL (qwen2.5:1.5b)
    """
    def __init__(self, base_url: Optional[str] = None, model: Optional[str] = None):
        self.base_url = base_url or settings.ollama_base_url
        self.model = model or settings.ollama_model
        self._cached_resolved_model: Optional[str] = None

    async def resolve_installed_model(self, client: Optional[httpx.AsyncClient] = None) -> str:
        """
        Dynamically resolves the configured model string (e.g. 'qwen3', 'qwen2.5', 'qwen')
        to the exact installed model tag in local Ollama (e.g. 'qwen3:8b', 'qwen2.5:1.5b').
        Caches result per instance for high performance.
        """
        if self._cached_resolved_model:
            return self._cached_resolved_model

        try:
            should_close = False
            if client is None:
                client = httpx.AsyncClient(timeout=30.0)
                should_close = True

            try:
                tags_resp = await client.get(f"{self.base_url}/api/tags")
                if tags_resp.status_code == 200:
                    installed = [m.get("name") for m in tags_resp.json().get("models", [])]
                    # 1. Exact match
                    if self.model in installed:
                        self._cached_resolved_model = self.model
                        return self.model
                    # 2. Tag match or base prefix match (e.g. qwen3 -> qwen3:8b, qwen2.5 -> qwen2.5:1.5b)
                    for m in installed:
                        base_name = m.split(":")[0]
                        conf_base = self.model.split(":")[0]
                        if conf_base == base_name or m.startswith(self.model) or self.model.startswith(base_name):
                            self._cached_resolved_model = m
                            return m
                    # 3. Any installed Qwen model if Qwen was requested
                    if "qwen" in self.model.lower():
                        qwen_models = [m for m in installed if "qwen" in m.lower()]
                        if qwen_models:
                            self._cached_resolved_model = qwen_models[0]
                            return qwen_models[0]
            finally:
                if should_close:
                    await client.aclose()
        except Exception:
            pass

        self._cached_resolved_model = self.model
        return self.model

    async def check_health(self) -> Dict[str, Any]:
        """
        Structured health check differentiating:
        1. OLLAMA SERVER AVAILABLE
        2. MODEL AVAILABLE
        3. MODEL GENERATION WORKS
        """
        result = {
            "server": False,
            "model": False,
            "generation": False,
            "installed_models": [],
            "configured_model": self.model,
            "resolved_model": self.model,
            "base_url": self.base_url,
            "error": None
        }
        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                tags_resp = await client.get(f"{self.base_url}/api/tags")
                if tags_resp.status_code != 200:
                    result["error"] = f"Ollama server returned HTTP {tags_resp.status_code}"
                    return result
                result["server"] = True

                models = [m.get("name") for m in tags_resp.json().get("models", [])]
                result["installed_models"] = models

                target_model = await self.resolve_installed_model(client=client)
                result["resolved_model"] = target_model

                model_match = any(
                    m == self.model or m == target_model or m.startswith(self.model) or self.model.startswith(m.split(":")[0])
                    for m in models
                )
                if not model_match:
                    result["error"] = f"Configured model '{self.model}' is not installed in local Ollama."
                    return result
                result["model"] = True

                gen_resp = await client.post(
                    f"{self.base_url}/api/generate",
                    json={"model": target_model, "prompt": "Reply with exactly: OK", "stream": False},
                    timeout=120.0
                )
                if gen_resp.status_code == 200:
                    result["generation"] = True
                else:
                    result["error"] = f"Generation failed with HTTP status {gen_resp.status_code}"
                return result
        except Exception as e:
            result["error"] = f"Ollama server unreachable at {self.base_url}: {str(e)}"
            return result

    async def generate(self, prompt: str, system_instruction: str) -> str:
        target_model = await self.resolve_installed_model()
        try:
            async with httpx.AsyncClient(timeout=180.0) as client:
                resp = await client.post(
                    f"{self.base_url}/api/generate",
                    json={
                        "model": target_model,
                        "prompt": prompt,
                        "system": system_instruction,
                        "stream": False,
                        "format": "json",
                        "options": {
                            "temperature": 0.1,
                            "num_predict": 800
                        }
                    }
                )
        except httpx.TimeoutException:
            raise LLMConnectionError("Ollama timeout")
        except httpx.RequestError:
            raise LLMConnectionError("Ollama unavailable")
            
        if resp.status_code == 404:
            raise LLMModelUnavailableError(f"Model {target_model} not found or Ollama unavailable at endpoint")
            
        if resp.status_code != 200:
            raise LLMConnectionError(f"Ollama returned {resp.status_code}: {resp.text}")
            
        data = resp.json()
        return data.get("response", "")
