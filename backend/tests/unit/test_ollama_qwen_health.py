import pytest
import uuid
from unittest.mock import AsyncMock, patch, MagicMock
from app.engines.llm_assistant.client import OllamaClient, LLMConnectionError, LLMModelUnavailableError
from app.engines.llm_assistant.service import LLMAssistantService
from app.contracts.llm import LLMInvestigationContext
from app.engines.llm_assistant.models import LLMResponseStatus

@pytest.mark.asyncio
async def test_1_ollama_server_available():
    client = OllamaClient(base_url="http://localhost:11434", model="qwen2.5:1.5b")
    with patch("httpx.AsyncClient.get") as mock_get, patch("httpx.AsyncClient.post") as mock_post:
        mock_get.return_value = MagicMock(status_code=200, json=lambda: {"models": [{"name": "qwen2.5:1.5b"}]})
        mock_post.return_value = MagicMock(status_code=200, json=lambda: {"response": "OK"})
        
        health = await client.check_health()
        assert health["server"] is True
        assert health["model"] is True
        assert health["generation"] is True

@pytest.mark.asyncio
async def test_2_ollama_server_unavailable():
    client = OllamaClient(base_url="http://localhost:11434", model="qwen2.5:1.5b")
    with patch("httpx.AsyncClient.get", side_effect=Exception("Connection refused")):
        health = await client.check_health()
        assert health["server"] is False
        assert "unreachable" in health["error"] or "refused" in health["error"]

@pytest.mark.asyncio
async def test_3_configured_model_installed():
    client = OllamaClient(base_url="http://localhost:11434", model="qwen2.5:1.5b")
    with patch("httpx.AsyncClient.get") as mock_get, patch("httpx.AsyncClient.post") as mock_post:
        mock_get.return_value = MagicMock(status_code=200, json=lambda: {"models": [{"name": "qwen2.5:1.5b"}]})
        mock_post.return_value = MagicMock(status_code=200, json=lambda: {"response": "OK"})
        
        health = await client.check_health()
        assert health["model"] is True

@pytest.mark.asyncio
async def test_4_configured_model_missing():
    client = OllamaClient(base_url="http://localhost:11434", model="missing-model:7b")
    with patch("httpx.AsyncClient.get") as mock_get:
        mock_get.return_value = MagicMock(status_code=200, json=lambda: {"models": [{"name": "gemma3:4b"}]})
        
        health = await client.check_health()
        assert health["server"] is True
        assert health["model"] is False
        assert "not installed" in health["error"]

@pytest.mark.asyncio
async def test_5_exact_model_name_mismatch():
    client = OllamaClient(base_url="http://localhost:11434", model="qwen2.5:7b")
    with patch("httpx.AsyncClient.get") as mock_get:
        mock_get.return_value = MagicMock(status_code=200, json=lambda: {"models": [{"name": "llama3:8b"}]})
        
        health = await client.check_health()
        assert health["model"] is False

@pytest.mark.asyncio
async def test_6_generation_success():
    client = OllamaClient()
    with patch("httpx.AsyncClient.post") as mock_post:
        mock_post.return_value = MagicMock(status_code=200, json=lambda: {"response": '{"summary": "Test response"}'})
        output = await client.generate("Test prompt", "System instruction")
        assert "summary" in output

@pytest.mark.asyncio
async def test_7_generation_timeout():
    client = OllamaClient()
    import httpx
    with patch("httpx.AsyncClient.post", side_effect=httpx.TimeoutException("Timeout")):
        with pytest.raises(LLMConnectionError):
            await client.generate("Test prompt", "System instruction")

@pytest.mark.asyncio
async def test_8_malformed_response():
    client = OllamaClient()
    service = LLMAssistantService(client)
    context = LLMInvestigationContext(case_id=str(uuid.uuid4()), case_metadata={"title": "Test Case"})
    
    with patch.object(client, "generate", return_value="INVALID NON JSON OUTPUT"):
        resp = await service.generate_summary(context)
        assert resp.status == LLMResponseStatus.SUCCESS
        assert "INVALID NON JSON OUTPUT" in resp.summary
