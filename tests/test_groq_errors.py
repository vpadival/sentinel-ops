from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import httpx
import pytest
from groq import APIStatusError
from backend.core.llm import call_llm, PRIMARY_MODEL, FALLBACK_MODEL


def api_error(status: int, code: str) -> APIStatusError:
    return APIStatusError("private response must not appear", response=httpx.Response(
        status, request=httpx.Request("POST", "https://api.groq.com/openai/v1/chat/completions"),
    ), body={"error": {"code": code, "message": "private response"}})


def test_unavailable_models_preserve_codes_and_attempt_count():
    client = MagicMock()
    client.chat.completions.create.side_effect = api_error(404, "model_not_found")
    with patch("backend.core.llm._get_client", return_value=client):
        with pytest.raises(RuntimeError) as error:
            call_llm("system", "user")
    assert "2 request attempt(s)" in str(error.value)
    assert "HTTP 404 (model_not_found)" in str(error.value)
    assert "private response" not in str(error.value)


def test_auth_failure_does_not_retry_or_fallback():
    client = MagicMock()
    client.chat.completions.create.side_effect = api_error(401, "invalid_api_key")
    with patch("backend.core.llm._get_client", return_value=client):
        with pytest.raises(RuntimeError, match="Invalid API key"):
            call_llm("system", "user")
    assert client.chat.completions.create.call_count == 1


def test_fallback_after_model_unavailable():
    client = MagicMock()
    client.chat.completions.create.side_effect = [api_error(400, "model_decommissioned"),
        SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content="ok"))])]
    with patch("backend.core.llm._get_client", return_value=client):
        assert call_llm("system", "user") == "ok"
    assert [call.kwargs["model"] for call in client.chat.completions.create.call_args_list] == [PRIMARY_MODEL, FALLBACK_MODEL]


def test_rate_limit_backoff_skips_last_attempt_sleep():
    client = MagicMock()
    client.chat.completions.create.side_effect = api_error(429, "rate_limit_exceeded")
    with patch("backend.core.llm._get_client", return_value=client), patch("backend.core.llm.time.sleep") as sleep:
        with pytest.raises(RuntimeError, match="6 request attempt"):
            call_llm("system", "user")
    assert [call.args[0] for call in sleep.call_args_list] == [3, 9, 3, 9]
