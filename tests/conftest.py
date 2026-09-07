"""Keep the default test suite independent of local credentials and services."""
import os

import pytest

# Set before collection: application imports load dotenv and cache tracing keys.
os.environ["PYTHON_DOTENV_DISABLED"] = "1"
for key in (
    "GROQ_API_KEY", "TAVILY_API_KEY", "DISCORD_WEBHOOK_URL",
    "SLACK_WEBHOOK_URL", "OMIUM_API_KEY", "SENTINEL_API_KEY",
):
    os.environ.pop(key, None)


@pytest.fixture(autouse=True)
def isolate_clients(monkeypatch: pytest.MonkeyPatch) -> None:
    from backend.core import llm
    monkeypatch.setattr(llm, "_client", None)
