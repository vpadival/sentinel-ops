"""
core/llm.py
────────────
Phase 5: Added exponential backoff retry, robust JSON cleaning,
         rate-limit handling, and startup key validation.
"""

from __future__ import annotations
import os
import re
import json
import time
import logging
from typing import Any, Dict, cast
from groq import Groq, APIStatusError, APIConnectionError
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

_client: Groq | None = None

PRIMARY_MODEL  = os.getenv("GROQ_PRIMARY_MODEL", "").strip() or "openai/gpt-oss-120b"
FALLBACK_MODEL = os.getenv("GROQ_FALLBACK_MODEL", "").strip() or "openai/gpt-oss-20b"

MAX_RETRIES    = 3
BACKOFF_BASE   = 3   # seconds


def _get_client() -> Groq:
    global _client
    if _client is None:
        api_key = os.getenv("GROQ_API_KEY", "").strip()
        if not api_key:
            raise EnvironmentError("GROQ_API_KEY not set. Add it to your .env file.")
        # Retry policy lives in call_llm; avoid nesting the SDK's retries and
        # long default timeout inside each agent's retries.
        _client = Groq(api_key=api_key, timeout=30.0, max_retries=0)
    return _client


def validate_keys() -> Dict[str, bool]:
    """
    Called at startup. Returns status of all configured API keys.
    Used by the /health endpoint.
    """
    return {
        "groq":    bool(os.getenv("GROQ_API_KEY", "").strip()),
        "tavily":  bool(os.getenv("TAVILY_API_KEY", "").strip()),
        "discord": bool(os.getenv("DISCORD_WEBHOOK_URL", "").strip()),
        "omium":   bool(os.getenv("OMIUM_API_KEY", "").strip()),    # ← was noveum/NOVEUM_API_KEY
    }


def clean_json(raw: str) -> str:
    """
    Phase 7: Robust JSON extraction from LLM output.
    Handles:
      - Markdown code fences (```json ... ```)
      - Leading/trailing prose before/after the JSON object
      - Trailing commas (common LLM mistake)
    Uses bracket-balanced extraction instead of greedy regex to avoid
    grabbing prose between two separate JSON-like fragments.
    """
    # Strip markdown fences
    text = raw.strip()
    text = re.sub(r'^```(?:json)?\s*', '', text, flags=re.MULTILINE)
    text = re.sub(r'```\s*$', '', text, flags=re.MULTILINE)
    text = text.strip()

    # Extract the first balanced JSON object using bracket counting.
    # This avoids the greedy regex problem where `{a} prose {b}` would
    # match from the first `{` to the last `}`.
    start = text.find('{')
    if start != -1:
        depth = 0
        in_string = False
        escape_next = False
        for i in range(start, len(text)):
            c = text[i]
            if escape_next:
                escape_next = False
                continue
            if c == '\\' and in_string:
                escape_next = True
                continue
            if c == '"' and not escape_next:
                in_string = not in_string
                continue
            if in_string:
                continue
            if c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    text = text[start:i + 1]
                    break

    # Fix trailing commas before } or ]  (common LLM mistake)
    # Match strings first so payload text such as "value,}" stays intact.
    text = re.sub(
        r'"(?:\\.|[^"\\])*"|,\s*(?=[}\]])',
        lambda match: match.group(0) if match.group(0).startswith('"') else '',
        text,
    )

    return text.strip()


def call_llm(
    system: str,
    user: str,
    temperature: float = 0.1,
    max_tokens: int = 1024,
) -> str:
    """
    Call Groq API with exponential backoff retry on rate limits.
    Falls back to smaller model if primary is unavailable.
    """
    client = _get_client()
    failures: list[str] = []
    attempts = 0

    for model in (PRIMARY_MODEL, FALLBACK_MODEL):
        for attempt in range(MAX_RETRIES):
            try:
                attempts += 1
                response = client.chat.completions.create(
                    model=model,
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user",   "content": user},
                    ],
                    temperature=temperature,
                    # Reasoning models share the completion budget with reasoning.
                    max_tokens=max_tokens + 2048 if model.startswith("openai/gpt-oss-") else max_tokens,
                    extra_body={"reasoning_effort": "low"} if model.startswith("openai/gpt-oss-") else {},
                )
                content = response.choices[0].message.content
                return (content or "").strip()

            except Exception as exc:
                if isinstance(exc, APIConnectionError):
                    raise RuntimeError("Cannot connect to Groq. Check network and proxy settings.") from exc
                if not isinstance(exc, APIStatusError):
                    raise
                status = exc.status_code
                body: Any = exc.body
                error: Any = body.get("error", body) if isinstance(body, dict) else {}
                code = error.get("code", "") if isinstance(error, dict) else ""
                # Expose only a short machine-readable code, never raw response
                # bodies (which may include credentials or submitted alert text).
                code = code if isinstance(code, str) and re.fullmatch(r"[a-zA-Z0-9_]{1,80}", code) else "unknown"
                detail = f"{model}: HTTP {status} ({code})"

                if status == 429:
                    if attempt + 1 < MAX_RETRIES:
                        wait = BACKOFF_BASE ** (attempt + 1)
                        logger.warning("%s; retrying in %ss", detail, wait)
                        time.sleep(wait)
                    else:
                        failures.append(detail + "; rate limit reached; check Groq usage limits.")
                    continue
                if code in {"model_not_found", "model_decommissioned",
                            "model_permission_blocked_org", "model_permission_blocked_project"}:
                    failures.append(detail + "; check model availability and Groq project/organization permissions.")
                    logger.warning("%s; trying the next configured model", detail)
                    break
                hint = {
                    400: "Request rejected; check the model's supported parameters.",
                    401: "Invalid API key; update GROQ_API_KEY and restart the backend.",
                    403: "Access denied; check Groq project/organization permissions.",
                    413: "Request too large; shorten the alert or evidence.",
                }.get(status, "Groq request failed; check service status and account settings.")
                raise RuntimeError(f"{detail}. {hint}") from exc

    raise RuntimeError(f"Groq failed after {attempts} request attempt(s). " + " | ".join(failures))


def call_llm_json(
    system: str,
    user: str,
    temperature: float = 0.1,
    max_tokens: int = 1024,
) -> Dict[str, Any]:
    """
    Phase 5: LLM call that guarantees a parsed dict back.
    Retries up to MAX_RETRIES times if JSON parsing fails.
    Raises ValueError only if all attempts fail.
    """
    last_err = None
    for attempt in range(MAX_RETRIES):
        try:
            raw    = call_llm(system, user, temperature, max_tokens)
            clean  = clean_json(raw)
            parsed = json.loads(clean)
            if not isinstance(parsed, dict):
                raise ValueError("Expected a JSON object")
            return cast(Dict[str, Any], parsed)
        except (json.JSONDecodeError, ValueError) as exc:
            last_err = exc
            logger.warning(f"JSON parse failed (attempt {attempt+1}): {exc}. Retrying with stricter prompt.")
            # On retry, append a stronger instruction
            user = user + "\n\nIMPORTANT: Your previous response was not valid JSON. Respond with ONLY a raw JSON object. No prose, no markdown, no code fences."

    raise ValueError(f"LLM returned invalid JSON after {MAX_RETRIES} attempts: {last_err}")
