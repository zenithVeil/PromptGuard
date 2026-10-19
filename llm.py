"""LLM provider abstraction for PromptGuard.

Provider order (resolved on every call):
  1. Nebius Token Factory (NVIDIA Nemotron) via the openai Python SDK
     (base_url=https://api.tokenfactory.nebius.com/v1/, key from NEBIUS_API_KEY)
  2. Groq (dev only; key from GROQ_API_KEY) - optional dependency
  3. RULES_ONLY - no LLM call, simple keyword rules decide

Model IDs are read from the NANO_MODEL / ULTRA_MODEL environment variables
and are never hard-coded here.
"""

from __future__ import annotations

import json
import os
import re
import time
from typing import Any

from openai import OpenAI

NEBIUS_BASE_URL = "https://api.tokenfactory.nebius.com/v1/"

# Keywords used by RULES_ONLY mode to flag likely injection attempts.
RULE_KEYWORDS = ("ignore previous", "system prompt", "exfiltrate")

_PROVIDER_ANNOUNCED = False


def _announce_provider() -> None:
    """Print a clear startup line/warning about the active LLM provider."""
    global _PROVIDER_ANNOUNCED
    if _PROVIDER_ANNOUNCED:
        return
    _PROVIDER_ANNOUNCED = True

    nebius_key = os.getenv("NEBIUS_API_KEY", "").strip()
    groq_key = os.getenv("GROQ_API_KEY", "").strip()
    if nebius_key:
        print(
            "[PromptGuard] LLM provider: Nebius Token Factory (NVIDIA Nemotron)"
        )
    elif groq_key:
        print(
            "[PromptGuard] WARNING: NEBIUS_API_KEY not set; falling back to Groq "
            "(dev only)."
        )
    else:
        print(
            "[PromptGuard] WARNING: no LLM API key configured; running in "
            "RULES_ONLY mode (no LLM calls)."
        )


_announce_provider()


def _strip_think(text: str) -> str:
    """Remove NVIDIA Nemotron  </think> reasoning traces from a response."""
    return re.sub(r"<\s*think\b.*?</\s*think\s*>", "", text, flags=re.DOTALL | re.IGNORECASE)


def _extract_json(text: str) -> dict[str, Any] | None:
    """Return the first JSON object found in *text*, or None."""
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        try:
            value = json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            return None
        return value if isinstance(value, dict) else None
    return None


def _rules_only(user: str) -> dict[str, Any]:
    """Keyword-based decision when no LLM provider is configured."""
    lowered = user.lower()
    flagged = any(kw in lowered for kw in RULE_KEYWORDS)
    return {
        "flagged": flagged,
        "reason": (
            "RULES_ONLY: content matches injection keyword(s)."
            if flagged
            else "RULES_ONLY: no injection keywords detected."
        ),
    }


def ask_json(model: str, system: str, user: str, max_tokens: int = 800) -> dict[str, Any]:
    """Chat a JSON-emitting LLM and return the parsed object plus metadata.

    Returns the parsed JSON dict augmented with ``_provider``, ``_model`` and
    ``_latency_s``. In RULES_ONLY mode no LLM call is made and keyword rules
    decide the result instead.
    """
    nebius_key = os.getenv("NEBIUS_API_KEY", "").strip()
    groq_key = os.getenv("GROQ_API_KEY", "").strip()

    start_time = time.perf_counter()

    if nebius_key:
        provider = "nebius"
        used_model = model

        def fetch() -> str:
            client = OpenAI(base_url=NEBIUS_BASE_URL, api_key=nebius_key)
            response = client.chat.completions.create(
                model=model,
                temperature=0,
                max_tokens=max_tokens,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            )
            return response.choices[0].message.content or ""

    elif groq_key:
        provider = "groq"
        used_model = model

        def fetch() -> str:
            # groq is an optional dev dependency; imported lazily.
            from groq import Groq  # type: ignore

            client = Groq(api_key=groq_key)
            response = client.chat.completions.create(
                model=model,
                temperature=0,
                max_tokens=max_tokens,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            )
            return response.choices[0].message.content or ""

    else:
        provider = "rules-only"
        used_model = "rules-only"
        result = _rules_only(user)
        result["_provider"] = provider
        result["_model"] = used_model
        result["_latency_s"] = round(time.perf_counter() - start_time, 4)
        return result

    # Nebius / Groq path: try parsing, retry once on invalid JSON.
    parsed: dict[str, Any] | None = None
    for _ in range(2):
        raw = fetch()
        text = _strip_think(raw)
        parsed = _extract_json(text)
        if parsed is not None:
            break

    if parsed is None:
        raise ValueError("LLM returned non-JSON output")

    parsed["_provider"] = provider
    parsed["_model"] = used_model
    parsed["_latency_s"] = round(time.perf_counter() - start_time, 4)
    return parsed
