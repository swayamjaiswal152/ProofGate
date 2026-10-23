"""Thin Claude client used by the Adversarial Twin.

Reads the API key from the environment only (never hard-coded, never logged).
If no key is present, callers fall back to deterministic generation so the
demo never breaks.
"""
from __future__ import annotations

import json
import os
import re

MODEL = "claude-opus-5-5"


class LLMUnavailable(Exception):
    """Raised when no API key is configured — callers should use the fallback."""


class LLMRefused(Exception):
    """Raised when the safety classifier declines the request."""


def available() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def _extract_json(text: str):
    """Be forgiving: strip code fences and grab the first JSON value."""
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.MULTILINE).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Find the outermost {...} or [...]
        match = re.search(r"(\{.*\}|\[.*\])", text, re.DOTALL)
        if not match:
            raise
        return json.loads(match.group(1))


def complete_json(system: str, user: str, max_tokens: int = 4096, model: str | None = None):
    """Ask Claude for JSON and return the parsed Python object.

    Raises LLMUnavailable if no key; lets other errors propagate so callers
    can decide whether to fall back.
    """
    if not available():
        raise LLMUnavailable("ANTHROPIC_API_KEY not set")

    import anthropic

    client = anthropic.Anthropic()
    system = system + "\n\nReturn ONLY valid JSON. No markdown, no prose, no code fences."

    kwargs = dict(
        model=model or MODEL,
        max_tokens=max_tokens,
        system=system,
        messages=[{"role": "user", "content": user}],
    )
    # Keep it snappy/cheap when the SDK supports effort; ignore if it doesn't.
    try:
        msg = client.messages.create(output_config={"effort": "low"}, **kwargs)
    except TypeError:
        msg = client.messages.create(**kwargs)

    if getattr(msg, "stop_reason", None) == "refusal":
        raise LLMRefused("Safety classifier declined the request")

    text = "".join(
        getattr(b, "text", "") for b in msg.content if getattr(b, "type", None) == "text"
    )
    if not text.strip():
        raise LLMRefused("Empty response (possible refusal or truncation)")
    return _extract_json(text)
