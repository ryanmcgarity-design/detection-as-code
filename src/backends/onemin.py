"""
1min.ai backend adapter.

Wraps the 1min.ai REST API in an interface compatible with the triage layer.
The API is NOT OpenAI-compatible — it uses its own endpoint and response shape,
so we can't just swap base_url into the OpenAI client.

API reference: /home/ryan/model-testing/1min-api-docs.md
Proven usage:  /home/ryan/model-testing/rpg_gen.py  (generate function)

Auth:
    Set ONEMIN_API_KEY env var. Key is sent as the API-KEY request header.

Usage in models.yaml:
    - name: deepseek-reasoner
      backend: 1min_ai
      mode: react          # 1min.ai has no tool calling — always use react

Known-working model IDs (from prior testing):
    deepseek-reasoner, deepseek-chat
    meta/llama-4-maverick-instruct, meta/llama-3.1-405b-instruct
    gpt-4o, gpt-4o-mini, gpt-4.1, o3, o3-mini, o4-mini
    claude-sonnet-4-6, claude-opus-4-6, claude-haiku-4-5-20251001
    qwen3-max, qwen-max, qwen-plus
    gemini-2.5-flash, gemini-3.1-pro-preview
    mistral-large-latest, mistral-small-latest
    grok-4, grok-3, grok-3-mini
"""

import logging
import os

import requests

log = logging.getLogger(__name__)

ONEMIN_BASE_URL = "https://api.1min.ai"
ONEMIN_API_KEY = os.environ.get("ONEMIN_API_KEY", "")

# Single-shot timeout in seconds — some reasoning models are slow
ONEMIN_TIMEOUT = int(os.environ.get("ONEMIN_TIMEOUT", "180"))


class OneminClient:
    """
    Minimal adapter that exposes the one method the triage layer needs:
    chat(model, messages) -> str

    messages is an OpenAI-style list of {"role": ..., "content": ...} dicts.
    We flatten it to a single prompt string since 1min.ai uses promptObject.prompt.
    Multi-turn context is preserved by serialising the full history as text.
    """

    def __init__(self, api_key: str = ONEMIN_API_KEY):
        if not api_key:
            raise ValueError("ONEMIN_API_KEY env var is not set")
        self.api_key = api_key
        self.headers = {"API-KEY": api_key, "Content-Type": "application/json"}

    def chat(self, model: str, messages: list[dict]) -> str:
        """Send a conversation to 1min.ai and return the assistant's reply."""
        prompt = _flatten_messages(messages)
        r = requests.post(
            f"{ONEMIN_BASE_URL}/api/chat-with-ai",
            headers=self.headers,
            json={
                "type": "UNIFY_CHAT_WITH_AI",
                "model": model,
                "promptObject": {"prompt": prompt},
            },
            timeout=ONEMIN_TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
        status = data.get("aiRecord", {}).get("status")
        if status != "SUCCESS":
            raise ValueError(f"1min.ai API returned status: {status} | body: {r.text[:300]}")
        return data["aiRecord"]["aiRecordDetail"]["resultObject"][0]


def _flatten_messages(messages: list[dict]) -> str:
    """
    Collapse an OpenAI-style message list into a single prompt string.
    System message becomes a preamble, then alternating Human/Assistant turns.
    """
    parts = []
    for msg in messages:
        role = msg.get("role", "user")
        content = msg.get("content", "")
        if role == "system":
            parts.append(f"[SYSTEM]\n{content}")
        elif role == "assistant":
            parts.append(f"[ASSISTANT]\n{content}")
        else:
            parts.append(f"[HUMAN]\n{content}")
    return "\n\n".join(parts)


def make_client() -> OneminClient:
    return OneminClient()
