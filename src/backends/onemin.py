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
        # Cost accounting — the API returns per-call credits + tokens in
        # aiRecord.metadata. We sum them so a whole triage run reports its cost,
        # splitting input vs output credits so we can derive per-token rates.
        self.total_credits = 0
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.total_input_credits = 0
        self.total_output_credits = 0
        self.calls = 0

    def chat(self, model: str, messages: list[dict]) -> str:
        """Send a conversation to 1min.ai and return the assistant's reply.
        Accumulates per-call credit/token cost from aiRecord.metadata."""
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
        rec = data.get("aiRecord", {})
        status = rec.get("status")
        if status != "SUCCESS":
            raise ValueError(f"1min.ai API returned status: {status} | body: {r.text[:300]}")
        meta = rec.get("metadata", {}) or {}
        credit = meta.get("credit", 0) or 0
        in_tok = meta.get("inputToken", 0) or 0
        out_tok = meta.get("outputToken", 0) or 0
        in_cr = meta.get("inputCredit", 0) or 0
        out_cr = meta.get("outputCredit", 0) or 0
        self.total_credits += credit
        self.total_input_tokens += in_tok
        self.total_output_tokens += out_tok
        self.total_input_credits += in_cr
        self.total_output_credits += out_cr
        self.calls += 1
        log.info("1min.ai %s: %s credits (in=%s/%s out=%s/%s tok/cr) | "
                 "run total=%s credits over %s calls",
                 model, credit, in_tok, in_cr, out_tok, out_cr, self.total_credits, self.calls)
        return rec["aiRecordDetail"]["resultObject"][0]

    def cost_summary(self) -> dict:
        """Totals for the run so far (for logging after a triage batch). Includes
        split input/output credits so per-token rates can be derived:
        in_rate = input_credits/input_tokens, out_rate = output_credits/output_tokens."""
        it, ot = self.total_input_tokens, self.total_output_tokens
        return {
            "credits": self.total_credits,
            "input_tokens": it,
            "output_tokens": ot,
            "input_credits": self.total_input_credits,
            "output_credits": self.total_output_credits,
            "credits_per_input_token": round(self.total_input_credits / it, 4) if it else None,
            "credits_per_output_token": round(self.total_output_credits / ot, 4) if ot else None,
            "calls": self.calls,
        }


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
