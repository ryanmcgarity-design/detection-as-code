"""Dump the full 1min.ai response for one call to find credit/usage/token fields.
We know the web UI shows '785 credits' per call — this checks whether the API
response carries that cost so we can meter runs programmatically."""
import json
import os

import requests
from dotenv import load_dotenv

load_dotenv()
key = os.environ["ONEMIN_API_KEY"]
r = requests.post(
    "https://api.1min.ai/api/chat-with-ai",
    headers={"API-KEY": key, "Content-Type": "application/json"},
    json={
        "type": "UNIFY_CHAT_WITH_AI",
        "model": "openai/gpt-oss-120b",
        "promptObject": {"prompt": "Reply with exactly: PONG"},
    },
    timeout=120,
)
d = r.json()


def walk(o, p=""):
    if isinstance(o, dict):
        for k, v in o.items():
            walk(v, p + "." + k)
    elif isinstance(o, list):
        for i, v in enumerate(o[:2]):
            walk(v, f"{p}[{i}]")
    else:
        s = str(o)[:90]
        print(f"{p} = {s}")


print("=== ALL SCALAR FIELDS IN RESPONSE ===")
walk(d)
print("\n=== fields matching credit/token/usage/cost/price ===")
flat = json.dumps(d)
for kw in ("credit", "token", "usage", "cost", "price", "balance"):
    if kw in flat.lower():
        print(f"  '{kw}' APPEARS in response")
    else:
        print(f"  '{kw}' not present")
