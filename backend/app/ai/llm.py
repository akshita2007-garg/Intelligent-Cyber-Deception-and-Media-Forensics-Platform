"""Optional LLM access (Anthropic Messages API or any OpenAI-compatible chat endpoint).

Configure with IDMF_LLM_PROVIDER (anthropic | openai), IDMF_LLM_API_KEY, IDMF_LLM_MODEL and,
optionally, IDMF_LLM_BASE_URL. The LLM only ever rewrites facts produced locally; every
sentence it returns is checked by reporting.verifier before it is shown.
"""
from __future__ import annotations

import json
import urllib.request

from .. import config


def configured() -> bool:
    return bool(config.LLM_PROVIDER and config.LLM_API_KEY)


def complete(prompt: str) -> str:
    if config.LLM_PROVIDER == "anthropic":
        body = {"model": config.LLM_MODEL or "claude-sonnet-4-5", "max_tokens": 2500,
                "messages": [{"role": "user", "content": prompt}]}
        req = urllib.request.Request((config.LLM_BASE_URL or "https://api.anthropic.com") + "/v1/messages",
                                     data=json.dumps(body).encode(), method="POST",
                                     headers={"x-api-key": config.LLM_API_KEY, "anthropic-version": "2023-06-01",
                                              "content-type": "application/json"})
        with urllib.request.urlopen(req, timeout=120) as r:
            return "".join(c.get("text", "") for c in json.loads(r.read())["content"])
    body = {"model": config.LLM_MODEL or "gpt-4o-mini", "messages": [{"role": "user", "content": prompt}], "temperature": 0}
    req = urllib.request.Request((config.LLM_BASE_URL or "https://api.openai.com/v1") + "/chat/completions",
                                 data=json.dumps(body).encode(), method="POST",
                                 headers={"Authorization": f"Bearer {config.LLM_API_KEY}", "content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read())["choices"][0]["message"]["content"]
