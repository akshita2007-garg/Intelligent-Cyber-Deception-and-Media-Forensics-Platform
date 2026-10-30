"""Honeytokens: decoy values with no legitimate use.

Any later appearance of a honeytoken in evidence (or any interaction with a decoy) is a
high-confidence intrusion signal. Tokens planted together (same placement) form a decoy set,
which the correlation engine uses as a tripwire.
"""
from __future__ import annotations

import secrets
import string

from .. import config

_WORDS = ["backup", "svc", "admin", "finance", "payroll", "deploy", "ops", "hr", "legacy", "sql"]


def generate_honeytoken(token_type: str, label: str = "") -> dict:
    """Creates a decoy value. Nothing here is a real credential; values are random and recorded
    so any later appearance in evidence is a high-confidence signal of intrusion."""
    rnd = secrets.token_hex(4)
    if token_type == "credential":
        user = f"{secrets.choice(_WORDS)}_{secrets.choice(_WORDS)}{secrets.randbelow(90) + 10}"
        pw = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(14))
        return {"token_type": token_type, "label": label or f"Decoy account {user}", "value": user, "secret": pw}
    if token_type == "api_key":
        key = "IDMFDECOY" + "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(11))
        sec = secrets.token_urlsafe(30)
        return {"token_type": token_type, "label": label or "Decoy cloud API key", "value": key, "secret": sec}
    if token_type == "canary_url":
        tok = secrets.token_urlsafe(12)
        return {"token_type": token_type, "label": label or "Canary URL",
                "value": f"{config.PUBLIC_BASE_URL.rstrip('/')}/decoy/t/{tok}", "secret": tok}
    if token_type == "email":
        return {"token_type": token_type, "label": label or "Honey email address",
                "value": f"{secrets.choice(_WORDS)}.{rnd}@decoy-mail.internal", "secret": ""}
    if token_type == "document":
        name = f"{secrets.choice(['Passwords', 'VPN_Access', 'Payroll_2026', 'AWS_keys'])}_{rnd}.txt"
        return {"token_type": token_type, "label": label or f"Decoy document {name}", "value": name.lower(), "secret": ""}
    raise ValueError(f"unknown honeytoken type {token_type}")


def honeytoken_document(ht: dict, related: list[dict]) -> str:
    """Text for a decoy file that embeds other honeytokens (credentials, keys, canary URL)."""
    lines = ["CONFIDENTIAL - internal use only", ""]
    for r in related:
        if r["token_type"] == "credential":
            lines.append(f"user: {r['value']}    pass: {r['secret']}")
        elif r["token_type"] == "api_key":
            lines.append(f"access_key_id = {r['value']}\nsecret_access_key = {r['secret']}")
        elif r["token_type"] == "canary_url":
            lines.append(f"admin console: {r['value']}")
    return "\n".join(lines) + "\n"
