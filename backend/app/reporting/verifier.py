"""Sentence-level verification of report text against cited evidence.

A sentence is verified only when it cites at least one evidence item as [E<id>] (optionally
[E<id>:<sha-prefix>]), every cited item exists, and every checkable token in the sentence
(IP, domain, e-mail, URL, hash, minute-level timestamp) occurs in the cited items' facts.
The check is lexical: it guarantees provenance of identifiers and times, not the meaning of
the claim made about them.
"""
from __future__ import annotations

import re

from ..core.entities import RE_EMAIL, RE_IPV4, RE_MD5, RE_SHA1, RE_SHA256, RE_URL, normalize

RE_CITE = re.compile(r"\[E(\d+)(?::[0-9a-f]{4,64})?\]")
RE_TS = re.compile(r"\b(20\d\d-\d\d-\d\d)[T ](\d\d:\d\d)")
RE_DOMAIN_STRICT = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I)

def evidence_facts(ev: dict) -> set[str]:
    vals = {ev.get("filename", "").lower(), ev.get("sha256", "").lower()}
    for a in ev.get("artifacts", []):
        for e in a.get("entities", []):
            vals.add(str(e["value"]).lower())
        if a.get("ts"):
            vals.add(a["ts"][:16].replace("T", " "))
        d = a.get("detail", {})
        for k in ("sha256", "md5", "url", "subject", "from", "sender_ip", "src", "dst"):
            if isinstance(d.get(k), str):
                vals.add(d[k].lower())
        # tokens stated in the module's own artifact title / indicators are facts about this evidence
        for text in [a.get("title", "")] + list(a.get("indicators", [])):
            for _t, v in checkable_tokens(text):
                vals.add(v)
    return {v for v in vals if v}


def checkable_tokens(sentence: str) -> set[tuple[str, str]]:
    s = RE_CITE.sub(" ", sentence)
    toks = set()
    for m in RE_URL.finditer(s):
        n = normalize("url", m.group(0).rstrip(".,;"))
        if n:
            toks.add(("url", n))
    s2 = RE_URL.sub(" ", s)
    for m in RE_EMAIL.finditer(s2):
        toks.add(("email", m.group(0).lower()))
    s3 = RE_EMAIL.sub(" ", s2)
    for rx, t in ((RE_SHA256, "sha256"), (RE_SHA1, "sha1"), (RE_MD5, "md5")):
        for m in rx.finditer(s3):
            toks.add((t, m.group(0).lower()))
        s3 = rx.sub(" ", s3)
    for m in RE_IPV4.finditer(s3):
        toks.add(("ip", m.group(0)))
    for m in RE_DOMAIN_STRICT.finditer(RE_IPV4.sub(" ", s3)):
        n = normalize("domain", m.group(0))
        if n and not re.search(r"\.(pdf|exe|txt|eml|pcap|png|jpe?g|json|log|db|sqlite|zip|docm|js|mem|raw|body)$", n):
            toks.add(("domain", n))
    for m in RE_TS.finditer(s):
        toks.add(("ts", f"{m.group(1)} {m.group(2)}"))
    return toks


def verify_sentence(sentence: str, facts_by_ev: dict[int, set[str]]) -> dict:
    cites = [int(c) for c in RE_CITE.findall(sentence)]
    if not cites:
        return {"status": "unsupported", "reason": "no evidence citation", "citations": []}
    bad = [c for c in cites if c not in facts_by_ev]
    if bad:
        return {"status": "invalid_citation", "reason": f"cites unknown evidence E{bad[0]}", "citations": cites}
    pool = set().union(*(facts_by_ev[c] for c in cites))
    missing = []
    for t, v in checkable_tokens(sentence):
        if t == "domain":
            ok = v in pool or any(p.endswith("." + v) or v.endswith("." + p) or ("//" + v) in p or ("@" + v) in p for p in pool)
        elif t == "ts":
            ok = v in pool
        else:
            ok = v in pool
        if not ok:
            missing.append(f"{t} {v}")
    if missing:
        return {"status": "contradicted", "reason": "not found in cited evidence: " + ", ".join(missing[:4]), "citations": cites}
    return {"status": "verified", "reason": "", "citations": cites}


def split_sentences(text: str) -> list[str]:
    parts = re.split(r"(?<=[.!?])\s+(?=[A-Z])|(?<=\])\s+(?=[A-Z])", text.strip())
    return [p.strip() for p in parts if p.strip()]
