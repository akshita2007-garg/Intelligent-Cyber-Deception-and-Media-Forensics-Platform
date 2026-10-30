"""Evidence-grounded investigation assistant.

ask() answers an investigator's question about a case.
  * Without an LLM: retrieval over the case's artifacts (terms and exact indicator values),
    returning the best-matching findings as cited statements.
  * With an LLM (ai.llm configured): the retrieved findings, case summary and insights are given
    as numbered facts; the model must answer only from them with citations, and every sentence
    of its answer is verified before it is returned.
"""
from __future__ import annotations

import json
import re

from ..core.entities import SEVERITY_RANK
from ..reporting.verifier import evidence_facts, split_sentences, verify_sentence
from . import llm
from .summarizer import cite

STOP = {"the", "a", "an", "is", "was", "were", "are", "of", "to", "in", "on", "and", "or", "what", "which", "who", "when",
        "where", "how", "did", "does", "do", "any", "there", "this", "that", "with", "from", "for", "by", "it", "be", "case",
        "evidence", "show", "me", "list", "find", "all", "about", "tell", "i", "we", "has", "have", "been"}
SYNONYMS = {"phishing": ["spf", "dkim", "reply-to", "spoof", "link text", "phish"], "c2": ["beacon", "c2", "implant"],
            "beacon": ["beacon"], "honeytoken": ["honeytoken", "decoy"], "decoy": ["decoy", "honeypot", "honeytoken"],
            "attacker": ["honeypot", "login", "decoy"], "tunnel": ["tunnel"], "fake": ["manipulated", "edit"],
            "manipulated": ["manipulated", "edit", "splice"], "download": ["download"], "credential": ["login", "credential", "pass"]}


def retrieve(question: str, evidence: list[dict], k: int = 8) -> list[dict]:
    q = question.lower()
    terms = [t for t in re.findall(r"[\w.@:/-]+", q) if t not in STOP and len(t) > 1]
    expanded = set(terms)
    for t in terms:
        expanded.update(SYNONYMS.get(t.rstrip("s"), []))
    hits = []
    for ev in evidence:
        for ai, a in enumerate(ev.get("artifacts", [])):
            if a.get("kind") == "evidence.file":
                continue
            blob = (a.get("title", "") + " " + " ".join(a.get("indicators", [])) + " " +
                    " ".join(e["value"] for e in a.get("entities", [])) + " " + a.get("kind", "")).lower()
            values = {e["value"] for e in a.get("entities", [])}
            score = sum(3 if t in values else 1 for t in expanded
                        if t in values or re.search(r"(?<![\w])" + re.escape(t), blob))
            if score:
                score += SEVERITY_RANK.get(a.get("severity", "info"), 0) * 0.5
                hits.append((score, ev, ai, a))
    hits.sort(key=lambda h: -h[0])
    out, seen = [], set()
    for score, ev, ai, a in hits:
        key = (ev["id"], a["title"])
        if key in seen:
            continue
        seen.add(key)
        when = f" at {a['ts'][:16].replace('T', ' ')}" if a.get("ts") else ""
        ind = f" ({'; '.join(a['indicators'][:2])})" if a.get("indicators") else ""
        out.append({"evidence_id": ev["id"], "filename": ev["filename"], "score": round(score, 2),
                    "text": f"{ev['filename']}: {a['title']}{when}{ind} {cite(ev)}."})
        if len(out) >= k:
            break
    return out


def ask(question: str, evidence: list[dict], summary: list[str], insights: dict, use_llm: bool = True) -> dict:
    found = retrieve(question, evidence)
    facts_by_ev = {e["id"]: evidence_facts(e) for e in evidence}
    if use_llm and llm.configured():
        facts = summary + [i["text"] for i in insights.get("items", [])] + [f["text"] for f in found]
        prompt = ("You assist a digital forensic investigator. Answer the question using ONLY the numbered facts. "
                  "End every sentence with the evidence citation(s) copied exactly from the facts, e.g. [E3:ab12cd34]. "
                  "If the facts do not answer the question, say so in one sentence citing nothing.\n\nQUESTION: " + question +
                  "\n\nFACTS:\n" + "\n".join(f"{n + 1}. {t}" for n, t in enumerate(facts[:80])))
        try:
            text = llm.complete(prompt)
            sents = [{"text": s, **verify_sentence(s, facts_by_ev)} for s in split_sentences(text)]
            return {"mode": "llm", "question": question, "answer": sents, "sources": found}
        except Exception as exc:  # fall back to retrieval
            note = f"LLM unavailable ({exc}); showing matching findings."
    else:
        note = "Matching findings from the case (configure an LLM for a written answer)."
    sents = [{"text": f["text"], **verify_sentence(f["text"], facts_by_ev)} for f in found]
    if not sents:
        sents = [{"text": "No artifact in this case matches the question.", "status": "info", "reason": "", "citations": []}]
    return {"mode": "retrieval", "question": question, "note": note, "answer": sents, "sources": found}
