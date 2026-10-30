"""Unified forensic investigation report: facts -> narrative (template or LLM) -> verification."""
from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone

from .. import config
from ..ai import llm
from ..core.entities import SEVERITY_RANK
from .narrative import template_sections
from .verifier import evidence_facts, split_sentences, verify_sentence


def llm_sections(case: dict, evidence: list[dict], corr: dict, template: list[dict]) -> list[dict]:
    facts = [{"section": s["title"], "statement": t} for s in template for t in s["sentences"]]
    prompt = (
        "You are assisting a digital forensic investigator. Rewrite the verified facts below into a clear "
        "investigation narrative with sections headed '## <title>'. Rules: (1) use ONLY information in the facts; "
        "(2) every sentence must end with one or more evidence citations copied exactly from the facts, e.g. [E3:ab12cd34]; "
        "(3) never introduce IP addresses, domains, hashes, e-mail addresses or times that are not in the cited facts; "
        "(4) do not speculate about attribution.\n\nCASE: " + case.get("name", "") + "\n\nFACTS:\n" +
        json.dumps(facts, indent=1)[:60000])
    text = llm.complete(prompt)
    secs, cur = [], None
    for line in text.splitlines():
        if line.startswith("## "):
            cur = {"title": line[3:].strip(), "sentences": []}
            secs.append(cur)
        elif line.strip():
            if cur is None:
                cur = {"title": "Narrative", "sentences": []}
                secs.append(cur)
            cur["sentences"] += split_sentences(line)
    return secs

def build_report(case: dict, evidence: list[dict], corr: dict, use_llm: bool = False,
                 extra_sections: list[dict] | None = None) -> dict:
    tmpl = template_sections(case, evidence, corr)
    if extra_sections:
        tmpl = tmpl[:1] + [s for s in extra_sections if s.get("sentences")] + tmpl[1:]
    generator, sections, note = "template", tmpl, ""
    if use_llm:
        if not llm.configured():
            note = "LLM not configured (set IDMF_LLM_PROVIDER and IDMF_LLM_API_KEY); template narrative used."
        else:
            try:
                sections = llm_sections(case, evidence, corr, tmpl)
                generator = f"llm:{config.LLM_PROVIDER}:{config.LLM_MODEL or 'default'}"
            except Exception as exc:
                note = f"LLM call failed ({exc}); template narrative used."
    facts = {e["id"]: evidence_facts(e) for e in evidence}
    out_secs, counts = [], defaultdict(int)
    for s in sections:
        rows = []
        for t in s["sentences"]:
            v = verify_sentence(t, facts)
            counts[v["status"]] += 1
            rows.append({"text": t, **v})
        out_secs.append({"title": s["title"], "sentences": rows})
    total = sum(counts.values()) or 1
    return {
        "case": {k: case.get(k) for k in ("id", "name", "description", "status", "created_by", "created_at")},
        "generated_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(timespec="seconds") + "Z",
        "generator": generator, "note": note,
        "sections": out_secs,
        "verification": {"sentences": total, **counts, "traceability": round(counts["verified"] / total, 4)},
        "evidence": [{"id": e["id"], "filename": e["filename"], "module": e["module"], "sha256": e["sha256"],
                      "size": e.get("size"), "integrity_ok": e.get("integrity_ok", True),
                      "uploaded_at": e.get("uploaded_at")} for e in evidence],
        "incidents": corr.get("incidents", []),
        "timeline": [r for r in corr.get("timeline", []) if r.get("pivot") or SEVERITY_RANK.get(r["severity"], 0) >= 2][:60],
    }
