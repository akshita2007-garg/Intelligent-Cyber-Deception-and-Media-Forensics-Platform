"""Evidence and case summarisation.

Summaries are generated deterministically from module output and correlation results, and
every sentence cites its evidence ([E<id>:<sha-prefix>]) so it can be verified. When an LLM is
configured, ai.assistant can rephrase them; the verifier still applies.
"""
from __future__ import annotations

from ..core.entities import SEVERITY_RANK


def cite(ev: dict) -> str:
    return f"[E{ev['id']}:{ev['sha256'][:8]}]"


def _top_indicators(ev: dict, k: int = 2) -> list[str]:
    arts = sorted(ev.get("artifacts", []), key=lambda a: -SEVERITY_RANK.get(a.get("severity", "info"), 0))
    out = []
    for a in arts:
        for i in a.get("indicators", []):
            if i not in out:
                out.append(i)
            if len(out) >= k:
                return out
    return out


def summarize_evidence(ev: dict) -> str:
    s, m, c = ev.get("summary", {}), ev.get("module"), cite(ev)
    times = sorted(a["ts"] for a in ev.get("artifacts", []) if a.get("ts"))
    span = f" between {times[0][:16].replace('T', ' ')} and {times[-1][:16].replace('T', ' ')}" if len(times) > 1 else ""
    if m == "email":
        head = f"{ev['filename']} holds {s.get('messages', 0)} message(s) with {s.get('attachments', 0)} attachment(s); {s.get('flagged_messages', 0)} message(s) carry phishing indicators"
    elif m == "browser":
        head = f"{ev['filename']} records {s.get('visits', 0)} visits to {s.get('unique_domains', 0)} domains and {s.get('downloads', 0)} download(s){span}"
    elif m == "network":
        head = f"{ev['filename']} contains {s.get('packets', 0)} packets in {s.get('flows', 0)} flows, {s.get('dns_queries', 0)} DNS names and {s.get('http_requests', 0)} HTTP requests{span}"
    elif m == "memory":
        head = f"{ev['filename']} yielded {s.get('iocs', 0)} indicators from {s.get('strings_scanned', 0)} carved strings and {s.get('suspicious_commands', 0)} suspicious command signature(s)"
    elif m == "disk":
        head = (f"{ev['filename']} provides {s.get('timeline_events', 0)} file-system timeline events{span}" if s.get("format")
                else f"{ev['filename']} yielded {s.get('iocs', 0)} indicators from carved strings")
    elif m == "deception":
        ips = ", ".join(s.get("attacker_ips", [])[:3]) or "unknown sources"
        head = f"{ev['filename']} logged {s.get('events', 0)} decoy events from {ips}, with {s.get('successful_logins', 0)} successful decoy login(s)"
    elif m == "media":
        t = s.get("type", "media")
        if t == "image":
            head = f"{ev['filename']} is an image with fused manipulation score {s.get('manipulation_score')} ({s.get('verdict')})"
        elif t == "audio":
            head = f"{ev['filename']} is audio of {s.get('duration_s', '?')} s with {s.get('splice_candidates', 0)} splice candidate(s) ({s.get('verdict', 'metadata only')})"
        else:
            head = f"{ev['filename']} is video; {s.get('duplicate_runs', 0)} duplicated-frame run(s) and {s.get('abrupt_changes', 0)} abrupt change(s) were found"
    else:
        head = f"{ev['filename']} produced {len(ev.get('artifacts', []))} artifacts"
    ind = _top_indicators(ev)
    tail = f" Key indicators: {'; '.join(ind)} {c}." if ind else ""
    return f"{head} {c}.{tail}"


def summarize_case(case: dict, evidence: list[dict], corr: dict, insights: dict | None = None) -> list[str]:
    byid = {e["id"]: e for e in evidence}
    out = []
    mods = sorted({e["module"] for e in evidence})
    ok = sum(1 for e in evidence if e.get("integrity_ok", True))
    out.append(f"The case holds {len(evidence)} evidence items from the {', '.join(mods)} modules; {ok} of {len(evidence)} "
               f"match their acquisition hash " + "".join(cite(e) for e in evidence) + ".")
    for inc in corr.get("incidents", [])[:3]:
        evs = [byid[i] for i in inc["evidence_ids"]]
        top = ", ".join(f"{k['type']} {k['value']}" for k in inc["key_entities"][:2])
        when = f" from {inc['first_seen'][:16].replace('T', ' ')} to {inc['last_seen'][:16].replace('T', ' ')}" if inc.get("first_seen") else ""
        out.append(f"Incident {inc['id']} joins {len(evs)} items across {', '.join(inc['modules'])} evidence{when}, "
                   f"anchored on {top} " + "".join(cite(e) for e in evs) + ".")
    if insights and insights.get("attack_chain"):
        chain = " → ".join(st["tactic"] for st in insights["attack_chain"])
        evs = sorted({i for st in insights["attack_chain"] for i in st["evidence_ids"]})
        out.append(f"The observed activity maps to the ATT&CK sequence {chain} " + "".join(cite(byid[i]) for i in evs) + ".")
    hits = corr.get("honeytoken_hits", [])
    if hits:
        evs = sorted({h["evidence_id"] for h in hits})
        out.append(f"Planted honeytokens appear in {len(evs)} item(s), confirming contact with decoy material "
                   + "".join(cite(byid[i]) for i in evs) + ".")
    return out
