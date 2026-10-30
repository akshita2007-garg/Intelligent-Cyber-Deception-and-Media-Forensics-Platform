"""Deterministic, evidence-cited narrative for the unified investigation report."""
from __future__ import annotations

from ..core.entities import SEVERITY_RANK

def _cite(ev: dict) -> str:
    return f"[E{ev['id']}:{ev['sha256'][:8]}]"


def template_sections(case: dict, evidence: list[dict], corr: dict) -> list[dict]:
    byid = {e["id"]: e for e in evidence}
    secs = []
    mods = sorted({e["module"] for e in evidence})
    ok = sum(1 for e in evidence if e.get("integrity_ok", True))
    summary = [f"{len(evidence)} evidence items from the {', '.join(mods)} modules were analysed, and {ok} of "
               f"{len(evidence)} matched their acquisition SHA-256 hash on re-verification "
               + "".join(_cite(e) for e in evidence) + "."]
    for inc in corr.get("incidents", []):
        evs = [byid[i] for i in inc["evidence_ids"]]
        ents = ", ".join(f"{k['type']} {k['value']}" for k in inc["key_entities"][:3])
        summary.append(f"Correlated incident {inc['id']} links {len(evs)} items across "
                       f"{', '.join(inc['modules'])} evidence through {ents} " + "".join(_cite(e) for e in evs) + ".")
    if corr.get("honeytoken_hits"):
        hit_evs = {h["evidence_id"] for h in corr["honeytoken_hits"]}
        summary.append(f"Decoy honeytokens were found in {len(hit_evs)} evidence item(s), which indicates "
                       f"attacker contact with planted bait " + "".join(_cite(byid[i]) for i in sorted(hit_evs)) + ".")
    secs.append({"title": "Executive summary", "sentences": summary})

    findings = []
    for ev in evidence:
        arts = sorted(ev.get("artifacts", []), key=lambda a: -SEVERITY_RANK.get(a.get("severity", "info"), 0))
        flagged = [a for a in arts if a.get("indicators") and SEVERITY_RANK.get(a.get("severity"), 0) >= 2][:4]
        for a in flagged:
            when = f" at {a['ts'][:16].replace('T', ' ')}" if a.get("ts") else ""
            findings.append(f"{ev['module'].title()} evidence {ev['filename']}: {a['title']}{when} "
                            f"({'; '.join(a['indicators'][:2])}) {_cite(ev)}.")
    secs.append({"title": "Key findings by evidence item", "sentences": findings or
                 ["No medium- or high-severity indicators were produced by the forensic modules "
                  + "".join(_cite(e) for e in evidence) + "."]})

    links = []
    for l in corr.get("links", [])[:15]:
        a, b = byid[l["source"]], byid[l["target"]]
        top = "; ".join(f"{s['type']} {s['value']}" for s in l["shared"][:3])
        gap = f", with related activity {l['min_gap_min']:.0f} minutes apart" if l.get("min_gap_min") is not None else ""
        trip = " This link is a honeytoken tripwire." if l.get("tripwire") else ""
        links.append(f"{a['filename']} and {b['filename']} are linked with score {l['score']:.2f} through {top}{gap} "
                     f"{_cite(a)}{_cite(b)}.{trip}")
    secs.append({"title": "Cross-domain correlation", "sentences": links or
                 ["No cross-evidence links exceeded the correlation threshold " + "".join(_cite(e) for e in evidence) + "."]})

    dec = []
    for h in corr.get("honeytoken_hits", []):
        ev = byid[h["evidence_id"]]
        dec.append(f"Honeytoken '{h['label']}' ({h['token_type']}, matched on {h['matched']}) appears in "
                   f"{ev['filename']}: {h['artifact_title']} {_cite(ev)}.")
    for ev in evidence:
        if ev["module"] == "deception":
            s = ev.get("summary", {})
            ips = ", ".join(s.get("attacker_ips", [])[:5])
            dec.append(f"Deception log {ev['filename']} recorded {s.get('events', 0)} events from {ips or 'unknown sources'}, "
                       f"including {s.get('successful_logins', 0)} successful decoy logins and "
                       f"{s.get('captured_downloads', 0)} captured downloads {_cite(ev)}.")
    if dec:
        secs.append({"title": "Deception findings", "sentences": dec})

    media = []
    for ev in evidence:
        if ev["module"] == "media":
            for a in ev.get("artifacts", []):
                d = a.get("detail", {})
                if "score" in d:
                    media.append(f"Image {ev['filename']} has a fused manipulation score of {d['score']:.2f} "
                                 f"(threshold {d['threshold']:.2f}) and is assessed as {d['verdict']} {_cite(ev)}.")
    if media:
        secs.append({"title": "Media forensics", "sentences": media})

    tl = [r for r in corr.get("timeline", []) if SEVERITY_RANK.get(r["severity"], 0) >= 2 or r.get("pivot")]
    if tl:
        f, l = tl[0], tl[-1]
        secs.append({"title": "Timeline", "sentences": [
            f"The earliest correlated or suspicious event is at {f['ts'][:16].replace('T', ' ')}: {f['title']} {_cite(byid[f['evidence_id']])}.",
            f"The latest is at {l['ts'][:16].replace('T', ' ')}: {l['title']} {_cite(byid[l['evidence_id']])}."]})
    secs.append({"title": "Limitations", "sentences": [
        "Findings are produced by automated modules and correlation heuristics and require investigator review before "
        "use in proceedings " + "".join(_cite(e) for e in evidence) + "."]})
    return secs
