"""Investigation insights.

Rule-based, explainable insights computed from module output and correlation results:
  * attack chain: artifacts mapped to MITRE ATT&CK tactics/techniques, ordered by tactic and time
  * pivots: the entities that carry the most cross-evidence link weight (what to hunt next)
  * deception: honeytoken hits and honeypot attacker IPs seen elsewhere
  * media: manipulated images, edited audio/video
  * review: high-severity evidence not linked to any incident, integrity or analysis failures
  * recommendations: next investigative steps derived from the above (marked as suggestions)
Every factual statement cites evidence and passes through reporting.verifier.
"""
from __future__ import annotations

import csv
import io
import re
from collections import defaultdict

from ..core import correlation
from ..core.entities import SEVERITY_RANK
from ..reporting.verifier import evidence_facts, verify_sentence
from .summarizer import cite

TACTIC_ORDER = ["Initial Access", "Execution", "Persistence", "Credential Access", "Discovery",
                "Defense Evasion", "Command and Control", "Exfiltration", "Impact"]

# (artifact-kind regex, indicator regex or None, tactic, technique id, technique name)
RULES = [
    (r"^email\.message$", r"SPF|DKIM|DMARC|Reply-To|Return-Path|spoof|Link text|raw IP", "Initial Access", "T1566", "Phishing"),
    (r"^email\.attachment$", r"Risky attachment", "Initial Access", "T1566.001", "Spearphishing Attachment"),
    (r"^browser\.visit$", r"Credential-themed|raw-IP|Suspicious TLD", "Initial Access", "T1566.002", "Spearphishing Link"),
    (r"^browser\.download$", r"risky file", "Execution", "T1204", "User Execution"),
    (r"^fs\.timeline$", r"Executable in user-writable", "Execution", "T1204.002", "Malicious File"),
    (r"^fs\.timeline$", r"Deleted file", "Defense Evasion", "T1070.004", "File Deletion"),
    (r"\.command$", r"PowerShell", "Execution", "T1059.001", "PowerShell"),
    (r"\.command$", r"Credential dumping", "Credential Access", "T1003", "OS Credential Dumping"),
    (r"\.command$", r"Scheduled task", "Persistence", "T1053.005", "Scheduled Task"),
    (r"\.command$", r"Run-key", "Persistence", "T1547.001", "Registry Run Keys"),
    (r"\.command$", r"Shadow copy", "Impact", "T1490", "Inhibit System Recovery"),
    (r"\.command$", r"payload download", "Command and Control", "T1105", "Ingress Tool Transfer"),
    (r"\.command$", r"Implant configuration", "Command and Control", "T1071", "Application Layer Protocol"),
    (r"^network\.flow$", r"Beaconing", "Command and Control", "T1071", "Application Layer Protocol"),
    (r"^network\.flow$", r"uncommon port", "Command and Control", "T1571", "Non-Standard Port"),
    (r"^network\.dns$", r"tunnelling", "Exfiltration", "T1071.004", "DNS"),
    (r"^network\.http$", r"Credentials posted", "Credential Access", "T1552", "Unsecured Credentials"),
    (r"^deception\.login\.success$", None, "Credential Access", "T1078", "Valid Accounts (decoy credential)"),
    (r"^deception\.command\.input$", None, "Discovery", "T1082", "System Information Discovery"),
    (r"^deception\.session\.file_download$", None, "Command and Control", "T1105", "Ingress Tool Transfer"),
    (r"^deception\.decoy_hit$", r"Honeytoken", "Credential Access", "T1078", "Valid Accounts (decoy credential)"),
]


def attack_chain(evidence: list[dict]) -> list[dict]:
    stages: dict[str, dict] = {}
    for ev in evidence:
        for a in ev.get("artifacts", []):
            text = " ".join(a.get("indicators", []))
            for kind_rx, ind_rx, tactic, tid, tname in RULES:
                if not re.search(kind_rx, a.get("kind", "")):
                    continue
                if ind_rx and not re.search(ind_rx, text, re.I):
                    continue
                st = stages.setdefault(tactic, {"tactic": tactic, "techniques": {}, "evidence_ids": set(),
                                                "first_seen": None, "first_artifact": None, "count": 0})
                st["techniques"][tid] = tname
                st["evidence_ids"].add(ev["id"])
                st["count"] += 1
                if a.get("ts") and (st["first_seen"] is None or a["ts"] < st["first_seen"]):
                    st["first_seen"], st["first_artifact"] = a["ts"], {"evidence_id": ev["id"], "title": a["title"]}
    out = []
    for t in TACTIC_ORDER:
        if t in stages:
            s = stages[t]
            out.append({**s, "techniques": [{"id": k, "name": v} for k, v in sorted(s["techniques"].items())],
                        "evidence_ids": sorted(s["evidence_ids"])})
    return out


def pivots(corr: dict, evidence: list[dict] | None = None, k: int = 8) -> list[dict]:
    homes = correlation.home_domains(evidence or [])
    agg: dict[tuple, dict] = {}
    for l in corr.get("links", []):
        for s in l["shared"]:
            if s["type"] == "honeytoken" or correlation._is_home((s["type"], s["value"]), homes):
                continue
            p = agg.setdefault((s["type"], s["value"]), {"type": s["type"], "value": s["value"], "weight": 0.0, "evidence_ids": set()})
            p["weight"] += s["weight"]
            p["evidence_ids"].update((l["source"], l["target"]))
    rows = sorted(agg.values(), key=lambda p: (-len(p["evidence_ids"]), -p["weight"]))[:k]
    return [{**p, "weight": round(p["weight"], 2), "evidence_ids": sorted(p["evidence_ids"])} for p in rows]


def ioc_csv(evidence: list[dict], corr: dict) -> str:
    """Indicators from incident evidence (allowlisted and own-organisation identifiers removed)."""
    homes = correlation.home_domains(evidence)
    dyn = correlation.benign_resolutions(evidence)
    inc_ids = {i for inc in corr.get("incidents", []) for i in inc["evidence_ids"]}
    rows: dict[tuple, dict] = {}
    for ev in evidence:
        if inc_ids and ev["id"] not in inc_ids:
            continue
        for a in ev.get("artifacts", []):
            if a.get("kind") == "evidence.file":
                continue
            for e in a.get("entities", []):
                key = (e["type"], e["value"])
                if e["type"] not in ("ip", "domain", "url", "sha256", "md5", "sha1", "email", "filename") or \
                        correlation._is_allowlisted(key) or key in dyn or correlation._is_home(key, homes):
                    continue
                r = rows.setdefault(key, {"type": e["type"], "value": e["value"], "evidence": set(), "first_seen": None})
                r["evidence"].add(ev["id"])
                if a.get("ts") and (r["first_seen"] is None or a["ts"] < r["first_seen"]):
                    r["first_seen"] = a["ts"]
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["type", "value", "evidence_ids", "evidence_count", "first_seen_utc"])
    for r in sorted(rows.values(), key=lambda r: (-len(r["evidence"]), r["type"], r["value"])):
        w.writerow([r["type"], r["value"], " ".join(f"E{i}" for i in sorted(r["evidence"])), len(r["evidence"]), r["first_seen"] or ""])
    return buf.getvalue()


def build_insights(evidence: list[dict], corr: dict) -> dict:
    byid = {e["id"]: e for e in evidence}
    items: list[dict] = []

    def add(kind, severity, title, text, ev_ids):
        items.append({"kind": kind, "severity": severity, "title": title, "text": text, "evidence_ids": sorted(set(ev_ids))})

    chain = attack_chain(evidence)
    for st in chain:
        tech = ", ".join(f"{t['id']} {t['name']}" for t in st["techniques"])
        when = ""
        if st["first_seen"]:
            fe = byid[st["first_artifact"]["evidence_id"]]
            when = f", first seen at {st['first_seen'][:16].replace('T', ' ')} in {fe['filename']}"
        add("attack_chain", "high" if st["tactic"] in ("Credential Access", "Command and Control", "Impact", "Exfiltration") else "medium",
            f"{st['tactic']}", f"{st['tactic']}: {tech} ({st['count']} artifact(s){when}) " +
            "".join(cite(byid[i]) for i in st["evidence_ids"]) + ".", st["evidence_ids"])

    pv = pivots(corr, evidence)
    for p in pv[:5]:
        names = ", ".join(byid[i]["filename"] for i in p["evidence_ids"][:4])
        add("pivot", "medium", f"Pivot: {p['type']} {p['value']}",
            f"The {p['type']} {p['value']} links {len(p['evidence_ids'])} evidence items ({names}) " +
            "".join(cite(byid[i]) for i in p["evidence_ids"]) + ".", p["evidence_ids"])

    for h in corr.get("honeytoken_hits", []):
        ev = byid[h["evidence_id"]]
        add("deception", "high", f"Honeytoken found: {h['label']}",
            f"Honeytoken '{h['label']}' ({h['token_type']}) appears in {ev['filename']}: {h['artifact_title']} {cite(ev)}.", [ev["id"]])
    honeypot_ips = {}
    for ev in evidence:
        if ev["module"] == "deception":
            for ip in ev.get("summary", {}).get("attacker_ips", []):
                honeypot_ips.setdefault(ip, ev["id"])
    for ip, hid in honeypot_ips.items():
        seen = [e["id"] for e in evidence if e["id"] != hid and e["module"] != "deception" and
                any(x["type"] == "ip" and x["value"] == ip for a in e.get("artifacts", []) for x in a.get("entities", []))]
        if seen:
            add("deception", "high", f"Honeypot attacker {ip} seen elsewhere",
                f"Honeypot source {ip} also appears in " + ", ".join(byid[i]["filename"] for i in seen) + " " +
                "".join(cite(byid[i]) for i in [hid] + seen) + ".", [hid] + seen)

    for ev in evidence:
        if ev["module"] != "media":
            continue
        for a in ev.get("artifacts", []):
            d = a.get("detail", {})
            if a.get("kind") == "media.image" and d.get("score") is not None and d["score"] >= d.get("threshold", 0.5):
                add("media", "high" if d["score"] >= 0.8 else "medium", f"Manipulated image: {ev['filename']}",
                    f"Image {ev['filename']} scores {d['score']:.2f} against a threshold of {d['threshold']:.2f} ({d['verdict']}) {cite(ev)}.", [ev["id"]])
            elif a.get("kind") in ("media.audio", "media.video") and SEVERITY_RANK.get(a.get("severity"), 0) >= 2:
                add("media", "medium", f"Edited {a['kind'].split('.')[1]}: {ev['filename']}",
                    f"{ev['filename']}: {'; '.join(a.get('indicators', [])[:2])} {cite(ev)}.", [ev["id"]])

    inc_ids = {i for inc in corr.get("incidents", []) for i in inc["evidence_ids"]}
    for ev in evidence:
        sev = ev.get("summary", {}).get("max_severity", "info")
        if SEVERITY_RANK.get(sev, 0) >= 3 and ev["id"] not in inc_ids:
            add("review", "medium", f"Unlinked high-severity evidence: {ev['filename']}",
                f"{ev['filename']} has high-severity findings but no link to other evidence and needs manual review {cite(ev)}.", [ev["id"]])
        if not ev.get("integrity_ok", True):
            add("review", "critical", f"Integrity failure: {ev['filename']}",
                f"{ev['filename']} no longer matches its acquisition SHA-256 {cite(ev)}.", [ev["id"]])
        if ev.get("status") == "error":
            add("review", "medium", f"Analysis error: {ev['filename']}", f"{ev['filename']} could not be analysed: {ev.get('error', '')[:120]} {cite(ev)}.", [ev["id"]])

    facts = {e["id"]: evidence_facts(e) for e in evidence}
    for it in items:
        v = verify_sentence(it["text"], facts)
        it["verification"] = v["status"]

    recs = []
    if pv:
        recs.append(f"Hunt the top pivot indicators ({', '.join(p['value'] for p in pv[:3])}) in logs from other hosts and the mail gateway; export them with the IOC button.")
    if corr.get("honeytoken_hits"):
        recs.append("Treat systems where decoy credentials appear as compromised; rotate any real credentials stored alongside the decoys and keep the decoys in place for further telemetry.")
    if any(st["tactic"] == "Command and Control" for st in chain):
        recs.append("Acquire full packet captures or firewall/proxy logs for the C2 destinations over the whole incident window, not only the captured interval.")
    if any(it["kind"] == "media" for it in items):
        recs.append("Request original copies of flagged media from their source to compare against the analysed versions.")
    if any(it["kind"] == "review" for it in items):
        recs.append("Review the unlinked or failed evidence items manually before closing the case.")
    if not any(e["module"] == "memory" for e in evidence) and chain:
        recs.append("No memory image is in the case; acquire volatile memory from affected hosts if they are still running.")

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    kinds = ["attack_chain", "deception", "pivot", "media", "review"]
    items.sort(key=lambda i: (kinds.index(i["kind"]), 0 if i["kind"] in ("attack_chain", "pivot") else order.get(i["severity"], 5)))
    return {"attack_chain": chain, "pivots": pv, "items": items, "recommendations": recs,
            "verification": {"statements": len(items), "verified": sum(1 for i in items if i["verification"] == "verified")}}
