"""Cross-domain evidence correlation engine.

Pipeline
1. Entity index: every normalised entity from every artifact of every evidence item.
2. Weighting: w(x) = type_weight(x) * log((N + 1) / df(x)), where df is the number of evidence
   items containing x (an IDF weight). Entities on a known-benign allowlist are ignored.
3. Temporal factor: a shared entity counts (1 + beta) times when its occurrences in the two
   items fall within a time window of each other.
4. Pairwise link score S(A, B) = sum over shared entities of w(x) * temporal(x). A link is
   declared when S >= theta. Honeytoken hits always link (tripwire rule).
5. Incidents are connected components of the link graph; the unified timeline merges all
   time-stamped artifacts.
"""
from __future__ import annotations

import math
import mmap
from collections import defaultdict
from datetime import datetime
from itertools import combinations
from pathlib import Path

from .. import config

TYPE_WEIGHT = {"sha256": 3.0, "sha1": 3.0, "md5": 3.0, "url": 2.5, "email": 2.0, "ip": 2.0,
               "honeytoken": 5.0, "user": 1.5, "domain": 1.5, "filename": 1.0, "process": 0.5}
IGNORED_TYPES = {"device", "software"}
# Known-benign infrastructure, analogous to NSRL hash allowlisting.
ALLOWLIST = {
    ("ip", "8.8.8.8"), ("ip", "8.8.4.4"), ("ip", "1.1.1.1"), ("ip", "1.0.0.1"), ("ip", "9.9.9.9"),
    ("domain", "google.com"), ("domain", "gstatic.com"), ("domain", "googleapis.com"),
    ("domain", "microsoft.com"), ("domain", "windowsupdate.com"), ("domain", "msftconnecttest.com"),
    ("domain", "apple.com"), ("domain", "icloud.com"), ("domain", "cloudflare.com"), ("domain", "akamaiedge.net"),
    ("domain", "w3.org"), ("domain", "schemas.microsoft.com"), ("domain", "office.com"), ("domain", "live.com"),
    ("process", "svchost.exe"), ("process", "explorer.exe"), ("process", "lsass.exe"), ("process", "csrss.exe"),
    ("process", "winlogon.exe"), ("process", "services.exe"), ("process", "smss.exe"),
}
# Popularity prior: widely visited sites carry little linking value (in production, load a
# full top-sites list such as Tranco; this is a short built-in excerpt).
POPULAR_DOMAINS = {
    "wikipedia.org", "github.com", "stackoverflow.com", "youtube.com", "facebook.com", "twitter.com", "x.com",
    "instagram.com", "linkedin.com", "reddit.com", "amazon.com", "amazon.in", "netflix.com", "bing.com", "yahoo.com",
    "bbc.co.uk", "bbc.com", "cnn.com", "nytimes.com", "theguardian.com", "medium.com", "python.org", "mozilla.org",
    "whatsapp.com", "zoom.us", "dropbox.com", "adobe.com", "paypal.com", "ebay.com", "imdb.com", "quora.com",
    "pinterest.com", "tiktok.com", "twitch.tv", "spotify.com", "slack.com", "salesforce.com", "oracle.com",
    "ibm.com", "intel.com", "nvidia.com", "samsung.com", "outlook.com", "hotmail.com", "gmail.com", "yandex.ru",
    "baidu.com", "naver.com", "flipkart.com", "zomato.com", "irctc.co.in", "sbi.co.in", "gov.in", "nic.in",
}
GENERIC_USERS = {"root", "admin", "administrator", "user", "test", "guest", "ubuntu", "pi", "oracle", "support",
                 "ubnt", "ftp", "postgres", "mysql", "default", "nobody", "operator"}
BETA = 0.5
HOME_WEIGHT = 0.2        # identifiers of the case's own organisation / mailbox owner


def _is_allowlisted(key: tuple) -> bool:
    t, v = key
    if key in ALLOWLIST:
        return True
    if t == "user" and v in GENERIC_USERS:
        return True
    if t == "domain" and any(v == d or v.endswith("." + d) for d in POPULAR_DOMAINS):
        return True
    if t == "url":
        host = v.split("/")[2] if v.count("/") >= 2 else ""
        host = host.split(":")[0]
        if host and any(host == d or host.endswith("." + d) for d in POPULAR_DOMAINS) and "?" not in v and v.count("/") <= 3:
            return True
    return False


def home_domains(evidence: list[dict]) -> set[str]:
    """Domains of recipient mailboxes = the investigated organisation's own namespace."""
    out = set()
    for ev in evidence:
        for a in ev.get("artifacts", []):
            for e in a.get("entities", []):
                if e.get("role") == "recipient" and e["type"] == "email":
                    out.add(e["value"].split("@", 1)[1])
    return out


def _is_home(key: tuple, homes: set[str]) -> bool:
    t, v = key
    if not homes:
        return False
    if t == "email":
        d = v.split("@", 1)[1]
    elif t == "domain":
        d = v
    elif t == "url":
        d = (v.split("/")[2] if v.count("/") >= 2 else "").split(":")[0]
    else:
        return False
    return any(d == h or d.endswith("." + h) for h in homes)


def _epoch_min(ts: str | None) -> float | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "")[:19]).timestamp() / 60.0
    except ValueError:
        return None


def benign_resolutions(evidence: list[dict]) -> set[tuple]:
    """IPs that DNS answers or TLS SNI in the evidence tie to allowlisted domains inherit the allowlist."""
    out = set()
    for ev in evidence:
        for a in ev.get("artifacts", []):
            d = a.get("detail", {})
            if a.get("kind") == "network.dns" and d.get("answer"):
                q = (d.get("query") or "").lower()
                if q.startswith("www."):
                    q = q[4:]
                if _is_allowlisted(("domain", q)):
                    out.add(("ip", d["answer"]))
            elif a.get("kind") == "network.tls" and d.get("sni"):
                s = d["sni"].lower()
                if _is_allowlisted(("domain", s[4:] if s.startswith("www.") else s)):
                    out.add(("ip", d.get("dst")))
    return out


def build_index(evidence: list[dict], use_allowlist: bool = True) -> dict:
    idx: dict[tuple, dict[int, list]] = defaultdict(lambda: defaultdict(list))
    dyn = benign_resolutions(evidence) if use_allowlist else set()
    for ev in evidence:
        for ai, a in enumerate(ev.get("artifacts", [])):
            t = _epoch_min(a.get("ts"))
            for e in a.get("entities", []):
                if e["type"] in IGNORED_TYPES:
                    continue
                key = (e["type"], e["value"])
                if use_allowlist and (_is_allowlisted(key) or key in dyn):
                    continue
                idx[key][ev["id"]].append((ai, t))
    return idx


def honeytoken_sweep(evidence: list[dict], honeytokens: list[dict], raw_paths: dict[int, str] | None = None) -> list[dict]:
    """Finds every place a honeytoken value (or its secret) appears: in artifact entities/details
    and, if raw_paths is given, anywhere in the raw evidence bytes (ASCII or UTF-16LE)."""
    hits = []
    needles = []
    for ht in honeytokens:
        for field in ("value", "secret"):
            v = (ht.get(field) or "").strip()
            if len(v) >= 6:
                needles.append((ht, field, v))
    for ev in evidence:
        found_in_ev = set()
        for ai, a in enumerate(ev.get("artifacts", [])):
            blob = (a.get("title", "") + " " + str(a.get("detail", "")) + " " +
                    " ".join(e["value"] for e in a.get("entities", []))).lower()
            for ht, field, v in needles:
                if v.lower() in blob and (ht["id"], ev["id"]) not in found_in_ev:
                    found_in_ev.add((ht["id"], ev["id"]))
                    hits.append({"honeytoken_id": ht["id"], "label": ht.get("label"), "token_type": ht.get("token_type"),
                                 "group": ht.get("group") or ht.get("placed_at") or None, "matched": field, "evidence_id": ev["id"], "artifact_index": ai,
                                 "artifact_title": a.get("title"), "ts": a.get("ts")})
        p = (raw_paths or {}).get(ev["id"])
        if p and Path(p).exists() and Path(p).stat().st_size > 0:
            with open(p, "rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                for ht, field, v in needles:
                    if (ht["id"], ev["id"]) in found_in_ev:
                        continue
                    for enc in (v.encode(), v.encode("utf-16-le")):
                        off = mm.find(enc)
                        if off >= 0:
                            found_in_ev.add((ht["id"], ev["id"]))
                            hits.append({"honeytoken_id": ht["id"], "label": ht.get("label"),
                                         "token_type": ht.get("token_type"), "group": ht.get("group") or ht.get("placed_at") or None,
                                         "matched": field,
                                         "evidence_id": ev["id"], "artifact_index": None,
                                         "artifact_title": f"Raw bytes at offset {off}", "ts": None})
                            break
    return hits


def score_pairs(evidence: list[dict], honey_hits: list[dict] | None = None,
                window_min: float | None = None, use_idf: bool = True, use_time: bool = True,
                use_allowlist: bool = True, use_home: bool = True, use_types: bool = True) -> dict[tuple, dict]:
    window = config.CORR_TIME_WINDOW_MIN if window_min is None else window_min
    idx = build_index(evidence, use_allowlist)
    homes = home_domains(evidence) if use_home else set()
    n = max(1, len(evidence))
    pairs: dict[tuple, dict] = {}
    for key, occ in idx.items():
        if len(occ) < 2:
            continue
        df = len(occ)
        w = (TYPE_WEIGHT.get(key[0], 1.0) if use_types else 1.0) * (math.log((n + 1) / df) if use_idf else 1.0)
        if _is_home(key, homes):
            w *= HOME_WEIGHT
        for a, b in combinations(sorted(occ), 2):
            tf = 1.0
            gap = None
            if use_time:
                ta = [t for _, t in occ[a] if t is not None]
                tb = [t for _, t in occ[b] if t is not None]
                if ta and tb:
                    gap = min(abs(x - y) for x in ta for y in tb)
                    if gap <= window:
                        tf = 1.0 + BETA
            p = pairs.setdefault((a, b), {"score": 0.0, "shared": [], "min_gap_min": None})
            p["score"] += w * tf
            p["shared"].append({"type": key[0], "value": key[1], "weight": round(w * tf, 3), "df": df,
                                "gap_min": round(gap, 1) if gap is not None else None})
            if gap is not None:
                p["min_gap_min"] = gap if p["min_gap_min"] is None else min(p["min_gap_min"], gap)
    # Tripwire rule: evidence sharing a honeytoken is linked regardless of score
    by_token = defaultdict(set)
    for h in honey_hits or []:
        by_token[h.get("group") or h["honeytoken_id"]].add(h["evidence_id"])
    for tok, evs in by_token.items():
        for a, b in combinations(sorted(evs), 2):
            p = pairs.setdefault((a, b), {"score": 0.0, "shared": [], "min_gap_min": None})
            p["score"] += TYPE_WEIGHT["honeytoken"]
            p["shared"].append({"type": "honeytoken", "value": f"decoy set {tok}" if isinstance(tok, str) else f"honeytoken #{tok}", "weight": 5.0, "df": len(evs)})
            p["tripwire"] = True
    return pairs


def components(nodes: list[int], edges: list[tuple[int, int]]) -> list[list[int]]:
    parent = {x: x for x in nodes}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for a, b in edges:
        parent[find(a)] = find(b)
    groups = defaultdict(list)
    for x in nodes:
        groups[find(x)].append(x)
    return [sorted(g) for g in groups.values()]


def correlate(evidence: list[dict], honeytokens: list[dict] | None = None, raw_paths: dict[int, str] | None = None,
              threshold: float | None = None, window_min: float | None = None) -> dict:
    theta = config.CORR_LINK_THRESHOLD if threshold is None else threshold
    hits = honeytoken_sweep(evidence, honeytokens or [], raw_paths)
    pairs = score_pairs(evidence, hits, window_min)
    meta = {e["id"]: e for e in evidence}
    links = []
    for (a, b), p in sorted(pairs.items(), key=lambda kv: -kv[1]["score"]):
        if p["score"] >= theta or p.get("tripwire"):
            links.append({"source": a, "target": b, "score": round(p["score"], 3),
                          "tripwire": bool(p.get("tripwire")),
                          "min_gap_min": round(p["min_gap_min"], 1) if p["min_gap_min"] is not None else None,
                          "shared": sorted(p["shared"], key=lambda s: -s["weight"])[:12],
                          "explanation": _explain(meta.get(a, {}), meta.get(b, {}), p)})
    ids = [e["id"] for e in evidence]
    comps = [c for c in components(ids, [(l["source"], l["target"]) for l in links]) if len(c) > 1]
    incidents = []
    for i, c in enumerate(sorted(comps, key=len, reverse=True), 1):
        ents = defaultdict(float)
        for l in links:
            if l["source"] in c:
                for s in l["shared"]:
                    ents[(s["type"], s["value"])] += s["weight"]
        top = sorted(ents.items(), key=lambda kv: -kv[1])[:8]
        times = [a.get("ts") for eid in c for a in meta[eid].get("artifacts", []) if a.get("ts")]
        incidents.append({"id": i, "evidence_ids": c, "modules": sorted({meta[e].get("module", "") for e in c}),
                          "key_entities": [{"type": k[0], "value": k[1], "weight": round(v, 2)} for k, v in top],
                          "first_seen": min(times) if times else None, "last_seen": max(times) if times else None})
    # Graph: evidence nodes + the entities that carry above-threshold links
    idx = build_index(evidence)
    nodes = [{"id": f"E{e['id']}", "label": e.get("filename", str(e["id"])), "kind": "evidence",
              "module": e.get("module")} for e in evidence]
    edges = []
    seen_nodes, seen_edges = set(), set()
    for l in links:                     # only entities (and evidence) that participate in an accepted link
        for s in l["shared"]:
            if s["type"] == "honeytoken":
                continue
            nid = f"{s['type']}:{s['value']}"
            if nid not in seen_nodes:
                seen_nodes.add(nid)
                nodes.append({"id": nid, "label": s["value"], "kind": s["type"]})
            for eid in (l["source"], l["target"]):
                if (eid, nid) not in seen_edges:
                    seen_edges.add((eid, nid))
                    edges.append({"source": f"E{eid}", "target": nid})
    for h in hits:
        nid = f"honeytoken:{h['honeytoken_id']}"
        if not any(nd["id"] == nid for nd in nodes):
            nodes.append({"id": nid, "label": h.get("label") or nid, "kind": "honeytoken"})
        edges.append({"source": f"E{h['evidence_id']}", "target": nid})
    timeline = timeline_of(evidence, links)
    return {"params": {"threshold": theta, "window_min": config.CORR_TIME_WINDOW_MIN if window_min is None else window_min,
                       "beta": BETA, "type_weights": TYPE_WEIGHT},
            "links": links, "incidents": incidents, "honeytoken_hits": hits,
            "graph": {"nodes": nodes, "edges": edges}, "timeline": timeline,
            "stats": {"evidence": len(evidence), "entities": len(idx),
                      "pivot_entities": sum(1 for o in idx.values() if len(o) >= 2),
                      "links": len(links), "incidents": len(incidents), "honeytoken_hits": len(hits)}}


def _explain(a: dict, b: dict, p: dict) -> str:
    top = sorted(p["shared"], key=lambda s: -s["weight"])[:3]
    parts = ", ".join(f"{s['type']} {s['value']}" for s in top)
    gap = p.get("min_gap_min")
    tw = f"; closest activity {gap:.0f} min apart" if gap is not None else ""
    trip = " Honeytoken tripwire." if p.get("tripwire") else ""
    return f"{a.get('filename', a.get('id'))} and {b.get('filename', b.get('id'))} share {parts}{tw}.{trip}"


def timeline_of(evidence: list[dict], links: list[dict] | None = None) -> list[dict]:
    pivots = defaultdict(set)
    for l in links or []:
        for s in l["shared"]:
            pivots[l["source"]].add(s["value"])
            pivots[l["target"]].add(s["value"])
    rows = []
    for ev in evidence:
        for ai, a in enumerate(ev.get("artifacts", [])):
            if not a.get("ts"):
                continue
            is_pivot = any(e["value"] in pivots.get(ev["id"], ()) for e in a.get("entities", []))
            rows.append({"ts": a["ts"], "evidence_id": ev["id"], "module": ev.get("module"),
                         "artifact_index": ai, "kind": a["kind"], "title": a["title"],
                         "severity": a.get("severity", "info"), "pivot": is_pivot})
    rows.sort(key=lambda r: r["ts"])
    return rows
