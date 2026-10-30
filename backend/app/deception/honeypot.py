"""Honeypot and decoy-event ingestion.

Cowrie SSH/Telnet honeypot JSON logs and IDMF's own captured decoy events are turned into
ordinary evidence artifacts, so deception telemetry flows through the same correlation and
reporting pipeline as disk, e-mail or network evidence (the "forensic tactic" gap identified by
Beltrán-López et al., 2026).
"""
from __future__ import annotations

import json
from pathlib import Path

from ..core.entities import artifact, ent, entities_from_url, extract_entities, is_public_ip, max_severity


def _cowrie(lines: list[str]) -> list[dict]:
    arts = []
    sessions: dict[str, dict] = {}
    for ln in lines:
        try:
            ev = json.loads(ln)
        except json.JSONDecodeError:
            continue
        eid = ev.get("eventid", "")
        ip = ev.get("src_ip", "")
        ts = (ev.get("timestamp") or "").replace("Z", "")[:19] or None
        sess = ev.get("session", "")
        s = sessions.setdefault(sess, {"ip": ip, "commands": 0, "logins": 0})
        ents = [ent("ip", ip)] if ip else []
        ind, sev, title = [], "low", eid
        detail = {k: v for k, v in ev.items() if k not in ("message",)}
        if eid == "cowrie.session.connect":
            title = f"Honeypot connection from {ip}:{ev.get('src_port')}"
            sev = "medium"
            ind.append("Interaction with decoy service (no legitimate use)")
        elif eid.startswith("cowrie.login"):
            user, pw = ev.get("username", ""), ev.get("password", "")
            ok = eid.endswith("success")
            title = f"Honeypot login {'SUCCESS' if ok else 'failed'} {user}/{pw} from {ip}"
            ents += [ent("user", user)]
            detail["password"] = pw
            sev = "high" if ok else "medium"
            if ok:
                s["logins"] += 1
                ind.append("Attacker authenticated to decoy")
        elif eid == "cowrie.command.input":
            cmd = ev.get("input", "")
            title = f"Honeypot command: {cmd[:100]}"
            ents += extract_entities(cmd)
            s["commands"] += 1
            sev = "high" if any(w in cmd for w in ("wget", "curl", "chmod", "tftp", "base64")) else "medium"
            ind.append("Command executed in decoy shell")
        elif eid == "cowrie.session.file_download":
            url = ev.get("url", "")
            title = f"Honeypot captured download {url}"
            ents += entities_from_url(url) + [ent("sha256", ev.get("shasum", "")), ent("filename", url.rsplit('/', 1)[-1])]
            sev = "high"
            ind.append("Malware sample captured by honeypot")
        elif eid == "cowrie.client.version":
            title = f"SSH client {ev.get('version')} from {ip}"
            sev = "low"
        else:
            sev = "info"
        arts.append(artifact(f"deception.{eid.replace('cowrie.', '')}", title, ts, ents, detail=detail,
                             severity=sev, indicators=ind))
    return arts


def _decoy_events(rows: list[dict]) -> list[dict]:
    arts = []
    for ev in rows:
        ip = ev.get("src_ip", "")
        d = ev.get("detail", {})
        ents = [ent("ip", ip)] if is_public_ip(ip) or ip else []
        if d.get("username"):
            ents.append(ent("user", d["username"]))
        if d.get("token_value"):
            ents.append({"type": "honeytoken", "value": d["token_value"].lower()})
        title = f"Decoy {ev.get('decoy')} triggered from {ip}"
        arts.append(artifact("deception.decoy_hit", title, ev.get("ts"), ents, detail=ev, severity="high",
                             indicators=["Decoy interaction (no legitimate use)"] +
                             (["Honeytoken used"] if ev.get("honeytoken_id") else [])))
    return arts


def analyse(path: Path) -> dict:
    text = path.read_text("utf-8", "replace")
    stripped = text.lstrip()
    if stripped.startswith("[") or (stripped.startswith("{") and '"decoy_events"' in stripped[:200]):
        data = json.loads(text)
        rows = data["decoy_events"] if isinstance(data, dict) else data
        arts = _decoy_events(rows)
        fmt = "IDMF decoy events"
    else:
        arts = _cowrie(text.splitlines())
        fmt = "Cowrie JSON log"
    ips = {e["value"] for a in arts for e in a["entities"] if e["type"] == "ip"}
    return {"module": "deception",
            "summary": {"format": fmt, "events": len(arts), "attacker_ips": sorted(ips),
                        "successful_logins": sum(1 for a in arts if a["kind"] == "deception.login.success"),
                        "commands": sum(1 for a in arts if a["kind"] == "deception.command.input"),
                        "captured_downloads": sum(1 for a in arts if a["kind"] == "deception.session.file_download"),
                        "max_severity": max_severity([a["severity"] for a in arts])},
            "artifacts": arts}
