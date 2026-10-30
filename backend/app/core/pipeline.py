"""Evidence routing: picks the analysis module for a file and runs it.

Every module returns {"module", "summary", "artifacts"}; the pipeline appends a file-identity
artifact (the item's own hashes) so identical bytes seen in different places link together.
"""
from __future__ import annotations

from pathlib import Path

from .. import media
from ..deception import honeypot
from ..forensics import browser_forensics, disk_forensics, email_forensics, memory_forensics, network_forensics
from .entities import artifact, ent
from .integrity import file_hashes

MODULES = {
    "email": email_forensics,
    "browser": browser_forensics,
    "network": network_forensics,
    "disk": disk_forensics,
    "memory": memory_forensics,
    "media": media,
    "deception": honeypot,
}

LAYER = {"email": "Forensic modules", "browser": "Forensic modules", "network": "Forensic modules",
         "disk": "Forensic modules", "memory": "Forensic modules", "media": "Media forensics",
         "deception": "Cyber deception"}


def detect_module(path: Path, original_name: str) -> str:
    name = original_name.lower()
    ext = Path(name).suffix
    with open(path, "rb") as fh:
        head = fh.read(4096)
    if head[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a") \
            or ext in (".pcap", ".pcapng", ".cap"):
        return "network"
    if ext in (".eml", ".mbox", ".msg") or (b"\nReceived:" in head or head.startswith(b"Received:")
                                            or (b"\nFrom:" in head and b"\nSubject:" in head) or head.startswith(b"Return-Path:")):
        return "email"
    if head.startswith(b"SQLite format 3") and ("history" in name or "places" in name or ext in (".sqlite", ".db", "")):
        return "browser"
    if "history" in name and ext in (".csv", ".json"):
        return "browser"
    if ext in media.IMAGE_EXT | media.VIDEO_EXT | media.AUDIO_EXT or head[:3] == b"\xff\xd8\xff" \
            or head[:8] == b"\x89PNG\r\n\x1a\n" or (head[:4] == b"RIFF" and head[8:12] == b"WAVE") or head[4:8] == b"ftyp":
        return "media"
    if b'"eventid": "cowrie.' in head or b'"eventid":"cowrie.' in head or "cowrie" in name \
            or b'"decoy_events"' in head or "decoy" in name:
        return "deception"
    if ext in (".mem", ".vmem", ".dmp", ".lime") or (ext == ".raw" and "mem" in name):
        return "memory"
    return "disk"


def file_identity(path: Path, original_name: str | None = None) -> dict:
    sha, md5 = file_hashes(path)
    name = original_name or path.name
    return artifact("evidence.file", f"Evidence file {name}", None,
                    [ent("sha256", sha), ent("md5", md5), ent("filename", name)],
                    detail={"sha256": sha, "md5": md5, "size": path.stat().st_size})


def run_module(module: str, path: Path, derived_dir: Path | None = None, original_name: str | None = None) -> dict:
    mod = MODULES[module]
    res = mod.analyse(path, derived_dir) if module == "media" else mod.analyse(path)
    if original_name and original_name != path.name:      # vault copies are named <sha256>_<name>
        vault = path.name
        for a in res["artifacts"]:
            a["title"] = a["title"].replace(vault, original_name)
            for e in a["entities"]:
                if e["type"] == "filename" and e["value"] == vault.lower():
                    e["value"] = original_name.lower()
    res["artifacts"].append(file_identity(path, original_name))
    return res
