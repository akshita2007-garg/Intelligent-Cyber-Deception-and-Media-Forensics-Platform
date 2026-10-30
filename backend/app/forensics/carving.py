"""Shared byte-level carving engine used by the disk and memory modules.

Streams a raw image in 4 MB chunks and extracts printable ASCII and UTF-16LE strings, IOCs
(IPs, domains, URLs, e-mails, hashes), process and file names, file signatures and
suspicious-command signatures. Pure Python, so it runs anywhere; see the README for
throughput figures.
"""
from __future__ import annotations

import re
from pathlib import Path

from ..core.entities import artifact, ent, extract_entities, max_severity

SIGNATURES = {
    b"MZ\x90\x00": "PE executable", b"%PDF-": "PDF document", b"PK\x03\x04": "ZIP/Office archive",
    b"\xff\xd8\xff": "JPEG image", b"\x89PNG\r\n\x1a\n": "PNG image", b"\x7fELF": "ELF executable",
    b"SQLite format 3\x00": "SQLite database", b"Rar!\x1a\x07": "RAR archive",
}
SUSPICIOUS_CMDS = [
    (re.compile(rb"powershell(\.exe)?\s+[^\n\x00]{0,40}-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{16,}", re.I), "Encoded PowerShell command"),
    (re.compile(rb"\bmimikatz\b|sekurlsa::", re.I), "Credential dumping tool (mimikatz)"),
    (re.compile(rb"\bnc(\.exe)?\s+-[a-z]*e\s", re.I), "Netcat reverse shell"),
    (re.compile(rb"(wget|curl)\s+(-[a-zA-Z]+\s+)*https?://[^\s\x00]+", re.I), "Remote payload download command"),
    (re.compile(rb"vssadmin(\.exe)?\s+delete\s+shadows", re.I), "Shadow copy deletion (ransomware)"),
    (re.compile(rb"schtasks(\.exe)?\s+/create", re.I), "Scheduled task persistence"),
    (re.compile(rb"reg(\.exe)?\s+add\s+[^\x00\n]{0,60}\\run", re.I), "Registry Run-key persistence"),
    (re.compile(rb"chmod\s+\+x\s+/tmp/", re.I), "Executable dropped in /tmp"),
    (re.compile(rb"SIMULATED-IMPLANT-CONFIG[^\x00]{0,200}"), "Implant configuration block (synthetic test marker)"),
]
RE_ASCII = re.compile(rb"[\x20-\x7e]{6,}")
RE_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")
RE_PROC = re.compile(rb"\b[\w-]{2,40}\.exe\b", re.I)
RE_FILE = re.compile(rb"[\w\-.]{2,80}\.(?:docm|docx|xlsm|xlsx|pdf|zip|rar|7z|ps1|vbs|js|hta|bat|dll|lnk|iso|txt)\b", re.I)
CHUNK = 4 * 1024 * 1024
MAX_STRINGS = 200_000



def scan(path: Path, kind: str) -> tuple[list[dict], dict]:
    """kind: 'disk' or 'memory' (prefix of the artifact kinds). Returns (artifacts, summary)."""
    strings_seen, iocs, cmds, sigs, procs = 0, {}, [], [], {}
    size = path.stat().st_size
    with open(path, "rb") as fh:
        offset, tail = 0, b""
        while True:
            block = fh.read(CHUNK)
            if not block:
                break
            buf = tail + block
            base = offset - len(tail)
            for sig, label in SIGNATURES.items():
                start = 0
                while len(sigs) < 500:
                    i = buf.find(sig, start)
                    if i < 0:
                        break
                    sigs.append({"offset": base + i, "type": label})
                    start = i + 1
            for rx in (RE_ASCII, RE_UTF16):
                for m in rx.finditer(buf):
                    if strings_seen >= MAX_STRINGS:
                        break
                    s = m.group(0).replace(b"\x00", b"") if rx is RE_UTF16 else m.group(0)
                    strings_seen += 1
                    txt = s.decode("latin-1")
                    for e in extract_entities(txt):
                        k = (e["type"], e["value"])
                        iocs.setdefault(k, base + m.start())
                    for pm in RE_PROC.finditer(s):
                        procs.setdefault(pm.group(0).decode().lower(), base + m.start())
                    for fm in RE_FILE.finditer(s):
                        nm = fm.group(0).decode("latin-1")
                        if len(nm) > 4:
                            iocs.setdefault(("filename", nm.lower()), base + m.start())
                    for rx2, label in SUSPICIOUS_CMDS:
                        mm = rx2.search(s)
                        if mm and len(cmds) < 200:
                            cmds.append({"offset": base + m.start(), "label": label,
                                         "text": mm.group(0).decode("latin-1")[:300]})
            tail = buf[-256:]
            offset += len(block)

    arts = []
    for (etype, val), off in sorted(iocs.items(), key=lambda kv: kv[1]):
        arts.append(artifact(f"{kind}.ioc",
                             f"{etype.upper()} {val} at offset {off}", None, [{"type": etype, "value": val}],
                             detail={"offset": off, "entity_type": etype}))
    for c in cmds:
        ents = extract_entities(c["text"])
        arts.append(artifact(f"{kind}.command", f"{c['label']} at offset {c['offset']}", None, ents,
                             detail=c, severity="high", indicators=[c["label"]]))
    for p, off in list(procs.items())[:300]:
        arts.append(artifact(f"{kind}.process_string", f"Process name {p}", None, [ent("process", p)],
                             detail={"offset": off}))
    sig_counts = {}
    for s in sigs:
        sig_counts[s["type"]] = sig_counts.get(s["type"], 0) + 1
    if sig_counts.get("PE executable"):
        arts.append(artifact("disk.carved", f"{sig_counts['PE executable']} embedded PE header(s)", None, [],
                             detail={"first_offsets": [s["offset"] for s in sigs if s["type"] == "PE executable"][:20]},
                             severity="low", indicators=["Embedded executable headers found"]))
    summary = {"bytes_scanned": size, "strings_scanned": strings_seen, "iocs": len(iocs),
               "suspicious_commands": len(cmds), "file_signatures": sig_counts}
    return arts, summary
