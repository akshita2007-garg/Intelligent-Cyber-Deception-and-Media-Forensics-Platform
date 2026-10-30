"""Disk forensics.

* Sleuth Kit / Autopsy body files (``fls -m`` / mactime format) -> file-system timeline with
  deleted-file and user-writable-executable indicators.
* Raw disk images (.dd, .img, .raw, .E01 exported as raw) -> byte-level carving (carving.py).
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from ..core.entities import artifact, ent, max_severity
from .carving import scan


def is_bodyfile(path: Path) -> bool:
    head = path.read_bytes()[:4096]
    return b"|" in head and head.count(b"|") >= 10 and path.suffix.lower() in (".body", ".txt", ".bodyfile")


def _bodyfile(path: Path) -> dict:
    arts = []
    for line in path.read_text("utf-8", "replace").splitlines():
        parts = line.split("|")
        if len(parts) < 11:
            continue
        md5, name, _inode, mode, uid, _gid, size, atime, mtime, ctime, crtime = parts[:11]
        for label, t in (("modified", mtime), ("accessed", atime), ("changed", ctime), ("created", crtime)):
            try:
                ti = int(t)
            except ValueError:
                continue
            if ti <= 0:
                continue
            ts = datetime.fromtimestamp(ti, tz=timezone.utc).replace(tzinfo=None).isoformat(timespec="seconds")
            fname = name.split(" (deleted)")[0]
            ind = []
            if "(deleted)" in name:
                ind.append("Deleted file")
            if re.search(r"\.(exe|ps1|bat|vbs|hta|scr|dll)$", fname, re.I) and re.search(r"temp|appdata|downloads|/tmp", fname, re.I):
                ind.append("Executable in user-writable location")
            ents = [ent("filename", fname)]
            if md5 and md5 != "0" and len(md5) == 32:
                ents.append(ent("md5", md5))
            arts.append(artifact("fs.timeline", f"File {label}: {fname}", ts, ents,
                                 detail={"path": fname, "event": label, "size": size, "mode": mode, "uid": uid},
                                 severity="medium" if ind else "info", indicators=ind))
    return {"module": "disk",
            "summary": {"format": "TSK body file", "timeline_events": len(arts),
                        "flagged": sum(1 for a in arts if a["indicators"]),
                        "max_severity": max_severity([a["severity"] for a in arts])},
            "artifacts": arts}



def analyse(path: Path) -> dict:
    if is_bodyfile(path):
        return _bodyfile(path)
    arts, summary = scan(path, "disk")
    summary["max_severity"] = max_severity([a["severity"] for a in arts])
    summary["flagged"] = sum(1 for a in arts if a["indicators"])
    return {"module": "disk", "summary": summary, "artifacts": arts}
