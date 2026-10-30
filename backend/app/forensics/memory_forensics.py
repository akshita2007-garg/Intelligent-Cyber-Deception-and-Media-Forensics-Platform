"""Memory forensics.

Byte-level carving of memory images (.mem, .vmem, .dmp, .raw, .lime) for IOCs, process names,
cached credentials/strings and suspicious-command signatures, plus an optional Volatility 3
process listing (``windows.pslist``) when the ``vol`` command is on PATH.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from ..core.entities import artifact, ent, max_severity
from .carving import scan


def _volatility(path: Path) -> list[dict]:
    vol = shutil.which("vol") or shutil.which("vol.py")
    if not vol:
        return []
    try:
        out = subprocess.run([vol, "-q", "-r", "csv", "-f", str(path), "windows.pslist"],
                             capture_output=True, text=True, timeout=600).stdout
    except Exception:
        return []
    arts = []
    lines = out.strip().splitlines()
    if len(lines) < 2:
        return []
    header = [h.strip() for h in lines[0].split(",")]
    for ln in lines[1:]:
        row = dict(zip(header, ln.split(",")))
        name = row.get("ImageFileName", "")
        arts.append(artifact("memory.process", f"Process {name} (PID {row.get('PID')})",
                             row.get("CreateTime") or None, [ent("process", name)], detail=row))
    return arts



def analyse(path: Path) -> dict:
    arts, summary = scan(path, "memory")
    arts += _volatility(path)
    summary["volatility"] = bool(shutil.which("vol") or shutil.which("vol.py"))
    summary["max_severity"] = max_severity([a["severity"] for a in arts])
    summary["flagged"] = sum(1 for a in arts if a["indicators"])
    return {"module": "memory", "summary": summary, "artifacts": arts}
