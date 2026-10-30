"""Browser forensics: Chrome/Edge 'History' and Firefox 'places.sqlite' databases, plus CSV/JSON exports."""
from __future__ import annotations

import csv
import io
import json
import shutil
import sqlite3
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

from ..core.entities import RE_IPV4, artifact, ent, entities_from_url, max_severity

SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "tk", "ml", "ga", "cf", "gq", "pw", "click", "link", "su", "ru"}
RISKY_DL = {".exe", ".scr", ".js", ".vbs", ".bat", ".ps1", ".hta", ".msi", ".iso", ".docm", ".xlsm", ".jar", ".zip"}
LOGIN_WORDS = ("login", "signin", "sign-in", "verify", "account", "password", "secure", "update")

_CHROME_EPOCH = datetime(1601, 1, 1)


def _chrome_ts(v) -> str | None:
    try:
        v = int(v)
        if v <= 0:
            return None
        return (_CHROME_EPOCH + timedelta(microseconds=v)).isoformat(timespec="seconds")
    except Exception:
        return None


def _unix_us(v) -> str | None:
    try:
        v = int(v)
        if v <= 0:
            return None
        return (datetime(1970, 1, 1) + timedelta(microseconds=v)).isoformat(timespec="seconds")
    except Exception:
        return None


def _url_indicators(url: str, title: str = "") -> list[str]:
    ind = []
    ents = entities_from_url(url)
    host = ents[-1]["value"] if ents else ""
    if host and RE_IPV4.fullmatch(host):
        ind.append(f"Visited raw-IP URL {url}")
    elif host and host.split(".")[-1] in SUSPICIOUS_TLDS:
        ind.append(f"Suspicious TLD .{host.split('.')[-1]} ({host})")
    if host and any(w in url.lower() for w in LOGIN_WORDS) and host.count("-") >= 2:
        ind.append(f"Credential-themed URL on hyphenated look-alike host {host}")
    if "@" in url.split("//", 1)[-1].split("/", 1)[0]:
        ind.append("URL contains embedded credentials / @ obfuscation")
    return ind


def _visit_art(url, title, ts, browser, visit_count=None):
    ind = _url_indicators(url, title or "")
    return artifact("browser.visit", f"Visited {url[:120]}", ts, entities_from_url(url),
                    detail={"url": url, "title": title, "browser": browser, "visit_count": visit_count},
                    severity="medium" if ind else "info", indicators=ind)


def _download_art(path, url, ts, size, browser):
    fname = Path(str(path).replace("\\", "/")).name
    ind = []
    if Path(fname).suffix.lower() in RISKY_DL:
        ind.append(f"Downloaded risky file type {fname}")
    ind += _url_indicators(url or "")
    ents = entities_from_url(url or "") + [ent("filename", fname)]
    return artifact("browser.download", f"Downloaded {fname}", ts, ents,
                    detail={"target_path": path, "url": url, "bytes": size, "browser": browser},
                    severity="high" if ind else "info", indicators=ind)


def _from_sqlite(path: Path) -> list[dict]:
    tmp = Path(tempfile.mkdtemp()) / "h.db"
    shutil.copyfile(path, tmp)          # never open evidence in place (SQLite may write journals)
    con = sqlite3.connect(f"file:{tmp}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    arts: list[dict] = []
    if {"urls", "visits"} <= tables:
        for r in con.execute("SELECT u.url, u.title, v.visit_time, u.visit_count FROM visits v "
                             "JOIN urls u ON u.id = v.url ORDER BY v.visit_time"):
            arts.append(_visit_art(r["url"], r["title"], _chrome_ts(r["visit_time"]), "chromium", r["visit_count"]))
        if "downloads" in tables:
            cols = {c[1] for c in con.execute("PRAGMA table_info(downloads)")}
            url_col = "tab_url" if "tab_url" in cols else ("url" if "url" in cols else None)
            q = f"SELECT target_path, {url_col or 'NULL'} AS url, start_time, total_bytes FROM downloads"
            for r in con.execute(q):
                arts.append(_download_art(r["target_path"], r["url"], _chrome_ts(r["start_time"]),
                                          r["total_bytes"], "chromium"))
    elif {"moz_places", "moz_historyvisits"} <= tables:
        for r in con.execute("SELECT p.url, p.title, h.visit_date, p.visit_count FROM moz_historyvisits h "
                             "JOIN moz_places p ON p.id = h.place_id ORDER BY h.visit_date"):
            arts.append(_visit_art(r["url"], r["title"], _unix_us(r["visit_date"]), "firefox", r["visit_count"]))
    con.close()
    return arts


def _from_export(path: Path) -> list[dict]:
    text = path.read_text("utf-8", "replace")
    rows = json.loads(text) if path.suffix.lower() == ".json" else list(csv.DictReader(io.StringIO(text)))
    arts = []
    for r in rows:
        url = r.get("url") or r.get("URL")
        if not url:
            continue
        ts = r.get("visit_time") or r.get("timestamp") or r.get("time")
        arts.append(_visit_art(url, r.get("title", ""), ts, r.get("browser", "export")))
    return arts


def analyse(path: Path) -> dict:
    head = path.read_bytes()[:16]
    arts = _from_sqlite(path) if head.startswith(b"SQLite format 3") else _from_export(path)
    visits = [a for a in arts if a["kind"] == "browser.visit"]
    dls = [a for a in arts if a["kind"] == "browser.download"]
    domains = {e["value"] for a in visits for e in a["entities"] if e["type"] == "domain"}
    return {
        "module": "browser",
        "summary": {"visits": len(visits), "downloads": len(dls), "unique_domains": len(domains),
                    "flagged": sum(1 for a in arts if a["indicators"]),
                    "max_severity": max_severity([a["severity"] for a in arts])},
        "artifacts": arts,
    }
