"""Entity extraction and normalisation shared by every forensic module.

All modules describe what they find as *artifacts*; each artifact carries a list of
normalised entities ({"type": ..., "value": ...}). The correlation engine works only on
these entities, which is what lets evidence from different domains be compared.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

ENTITY_TYPES = ("ip", "domain", "email", "url", "sha256", "md5", "sha1", "filename", "user", "process")

# Common and frequently abused TLDs. Restricting to a list avoids treating "report.pdf"
# or "kernel32.dll" as domains.
_TLDS = {
    "com", "net", "org", "edu", "gov", "mil", "int", "io", "co", "ai", "app", "dev", "info", "biz",
    "me", "tv", "cc", "ws", "xyz", "top", "site", "online", "club", "live", "shop", "store", "tech",
    "space", "website", "link", "click", "zip", "mov", "ru", "cn", "uk", "de", "fr", "in", "jp",
    "br", "au", "ca", "nl", "es", "it", "pl", "ir", "kp", "su", "tk", "ml", "ga", "cf", "gq", "pw",
    "ly", "to", "su", "us", "eu", "ch", "se", "no", "fi", "kr", "sg", "hk", "tw", "za", "mx", "ar",
    "onion", "local", "lan", "corp", "internal", "example", "test",
}

RE_IPV4 = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")
RE_EMAIL = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}(?![\w-])")
RE_URL = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>()\[\]{}|\\^`]{3,2048}", re.I)
RE_DOMAIN = re.compile(r"(?<![\w@.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+([A-Za-z]{2,24})(?![\w-])")
RE_SHA256 = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")
RE_SHA1 = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{40}(?![0-9a-fA-F])")
RE_MD5 = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{32}(?![0-9a-fA-F])")


def is_public_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_multicast or a.is_reserved
                    or a.is_link_local or a.is_unspecified)
    except ValueError:
        return False


def normalize(etype: str, value: str) -> str | None:
    if value is None:
        return None
    v = str(value).strip().strip(".,;:'\"<>()[]")
    if not v:
        return None
    if etype == "ip":
        try:
            return str(ipaddress.ip_address(v))
        except ValueError:
            return None
    if etype == "domain":
        v = v.lower().rstrip(".")
        if v.startswith("www."):
            v = v[4:]
        if "." not in v or v.split(".")[-1] not in _TLDS:
            return None
        return v
    if etype == "email":
        v = v.lower()
        return v if RE_EMAIL.fullmatch(v) else None
    if etype == "url":
        try:
            p = urlsplit(v)
        except ValueError:
            return None
        if not p.scheme or not p.netloc:
            return None
        host = (p.hostname or "").lower()
        if host.startswith("www."):
            host = host[4:]
        port = f":{p.port}" if p.port and p.port not in (80, 443) else ""
        path = p.path.rstrip("/") or ""
        q = f"?{p.query}" if p.query else ""
        return f"{p.scheme.lower()}://{host}{port}{path}{q}"
    if etype in ("sha256", "sha1", "md5"):
        return v.lower()
    if etype in ("user", "process"):
        return v.lower()
    if etype == "filename":
        return v.replace("\\", "/").split("/")[-1].lower()
    return v


def ent(etype: str, value: str) -> dict | None:
    n = normalize(etype, value)
    return {"type": etype, "value": n} if n else None


def url_host(url: str) -> str | None:
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


def entities_from_url(url: str) -> list[dict]:
    out = []
    u = ent("url", url)
    if u:
        out.append(u)
        host = url_host(u["value"]) or ""
        out.append(ent("ip", host) if RE_IPV4.fullmatch(host) else ent("domain", host))
    return [e for e in out if e]


def extract_entities(text: str, include_private_ips: bool = False, hashes: bool = True) -> list[dict]:
    """Regex-based IOC extraction from free text (bodies, strings, logs)."""
    if not text:
        return []
    found: list[dict] = []
    for m in RE_URL.finditer(text):
        found.extend(entities_from_url(m.group(0)))
    text_wo_urls = RE_URL.sub(" ", text)
    for m in RE_EMAIL.finditer(text_wo_urls):
        e = ent("email", m.group(0))
        if e:
            found.append(e)
            found.append(ent("domain", e["value"].split("@", 1)[1]))
    text_wo_emails = RE_EMAIL.sub(" ", text_wo_urls)
    for m in RE_IPV4.finditer(text_wo_emails):
        ip = m.group(0)
        if include_private_ips or is_public_ip(ip):
            found.append(ent("ip", ip))
    for m in RE_DOMAIN.finditer(text_wo_emails):
        if RE_IPV4.fullmatch(m.group(0)):
            continue
        found.append(ent("domain", m.group(0)))
    if hashes:
        for m in RE_SHA256.finditer(text):
            found.append(ent("sha256", m.group(0)))
        t2 = RE_SHA256.sub(" ", text)
        for m in RE_SHA1.finditer(t2):
            found.append(ent("sha1", m.group(0)))
        t3 = RE_SHA1.sub(" ", t2)
        for m in RE_MD5.finditer(t3):
            found.append(ent("md5", m.group(0)))
    return dedupe([e for e in found if e])


def dedupe(entities: list[dict]) -> list[dict]:
    seen, out = set(), []
    for e in entities:
        if not e:
            continue
        k = (e["type"], e["value"])
        if k not in seen:
            seen.add(k)
            out.append(e)
    return out


def artifact(kind: str, title: str, ts: str | None = None, entities: list | None = None,
             detail: dict | None = None, severity: str = "info", indicators: list | None = None) -> dict:
    """Uniform artifact record produced by every module."""
    return {
        "kind": kind,
        "title": title,
        "ts": ts,
        "entities": dedupe([e for e in (entities or []) if e]),
        "detail": detail or {},
        "severity": severity,
        "indicators": indicators or [],
    }


SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def max_severity(levels: list[str]) -> str:
    return max(levels or ["info"], key=lambda s: SEVERITY_RANK.get(s, 0))
