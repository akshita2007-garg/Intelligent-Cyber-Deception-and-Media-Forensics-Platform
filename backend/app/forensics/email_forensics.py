"""Email forensics: RFC 5322 (.eml) and mbox parsing, header path analysis, phishing indicators."""
from __future__ import annotations

import hashlib
import mailbox
import re
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from html.parser import HTMLParser
from pathlib import Path

from ..core.entities import artifact, ent, entities_from_url, extract_entities, is_public_ip, max_severity, RE_IPV4

RISKY_EXT = {".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".bat", ".cmd", ".ps1", ".hta", ".lnk",
             ".iso", ".img", ".docm", ".xlsm", ".pptm", ".jar", ".msi", ".dll", ".zip", ".rar", ".7z"}
URGENCY = re.compile(r"\b(urgent|immediately|suspend(ed)?|verify your|password (will )?expire|"
                     r"invoice overdue|wire transfer|gift card|action required|unusual sign-?in)\b", re.I)


class _LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self._href = None
        self._text = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None


def _iso(date_hdr: str | None) -> str | None:
    if not date_hdr:
        return None
    try:
        dt = parsedate_to_datetime(date_hdr)
        if dt.tzinfo:
            from datetime import timezone
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt.isoformat(timespec="seconds")
    except Exception:
        return None


def _domain(addr: str) -> str:
    return addr.split("@", 1)[1].lower() if "@" in addr else ""


def analyse_message(msg: EmailMessage, index: int = 0) -> list[dict]:
    arts: list[dict] = []
    indicators: list[str] = []
    entities: list[dict] = []

    from_list = getaddresses([str(msg.get("From", ""))])
    from_name, from_addr = (from_list[0] if from_list else ("", ""))
    from_addr = from_addr.lower()
    to_addrs = [a.lower() for _, a in getaddresses([str(msg.get("To", "")), str(msg.get("Cc", ""))]) if a]
    reply_to = [a.lower() for _, a in getaddresses([str(msg.get("Reply-To", ""))]) if a]
    return_path = re.sub(r"[<>]", "", str(msg.get("Return-Path", ""))).strip().lower()
    subject = str(msg.get("Subject", ""))
    ts = _iso(msg.get("Date"))

    for a in [from_addr, *reply_to, return_path]:
        e = ent("email", a)
        if e:
            entities += [e, ent("domain", _domain(e["value"]))]
    for a in to_addrs:                       # mailbox owner / recipients: tagged so correlation can dampen them
        e = ent("email", a)
        if e:
            entities += [{**e, "role": "recipient"}, {**ent("domain", _domain(e["value"])), "role": "recipient"}]

    # Received chain: oldest hop is last header
    hops = []
    for h in reversed(msg.get_all("Received", []) or []):
        h = str(h)
        ips = [ip for ip in RE_IPV4.findall(h)]
        m = re.search(r"from\s+([\w.-]+)", h)
        hops.append({"from_host": m.group(1) if m else "", "ips": ips})
        for ip in ips:
            if is_public_ip(ip):
                entities.append(ent("ip", ip))
    origin_ip = str(msg.get("X-Originating-IP", "")).strip("[] ")
    if origin_ip:
        entities.append(ent("ip", origin_ip))
    sender_ip = origin_ip or next((ip for hop in hops for ip in hop["ips"] if is_public_ip(ip)), "")

    auth = str(msg.get("Authentication-Results", "")).lower()
    auth_res = {k: (re.search(rf"{k}=(\w+)", auth).group(1) if re.search(rf"{k}=(\w+)", auth) else None)
                for k in ("spf", "dkim", "dmarc")}
    for k, v in auth_res.items():
        if v in ("fail", "softfail", "none", "permerror"):
            indicators.append(f"{k.upper()} result is '{v}'")

    if reply_to and _domain(reply_to[0]) != _domain(from_addr):
        indicators.append(f"Reply-To domain ({_domain(reply_to[0])}) differs from From domain ({_domain(from_addr)})")
    if return_path and _domain(return_path) and _domain(return_path) != _domain(from_addr):
        indicators.append(f"Return-Path domain ({_domain(return_path)}) differs from From domain")
    if from_name and "@" in from_name and from_name.lower().strip() != from_addr:
        indicators.append(f"Display name '{from_name}' contains a different address (spoofing)")
    if URGENCY.search(subject):
        indicators.append("Urgency/pressure language in subject")

    # Bodies, links, attachments
    urls, link_mismatch, attachments = [], [], []
    body_text = ""
    for part in msg.walk():
        if part.is_multipart():
            continue
        disp = part.get_content_disposition()
        ctype = part.get_content_type()
        if disp == "attachment" or (part.get_filename() and disp != "inline"):
            payload = part.get_payload(decode=True) or b""
            fname = part.get_filename() or "unnamed"
            sha = hashlib.sha256(payload).hexdigest()
            attachments.append({"filename": fname, "content_type": ctype, "size": len(payload),
                                "sha256": sha, "md5": hashlib.md5(payload).hexdigest()})
            entities += [ent("filename", fname), ent("sha256", sha)]
            if Path(fname).suffix.lower() in RISKY_EXT:
                indicators.append(f"Risky attachment type: {fname}")
            continue
        try:
            content = part.get_content()
        except Exception:
            content = (part.get_payload(decode=True) or b"").decode("utf-8", "replace")
        if not isinstance(content, str):
            continue
        body_text += "\n" + content
        if ctype == "text/html":
            lp = _LinkParser()
            lp.feed(content)
            for href, text in lp.links:
                urls.append(href)
                if text.startswith("http") and entities_from_url(text) and entities_from_url(href):
                    t_host = entities_from_url(text)[-1]["value"]
                    h_host = entities_from_url(href)[-1]["value"]
                    if t_host != h_host:
                        link_mismatch.append({"shown": text, "actual": href})
    if URGENCY.search(body_text):
        indicators.append("Urgency/pressure language in body")
    body_ents = extract_entities(body_text)
    entities += body_ents
    for u in urls:
        entities += entities_from_url(u)
    for mm in link_mismatch:
        indicators.append(f"Link text {mm['shown']} points to {mm['actual']}")
    if any(e and e["type"] == "url" and RE_IPV4.search(e["value"].split("/")[2]) for e in entities):
        indicators.append("Body links to a raw IP address")

    sev = "info"
    if indicators:
        sev = "medium" if len(indicators) < 3 else "high"

    arts.append(artifact(
        "email.message", f"Email: {subject or '(no subject)'}", ts, entities,
        detail={"index": index, "from": from_addr, "from_name": from_name, "to": to_addrs,
                "reply_to": reply_to, "return_path": return_path, "subject": subject,
                "message_id": str(msg.get("Message-ID", "")), "sender_ip": sender_ip,
                "received_hops": hops, "auth": auth_res, "attachments": attachments,
                "urls": sorted({e["value"] for e in entities if e and e["type"] == "url"}),
                "link_mismatch": link_mismatch, "body_preview": body_text.strip()[:600]},
        severity=sev, indicators=indicators))
    for a in attachments:
        arts.append(artifact("email.attachment", f"Attachment {a['filename']}", ts,
                             [ent("filename", a["filename"]), ent("sha256", a["sha256"]),
                              ent("md5", a["md5"]), ent("email", from_addr)],
                             detail=a,
                             severity="high" if Path(a["filename"]).suffix.lower() in RISKY_EXT else "info",
                             indicators=[f"Risky attachment type: {a['filename']}"]
                             if Path(a["filename"]).suffix.lower() in RISKY_EXT else []))
    return arts


def analyse(path: Path) -> dict:
    raw = path.read_bytes()
    artifacts: list[dict] = []
    if raw.startswith(b"From ") and b"\nFrom " in raw[5:] or path.suffix.lower() == ".mbox":
        for i, m in enumerate(mailbox.mbox(str(path), factory=lambda f: BytesParser(policy=policy.default).parse(f))):
            artifacts += analyse_message(m, i)
    else:
        msg = BytesParser(policy=policy.default).parsebytes(raw)
        artifacts += analyse_message(msg, 0)
    msgs = [a for a in artifacts if a["kind"] == "email.message"]
    return {
        "module": "email",
        "summary": {"messages": len(msgs),
                    "attachments": sum(len(a["detail"]["attachments"]) for a in msgs),
                    "flagged_messages": sum(1 for a in msgs if a["indicators"]),
                    "max_severity": max_severity([a["severity"] for a in artifacts])},
        "artifacts": artifacts,
    }
