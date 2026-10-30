"""Synthetic, labelled investigation scenarios.

Each scenario is one case: a simulated multi-stage intrusion (phishing e-mail -> payload
download -> C2-like traffic -> memory artefacts -> honeypot interaction using a stolen
honeytoken credential -> file-system traces -> doctored image) plus unrelated background
evidence that shares common identifiers (the victim's mailbox, the company domain, public
DNS, internet-scanner honeypot noise). All "malicious" content is inert: payloads are random
bytes, memory artefacts are labelled placeholder markers, and honeypot sessions contain only
harmless commands. Ground truth records which evidence items belong to the incident and which
entities were planted in each file, so extraction and correlation can be scored.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import random
import socket
import sqlite3
import struct
from datetime import datetime, timedelta
from email.message import EmailMessage
from email.utils import format_datetime
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw, ImageFilter

WORDS = ["cloud", "secure", "update", "portal", "data", "sync", "files", "mail", "cdn", "auth", "verify",
         "account", "service", "office", "share", "drive", "login", "safe", "net", "hub", "bit", "zone"]
EVIL_TLDS = ["xyz", "top", "click", "ru", "info", "site", "online", "pw"]
ORGS = ["acmecorp", "northwind", "globex", "initech", "umbrella", "contoso", "vandelay", "wayneent"]
FIRST = ["alice", "rahul", "priya", "john", "meera", "arjun", "sara", "vikram", "neha", "david"]
BENIGN_SITES = ["wikipedia.org", "github.com", "stackoverflow.com", "bbc.co.uk", "nytimes.com",
                "linkedin.com", "python.org", "reddit.com", "medium.com", "amazon.in"]
HARMLESS_CMDS = ["uname -a", "whoami", "cat /etc/hostname", "ls -la", "id", "pwd", "w", "uptime", "free -m"]


def _pub_ip(rng: random.Random) -> str:
    a = rng.choice([23, 31, 45, 62, 77, 91, 103, 141, 149, 176, 185, 193, 194, 203, 212])
    return f"{a}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _domain(rng, tlds=EVIL_TLDS):
    return f"{rng.choice(WORDS)}-{rng.choice(WORDS)}{rng.randint(1, 99)}.{rng.choice(tlds)}"


# --------------------------------------------------------------------------- PCAP writer
def _csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def _ipv4(src, dst, proto, payload, ident=0):
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident & 0xFFFF, 0, 64, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    hdr = hdr[:10] + struct.pack("!H", _csum(hdr)) + hdr[12:]
    return hdr + payload


def _eth(ip_pkt):
    return b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + b"\x08\x00" + ip_pkt


def _udp(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def _tcp(sport, dport, payload, flags=0x18, seq=1):
    return struct.pack("!HHIIBBHHH", sport, dport, seq, 1, 5 << 4, flags, 65535, 0, 0) + payload


def _dns_name(n):
    return b"".join(bytes([len(p)]) + p.encode() for p in n.split(".")) + b"\x00"


def _dns_query(tid, name):
    return struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0) + _dns_name(name) + struct.pack("!HH", 1, 1)


def _dns_resp(tid, name, ip):
    q = _dns_name(name) + struct.pack("!HH", 1, 1)
    a = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + socket.inet_aton(ip)
    return struct.pack("!HHHHHH", tid, 0x8180, 1, 1, 0, 0) + q + a


def _client_hello(sni):
    name = sni.encode()
    sni_ext = struct.pack("!HHHBH", 0, len(name) + 5, len(name) + 3, 0, len(name)) + name
    body = b"\x03\x03" + bytes(32) + b"\x00" + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00" + \
        struct.pack("!H", len(sni_ext)) + sni_ext
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


class Pcap:
    def __init__(self, rng: random.Random):
        self.pkts: list[tuple[float, bytes]] = []
        self.ident = 1
        self.rng = rng

    def add(self, ts: datetime, src, dst, proto, seg):
        self.ident += 1
        self.pkts.append((ts.timestamp(), _eth(_ipv4(src, dst, proto, seg, self.ident))))

    def dns(self, ts, client, server, name, answer=None):
        tid = self.rng.randint(1, 65000)
        sp = 53000 + tid % 1000
        self.add(ts, client, server, 17, _udp(sp, 53, _dns_query(tid, name)))
        if answer:
            self.add(ts + timedelta(milliseconds=20), server, client, 17, _udp(53, sp, _dns_resp(tid, name, answer)))

    def http_get(self, ts, client, server, host, uri, ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"):
        req = f"GET {uri} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\nAccept: */*\r\n\r\n".encode()
        sp = 49152 + self.rng.randint(0, 9000)
        self.add(ts, client, server, 6, _tcp(sp, 80, req))
        self.add(ts + timedelta(milliseconds=80), server, client, 6, _tcp(80, sp, b"HTTP/1.1 200 OK\r\n\r\n" + bytes(200)))

    def tcp_session(self, ts, client, server, dport, nbytes=120):
        sp = 49152 + self.rng.randint(0, 15000)
        self.add(ts, client, server, 6, _tcp(sp, dport, b"", flags=0x02))
        self.add(ts + timedelta(milliseconds=30), client, server, 6, _tcp(sp, dport, bytes(nbytes)))

    def tls(self, ts, client, server, sni):
        self.add(ts, client, server, 6, _tcp(49152 + self.rng.randint(0, 15000), 443, _client_hello(sni)))

    def write(self, path: Path):
        out = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, p in sorted(self.pkts, key=lambda x: x[0]):
            out += struct.pack("<IIII", int(ts), int(round((ts % 1) * 1e6)) % 1000000, len(p), len(p)) + p
        path.write_bytes(bytes(out))


# --------------------------------------------------------------------------- browser history
def _chrome_time(dt: datetime) -> int:
    return int((dt - datetime(1601, 1, 1)).total_seconds() * 1e6)


def write_chrome_history(path: Path, visits, downloads):
    if path.exists():
        path.unlink()
    con = sqlite3.connect(path)
    con.executescript("""
      CREATE TABLE urls(id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR, visit_count INTEGER DEFAULT 0,
                        typed_count INTEGER DEFAULT 0, last_visit_time INTEGER, hidden INTEGER DEFAULT 0);
      CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, from_visit INTEGER,
                          transition INTEGER DEFAULT 0, segment_id INTEGER, visit_duration INTEGER DEFAULT 0);
      CREATE TABLE downloads(id INTEGER PRIMARY KEY, guid VARCHAR, current_path LONGVARCHAR, target_path LONGVARCHAR,
                             start_time INTEGER, received_bytes INTEGER, total_bytes INTEGER, state INTEGER,
                             tab_url VARCHAR, mime_type VARCHAR);""")
    ids = {}
    for dt, url, title in sorted(visits):
        if url not in ids:
            cur = con.execute("INSERT INTO urls(url,title,visit_count,last_visit_time) VALUES(?,?,0,?)", (url, title, _chrome_time(dt)))
            ids[url] = cur.lastrowid
        con.execute("UPDATE urls SET visit_count=visit_count+1, last_visit_time=? WHERE id=?", (_chrome_time(dt), ids[url]))
        con.execute("INSERT INTO visits(url,visit_time,from_visit) VALUES(?,?,0)", (ids[url], _chrome_time(dt)))
    for dt, target, url, size in downloads:
        con.execute("INSERT INTO downloads(guid,current_path,target_path,start_time,received_bytes,total_bytes,state,tab_url,mime_type)"
                    " VALUES(?,?,?,?,?,?,1,?,?)", (hashlib.md5(target.encode()).hexdigest(), target, target, _chrome_time(dt),
                                                  size, size, url, "application/octet-stream"))
    con.commit()
    con.close()


# --------------------------------------------------------------------------- images
def synth_photo(rng: np.random.Generator, w=512, h=384, sigma=None) -> np.ndarray:
    yy, xx = np.mgrid[0:h, 0:w] / max(w, h)
    c0, c1 = rng.uniform(30, 220, 3), rng.uniform(30, 220, 3)
    ang = rng.uniform(0, np.pi)
    t = np.cos(ang) * xx + np.sin(ang) * yy
    t = (t - t.min()) / (np.ptp(t) + 1e-9)
    img = (1 - t)[..., None] * c0 + t[..., None] * c1
    small = rng.uniform(-40, 40, (6, 8, 3)).astype(np.float32)
    low = np.asarray(Image.fromarray(np.uint8(np.clip(small + 128, 0, 255))).resize((w, h), Image.BICUBIC), dtype=float) - 128
    pil = Image.fromarray(np.uint8(np.clip(img + low, 0, 255)))
    d = ImageDraw.Draw(pil)
    for _ in range(int(rng.integers(4, 10))):
        x0, y0 = int(rng.integers(0, w)), int(rng.integers(0, h))
        x1, y1 = x0 + int(rng.integers(20, 180)), y0 + int(rng.integers(20, 140))
        col = tuple(int(v) for v in rng.uniform(0, 255, 3))
        (d.ellipse if rng.random() < 0.5 else d.rectangle)([x0, y0, x1, y1], fill=col)
    pil = pil.filter(ImageFilter.GaussianBlur(float(rng.uniform(0.8, 2.0))))
    tex = rng.normal(0, 1, (h // 4, w // 4))
    tex = np.asarray(Image.fromarray(np.uint8(np.clip(tex * 20 + 128, 0, 255))).resize((w, h), Image.BILINEAR), dtype=float) - 128
    arr = np.asarray(pil, dtype=float) + tex[..., None] * 0.3
    s = float(rng.uniform(1.5, 4.0)) if sigma is None else sigma
    arr = arr + rng.normal(0, s, arr.shape)
    return np.uint8(np.clip(arr, 0, 255))


def _jpeg(arr: np.ndarray, q: int, exif: dict | None = None) -> bytes:
    buf = io.BytesIO()
    ex = Image.Exif()
    for k, v in (exif or {}).items():
        ex[k] = v
    Image.fromarray(arr).save(buf, "JPEG", quality=int(q), exif=ex.tobytes() if exif else b"")
    return buf.getvalue()


def _decode(b: bytes) -> np.ndarray:
    return np.asarray(Image.open(io.BytesIO(b)).convert("RGB"))


CAMERAS = [("Canon", "Canon EOS 200D"), ("NIKON CORPORATION", "NIKON D5600"), ("Apple", "iPhone 13"),
           ("samsung", "SM-G991B"), ("Google", "Pixel 7")]
EDIT_SW = ["Adobe Photoshop 25.0 (Windows)", "GIMP 2.10.34", "Adobe Photoshop Lightroom Classic 13.0"]


def make_image(rng: np.random.Generator, label: str, kind: str | None = None, w=512, h=384) -> tuple[bytes, dict]:
    """label: 'authentic' | 'tampered'. Returns (jpeg bytes, info)."""
    make, model = CAMERAS[int(rng.integers(len(CAMERAS)))]
    dt = datetime(2026, int(rng.integers(1, 10)), int(rng.integers(1, 28)), int(rng.integers(7, 21)),
                  int(rng.integers(0, 59)), int(rng.integers(0, 59)))
    dts = dt.strftime("%Y:%m:%d %H:%M:%S")
    exif = {0x010F: make, 0x0110: model, 0x0132: dts}
    q1 = int(rng.integers(85, 96))
    base = synth_photo(rng, w, h)
    info = {"label": label, "camera": model, "q1": q1}
    if label == "authentic":
        if rng.random() < 0.3:                      # benign re-save (social-media style)
            base = _decode(_jpeg(base, int(rng.integers(75, 90))))
            info["resaved"] = True
        if rng.random() < 0.1:
            exif[0x0131] = "Ver.1.02"              # camera firmware tag, not an editor
        return _jpeg(base, q1, exif), info
    kind = kind or str(rng.choice(["splice", "splice", "resampled_splice", "copy_move"]))
    info["kind"] = kind
    ph, pw = int(rng.integers(70, 170)), int(rng.integers(70, 200))
    y0, x0 = int(rng.integers(0, h - ph)), int(rng.integers(0, w - pw))
    out = base.copy()
    sy, sx = int(rng.integers(0, h - ph)), int(rng.integers(0, w - pw))
    if kind in ("splice", "resampled_splice"):
        donor = _decode(_jpeg(synth_photo(rng, w, h, sigma=float(rng.uniform(0.3, 6.0))), int(rng.integers(55, 80))))
        if kind == "resampled_splice":
            patch = np.asarray(Image.fromarray(donor[sy:sy + int(ph / 1.4) + 1, sx:sx + int(pw / 1.4) + 1]).resize((pw, ph), Image.BICUBIC))
        else:
            patch = donor[sy:sy + ph, sx:sx + pw]
        out[y0:y0 + ph, x0:x0 + pw] = patch
    else:  # copy-move within the same image, slightly blurred
        patch = Image.fromarray(base[sy:sy + ph, sx:sx + pw]).filter(ImageFilter.GaussianBlur(0.6))
        out[y0:y0 + ph, x0:x0 + pw] = np.asarray(patch)
    info["region"] = [x0, y0, pw, ph]
    if rng.random() < 0.35:
        exif[0x0131] = EDIT_SW[int(rng.integers(len(EDIT_SW)))]
        exif[0x0132] = (dt + timedelta(days=int(rng.integers(1, 40)))).strftime("%Y:%m:%d %H:%M:%S")
        info["metadata_edited"] = True
    return _jpeg(out, q1, exif), info


# --------------------------------------------------------------------------- scenario helpers
def _eml(path: Path, rng, frm, to, subject, date, html, text, reply_to=None, received_ips=(), auth=None, attachments=()):
    m = EmailMessage()
    for ip in received_ips:
        m["Received"] = f"from mx{rng.randint(1, 9)}.relay.net ([{ip}]) by mail.server with ESMTPS; {format_datetime(date)}"
    if auth:
        m["Authentication-Results"] = auth
    m["From"] = frm
    m["To"] = to
    if reply_to:
        m["Reply-To"] = reply_to
    m["Subject"] = subject
    m["Date"] = format_datetime(date)
    m["Message-ID"] = f"<{hashlib.md5((subject + str(date)).encode()).hexdigest()}@mail.server>"
    m.set_content(text)
    m.add_alternative(html, subtype="html")
    for fname, data, mt in attachments:
        maintype, subtype = mt.split("/")
        m.add_attachment(data, maintype=maintype, subtype=subtype, filename=fname)
    path.write_bytes(m.as_bytes())


def _rand_bytes(rng: random.Random, n: int) -> bytearray:
    return bytearray(rng.getrandbits(8 * n).to_bytes(n, "little"))


def _embed(buf: bytearray, rng: random.Random, s: str, utf16: bool = False):
    data = s.encode("utf-16-le") if utf16 else s.encode()
    off = rng.randint(0, len(buf) - len(data) - 1)
    buf[off - 1 if off else 0] = 0
    buf[off:off + len(data)] = data
    buf[off + len(data)] = 0


def _cowrie_line(ts: datetime, eventid: str, ip: str, session: str, **kw) -> str:
    return json.dumps({"eventid": eventid, "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.000000Z"),
                       "src_ip": ip, "session": session, "sensor": "decoy-ssh-01", **kw})


# --------------------------------------------------------------------------- scenario
def generate_scenario(out_dir: Path, seed: int) -> dict:
    """Writes one labelled case into out_dir and returns its manifest."""
    rng = random.Random(seed)
    nrng = np.random.default_rng(seed)
    out_dir.mkdir(parents=True, exist_ok=True)

    org = rng.choice(ORGS)
    org_dom = f"{org}.com"
    victim = f"{rng.choice(FIRST)}.{rng.choice('ksmrp')}@{org_dom}"
    colleague = f"{rng.choice(FIRST)}.{rng.choice('abv')}@{org_dom}"
    victim_ws = f"10.{rng.randint(0, 50)}.{rng.randint(0, 255)}.{rng.randint(10, 250)}"
    coll_ws = f"10.60.{rng.randint(0, 255)}.{rng.randint(10, 250)}"
    dns_server = rng.choice(["8.8.8.8", "1.1.1.1"])
    att_ip = _pub_ip(rng)
    honey_ip = att_ip if rng.random() < 0.5 else _pub_ip(rng)   # attacker may switch infrastructure
    c2_dom, c2_ip = _domain(rng), _pub_ip(rng)
    phish_dom = f"{org}-{rng.choice(['secure', 'login', 'verify', 'sso'])}-{rng.choice(['portal', 'account', 'access'])}.{rng.choice(EVIL_TLDS)}"
    phish_url = f"https://{phish_dom}/{rng.choice(['signin', 'auth', 'verify'])}?id={rng.randint(10000, 99999)}"
    payload_name = rng.choice(["invoice", "remittance", "po", "salary_revision", "payslip"]) + f"_{rng.randint(100, 999)}.docm"
    payload = bytes(_rand_bytes(rng, rng.randint(3000, 9000)))          # inert random bytes
    payload_sha, payload_md5 = hashlib.sha256(payload).hexdigest(), hashlib.md5(payload).hexdigest()
    payload_url = f"http://{c2_dom}/dl/{payload_name}"
    implant = rng.choice(["updater", "svchelper", "msedgeupd", "onedrive_sync"]) + ".exe"
    ht_user = f"svc_{rng.choice(['backup', 'deploy', 'sql', 'payroll'])}{rng.randint(10, 99)}"
    ht_pass = "".join(rng.choice("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789") for _ in range(14))
    decoy_doc = f"Passwords_backup_{rng.randint(100, 999)}.txt"
    honeytokens = [{"id": 1, "token_type": "credential", "label": f"Decoy account {ht_user}", "value": ht_user, "secret": ht_pass,
                    "group": "decoy-set-1"},
                   {"id": 2, "token_type": "document", "label": f"Decoy document {decoy_doc}", "value": decoy_doc.lower(), "secret": "",
                    "group": "decoy-set-1"}]

    t0 = datetime(2026, rng.randint(1, 9), rng.randint(1, 27), rng.randint(8, 11), rng.randint(0, 59), 0)
    late = rng.random() < 0.35            # later stages a day or more later (no temporal boost)
    lag = timedelta(days=rng.randint(1, 3)) if late else timedelta(0)
    files, planted_all = [], {}

    def add(name, module, related, planted):
        files.append({"name": name, "module": module, "related": related})
        planted_all[name] = sorted({f"{t}|{v}" for t, v in planted})

    # 1. phishing e-mail, sometimes with a doctored receipt image
    img_bytes, img_info = make_image(nrng, "tampered")
    receipt = f"receipt_{rng.randint(1000, 9999)}.jpg"
    with_image = rng.random() < 0.6
    atts = [(payload_name, payload, "application/vnd.ms-word.document.macroEnabled.12")]
    if with_image:
        atts.append((receipt, img_bytes, "image/jpeg"))
    html = (f"<p>Dear colleague,</p><p>Your mailbox password expires today. Verify immediately at "
            f"<a href=\"{phish_url}\">https://portal.{org_dom}/account</a>.</p><p>The pending invoice is attached.</p>")
    _eml(out_dir / "01_phishing.eml", rng, f"\"IT Service Desk\" <helpdesk@{org_dom}>", victim,
         "Action required: password will expire", t0, html, f"Your mailbox password expires today. Verify at {phish_url}",
         reply_to=f"it-support@{phish_dom}", received_ips=[att_ip],
         auth=f"mx.{org_dom}; spf=fail smtp.mailfrom={phish_dom}; dkim=none; dmarc=fail", attachments=atts)
    planted = [("email", victim), ("email", f"helpdesk@{org_dom}"), ("email", f"it-support@{phish_dom}"), ("ip", att_ip),
               ("url", phish_url), ("domain", phish_dom), ("domain", org_dom), ("url", f"https://portal.{org_dom}/account"),
               ("domain", f"portal.{org_dom}"), ("sha256", payload_sha), ("filename", payload_name)]
    if with_image:
        planted += [("sha256", hashlib.sha256(img_bytes).hexdigest()), ("filename", receipt)]
    add("01_phishing.eml", "email", True, planted)

    # 2. victim browser history
    tb = t0 + timedelta(minutes=rng.randint(4, 25))
    benign = rng.sample(BENIGN_SITES, 5)
    visits = [(tb - timedelta(minutes=rng.randint(60, 300)), f"https://{s}/", s) for s in benign]
    visits += [(tb - timedelta(minutes=50), "https://www.google.com/search?q=quarterly+report", "Google"),
               (tb - timedelta(minutes=40), f"https://intranet.{org_dom}/home", "Intranet"),
               (tb, phish_url, "Sign in"), (tb + timedelta(minutes=2), payload_url, payload_name)]
    write_chrome_history(out_dir / "02_victim_History", visits,
                         [(tb + timedelta(minutes=2), f"C:\\Users\\{victim.split('.')[0]}\\Downloads\\{payload_name}", payload_url, len(payload))])
    add("02_victim_History", "browser", True,
        [("url", phish_url), ("domain", phish_dom), ("url", payload_url), ("domain", c2_dom), ("filename", payload_name),
         ("domain", f"intranet.{org_dom}"), ("url", f"https://intranet.{org_dom}/home"), ("domain", "google.com"),
         ("url", "https://google.com/search?q=quarterly+report")] +
        [("domain", s) for s in benign] + [("url", f"https://{s}") for s in benign])

    # 3. victim network capture
    pc = Pcap(rng)
    tn = tb + timedelta(minutes=2)
    pc.dns(tn - timedelta(minutes=5), victim_ws, dns_server, "www.google.com", "142.250.183.4")
    pc.tls(tn - timedelta(minutes=5), victim_ws, "142.250.183.4", "www.google.com")
    pc.dns(tn - timedelta(minutes=3), victim_ws, dns_server, f"intranet.{org_dom}", "10.0.0.15")
    pc.dns(tn, victim_ws, dns_server, c2_dom, c2_ip)
    pc.http_get(tn + timedelta(seconds=2), victim_ws, c2_ip, c2_dom, f"/dl/{payload_name}")
    period = rng.choice([30, 60, 120])
    for i in range(rng.randint(8, 20)):
        pc.tcp_session(tn + timedelta(minutes=3, seconds=i * period + rng.uniform(-1.5, 1.5)), victim_ws, c2_ip, 8443)
    planted = [("domain", c2_dom), ("ip", c2_ip), ("url", payload_url), ("domain", "google.com"), ("ip", "142.250.183.4"),
               ("domain", f"intranet.{org_dom}"), ("ip", dns_server)]
    tunnel = rng.random() < 0.5
    if tunnel:
        for i in range(rng.randint(5, 12)):
            lab = base64.b32encode(bytes(_rand_bytes(rng, 30))).decode().strip("=").lower()
            pc.dns(tn + timedelta(minutes=10, seconds=i * 7), victim_ws, dns_server, f"{lab}.t.{c2_dom}")
            planted.append(("domain", f"{lab}.t.{c2_dom}"))
    pc.write(out_dir / "03_victim_capture.pcap")
    add("03_victim_capture.pcap", "network", True, planted)

    # 4. memory image of the victim workstation (random bytes + inert labelled markers)
    mem = _rand_bytes(rng, rng.randint(600_000, 1_200_000))
    mem_ioc = [("domain", c2_dom), ("process", implant), ("filename", payload_name)]
    _embed(mem, rng, f"SIMULATED-IMPLANT-CONFIG host={c2_dom} port=8443 interval={period}")
    _embed(mem, rng, f"C:\\Users\\Public\\{implant}", utf16=True)
    _embed(mem, rng, f"Downloads\\{payload_name}", utf16=True)
    if rng.random() < 0.6:
        _embed(mem, rng, f"connect {c2_ip}:8443")
        mem_ioc.append(("ip", c2_ip))
    if rng.random() < 0.5:                       # stolen decoy credential cached in memory
        _embed(mem, rng, f"user={ht_user} pass={ht_pass}")
    _embed(mem, rng, "explorer.exe")
    _embed(mem, rng, "svchost.exe")
    _embed(mem, rng, f"https://intranet.{org_dom}/home", utf16=True)
    mem_ioc += [("url", f"https://intranet.{org_dom}/home"), ("domain", f"intranet.{org_dom}"),
                ("process", "explorer.exe"), ("process", "svchost.exe")]
    (out_dir / "04_victim_memory.mem").write_bytes(bytes(mem))
    add("04_victim_memory.mem", "memory", True, mem_ioc)

    # 5. honeypot (Cowrie) log: attacker reuses the stolen decoy credential
    th = t0 + lag + timedelta(minutes=rng.randint(60, 180))
    sess = hashlib.md5(f"{seed}h".encode()).hexdigest()[:12]
    lines = [_cowrie_line(th, "cowrie.session.connect", honey_ip, sess, src_port=rng.randint(30000, 60000), dst_port=22),
             _cowrie_line(th + timedelta(seconds=3), "cowrie.login.failed", honey_ip, sess, username="root", password="admin"),
             _cowrie_line(th + timedelta(seconds=9), "cowrie.login.success", honey_ip, sess, username=ht_user, password=ht_pass)]
    for i, cmd in enumerate(rng.sample(HARMLESS_CMDS, 3)):
        lines.append(_cowrie_line(th + timedelta(seconds=20 + i * 6), "cowrie.command.input", honey_ip, sess, input=cmd))
    hp_planted = [("ip", honey_ip), ("user", "root"), ("user", ht_user)]
    honey_download = rng.random() < 0.5
    if honey_download:
        lines.append(_cowrie_line(th + timedelta(seconds=60), "cowrie.session.file_download", honey_ip, sess,
                                  url=payload_url, shasum=payload_sha, outfile=f"var/lib/cowrie/downloads/{payload_sha}"))
        hp_planted += [("url", payload_url), ("domain", c2_dom), ("sha256", payload_sha), ("filename", payload_name)]
    (out_dir / "05_honeypot_cowrie.json").write_text("\n".join(lines) + "\n")
    add("05_honeypot_cowrie.json", "deception", True, hp_planted)

    # 6. file-system timeline (TSK body file) from the victim disk
    user = victim.split(".")[0]
    td = int((tb + timedelta(minutes=2)).timestamp())
    body = [f"{payload_md5}|C:/Users/{user}/Downloads/{payload_name}|1201|r/rrwxrwxrwx|0|0|{len(payload)}|{td}|{td}|{td}|{td}",
            f"0|C:/Users/Public/{implant}|1202|r/rrwxrwxrwx|0|0|48211|{td + 300}|{td + 300}|{td + 300}|{td + 300}",
            f"0|C:/Users/{user}/Documents/Q3_report.xlsx|1100|r/rrwxrwxrwx|0|0|88211|{td - 86400}|{td - 86400}|{td - 86400}|{td - 90000}",
            f"0|C:/Windows/System32/drivers/etc/hosts|300|r/rrwxrwxrwx|0|0|824|{td - 999999}|{td - 999999}|{td - 999999}|{td - 999999}"]
    disk_planted = [("filename", payload_name), ("md5", payload_md5), ("filename", implant), ("filename", "q3_report.xlsx"), ("filename", "hosts")]
    decoy_accessed = rng.random() < 0.6
    if decoy_accessed:
        ta = td + rng.randint(600, 3000)
        body.append(f"0|C:/Users/Public/Documents/{decoy_doc}|1303|r/rrwxrwxrwx|0|0|212|{ta}|{td - 864000}|{td - 864000}|{td - 864000}")
        disk_planted.append(("filename", decoy_doc))
    (out_dir / "06_victim_disk.body").write_text("\n".join(body) + "\n")
    add("06_victim_disk.body", "disk", True, disk_planted)

    # 7. doctored image seized separately (same bytes as the attachment when attached)
    (out_dir / f"07_{receipt}").write_bytes(img_bytes)
    add(f"07_{receipt}", "media", with_image, [("filename", f"07_{receipt}")])

    # ---------------- unrelated background evidence ----------------
    news_dom = rng.choice(["techweekly.com", "dailybrief.net", "marketpulse.io"])
    _eml(out_dir / "08_newsletter.eml", rng, f"Newsletter <news@{news_dom}>", victim, "Your weekly digest",
         t0 - timedelta(days=rng.randint(1, 5)),
         f"<p>Top stories this week. <a href=\"https://{news_dom}/issue\">Read online</a> "
         f"or search on <a href=\"https://www.google.com/\">Google</a>.</p>", "Top stories this week.",
         received_ips=[_pub_ip(rng)], auth=f"mx.{org_dom}; spf=pass; dkim=pass; dmarc=pass")
    add("08_newsletter.eml", "email", False, [("email", victim), ("email", f"news@{news_dom}"), ("domain", news_dom), ("domain", org_dom),
                                              ("url", f"https://{news_dom}/issue"), ("domain", "google.com"), ("url", "https://google.com")])

    _eml(out_dir / "09_internal_memo.eml", rng, f"\"{colleague.split('@')[0]}\" <{colleague}>", victim,
         "Team offsite agenda", t0 + timedelta(minutes=rng.randint(-90, 90)),
         f"<p>Agenda attached on the <a href=\"https://intranet.{org_dom}/offsite\">intranet</a>.</p>", "Agenda on the intranet.",
         received_ips=[], auth=f"mx.{org_dom}; spf=pass; dkim=pass; dmarc=pass")
    add("09_internal_memo.eml", "email", False, [("email", victim), ("email", colleague), ("domain", org_dom),
                                                 ("url", f"https://intranet.{org_dom}/offsite"), ("domain", f"intranet.{org_dom}")])

    scan_ip = _pub_ip(rng)
    ts_ = t0 + lag + timedelta(minutes=rng.randint(-120, 240))
    s2 = hashlib.md5(f"{seed}s".encode()).hexdigest()[:12]
    sl = [_cowrie_line(ts_, "cowrie.session.connect", scan_ip, s2, src_port=rng.randint(30000, 60000), dst_port=22)]
    for j, (u, p) in enumerate([("root", "admin"), ("root", "123456"), ("admin", "admin"), ("ubnt", "ubnt")]):
        sl.append(_cowrie_line(ts_ + timedelta(seconds=2 + j), "cowrie.login.failed", scan_ip, s2, username=u, password=p))
    (out_dir / "10_scanner_cowrie.json").write_text("\n".join(sl) + "\n")
    add("10_scanner_cowrie.json", "deception", False, [("ip", scan_ip), ("user", "root"), ("user", "admin"), ("user", "ubnt")])

    hol = f"10_holiday_{rng.randint(100, 999)}.jpg".replace("10_", "11_")
    hb, _ = make_image(nrng, "authentic")
    (out_dir / hol).write_bytes(hb)
    add(hol, "media", False, [("filename", hol)])

    cb = rng.sample(BENIGN_SITES, 4)
    tc = t0 + timedelta(minutes=rng.randint(-60, 60))
    cvis = [(tc + timedelta(minutes=i * 7), f"https://{s}/", s) for i, s in enumerate(cb)]
    cvis += [(tc + timedelta(minutes=40), f"https://intranet.{org_dom}/home", "Intranet"),
             (tc + timedelta(minutes=45), "https://www.google.com/search?q=offsite+venue", "Google")]
    write_chrome_history(out_dir / "12_colleague_History", cvis, [])
    add("12_colleague_History", "browser", False,
        [("domain", s) for s in cb] + [("url", f"https://{s}") for s in cb] +
        [("domain", f"intranet.{org_dom}"), ("url", f"https://intranet.{org_dom}/home"), ("domain", "google.com"),
         ("url", "https://google.com/search?q=offsite+venue")])

    pc2 = Pcap(rng)
    pc2.dns(tc, coll_ws, dns_server, "www.google.com", "142.250.183.4")
    pc2.tls(tc, coll_ws, "142.250.183.4", "www.google.com")
    pc2.dns(tc + timedelta(minutes=1), coll_ws, dns_server, f"intranet.{org_dom}", "10.0.0.15")
    coll_ips = []
    for s in cb[:2]:
        ip = _pub_ip(rng)
        coll_ips.append(ip)
        pc2.dns(tc + timedelta(minutes=2), coll_ws, dns_server, f"www.{s}", ip)
        pc2.tls(tc + timedelta(minutes=2), coll_ws, ip, f"www.{s}")
    pc2.write(out_dir / "13_colleague_capture.pcap")
    add("13_colleague_capture.pcap", "network", False,
        [("domain", "google.com"), ("ip", "142.250.183.4"), ("domain", f"intranet.{org_dom}"), ("ip", dns_server)] +
        [("domain", s) for s in cb[:2]] + [("ip", ip) for ip in coll_ips])

    manifest = {"seed": seed, "org": org_dom, "victim": victim, "late_stages": late, "dns_tunnel": tunnel,
                "image_attached": with_image, "honeypot_ip_reused": honey_ip == att_ip,
                "honeypot_download": honey_download, "decoy_document_accessed": decoy_accessed,
                "attacker": {"ip": att_ip, "honeypot_ip": honey_ip, "c2_domain": c2_dom, "c2_ip": c2_ip,
                             "phish_domain": phish_dom, "payload_sha256": payload_sha},
                "honeytokens": honeytokens, "files": files, "planted": planted_all,
                "image": img_info}
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=1))
    return manifest


def make_decoy_document(path: Path, honeytokens: list[dict]) -> None:
    lines = ["CONFIDENTIAL - internal use only", ""]
    for h in honeytokens:
        if h["token_type"] == "credential":
            lines.append(f"user: {h['value']}    pass: {h['secret']}")
    path.write_text("\n".join(lines) + "\n")
