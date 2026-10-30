"""Network forensics: dependency-free pcap / pcapng parser with flow, DNS, HTTP and TLS-SNI extraction.

Detections follow the challenges listed by Rizvi et al. (2022): DNS tunnelling (long,
high-entropy labels), beaconing (regular inter-arrival times), uncommon ports and
plaintext credential/HTTP use. Scapy, Zeek or Wireshark can be used upstream; their
pcaps are read here directly.
"""
from __future__ import annotations

import math
import socket
import statistics
import struct
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from ..core.entities import artifact, ent, entities_from_url, is_public_ip, max_severity

COMMON_PORTS = {20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 123, 137, 138, 139, 143, 161, 389, 443, 445,
                465, 587, 993, 995, 1433, 3306, 3389, 5353, 8080, 8443}


def _ts(sec: float) -> str:
    return datetime.fromtimestamp(sec, tz=timezone.utc).replace(tzinfo=None).isoformat(timespec="seconds")


def _iter_pcap(data: bytes):
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        en = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        en = ">"
    else:
        raise ValueError("not a pcap file")
    nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    linktype = struct.unpack(en + "I", data[20:24])[0]
    off = 24
    while off + 16 <= len(data):
        sec, frac, incl, _orig = struct.unpack(en + "IIII", data[off:off + 16])
        off += 16
        pkt = data[off:off + incl]
        off += incl
        yield sec + frac / (1e9 if nano else 1e6), linktype, pkt


def _iter_pcapng(data: bytes):
    off, en, linktypes = 0, "<", {}
    while off + 12 <= len(data):
        btype = struct.unpack("<I", data[off:off + 4])[0]
        if btype == 0x0A0D0D0A:  # section header
            bom = data[off + 8:off + 12]
            en = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
        btype, blen = struct.unpack(en + "II", data[off:off + 8])
        body = data[off + 8:off + blen - 4]
        if btype == 1:  # interface description
            linktypes[len(linktypes)] = struct.unpack(en + "H", body[:2])[0]
        elif btype == 6:  # enhanced packet
            iface, hi, lo, cap, _orig = struct.unpack(en + "IIIII", body[:20])
            ts = ((hi << 32) | lo) / 1e6
            yield ts, linktypes.get(iface, 1), body[20:20 + cap]
        if blen < 12:
            break
        off += blen


def _ip_payload(linktype: int, pkt: bytes):
    if linktype == 1:            # Ethernet
        if len(pkt) < 14:
            return None
        etype = struct.unpack("!H", pkt[12:14])[0]
        off = 14
        if etype == 0x8100:      # VLAN
            etype = struct.unpack("!H", pkt[16:18])[0]
            off = 18
        return pkt[off:] if etype == 0x0800 else None
    if linktype == 113:          # Linux SLL
        return pkt[16:] if struct.unpack("!H", pkt[14:16])[0] == 0x0800 else None
    if linktype in (101, 228, 12):  # raw IP
        return pkt
    return None


def _parse_dns(payload: bytes):
    """Returns (is_response, [qnames], [(name, A-record)])."""
    try:
        _tid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", payload[:12])
    except struct.error:
        return None

    def name_at(o, depth=0):
        labels = []
        while o < len(payload):
            ln = payload[o]
            if ln == 0:
                return ".".join(labels), o + 1
            if ln & 0xC0 == 0xC0:
                ptr = struct.unpack("!H", payload[o:o + 2])[0] & 0x3FFF
                if depth > 5:
                    return ".".join(labels), o + 2
                rest, _ = name_at(ptr, depth + 1)
                labels.append(rest)
                return ".".join(labels), o + 2
            labels.append(payload[o + 1:o + 1 + ln].decode("ascii", "replace"))
            o += 1 + ln
        return ".".join(labels), o

    o, qnames, answers = 12, [], []
    try:
        for _ in range(qd):
            n, o = name_at(o)
            qnames.append(n)
            o += 4
        for _ in range(an):
            n, o = name_at(o)
            rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", payload[o:o + 10])
            o += 10
            if rtype == 1 and rdlen == 4:
                answers.append((n, socket.inet_ntoa(payload[o:o + 4])))
            o += rdlen
    except (struct.error, IndexError):
        pass
    return bool(flags & 0x8000), qnames, answers


def _tls_sni(payload: bytes) -> str | None:
    try:
        if payload[0] != 0x16 or payload[5] != 0x01:
            return None
        o = 5 + 4 + 2 + 32
        sid = payload[o]; o += 1 + sid
        cs = struct.unpack("!H", payload[o:o + 2])[0]; o += 2 + cs
        cm = payload[o]; o += 1 + cm
        ext_total = struct.unpack("!H", payload[o:o + 2])[0]; o += 2
        end = o + ext_total
        while o + 4 <= end:
            et, el = struct.unpack("!HH", payload[o:o + 4]); o += 4
            if et == 0:
                nl = struct.unpack("!H", payload[o + 3:o + 5])[0]
                return payload[o + 5:o + 5 + nl].decode("ascii", "replace")
            o += el
    except (IndexError, struct.error):
        return None
    return None


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    return -sum(v / len(s) * math.log2(v / len(s)) for v in c.values())


def analyse(path: Path) -> dict:
    data = path.read_bytes()
    it = _iter_pcapng(data) if data[:4] == b"\x0a\x0d\x0d\x0a" else _iter_pcap(data)

    flows: dict[tuple, dict] = {}
    dns_q, http, sni = [], [], []
    packets = 0
    first = last = None
    for ts, lt, pkt in it:
        ip = _ip_payload(lt, pkt)
        if not ip or len(ip) < 20 or ip[0] >> 4 != 4:
            continue
        packets += 1
        first = ts if first is None else min(first, ts)
        last = ts if last is None else max(last, ts)
        ihl = (ip[0] & 0x0F) * 4
        proto = ip[9]
        src, dst = socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
        seg = ip[ihl:]
        sport = dport = 0
        payload = b""
        if proto == 6 and len(seg) >= 20:
            sport, dport = struct.unpack("!HH", seg[:4])
            payload = seg[(seg[12] >> 4) * 4:]
        elif proto == 17 and len(seg) >= 8:
            sport, dport = struct.unpack("!HH", seg[:4])
            payload = seg[8:]
        key = (src, dst, sport, dport, proto)
        f = flows.setdefault(key, {"src": src, "dst": dst, "sport": sport, "dport": dport,
                                    "proto": {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, str(proto)),
                                    "packets": 0, "bytes": 0, "first": ts, "last": ts, "times": []})
        f["packets"] += 1
        f["bytes"] += len(ip)
        f["first"], f["last"] = min(f["first"], ts), max(f["last"], ts)
        if len(f["times"]) < 500:
            f["times"].append(ts)

        if proto == 17 and 53 in (sport, dport) and payload:
            r = _parse_dns(payload)
            if r:
                is_resp, qn, ans = r
                if not is_resp:
                    for q in qn:
                        dns_q.append({"ts": ts, "src": src, "server": dst, "query": q})
                else:
                    for n, a in ans:
                        dns_q.append({"ts": ts, "src": dst, "server": src, "query": n, "answer": a})
        elif proto == 6 and payload:
            head = payload[:2048]
            if head[:4] in (b"GET ", b"POST", b"PUT ", b"HEAD") or head[:7] == b"OPTIONS":
                lines = head.split(b"\r\n")
                method, _, rest = lines[0].decode("latin-1").partition(" ")
                uri = rest.rsplit(" ", 1)[0]
                hdrs = {}
                for ln in lines[1:]:
                    if b":" in ln:
                        k, v = ln.split(b":", 1)
                        hdrs[k.decode("latin-1").strip().lower()] = v.decode("latin-1").strip()
                host = hdrs.get("host", dst)
                http.append({"ts": ts, "src": src, "dst": dst, "dport": dport, "method": method,
                             "host": host, "uri": uri, "user_agent": hdrs.get("user-agent", ""),
                             "body": payload.split(b"\r\n\r\n", 1)[1][:300].decode("latin-1", "replace")
                             if b"\r\n\r\n" in payload else ""})
            else:
                s = _tls_sni(head)
                if s:
                    sni.append({"ts": ts, "src": src, "dst": dst, "dport": dport, "sni": s})

    arts: list[dict] = []
    # Flow artifacts (aggregate per src->dst:port)
    agg: dict[tuple, dict] = {}
    for f in flows.values():
        k = (f["src"], f["dst"], f["dport"], f["proto"])
        a = agg.setdefault(k, {**{x: f[x] for x in ("src", "dst", "dport", "proto")},
                               "packets": 0, "bytes": 0, "first": f["first"], "last": f["last"],
                               "sessions": 0, "starts": []})
        a["packets"] += f["packets"]; a["bytes"] += f["bytes"]; a["sessions"] += 1
        a["first"], a["last"] = min(a["first"], f["first"]), max(a["last"], f["last"])
        a["starts"].append(f["first"])
    for a in sorted(agg.values(), key=lambda x: x["first"]):
        ind = []
        if a["dport"] and a["dport"] not in COMMON_PORTS and a["dport"] < 49152 and is_public_ip(a["dst"]):
            ind.append(f"Connection to uncommon port {a['dport']} on {a['dst']}")
        starts = sorted(a["starts"])
        if len(starts) >= 5:
            gaps = [b - c for b, c in zip(starts[1:], starts[:-1])]
            med = statistics.median(gaps)
            # regular if most gaps sit within 15% of the median period or of a whole multiple of it
            # (a missed beacon or merged session doubles one gap)
            regular = sum(1 for g in gaps if med > 0 and abs(g / med - round(g / med)) <= 0.15 and round(g / med) >= 1)
            if med > 1 and regular / len(gaps) >= 0.8:
                ind.append(f"Beaconing: {len(starts)} sessions to {a['dst']}:{a['dport']} every ~{med:.0f}s")
        if a["proto"] == "TCP" and a["dport"] in (21, 23):
            ind.append(f"Cleartext protocol on port {a['dport']}")
        ents = [ent("ip", x) for x in (a["src"], a["dst"]) if is_public_ip(x)]
        arts.append(artifact("network.flow", f"{a['proto']} {a['src']} → {a['dst']}:{a['dport']}", _ts(a["first"]),
                             ents, detail={k: v for k, v in a.items() if k != "starts"} |
                             {"first": _ts(a["first"]), "last": _ts(a["last"])},
                             severity="high" if any("Beacon" in i for i in ind) else ("medium" if ind else "info"),
                             indicators=ind))
    # DNS
    seen = set()
    for d in dns_q:
        key = (d["query"], d.get("answer"))
        if key in seen:
            continue
        seen.add(key)
        ind = []
        labels = d["query"].split(".")
        longest = max(labels, key=len) if labels else ""
        if len(longest) > 40 or (len(longest) > 20 and _entropy(longest) > 3.8):
            ind.append(f"Possible DNS tunnelling: long/high-entropy label ({len(longest)} chars, H={_entropy(longest):.2f})")
        ents = [ent("domain", d["query"])]
        if d.get("answer") and is_public_ip(d["answer"]):
            ents.append(ent("ip", d["answer"]))
        title = f"DNS {d['query']}" + (f" → {d['answer']}" if d.get("answer") else "")
        arts.append(artifact("network.dns", title, _ts(d["ts"]), ents, detail=d | {"ts": _ts(d["ts"])},
                             severity="high" if ind else "info", indicators=ind))
    for h in http:
        url = f"http://{h['host']}{h['uri']}"
        ind = []
        if h["method"] == "POST" and any(w in h["body"].lower() for w in ("pass", "pwd", "token")):
            ind.append("Credentials posted over cleartext HTTP")
        if h["host"].replace(".", "").isdigit():
            ind.append(f"HTTP to raw IP host {h['host']}")
        ents = entities_from_url(url) + [ent("ip", h["dst"]) if is_public_ip(h["dst"]) else None]
        arts.append(artifact("network.http", f"HTTP {h['method']} {url[:120]}", _ts(h["ts"]), ents,
                             detail=h | {"ts": _ts(h["ts"]), "url": url},
                             severity="medium" if ind else "info", indicators=ind))
    for s in sni:
        arts.append(artifact("network.tls", f"TLS SNI {s['sni']}", _ts(s["ts"]),
                             [ent("domain", s["sni"]), ent("ip", s["dst"]) if is_public_ip(s["dst"]) else None],
                             detail=s | {"ts": _ts(s["ts"])}))

    talkers = Counter()
    for f in flows.values():
        talkers[f["dst"]] += f["bytes"]
    return {
        "module": "network",
        "summary": {"packets": packets, "flows": len(flows), "dns_queries": len({d['query'] for d in dns_q}),
                    "http_requests": len(http), "tls_sni": len(sni),
                    "capture_start": _ts(first) if first else None, "capture_end": _ts(last) if last else None,
                    "top_destinations": [{"ip": ip, "bytes": b} for ip, b in talkers.most_common(5)],
                    "flagged": sum(1 for a in arts if a["indicators"]),
                    "max_severity": max_severity([a["severity"] for a in arts])},
        "artifacts": arts,
    }
