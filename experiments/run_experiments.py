"""Reproducible evaluation of the IDMF prototype on synthetic, labelled data.

    python -m experiments.run_experiments            # full run (writes experiments/results/)
    python -m experiments.run_experiments --quick    # smaller run for a smoke test

Experiments
  E1 evidence integrity (hash before/after analysis, tamper detection, audit-chain tamper detection)
  E2 artifact/entity extraction accuracy per module
  E3 cross-domain correlation: baselines, proposed engine, ablations (calibration/test split)
  E4 deception-to-forensics linkage (honeytoken tripwire)
  E5 report traceability and hallucination detection (injected errors)
  E6 media manipulation detection (learned fusion vs single-trace baselines)
  E7 processing performance and scaling
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import random
import re
import shutil
import sys
import tempfile
import time
from collections import defaultdict
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("IDMF_DATA_DIR", tempfile.mkdtemp(prefix="idmf_exp_"))

from backend.app import reporting  # noqa: E402
from backend.app.reporting import verifier  # noqa: E402
from backend.app.core import correlation  # noqa: E402
from backend.app.core.entities import normalize  # noqa: E402
from backend.app.core.integrity import file_hashes  # noqa: E402
from backend.app.core.pipeline import detect_module, run_module  # noqa: E402
from backend.app.demo import scenario as synth  # noqa: E402
from backend.app.media import image_forensics as media_forensics  # noqa: E402

OUT = ROOT / "experiments" / "results"


def prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return {"precision": round(p, 4), "recall": round(r, 4), "f1": round(f, 4), "tp": tp, "fp": fp, "fn": fn}


# ----------------------------------------------------------------------------- scenario cache
def build_scenarios(seeds, workdir: Path):
    cases = []
    for s in seeds:
        d = workdir / f"case_{s}"
        man = synth.generate_scenario(d, s)
        evs, timings = [], []
        for i, f in enumerate(man["files"], 1):
            p = d / f["name"]
            mod = detect_module(p, f["name"])
            sha0, _ = file_hashes(p)
            t = time.perf_counter()
            res = run_module(mod, p, d / "derived", f["name"])
            dt = time.perf_counter() - t
            sha1, _ = file_hashes(p)
            evs.append({"id": i, "filename": f["name"], "module": res.get("module", mod), "detected_module": mod,
                        "expected_module": f["module"], "sha256": sha0, "sha256_after": sha1, "size": p.stat().st_size,
                        "integrity_ok": sha0 == sha1, "artifacts": res["artifacts"], "summary": res["summary"],
                        "related": f["related"], "path": str(p), "seconds": dt})
        cases.append({"seed": s, "manifest": man, "evidence": evs, "dir": d})
    return cases


# ----------------------------------------------------------------------------- E1
def e1_integrity(cases, workdir: Path):
    total = sum(len(c["evidence"]) for c in cases)
    match = sum(e["integrity_ok"] for c in cases for e in c["evidence"])
    rng = random.Random(1)
    detected = trials = 0
    for c in cases:
        for e in c["evidence"]:
            p = Path(e["path"])
            cp = workdir / "tamper.bin"
            shutil.copyfile(p, cp)
            b = bytearray(cp.read_bytes())
            i = rng.randrange(len(b))
            b[i] ^= 1 << rng.randrange(8)                      # flip a single bit
            cp.write_bytes(bytes(b))
            trials += 1
            detected += file_hashes(cp)[0] != e["sha256"]
    # audit chain tamper test through the real DB layer
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from backend.app import db as dbm
    eng = create_engine(f"sqlite:///{workdir / 'audit.db'}")
    dbm.Base.metadata.create_all(eng)
    S = sessionmaker(bind=eng)
    chain_trials = chain_detected = 0
    with S() as s:
        for k in range(200):
            dbm.audit(s, "tester", "evidence.acquire", f"E{k} sha256={'%064x' % k}", 1)
        s.commit()
        ok, _ = dbm.verify_audit_chain(s)
        assert ok
        rows = s.query(dbm.AuditLog).all()
        for k in range(50):
            r = rng.choice(rows)
            old = r.detail
            r.detail = old + " (edited)"
            s.flush()
            chain_trials += 1
            ok, bad = dbm.verify_audit_chain(s)
            chain_detected += (not ok and bad == r.id)
            r.detail = old
            s.flush()
    return {"files": total, "hash_unchanged_after_analysis": match,
            "bit_flip_trials": trials, "bit_flip_detected": detected,
            "audit_edit_trials": chain_trials, "audit_edit_detected_at_exact_entry": chain_detected,
            "module_routing_correct": sum(e["detected_module"] in (e["expected_module"], "disk", "memory")
                                          if e["expected_module"] in ("disk", "memory") else e["detected_module"] == e["expected_module"]
                                          for c in cases for e in c["evidence"])}


# ----------------------------------------------------------------------------- E2
def _norm_planted(items):
    out = set()
    for it in items:
        t, v = it.split("|", 1)
        n = normalize(t, v)
        if n:
            out.add((t, n))
    return out


def e2_extraction(cases):
    per = defaultdict(lambda: [0, 0, 0])
    per_type = defaultdict(lambda: [0, 0, 0])
    misses = defaultdict(list)
    for c in cases:
        planted = c["manifest"]["planted"]
        for e in c["evidence"]:
            mod = e["expected_module"]
            if mod == "media":
                continue
            gt = _norm_planted(planted[e["filename"]])
            types = {t for t, _ in gt}
            ext = {(x["type"], x["value"]) for a in e["artifacts"] if a["kind"] != "evidence.file" for x in a["entities"] if x["type"] in types}
            tp, fp, fn = len(gt & ext), len(ext - gt), len(gt - ext)
            k = {"memory": "memory", "disk": "disk (body file)"}.get(mod, mod)
            per[k][0] += tp; per[k][1] += fp; per[k][2] += fn
            for t in types:
                g = {x for x in gt if x[0] == t}; x_ = {x for x in ext if x[0] == t}
                per_type[t][0] += len(g & x_); per_type[t][1] += len(x_ - g); per_type[t][2] += len(g - x_)
            if fn or fp:
                misses[k].append({"file": e["filename"], "seed": c["seed"], "missed": sorted(gt - ext)[:4], "extra": sorted(ext - gt)[:4]})
    allc = [sum(v[i] for v in per.values()) for i in range(3)]
    return {"per_module": {k: prf(*v) for k, v in per.items()}, "per_type": {k: prf(*v) for k, v in per_type.items()},
            "overall": prf(*allc), "error_examples": {k: v[:5] for k, v in misses.items()}}


# ----------------------------------------------------------------------------- E3/E4
def clusters_from_links(ids, links):
    return correlation.components(ids, links)


def pair_set(clusters):
    s = set()
    for c in clusters:
        for i in range(len(c)):
            for j in range(i + 1, len(c)):
                s.add((c[i], c[j]))
    return s


def gt_pairs(case):
    rel = sorted(e["id"] for e in case["evidence"] if e["related"])
    return pair_set([rel])


def predict(case, method, theta, window, honey=True):
    evs = case["evidence"]
    ids = [e["id"] for e in evs]
    hts = case["manifest"]["honeytokens"] if honey else []
    raw = {e["id"]: e["path"] for e in evs}
    if method == "naive":
        pairs = correlation.score_pairs(evs, None, window, use_idf=False, use_time=False, use_allowlist=False,
                                        use_home=False, use_types=False)
        links = [k for k, p in pairs.items() if p["score"] > 0]
    elif method == "temporal":
        links = []
        tmap = {e["id"]: [correlation._epoch_min(a.get("ts")) for a in e["artifacts"] if a.get("ts")] for e in evs}
        for i in ids:
            for j in ids:
                if i < j and tmap[i] and tmap[j]:
                    if min(abs(x - y) for x in tmap[i][:200] for y in tmap[j][:200]) <= window:
                        links.append((i, j))
    else:
        cfg = dict(use_idf=True, use_time=True, use_allowlist=True, use_home=True, use_types=True)
        if method == "idf_only":
            cfg.update(use_time=False, use_allowlist=False, use_home=False)
        for k in ("use_idf", "use_time", "use_allowlist", "use_home", "use_types"):
            if method == f"no_{k[4:]}":
                cfg[k] = False
        hits = correlation.honeytoken_sweep(evs, hts, raw) if (honey and method != "no_tripwire") else []
        pairs = correlation.score_pairs(evs, hits, window, **cfg)
        links = [k for k, p in pairs.items() if p["score"] >= theta or p.get("tripwire")]
    return pair_set(clusters_from_links(ids, links)), links


def evaluate(cases, method, theta, window, honey=True):
    tp = fp = fn = 0
    direct = [0, 0, 0]
    for c in cases:
        pred, links = predict(c, method, theta, window, honey)
        gt = gt_pairs(c)
        tp += len(pred & gt); fp += len(pred - gt); fn += len(gt - pred)
        lk = {tuple(sorted(l)) for l in links}
        direct[0] += len(lk & gt); direct[1] += len(lk - gt)
    r = prf(tp, fp, fn)
    r["direct_link_precision"] = round(direct[0] / (direct[0] + direct[1]), 4) if direct[0] + direct[1] else 0.0
    return r


def tune(cases, method):
    best = None
    thetas = [0.5, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12] if method not in ("naive", "temporal") else [0]
    windows = [15, 30, 60, 120, 240, 720] if method != "naive" else [0]
    grid = []
    for th in thetas:
        for w in windows:
            r = evaluate(cases, method, th, w)
            grid.append({"theta": th, "window": w, **r})
            if best is None or r["f1"] > best[2]["f1"] or (r["f1"] == best[2]["f1"] and th > best[0]):
                best = (th, w, r)
    return best, grid


def e3_correlation(cal, test):
    methods = ["naive", "temporal", "idf_only", "full", "no_time", "no_idf", "no_allowlist", "no_home", "no_types", "no_tripwire"]
    out, grids = {}, {}
    for m in methods:
        (th, w, rcal), grid = tune(cal, m)
        rt = evaluate(test, m, th, w)
        out[m] = {"theta": th, "window_min": w, "calibration": rcal, "test": rt}
        if m == "full":
            grids[m] = grid
    return out, grids


def e4_deception(test, theta, window):
    res = {}
    for honey in (True, False):
        linked = total = 0
        linked_noreuse = total_noreuse = 0
        for c in test:
            pred, _ = predict(c, "full" if honey else "no_tripwire", theta, window, honey)
            hp = next(e["id"] for e in c["evidence"] if e["filename"].startswith("05_"))
            rel = [e["id"] for e in c["evidence"] if e["related"] and e["id"] != hp]
            ok = any(tuple(sorted((hp, r))) in pred for r in rel)
            total += 1; linked += ok
            if not c["manifest"]["honeypot_ip_reused"]:
                total_noreuse += 1; linked_noreuse += ok
        res["with_tripwire" if honey else "without_tripwire"] = {
            "honeypot_linked": linked, "cases": total,
            "honeypot_linked_when_attacker_changed_ip": linked_noreuse, "cases_attacker_changed_ip": total_noreuse}
    mem_hits = sum(1 for c in test for h in correlation.honeytoken_sweep(c["evidence"], c["manifest"]["honeytokens"],
                                                                            {e["id"]: e["path"] for e in c["evidence"]})
                   if h["artifact_index"] is None)
    res["raw_byte_honeytoken_hits_in_memory_images"] = mem_hits
    return res


# ----------------------------------------------------------------------------- E5
def _rand_ip(rng):
    return f"{rng.randint(11, 220)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def perturb(sentence, rng, kind, other_ids):
    cites = verifier.RE_CITE.findall(sentence)
    if kind == "wrong_ip":
        m = verifier.RE_IPV4.search(verifier.RE_CITE.sub("", sentence))
        return sentence.replace(m.group(0), _rand_ip(rng), 1) if m else None
    if kind == "wrong_domain":
        toks = [v for t, v in reporting.checkable_tokens(sentence) if t == "domain"]
        if not toks:
            return None
        return re.sub(re.escape(toks[0]), f"{rng.choice(synth.WORDS)}{rng.randint(10, 99)}.{rng.choice(synth.EVIL_TLDS)}", sentence, 1, flags=re.I)
    if kind == "wrong_hash":
        m = verifier.RE_SHA256.search(sentence) or verifier.RE_MD5.search(sentence)
        return sentence.replace(m.group(0), "%x" % rng.getrandbits(len(m.group(0)) * 4), 1) if m else None
    if kind == "wrong_time":
        m = verifier.RE_TS.search(sentence)
        if not m:
            return None
        hh, mm = m.group(2).split(":")
        return sentence.replace(m.group(2), f"{(int(hh) + rng.randint(1, 5)) % 24:02d}:{mm}", 1)
    if kind == "wrong_citation":
        if not cites or len(cites) > 1:
            return None
        toks = reporting.checkable_tokens(sentence)
        if not toks:
            return None
        new = rng.choice([i for i in other_ids if str(i) != cites[0]])
        return verifier.RE_CITE.sub(f"[E{new}]", sentence)
    if kind == "missing_citation":
        return verifier.RE_CITE.sub("", sentence).strip() if cites else None
    if kind == "fabricated_evidence_id":
        return verifier.RE_CITE.sub("[E999]", sentence, count=1) if cites else None
    if kind == "semantic_flip":
        for a, b in (("SUCCESS", "failed"), ("successful", "failed"), ("likely manipulated", "no strong manipulation evidence"),
                     ("high", "low"), ("Beaconing", "Normal traffic")):
            if a in sentence:
                return sentence.replace(a, b, 1)
        return None
    raise ValueError(kind)


def e5_reports(test, theta, window):
    kinds = ["wrong_ip", "wrong_domain", "wrong_hash", "wrong_time", "wrong_citation", "missing_citation",
             "fabricated_evidence_id", "semantic_flip"]
    rng = random.Random(5)
    total_sent = verified = 0
    det = {k: [0, 0] for k in kinds}
    secs_per = []
    for c in test:
        evs = [dict(e, integrity_ok=True) for e in c["evidence"]]
        t = time.perf_counter()
        corr = correlation.correlate(evs, c["manifest"]["honeytokens"], {e["id"]: e["path"] for e in evs}, theta, window)
        rep = reporting.build_report({"id": c["seed"], "name": f"case {c['seed']}"}, evs, corr)
        secs_per.append(time.perf_counter() - t)
        total_sent += rep["verification"]["sentences"]; verified += rep["verification"].get("verified", 0)
        facts = {e["id"]: reporting.evidence_facts(e) for e in evs}
        sents = [s["text"] for sec in rep["sections"] for s in sec["sentences"]]
        ids = [e["id"] for e in evs]
        for k in kinds:
            for s in rng.sample(sents, len(sents)):
                bad = perturb(s, rng, k, ids)
                if bad and bad != s:
                    v = reporting.verify_sentence(bad, facts)
                    det[k][1] += 1
                    det[k][0] += v["status"] != "verified"
    return {"sentences": total_sent, "verified": verified, "traceability": round(verified / total_sent, 4),
            "false_alarm_rate_on_clean_sentences": round(1 - verified / total_sent, 4),
            "mean_report_seconds": round(float(np.mean(secs_per)), 4),
            "injected": {k: {"trials": v[1], "detected": v[0], "detection_rate": round(v[0] / v[1], 4) if v[1] else None}
                         for k, v in det.items()}}


# ----------------------------------------------------------------------------- E6
def fit_logreg(X, y, l2=0.05, iters=3000, lr=0.1):
    mu, sd = X.mean(0), X.std(0) + 1e-9
    Z = (X - mu) / sd
    w, b = np.zeros(Z.shape[1]), 0.0
    for _ in range(iters):
        p = 1 / (1 + np.exp(-(Z @ w + b)))
        g = Z.T @ (p - y) / len(y) + l2 * w
        w -= lr * g; b -= lr * float(np.mean(p - y))
    return mu, sd, w, b


def auc(scores, y):
    order = np.argsort(scores)
    ranks = np.empty(len(scores)); ranks[order] = np.arange(1, len(scores) + 1)
    pos = y == 1
    return float((ranks[pos].sum() - pos.sum() * (pos.sum() + 1) / 2) / (pos.sum() * (~pos).sum()))


def best_threshold(scores, y):
    best = (0.5, -1)
    for t in np.unique(scores):
        pred = scores >= t
        tp = int((pred & (y == 1)).sum()); fp = int((pred & (y == 0)).sum()); fn = int((~pred & (y == 1)).sum())
        f = prf(tp, fp, fn)["f1"]
        if f > best[1]:
            best = (float(t), f)
    return best[0]


def metrics(pred, y):
    tp = int((pred & (y == 1)).sum()); fp = int((pred & (y == 0)).sum()); fn = int((~pred & (y == 1)).sum())
    tn = int((~pred & (y == 0)).sum())
    r = prf(tp, fp, fn)
    r["accuracy"] = round((tp + tn) / len(y), 4)
    r["tn"] = tn
    return r


def e6_media(n_per_class, seed=2026):
    rng = np.random.default_rng(seed)
    from PIL import Image
    import io
    rows = []
    t0 = time.perf_counter()
    for label in ("authentic", "tampered"):
        for _ in range(n_per_class):
            b, info = synth.make_image(rng, label)
            img = Image.open(io.BytesIO(b)); img.load()
            f, _ = media_forensics.image_features(img)
            rows.append({"y": int(label == "tampered"), "kind": info.get("kind", "authentic"),
                         "meta": bool(info.get("metadata_edited")), **f})
    feat_secs = (time.perf_counter() - t0) / len(rows)
    idx = np.arange(len(rows)); rng.shuffle(idx)
    half = len(idx) // 2
    cal, test = [rows[i] for i in idx[:half]], [rows[i] for i in idx[half:]]
    F = media_forensics.FEATURES
    Xc = np.array([[r[f] for f in F] for r in cal]); yc = np.array([r["y"] for r in cal])
    Xt = np.array([[r[f] for f in F] for r in test]); yt = np.array([r["y"] for r in test])
    mu, sd, w, b = fit_logreg(Xc, yc)
    sc = 1 / (1 + np.exp(-(((Xc - mu) / sd) @ w + b)))
    st = 1 / (1 + np.exp(-(((Xt - mu) / sd) @ w + b)))
    thr = best_threshold(sc, yc)
    model = {"features": F, "mean": mu.round(6).tolist(), "std": np.where(sd < 1e-6, 1.0, sd).round(6).tolist(), "coef": w.round(6).tolist(),
             "intercept": round(b, 6), "threshold": round(thr, 4),
             "note": f"logistic fusion fitted on {len(cal)} synthetic calibration images (seed {seed})"}
    res = {"images": len(rows), "calibration": len(cal), "test": len(test), "feature_seconds_per_image": round(feat_secs, 4),
           "fusion": {**metrics(st >= thr, yt), "auc": round(auc(st, yt), 4), "threshold": round(thr, 4)},
           "coefficients": dict(zip(F, w.round(3).tolist()))}
    for name, cols in {"ela_only": ["ela_peak_z", "ela_ratio", "ela_dip_z"], "jpeg_ghost_only": ["ghost_z"], "noise_only": ["noise_peak_z", "noise_ratio"],
                       "metadata_only": ["meta_editor", "meta_date_mismatch"]}.items():
        ci = [F.index(c) for c in cols]
        m2 = fit_logreg(Xc[:, ci], yc)
        s2c = 1 / (1 + np.exp(-(((Xc[:, ci] - m2[0]) / m2[1]) @ m2[2] + m2[3])))
        s2t = 1 / (1 + np.exp(-(((Xt[:, ci] - m2[0]) / m2[1]) @ m2[2] + m2[3])))
        t2 = best_threshold(s2c, yc)
        res[name] = {**metrics(s2t >= t2, yt), "auc": round(auc(s2t, yt), 4)}
    kinds = defaultdict(lambda: [0, 0])
    for r, s in zip(test, st):
        kinds[r["kind"]][1] += 1
        kinds[r["kind"]][0] += int((s >= thr) == bool(r["y"]))
    res["per_kind_accuracy"] = {k: {"n": v[1], "correct": v[0], "rate": round(v[0] / v[1], 4)} for k, v in kinds.items()}
    return res, model


# ----------------------------------------------------------------------------- E7
def e7_performance(cases, workdir: Path, theta, window, big=True):
    per_mod = defaultdict(list)
    for c in cases:
        for e in c["evidence"]:
            per_mod[e["module"]].append((e["size"], e["seconds"]))
    mod_stats = {m: {"files": len(v), "mean_kb": round(np.mean([s for s, _ in v]) / 1024, 1),
                     "mean_ms": round(1000 * np.mean([t for _, t in v]), 2),
                     "max_ms": round(1000 * max(t for _, t in v), 2)} for m, v in per_mod.items()}
    # memory/disk scanner throughput
    thr = []
    from backend.app.forensics import memory_forensics as disk_memory
    sizes = [8, 32, 64] if big else [4]
    for mb in sizes:
        p = workdir / f"scan_{mb}.mem"
        rr = random.Random(mb)
        buf = bytearray(rr.getrandbits(8 * 1024 * 1024).to_bytes(1024 * 1024, "little")) * mb
        for k in range(50):
            off = rr.randrange(len(buf) - 64)
            s = f"host-{k}.example{k}.xyz 10.0.{k}.1".encode()
            buf[off:off + len(s)] = s
        p.write_bytes(bytes(buf))
        t = time.perf_counter()
        r = disk_memory.analyse(p)
        dt = time.perf_counter() - t
        thr.append({"mb": mb, "seconds": round(dt, 3), "mb_per_s": round(mb / dt, 2), "iocs": r["summary"]["iocs"]})
        p.unlink()
    # correlation scaling: merge k cases into one large case
    scale = []
    for k in [1, 2, 4, 8, 16] if big else [1, 2]:
        evs, hts = [], []
        nid = 0
        for c in cases[:k]:
            for e in c["evidence"]:
                nid += 1
                evs.append(dict(e, id=nid))
            hts += [dict(h, id=len(hts) + 1) for h in c["manifest"]["honeytokens"]]
        arts = sum(len(e["artifacts"]) for e in evs)
        t = time.perf_counter()
        correlation.correlate(evs, hts, None, theta, window)
        scale.append({"evidence_items": len(evs), "artifacts": arts, "seconds": round(time.perf_counter() - t, 4)})
    return {"per_module": mod_stats, "scanner_throughput": thr, "correlation_scaling": scale,
            "peak_rss_mb": _peak_rss_mb()}


def _peak_rss_mb():
    try:
        import resource  # POSIX only
        return round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1)
    except ImportError:
        return None


# ----------------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--cases", type=int, default=40)
    ap.add_argument("--images", type=int, default=200, help="images per class")
    args = ap.parse_args()
    n_cases = 6 if args.quick else args.cases
    n_img = 30 if args.quick else args.images
    OUT.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="idmf_cases_"))
    results = {"config": {"cases": n_cases, "images_per_class": n_img, "python": sys.version.split()[0]}}
    T = time.perf_counter()

    print(f"[1/7] generating and analysing {n_cases} synthetic cases ...", flush=True)
    seeds = list(range(1000, 1000 + n_cases))
    cases = build_scenarios(seeds, work)
    cal, test = cases[: n_cases // 2], cases[n_cases // 2:]
    results["dataset"] = {"cases": n_cases, "calibration_cases": len(cal), "test_cases": len(test),
                          "evidence_items": sum(len(c["evidence"]) for c in cases),
                          "artifacts": sum(len(e["artifacts"]) for c in cases for e in c["evidence"]),
                          "related_items": sum(e["related"] for c in cases for e in c["evidence"]),
                          "late_stage_cases": sum(c["manifest"]["late_stages"] for c in cases),
                          "attacker_changed_ip_cases": sum(not c["manifest"]["honeypot_ip_reused"] for c in cases),
                          "image_attached_cases": sum(c["manifest"]["image_attached"] for c in cases)}

    print("[2/7] E1 integrity", flush=True)
    results["E1_integrity"] = e1_integrity(cases, work)
    print("[3/7] E2 extraction", flush=True)
    results["E2_extraction"] = e2_extraction(cases)
    print("[4/7] E3 correlation (tuning on calibration split)", flush=True)
    results["E3_correlation"], grids = e3_correlation(cal, test)
    th, w = results["E3_correlation"]["full"]["theta"], results["E3_correlation"]["full"]["window_min"]
    results["E3_grid_full"] = grids["full"]
    print("[5/7] E4 deception linkage + E5 reports", flush=True)
    results["E4_deception"] = e4_deception(test, th, w)
    results["E5_reports"] = e5_reports(test, th, w)
    print("[6/7] E6 media", flush=True)
    results["E6_media"], model = e6_media(n_img)
    if not args.quick:
        (ROOT / "backend" / "app" / "media" / "media_model.json").write_text(json.dumps(model, indent=1))
        results["tuned_parameters"] = {"corr_threshold": th, "corr_window_min": w, "media_threshold": model["threshold"]}
    print("[7/7] E7 performance", flush=True)
    results["E7_performance"] = e7_performance(cases, work, th, w, big=not args.quick)
    results["total_seconds"] = round(time.perf_counter() - T, 1)
    name = "results_quick.json" if args.quick else "results.json"
    (OUT / name).write_text(json.dumps(results, indent=1))
    shutil.rmtree(work, ignore_errors=True)
    print(json.dumps({k: v for k, v in results.items() if k not in ("E3_grid_full",)}, indent=1)[:6000])
    print(f"\nWrote {OUT / name}")


if __name__ == "__main__":
    main()
