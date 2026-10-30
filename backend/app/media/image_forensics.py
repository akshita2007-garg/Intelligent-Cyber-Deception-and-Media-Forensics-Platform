"""Image forensics: metadata analysis, JPEG quality estimation, Error Level Analysis (ELA),
JPEG ghosts, noise-residual inconsistency and a lightweight learned fusion of these traces.

Following Verdoliva (2020), no single trace is trusted on its own: each detector yields an
indicator and a logistic model fuses them into one manipulation score in [0, 1]. The model
coefficients live in media_model.json and are re-fitted by experiments/run_experiments.py.
"""
from __future__ import annotations

import io
import json
import math
import os
from pathlib import Path

import numpy as np
from PIL import ExifTags, Image, ImageOps

from .. import config
from ..core.entities import artifact, ent, max_severity
from .deepfake import status as deepfake_status

IMAGE_EXT = {".jpg", ".jpeg", ".png", ".tif", ".tiff", ".bmp", ".webp"}
EDITORS = ("photoshop", "gimp", "lightroom", "paint.net", "pixlr", "affinity", "snapseed", "canva",
           "facetune", "faceapp", "stable diffusion", "midjourney", "dall")
MODEL_PATH = Path(__file__).with_name("media_model.json")
FEATURES = ["ela_ratio", "ela_peak_z", "ela_dip_z", "ghost_z", "noise_peak_z", "noise_dip_z", "noise_ratio", "meta_editor", "meta_date_mismatch"]
DEFAULT_MODEL = {"features": FEATURES, "mean": [0.0] * 9, "std": [1.0] * 9,
                 "coef": [0.5, 0.3, 0.3, 0.5, 0.5, 0.3, 0.8, 1.5, 0.5], "intercept": -1.0, "threshold": 0.5,
                 "note": "untrained defaults"}

_STD_LUMA = np.array([16, 11, 10, 16, 24, 40, 51, 61, 12, 12, 14, 19, 26, 58, 60, 55, 14, 13, 16, 24, 40,
                      57, 69, 56, 14, 17, 22, 29, 51, 87, 80, 62, 18, 22, 37, 56, 68, 109, 103, 77, 24, 35,
                      55, 64, 81, 104, 113, 92, 49, 64, 78, 87, 103, 121, 120, 101, 72, 92, 95, 98, 112,
                      100, 103, 99], dtype=float)


def load_model() -> dict:
    try:
        return json.loads(MODEL_PATH.read_text())
    except Exception:
        return DEFAULT_MODEL


def jpeg_quality(img: Image.Image) -> int | None:
    q = getattr(img, "quantization", None)
    if not q or 0 not in q:
        return None
    t = np.array(q[0], dtype=float)
    if t.size != 64:
        return None
    scale = float(np.mean(t / _STD_LUMA) * 100)
    quality = (200 - scale) / 2 if scale <= 100 else 5000 / scale
    return int(max(1, min(100, round(quality))))


def exif_dict(img: Image.Image) -> dict:
    out = {}
    try:
        ex = img.getexif()
        for k, v in ex.items():
            out[ExifTags.TAGS.get(k, str(k))] = v
        for ifd_id in (0x8769, 0x8825):
            try:
                for k, v in ex.get_ifd(ifd_id).items():
                    name = (ExifTags.GPSTAGS.get(k, str(k)) if ifd_id == 0x8825 else ExifTags.TAGS.get(k, str(k)))
                    out[name] = v
            except Exception:
                pass
    except Exception:
        pass
    clean = {}
    for k, v in out.items():
        if isinstance(v, bytes):
            continue
        clean[k] = v if isinstance(v, (int, float, str)) else str(v)
    return clean


def _blocks(arr: np.ndarray, b: int) -> np.ndarray:
    h, w = arr.shape[:2]
    h2, w2 = h - h % b, w - w % b
    a = arr[:h2, :w2]
    return a.reshape(h2 // b, b, w2 // b, b, *a.shape[2:]).swapaxes(1, 2)


def _robust_peak_z(vals: np.ndarray) -> float:
    med = float(np.median(vals))
    mad = float(np.median(np.abs(vals - med))) * 1.4826 + 1e-6
    return float((np.percentile(vals, 99.5) - med) / mad)


def _robust_dip_z(vals: np.ndarray) -> float:
    med = float(np.median(vals))
    mad = float(np.median(np.abs(vals - med))) * 1.4826 + 1e-6
    return float((med - np.percentile(vals, 0.5)) / mad)


def _gradient_blocks(img: Image.Image, block: int) -> np.ndarray:
    g = np.asarray(img.convert("L"), dtype=float)
    gx = np.abs(np.diff(g, axis=1, append=g[:, -1:]))
    gy = np.abs(np.diff(g, axis=0, append=g[-1:, :]))
    return _blocks(gx + gy, block).mean(axis=(2, 3))


def ela(img: Image.Image, quality: int = 90, block: int = 16):
    rgb = img.convert("RGB")
    buf = io.BytesIO()
    rgb.save(buf, "JPEG", quality=quality)
    re = Image.open(io.BytesIO(buf.getvalue())).convert("RGB")
    diff = np.abs(np.asarray(rgb, dtype=np.int16) - np.asarray(re, dtype=np.int16)).max(axis=2).astype(float)
    bm = _blocks(diff, block).mean(axis=(2, 3))
    # content-normalised ELA: error level relative to local edge energy, so strong edges are not mistaken for edits
    nb = bm / (_gradient_blocks(rgb, block) + 2.0)
    med = float(np.median(nb)) + 1e-6
    feats = {"ela_ratio": math.log(float(np.percentile(nb, 99)) / med + 1e-6), "ela_peak_z": _robust_peak_z(nb.ravel()),
             "ela_dip_z": _robust_dip_z(nb.ravel())}
    return diff, bm, feats


def jpeg_ghost(img: Image.Image, block: int = 16, qualities=(50, 60, 70, 80)) -> float:
    """JPEG ghosts (Farid, 2009): a region previously compressed at quality q shows an unusually
    small re-compression error at q. Returns the strongest localised dip across qualities."""
    rgb = img.convert("RGB")
    a = np.asarray(rgb, dtype=float)
    grad = _gradient_blocks(rgb, block) + 2.0
    best = 0.0
    for q in qualities:
        buf = io.BytesIO()
        rgb.save(buf, "JPEG", quality=q)
        r = np.asarray(Image.open(io.BytesIO(buf.getvalue())).convert("RGB"), dtype=float)
        d = _blocks(((a - r) ** 2).mean(axis=2), block).mean(axis=(2, 3)) / grad
        best = max(best, _robust_dip_z(d.ravel()))
    return best


def noise_residual(img: Image.Image, block: int = 32):
    g = np.asarray(img.convert("L"), dtype=float)
    pad = np.pad(g, 1, mode="edge")
    stack = np.stack([pad[i:i + g.shape[0], j:j + g.shape[1]] for i in range(3) for j in range(3)])
    res = g - np.median(stack, axis=0)
    bs = _blocks(res, block).std(axis=(2, 3))
    med = float(np.median(bs)) + 1e-3
    return bs, {"noise_peak_z": _robust_peak_z(bs.ravel()), "noise_dip_z": _robust_dip_z(bs.ravel()),
                "noise_ratio": math.log(float(np.percentile(bs, 99)) / med + 1e-6)}


def score(feats: dict, model: dict | None = None) -> float:
    m = model or load_model()
    x = np.array([feats.get(f, 0.0) for f in m["features"]], dtype=float)
    sd = np.array(m["std"], dtype=float)
    sd = np.where(sd < 1e-6, 1.0, sd)                     # constant features contribute nothing
    z = np.nan_to_num((x - np.array(m["mean"])) / sd)
    logit = float(np.dot(z, m["coef"]) + m["intercept"])
    return 1 / (1 + math.exp(-max(-30, min(30, logit))))


def image_features(img: Image.Image) -> tuple[dict, dict]:
    """Returns (features, extras) for an already-opened image."""
    exif = exif_dict(img)
    software = str(exif.get("Software", "")).lower()
    dto, dt = str(exif.get("DateTimeOriginal", "")), str(exif.get("DateTime", ""))
    _, bm, ef = ela(img)
    _, nf = noise_residual(img)
    feats = {**ef, **nf, "ghost_z": jpeg_ghost(img),
             "meta_editor": 1.0 if any(e in software for e in EDITORS) else 0.0,
             "meta_date_mismatch": 1.0 if (dto and dt and dto != dt) else 0.0}
    return feats, {"exif": exif, "ela_blocks": bm}


def _save_ela_png(diff: np.ndarray, out: Path) -> None:
    amp = np.clip(diff * (255.0 / max(1.0, np.percentile(diff, 99.5))), 0, 255).astype(np.uint8)
    heat = ImageOps.colorize(Image.fromarray(amp), black="#0b1020", white="#ffd166", mid="#ef476f")
    heat.save(out)


def analyse_image(path: Path, derived_dir: Path | None = None) -> dict:
    img = Image.open(path)
    img.load()
    fmt = img.format
    q = jpeg_quality(img) if fmt == "JPEG" else None
    feats, extra = image_features(img)
    exif = extra["exif"]
    model = load_model()
    s = score(feats, model)
    thr = model.get("threshold", config.MEDIA_THRESHOLD)
    indicators = []
    if feats["meta_editor"]:
        indicators.append(f"Edited with software: {exif.get('Software')}")
    if feats["meta_date_mismatch"]:
        indicators.append(f"DateTimeOriginal ({exif.get('DateTimeOriginal')}) differs from DateTime ({exif.get('DateTime')})")
    if feats["ela_peak_z"] > 8:
        indicators.append(f"Localised ELA anomaly (robust z = {feats['ela_peak_z']:.1f})")
    if feats["noise_peak_z"] > 6:
        indicators.append(f"Noise-level inconsistency (robust z = {feats['noise_peak_z']:.1f})")
    if not any(k in exif for k in ("Make", "Model")):
        indicators.append("No camera make/model metadata")
    ela_file = None
    if derived_dir is not None:
        derived_dir.mkdir(parents=True, exist_ok=True)
        diff, _, _ = ela(img)
        ela_file = derived_dir / f"{path.stem}_ela.png"
        _save_ela_png(diff, ela_file)
    ents = [ent("filename", path.name)]
    for k in ("Make", "Model", "Software", "Artist"):
        if exif.get(k):
            ents.append({"type": "device" if k in ("Make", "Model") else ("software" if k == "Software" else "user"),
                         "value": str(exif[k]).strip().lower()})
    ts = None
    if exif.get("DateTimeOriginal") or exif.get("DateTime"):
        raw = str(exif.get("DateTimeOriginal") or exif.get("DateTime"))
        try:
            d, t = raw.split(" ")
            ts = f"{d.replace(':', '-')}T{t}"
        except ValueError:
            ts = None
    verdict = "likely manipulated" if s >= thr else "no strong manipulation evidence"
    sev = "high" if s >= max(thr, 0.8) else ("medium" if s >= thr else "info")
    art = artifact("media.image", f"Image {path.name}: {verdict} (score {s:.2f})", ts, ents,
                   detail={"format": fmt, "size": list(img.size), "mode": img.mode, "jpeg_quality": q,
                           "features": {k: round(v, 3) for k, v in feats.items()}, "score": round(s, 4),
                           "threshold": thr, "verdict": verdict, "exif": exif,
                           "ela_image": ela_file.name if ela_file else None,
                           "gps": {k: exif[k] for k in exif if k.startswith("GPS")}},
                   severity=sev, indicators=indicators)
    return {"module": "media",
            "summary": {"type": "image", "format": fmt, "dimensions": f"{img.size[0]}x{img.size[1]}",
                        "jpeg_quality": q, "manipulation_score": round(s, 3), "verdict": verdict,
                        "deepfake_model": deepfake_status(),
                        "max_severity": sev},
            "artifacts": [art]}
