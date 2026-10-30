"""Video forensics.

* Container metadata through ffprobe when installed (codec, resolution, frame rate, encoder,
  creation time), with a dependency-free fallback that reads the MP4 'ftyp' brand and common
  encoder strings.
* Temporal analysis through OpenCV when installed (``pip install opencv-python-headless``):
  the first frames are read in order to find duplicated/frozen frames (possible insertion or
  freeze-frame) and abrupt inter-frame changes (possible cut or splice); evenly sampled frames
  are also scored with the image-forensics model.
Deepfake classification is not bundled (see deepfake.py).
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import numpy as np
from PIL import Image

from ..core.entities import artifact, ent, max_severity
from . import image_forensics
from .deepfake import status as deepfake_status

VIDEO_EXT = {".mp4", ".mov", ".avi", ".mkv", ".webm", ".m4v", ".3gp", ".wmv"}
EDITORS = ("premiere", "after effects", "davinci", "final cut", "handbrake", "lavf", "ffmpeg", "capcut",
           "imovie", "filmora", "kdenlive", "shotcut", "vegas")


def _ffprobe(path: Path) -> dict:
    if not shutil.which("ffprobe"):
        return {}
    try:
        out = subprocess.run(["ffprobe", "-v", "quiet", "-print_format", "json", "-show_format", "-show_streams", str(path)],
                             capture_output=True, text=True, timeout=60).stdout
        return json.loads(out or "{}")
    except Exception:
        return {}


def _sniff(path: Path) -> dict:
    head = path.read_bytes()[:4 * 1024 * 1024]
    info = {}
    if head[4:8] == b"ftyp":
        info["brand"] = head[8:12].decode("latin-1", "replace").strip()
    m = re.search(rb"(Lavf[\d.]+|HandBrake[ \w.]*|Adobe Premiere[ \w.]*|DaVinci[ \w.]*|CapCut[ \w.]*)", head)
    if m:
        info["encoder_string"] = m.group(0).decode("latin-1", "replace")
    return info


def _temporal(path: Path, max_frames: int = 300, samples: int = 12) -> dict:
    try:
        import cv2  # optional
    except ImportError:
        return {"available": False}
    cap = cv2.VideoCapture(str(path))
    if not cap.isOpened():
        return {"available": True, "error": "could not open video"}
    fps = cap.get(cv2.CAP_PROP_FPS) or 0.0
    total = int(cap.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
    diffs, prev, frames = [], None, 0
    while frames < max_frames:
        ok, fr = cap.read()
        if not ok:
            break
        g = cv2.cvtColor(cv2.resize(fr, (160, 90)), cv2.COLOR_BGR2GRAY).astype(np.float32)
        if prev is not None:
            diffs.append(float(np.mean(np.abs(g - prev))))
        prev = g
        frames += 1
    scores = []
    if total > 0:
        for idx in np.linspace(0, max(total - 1, 0), num=min(samples, total)).astype(int):
            cap.set(cv2.CAP_PROP_POS_FRAMES, int(idx))
            ok, fr = cap.read()
            if not ok:
                continue
            img = Image.fromarray(cv2.cvtColor(fr, cv2.COLOR_BGR2RGB))
            feats, _ = image_forensics.image_features(img)
            scores.append({"frame": int(idx), "score": round(image_forensics.score(feats), 3)})
    cap.release()
    d = np.array(diffs) if diffs else np.zeros(0)
    dup_runs, run = [], 0
    for i, v in enumerate(d):
        if v < 0.3:
            run += 1
        else:
            if run >= 2:
                dup_runs.append({"end_frame": i, "length": run})
            run = 0
    if run >= 2:
        dup_runs.append({"end_frame": len(d), "length": run})
    cuts = []
    if len(d) > 10:
        med = float(np.median(d))
        mad = float(np.median(np.abs(d - med))) * 1.4826 + 1e-3
        for i, v in enumerate(d):
            if (v - med) / mad > 12 and v > 8:
                cuts.append({"frame": i + 1, "time_s": round((i + 1) / fps, 2) if fps else None, "mean_abs_diff": round(v, 1)})
    return {"available": True, "fps": round(fps, 3), "frame_count": total, "frames_examined": frames,
            "duplicate_runs": dup_runs[:20], "abrupt_changes": cuts[:20], "sampled_frame_scores": scores}


def analyse(path: Path, derived_dir: Path | None = None) -> dict:
    meta = _ffprobe(path)
    fmt = meta.get("format", {})
    tags = {k.lower(): v for k, v in (fmt.get("tags") or {}).items()}
    sniff = _sniff(path)
    vs = next((s for s in meta.get("streams", []) if s.get("codec_type") == "video"), {})
    temporal = _temporal(path)
    ind = []
    enc = " ".join(dict.fromkeys(filter(None, [tags.get("encoder"), tags.get("software"), sniff.get("encoder_string")])))
    if any(e in enc.lower() for e in EDITORS):
        ind.append(f"Re-encoded or edited with {enc.strip()}")
    if temporal.get("duplicate_runs"):
        ind.append(f"{len(temporal['duplicate_runs'])} run(s) of duplicated/frozen frames (possible insertion or freeze)")
    if temporal.get("abrupt_changes"):
        ind.append(f"{len(temporal['abrupt_changes'])} abrupt inter-frame change(s) (cut or splice)")
    # the photo model is not calibrated for re-encoded video, so only frames that stand out from the
    # rest of the same video are reported
    fs = temporal.get("sampled_frame_scores", [])
    med = float(np.median([s["score"] for s in fs])) if fs else 0.0
    high_frames = [s for s in fs if s["score"] - med >= 0.35]
    if high_frames:
        ind.append(f"{len(high_frames)} sampled frame(s) stand out from the rest of the video on image-manipulation traces")
    temporal_flags = bool(temporal.get("duplicate_runs") or temporal.get("abrupt_changes"))
    sev = "medium" if temporal_flags or high_frames else ("low" if ind else "info")
    art = artifact("media.video", f"Video {path.name}" + (": editing indicators found" if temporal_flags else ""),
                   tags.get("creation_time"), [ent("filename", path.name)],
                   detail={"ffprobe": bool(meta), "duration_s": fmt.get("duration"), "codec": vs.get("codec_name"),
                           "resolution": f"{vs.get('width')}x{vs.get('height')}" if vs else None,
                           "tags": tags, "container": sniff, "temporal": temporal,
                           "deepfake": deepfake_status()},
                   severity=sev, indicators=ind)
    return {"module": "media",
            "summary": {"type": "video", "ffprobe_available": bool(shutil.which("ffprobe")),
                        "opencv_available": temporal.get("available", False),
                        "frames_examined": temporal.get("frames_examined"),
                        "duplicate_runs": len(temporal.get("duplicate_runs", [])),
                        "abrupt_changes": len(temporal.get("abrupt_changes", [])),
                        "deepfake_model": deepfake_status(), "max_severity": max_severity([sev])},
            "artifacts": [art]}
