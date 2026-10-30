"""Synthetic audio and video samples for the demo case and tests (inert, generated from a seed)."""
from __future__ import annotations

import struct
import wave
from pathlib import Path

import numpy as np


def _write_wav(path: Path, x: np.ndarray, sr: int, info: dict[bytes, str] | None = None) -> None:
    with wave.open(str(path), "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(sr)
        w.writeframes((np.clip(x, -1, 1) * 32767).astype("<i2").tobytes())
    if info:
        sub = b"INFO"
        for k, v in info.items():
            vb = v.encode() + b"\x00"
            if len(vb) % 2:
                vb += b"\x00"
            sub += k + struct.pack("<I", len(vb)) + vb
        lst = b"LIST" + struct.pack("<I", len(sub)) + sub
        b = path.read_bytes()
        path.write_bytes(b[:4] + struct.pack("<I", len(b) - 8 + len(lst)) + b[8:] + lst)


def make_voicemail(path: Path, seed: int = 0, spliced: bool = True, sr: int = 22050, seconds: float = 4.0) -> dict:
    """A speech-like signal (vowel formants, syllable envelope). If spliced, a segment from a
    different 'take' is inserted with a phase/level discontinuity and editing-software metadata."""
    rng = np.random.default_rng(seed)
    n = int(sr * seconds)
    t = np.arange(n) / sr

    def take(f0, phase):
        env = 0.55 + 0.45 * np.sin(2 * np.pi * 3.2 * t + phase) ** 2
        sig = sum(a * np.sin(2 * np.pi * f0 * h * t + phase * h) for h, a in ((1, 0.5), (2, 0.25), (3, 0.12), (5, 0.06)))
        return 0.5 * env * sig + 0.01 * rng.normal(size=n)

    a = take(rng.uniform(110, 140), 0.0)
    if not spliced:
        _write_wav(path, a, sr)
        return {"spliced": False}
    b = 1.4 * take(rng.uniform(150, 190), 2.1)
    # a careless cut: join the takes where the waveforms disagree, as hand edits often do
    cut1 = int(n * 0.35)
    off = next((o for o in range(0, 4000) if abs(a[cut1 - 1] - b[cut1 + o]) > 0.35), 777)
    cut2 = next((c for c in range(int(n * 0.6), int(n * 0.6) + 4000) if abs(b[c - 1] - a[c]) > 0.35), int(n * 0.6))
    x = np.concatenate([a[:cut1], b[cut1 + off:cut2], a[cut2:]])
    _write_wav(path, x, sr, {b"ISFT": "Audacity 3.4.2", b"ICRD": "2026-03-02"})
    return {"spliced": True, "splice_times_s": [round(cut1 / sr, 3), round((cut2 - off) / sr, 3)]}


def make_cctv_clip(path: Path, frames: int = 90, freeze=(40, 47), cut_at: int = 70) -> dict:
    """A short MP4 with a moving object, a frozen-frame run and a hard cut. Requires OpenCV."""
    try:
        import cv2
    except ImportError:
        return {"created": False, "reason": "opencv not installed"}
    vw = cv2.VideoWriter(str(path), cv2.VideoWriter_fourcc(*"mp4v"), 25, (320, 240))
    for i in range(frames):
        j = freeze[0] if freeze[0] <= i < freeze[1] else i
        img = np.full((240, 320, 3), 45, np.uint8)
        if i >= cut_at:
            img[:] = (190, 170, 70)
        cv2.rectangle(img, (10 + (j * 3) % 260, 100), (50 + (j * 3) % 260, 140), (240, 240, 240), -1)
        cv2.putText(img, f"CAM-02 {i:04d}", (8, 20), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (200, 200, 200), 1)
        vw.write(img)
    vw.release()
    return {"created": path.exists(), "freeze": list(freeze), "cut_at": cut_at}
