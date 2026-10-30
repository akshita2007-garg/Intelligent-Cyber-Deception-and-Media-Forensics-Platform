"""Audio forensics.

WAV files are analysed natively (standard library + NumPy):
  * format and RIFF LIST/INFO metadata (software, creation date, artist)
  * level statistics: peak and RMS in dBFS, clipping ratio, DC offset, silence ratio
  * effective bandwidth (99% spectral roll-off): a hard cut-off well below Nyquist suggests a
    lossy-compression or resampling history
  * splice candidates: sample-to-sample discontinuities that are extreme relative to the
    local signal (robust z-score), and abrupt level jumps between adjacent 10 ms frames
Other formats (mp3, m4a, flac, ogg, aac) get container metadata through ffprobe when it is
installed. Results are indicators for an examiner, not a verdict.
"""
from __future__ import annotations

import json
import shutil
import struct
import subprocess
import wave
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw

from ..core.entities import artifact, ent, max_severity

AUDIO_EXT = {".wav", ".mp3", ".m4a", ".flac", ".ogg", ".aac", ".wma", ".opus"}
EDITORS = ("audacity", "audition", "lavf", "ffmpeg", "sox", "garageband", "reaper", "logic", "wavepad", "ocenaudio")


def _riff_info(path: Path) -> dict:
    """Reads LIST/INFO tags from a RIFF/WAVE file."""
    tags = {}
    names = {b"ISFT": "software", b"ICRD": "created", b"IART": "artist", b"INAM": "title",
             b"ICMT": "comment", b"IENG": "engineer"}
    data = path.read_bytes()
    if data[:4] != b"RIFF" or data[8:12] != b"WAVE":
        return tags
    off = 12
    while off + 8 <= len(data):
        cid, size = data[off:off + 4], struct.unpack("<I", data[off + 4:off + 8])[0]
        body = data[off + 8:off + 8 + size]
        if cid == b"LIST" and body[:4] == b"INFO":
            o = 4
            while o + 8 <= len(body):
                tid, tsz = body[o:o + 4], struct.unpack("<I", body[o + 4:o + 8])[0]
                val = body[o + 8:o + 8 + tsz].split(b"\x00")[0].decode("latin-1", "replace").strip()
                if tid in names and val:
                    tags[names[tid]] = val
                o += 8 + tsz + (tsz & 1)
        off += 8 + size + (size & 1)
    return tags


def read_wav(path: Path) -> tuple[np.ndarray, int, int, int]:
    """Returns (mono float signal in [-1, 1], sample_rate, channels, bits)."""
    with wave.open(str(path), "rb") as w:
        sr, ch, sw, n = w.getframerate(), w.getnchannels(), w.getsampwidth(), w.getnframes()
        raw = w.readframes(n)
    if sw == 1:
        x = (np.frombuffer(raw, dtype=np.uint8).astype(np.float32) - 128) / 128
    elif sw == 2:
        x = np.frombuffer(raw, dtype="<i2").astype(np.float32) / 32768
    elif sw == 3:
        b = np.frombuffer(raw, dtype=np.uint8).reshape(-1, 3)
        v = (b[:, 0].astype(np.int32) | (b[:, 1].astype(np.int32) << 8) | (b[:, 2].astype(np.int32) << 16))
        v = np.where(v & 0x800000, v - 0x1000000, v)
        x = v.astype(np.float32) / 8388608
    else:
        x = np.frombuffer(raw, dtype="<i4").astype(np.float32) / 2147483648
    if ch > 1:
        x = x.reshape(-1, ch).mean(axis=1)
    return x, sr, ch, sw * 8


def _db(v: float) -> float:
    return float(20 * np.log10(max(v, 1e-9)))


def _avg_spectrum(x: np.ndarray, nfft: int = 4096) -> np.ndarray | None:
    if len(x) < nfft * 2:
        return None
    frames = np.lib.stride_tricks.sliding_window_view(x, nfft)[:: nfft // 2][:400]
    return (np.abs(np.fft.rfft(frames * np.hanning(nfft), axis=1)) ** 2).mean(axis=0)


def bandwidth_hz(x: np.ndarray, sr: int, nfft: int = 4096) -> float | None:
    """99% spectral roll-off (where most of the energy lies)."""
    spec = _avg_spectrum(x, nfft)
    if spec is None:
        return None
    cum = np.cumsum(spec) / (spec.sum() + 1e-12)
    return float(int(np.searchsorted(cum, 0.99)) * sr / nfft)


def lowpass_wall_hz(x: np.ndarray, sr: int, nfft: int = 4096) -> float | None:
    """Frequency of a sharp spectral 'wall' (>= 40 dB drop within ~1 kHz, nothing above it), as left by
    MP3/AAC encoders' low-pass filters. Returns None for signals with no such wall (e.g. a tone in noise)."""
    spec = _avg_spectrum(x, nfft)
    if spec is None:
        return None
    db = 10 * np.log10(spec / (spec.max() + 1e-20) + 1e-20)
    above = np.where(db > -70)[0]
    if not len(above):
        return None
    top = int(above[-1])
    f_top = top * sr / nfft
    if not (8000 <= f_top <= 0.8 * sr / 2):
        return None
    k = max(2, int(1000 / (sr / nfft)))
    below = float(np.median(db[max(0, top - k):top]))
    beyond = float(np.median(db[top + 1:top + 1 + k])) if top + 1 + k <= len(db) else -200.0
    return f_top if below > -45 and below - beyond >= 40 else None


def splice_candidates(x: np.ndarray, sr: int, block: int = 1024, z_thr: float = 14.0, abs_thr: float = 0.08) -> list[dict]:
    """Samples whose first difference is extreme relative to the surrounding block."""
    if len(x) < block * 4:
        return []
    d = np.abs(np.diff(x))
    nb = len(d) // block
    blocks = d[: nb * block].reshape(nb, block)
    med = np.median(blocks, axis=1)
    mad = np.median(np.abs(blocks - med[:, None]), axis=1) * 1.4826 + 1e-4
    # use the neighbouring blocks' scale so the jump itself does not inflate its own MAD
    scale = np.minimum(np.roll(mad, 1), np.roll(mad, -1))
    scale[0], scale[-1] = mad[1], mad[-2]
    z = (blocks - med[:, None]) / np.maximum(scale, 1e-4)[:, None]
    hits = np.argwhere((z > z_thr) & (blocks > abs_thr))
    out, last = [], -10 ** 9
    for b, i in hits:
        pos = int(b * block + i)
        if pos - last > sr * 0.05:            # merge hits closer than 50 ms
            out.append({"time_s": round(pos / sr, 3), "jump": round(float(blocks[b, i]), 3), "z": round(float(z[b, i]), 1)})
        last = pos
        if len(out) >= 20:
            break
    return out


def level_jumps(x: np.ndarray, sr: int, jump_db: float = 24.0) -> list[dict]:
    """Abrupt level changes between adjacent 10 ms frames (both frames above the noise floor)."""
    n = max(1, sr // 100)
    nf = len(x) // n
    if nf < 3:
        return []
    rms = np.sqrt((x[: nf * n].reshape(nf, n) ** 2).mean(axis=1) + 1e-12)
    db = 20 * np.log10(rms)
    out = []
    for i in range(1, nf):
        if min(db[i], db[i - 1]) > -45 and abs(db[i] - db[i - 1]) > jump_db:
            out.append({"time_s": round(i * n / sr, 3), "delta_db": round(float(db[i] - db[i - 1]), 1)})
            if len(out) >= 20:
                break
    return out


def _waveform_png(x: np.ndarray, out: Path, marks: list[float], sr: int) -> None:
    w, h = 900, 160
    img = Image.new("RGB", (w, h), (11, 16, 32))
    d = ImageDraw.Draw(img)
    if len(x):
        cols = np.array_split(np.abs(x), w)
        for i, c in enumerate(cols):
            a = float(c.max()) if len(c) else 0.0
            d.line([(i, h / 2 - a * h / 2), (i, h / 2 + a * h / 2)], fill=(76, 201, 240))
        dur = len(x) / sr
        for t in marks:
            xp = int(t / dur * w) if dur else 0
            d.line([(xp, 0), (xp, h)], fill=(255, 93, 115), width=2)
    img.save(out)


def analyse(path: Path, derived_dir: Path | None = None) -> dict:
    ents = [ent("filename", path.name)]
    if path.suffix.lower() != ".wav":
        return _ffprobe_only(path, ents)
    x, sr, ch, bits = read_wav(path)
    tags = _riff_info(path)
    dur = len(x) / sr if sr else 0
    peak = float(np.max(np.abs(x))) if len(x) else 0.0
    rms = float(np.sqrt(np.mean(x ** 2))) if len(x) else 0.0
    clip = float(np.mean(np.abs(x) >= 0.999)) if len(x) else 0.0
    n10 = max(1, sr // 100)
    nf = len(x) // n10
    silence = float(np.mean(20 * np.log10(np.sqrt((x[: nf * n10].reshape(nf, n10) ** 2).mean(axis=1) + 1e-12)) < -60)) if nf else 0.0
    bw = bandwidth_hz(x, sr)
    wall = lowpass_wall_hz(x, sr)
    splices = splice_candidates(x, sr)
    jumps = level_jumps(x, sr)
    ind = []
    sw = tags.get("software", "")
    if any(e in sw.lower() for e in EDITORS):
        ind.append(f"Processed with audio software: {sw}")
    if splices:
        ind.append(f"{len(splices)} abrupt waveform discontinuity(ies), first at {splices[0]['time_s']} s (possible splice)")
    if jumps:
        ind.append(f"{len(jumps)} abrupt level jump(s) >24 dB between 10 ms frames, first at {jumps[0]['time_s']} s")
    if clip > 0.01:
        ind.append(f"Clipping on {clip * 100:.1f}% of samples")
    if wall:
        ind.append(f"Sharp low-pass at {wall / 1000:.1f} kHz although Nyquist is {sr / 2000:.1f} kHz (possible lossy-codec or resampling history)")
    wav_png = None
    if derived_dir is not None:
        derived_dir.mkdir(parents=True, exist_ok=True)
        wav_png = derived_dir / f"{path.stem}_waveform.png"
        _waveform_png(x, wav_png, [s["time_s"] for s in splices], sr)
    if tags.get("software"):
        ents.append({"type": "software", "value": tags["software"].lower()})
    if tags.get("artist"):
        ents.append(ent("user", tags["artist"]))
    edit_signals = len(splices) > 0 or len(jumps) > 0
    editor_meta = any(e in sw.lower() for e in EDITORS)
    sev = "medium" if edit_signals else ("low" if ind else "info")
    verdict = ("possible editing detected" if edit_signals else
               "processed with editing software (metadata only)" if editor_meta else "no editing indicators")
    art = artifact("media.audio", f"Audio {path.name}: {verdict}", None, ents,
                   detail={"format": "WAV", "sample_rate": sr, "channels": ch, "bits": bits, "duration_s": round(dur, 3),
                           "peak_dbfs": round(_db(peak), 1), "rms_dbfs": round(_db(rms), 1),
                           "clipping_ratio": round(clip, 5), "dc_offset": round(float(np.mean(x)) if len(x) else 0.0, 5),
                           "silence_ratio": round(silence, 3), "bandwidth_hz": round(bw) if bw else None,
                           "lowpass_wall_hz": round(wall) if wall else None,
                           "splice_candidates": splices, "level_jumps": jumps, "tags": tags, "verdict": verdict,
                           "waveform_image": wav_png.name if wav_png else None},
                   severity=sev, indicators=ind)
    return {"module": "media",
            "summary": {"type": "audio", "format": "WAV", "duration_s": round(dur, 2), "sample_rate": sr,
                        "splice_candidates": len(splices), "level_jumps": len(jumps), "verdict": verdict,
                        "max_severity": max_severity([sev])},
            "artifacts": [art]}


def _ffprobe_only(path: Path, ents: list) -> dict:
    meta = {}
    if shutil.which("ffprobe"):
        try:
            meta = json.loads(subprocess.run(["ffprobe", "-v", "quiet", "-print_format", "json", "-show_format",
                                              "-show_streams", str(path)], capture_output=True, text=True, timeout=60).stdout or "{}")
        except Exception:
            meta = {}
    fmt = meta.get("format", {})
    tags = {k.lower(): v for k, v in (fmt.get("tags") or {}).items()}
    enc = (tags.get("encoder", "") + " " + tags.get("encoded_by", "")).strip()
    ind = [f"Encoded/processed with {enc}"] if any(e in enc.lower() for e in EDITORS) else []
    art = artifact("media.audio", f"Audio {path.name}", tags.get("creation_time"), ents,
                   detail={"ffprobe": bool(meta), "duration_s": fmt.get("duration"), "tags": tags,
                           "streams": [{"codec": s.get("codec_name"), "sample_rate": s.get("sample_rate")} for s in meta.get("streams", [])],
                           "note": "Waveform analysis is implemented for WAV; convert with ffmpeg for full analysis."},
                   severity="low" if ind else "info", indicators=ind)
    return {"module": "media", "summary": {"type": "audio", "ffprobe_available": bool(shutil.which("ffprobe")),
                                           "max_severity": art["severity"]}, "artifacts": [art]}
