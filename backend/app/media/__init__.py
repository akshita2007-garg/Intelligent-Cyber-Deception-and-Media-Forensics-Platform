"""Media forensics layer: image, audio, video (deepfake classification slot not bundled)."""
from __future__ import annotations

from pathlib import Path

from . import audio_forensics, image_forensics, video_forensics

IMAGE_EXT = image_forensics.IMAGE_EXT
AUDIO_EXT = audio_forensics.AUDIO_EXT
VIDEO_EXT = video_forensics.VIDEO_EXT


def analyse(path: Path, derived_dir: Path | None = None) -> dict:
    ext = path.suffix.lower()
    head = path.read_bytes()[:16]
    if ext in IMAGE_EXT or head[:3] == b"\xff\xd8\xff" or head[:8] == b"\x89PNG\r\n\x1a\n":
        return image_forensics.analyse_image(path, derived_dir)
    if ext in AUDIO_EXT or (head[:4] == b"RIFF" and head[8:12] == b"WAVE"):
        return audio_forensics.analyse(path, derived_dir)
    return video_forensics.analyse(path, derived_dir)
