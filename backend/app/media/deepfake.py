"""Deepfake analysis slot.

No face-manipulation detector is bundled with IDMF. Media evidence still receives image,
audio and video integrity analysis; this module only reports that deepfake classification
is unavailable, so reports and the dashboard state the gap explicitly instead of implying
a check was performed.
"""
from __future__ import annotations


def status() -> str:
    return "not bundled"


def describe() -> dict:
    return {"enabled": False, "status": status(),
            "note": "Deepfake classification is outside the scope of this prototype; see README roadmap."}
