"""Runtime configuration. Everything can be overridden with environment variables."""
from __future__ import annotations

import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = Path(os.environ.get("IDMF_DATA_DIR", BASE_DIR / "data"))
EVIDENCE_DIR = DATA_DIR / "evidence"          # write-once evidence vault
DERIVED_DIR = DATA_DIR / "derived"            # ELA maps, exports, reports
FRONTEND_DIR = BASE_DIR / "frontend"

for _d in (DATA_DIR, EVIDENCE_DIR, DERIVED_DIR):
    _d.mkdir(parents=True, exist_ok=True)

# SQLite by default so the prototype runs anywhere; set DATABASE_URL to use PostgreSQL,
# e.g. postgresql+psycopg2://user:pass@localhost:5432/idmf
DATABASE_URL = os.environ.get("DATABASE_URL", f"sqlite:///{(DATA_DIR / 'idmf.db').as_posix()}")


def _load_secret() -> str:
    env = os.environ.get("IDMF_SECRET")
    if env:
        return env
    f = DATA_DIR / ".secret"
    if f.exists():
        return f.read_text().strip()
    s = secrets.token_hex(32)
    f.write_text(s)
    return s


SECRET_KEY = _load_secret()
TOKEN_TTL_SECONDS = int(os.environ.get("IDMF_TOKEN_TTL", 12 * 3600))
MAX_UPLOAD_MB = int(os.environ.get("IDMF_MAX_UPLOAD_MB", 512))

# Correlation engine parameters (tuned on the synthetic calibration split; see experiments/)
CORR_TIME_WINDOW_MIN = float(os.environ.get("IDMF_CORR_WINDOW_MIN", 15))
CORR_LINK_THRESHOLD = float(os.environ.get("IDMF_CORR_THRESHOLD", 3.0))
CORR_MAX_DF_RATIO = float(os.environ.get("IDMF_CORR_MAX_DF", 0.5))

# Media forensics decision threshold on the combined manipulation score (0..1)
MEDIA_THRESHOLD = float(os.environ.get("IDMF_MEDIA_THRESHOLD", 0.5))

# Optional LLM for narrative generation. Facts are always produced locally; the LLM only
# rewrites them into prose and its output is verified sentence by sentence.
LLM_PROVIDER = os.environ.get("IDMF_LLM_PROVIDER", "")        # "anthropic" | "openai" | ""
LLM_API_KEY = os.environ.get("IDMF_LLM_API_KEY", "")
LLM_MODEL = os.environ.get("IDMF_LLM_MODEL", "")
LLM_BASE_URL = os.environ.get("IDMF_LLM_BASE_URL", "")

# Public base URL used inside canary-URL honeytokens
PUBLIC_BASE_URL = os.environ.get("IDMF_PUBLIC_URL", "http://127.0.0.1:8000")
