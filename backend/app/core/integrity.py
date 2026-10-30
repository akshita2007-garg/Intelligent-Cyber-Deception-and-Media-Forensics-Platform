"""Evidence integrity: streaming SHA-256/MD5 and write-once storage."""
from __future__ import annotations

import hashlib
import os
import shutil
import stat
from pathlib import Path

CHUNK = 1024 * 1024


def file_hashes(path: str | Path) -> tuple[str, str]:
    sha, md5 = hashlib.sha256(), hashlib.md5()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(CHUNK), b""):
            sha.update(block)
            md5.update(block)
    return sha.hexdigest(), md5.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def store_write_once(src: Path, vault_dir: Path, sha256: str, filename: str) -> Path:
    """Copy into the vault under its hash and mark read-only, so analysis never touches the original."""
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in filename)[-120:]
    dest = vault_dir / sha256[:2] / f"{sha256}_{safe}"
    dest.parent.mkdir(parents=True, exist_ok=True)
    if not dest.exists():
        shutil.copyfile(src, dest)
        os.chmod(dest, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
    return dest
