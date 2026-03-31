from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def utc_now() -> datetime:
    return datetime.now(UTC)


def utc_timestamp(value: datetime | None = None) -> str:
    stamp = value or utc_now()
    return stamp.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def ensure_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def dated_directory(base: Path, stamp: datetime) -> Path:
    return ensure_directory(base / stamp.strftime("%Y") / stamp.strftime("%m") / stamp.strftime("%d"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_name(name: str) -> str:
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
    return "".join(character if character in allowed else "_" for character in name)


def capture_basename(stamp: datetime, source_name: str, sha256: str) -> str:
    original = Path(source_name)
    safe_stem = safe_name(original.stem) or "capture"
    extension = original.suffix.lower() or ".pcap"
    return f"{stamp.strftime('%Y%m%dT%H%M%SZ')}_{safe_stem}_{sha256[:8]}{extension}"


def unique_path(path: Path) -> Path:
    if not path.exists():
        return path
    counter = 1
    while True:
        candidate = path.with_name(f"{path.stem}_{counter}{path.suffix}")
        if not candidate.exists():
            return candidate
        counter += 1


def move_file(source: Path, destination: Path) -> Path:
    ensure_directory(destination.parent)
    target = unique_path(destination)
    shutil.move(str(source), str(target))
    return target


def copy_file(source: Path, destination: Path) -> Path:
    ensure_directory(destination.parent)
    target = unique_path(destination)
    shutil.copy2(source, target)
    return target


def atomic_write_text(path: Path, content: str) -> None:
    ensure_directory(path.parent)
    with tempfile.NamedTemporaryFile("w", delete=False, dir=str(path.parent), encoding="utf-8") as handle:
        handle.write(content)
        temp_path = Path(handle.name)
    temp_path.replace(path)


def atomic_write_json(path: Path, payload: Any) -> None:
    atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def copy_to_latest(source: Path, destination: Path) -> None:
    ensure_directory(destination.parent)
    shutil.copyfile(source, destination)
