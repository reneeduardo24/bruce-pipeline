from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from .models import ClassificationBand, IACOProfile, MetricProfile


REPO_ROOT = Path(__file__).resolve().parents[2]
CONTAINER_CONFIG_PATH = Path("/app/config/settings.json")
CONTAINER_PROFILE_PATH = Path("/app/config/profiles/default.json")
LOCAL_CONFIG_PATH = REPO_ROOT / "config" / "settings.json"
LOCAL_PROFILE_PATH = REPO_ROOT / "config" / "profiles" / "default.json"
CONTAINER_HOOK_PATH = Path("/app/hooks/on_state_change.sh")
LOCAL_HOOK_PATH = REPO_ROOT / "hooks" / "on_state_change.sh"


@dataclass(frozen=True)
class RuntimePaths:
    data_root: Path
    inbox: Path
    processed_pcap: Path
    quarantine: Path
    duplicates: Path
    reports_json: Path
    reports_csv: Path
    reports_html: Path
    state: Path
    database: Path
    latest_summary: Path
    latest_csv: Path
    latest_html: Path
    current_state: Path
    active_profile: Path
    hook_log: Path


@dataclass(frozen=True)
class AppConfig:
    app_name: str
    poll_interval_seconds: int
    stable_seconds: int
    tshark_timeout_seconds: int
    hook_timeout_seconds: int
    allowed_extensions: tuple[str, ...]
    hook_path: Path
    profile_path: Path
    config_path: Path
    paths: RuntimePaths
    profile: IACOProfile


def _read_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _default_path(container_path: Path, local_path: Path) -> Path:
    return container_path if container_path.exists() else local_path


def _load_profile(path: Path) -> IACOProfile:
    data = _read_json(path)
    metrics = {
        key: MetricProfile(
            key=key,
            label=value["label"],
            cap=float(value["cap"]),
            weight=float(value["weight"]),
        )
        for key, value in data["metrics"].items()
    }
    bands = tuple(
        ClassificationBand(
            name=band["name"],
            minimum=float(band["min"]),
            maximum=float(band["max"]),
            description=band["description"],
        )
        for band in data["bands"]
    )
    return IACOProfile(
        name=data["name"],
        version=data["version"],
        description=data["description"],
        metrics=metrics,
        bands=bands,
    )


def load_config(
    config_path: str | None = None,
    profile_path: str | None = None,
    data_root: str | None = None,
) -> AppConfig:
    selected_config = Path(
        config_path
        or os.getenv("CONFIG_PATH")
        or _default_path(CONTAINER_CONFIG_PATH, LOCAL_CONFIG_PATH)
    )
    selected_profile = Path(
        profile_path
        or os.getenv("PROFILE_PATH")
        or _default_path(CONTAINER_PROFILE_PATH, LOCAL_PROFILE_PATH)
    )
    settings = _read_json(selected_config)

    root = Path(data_root or os.getenv("DATA_ROOT") or "/data")
    directories = settings["directories"]
    paths = RuntimePaths(
        data_root=root,
        inbox=root / directories["inbox"],
        processed_pcap=root / directories["processed_pcap"],
        quarantine=root / directories["quarantine"],
        duplicates=root / directories["duplicates"],
        reports_json=root / directories["reports_json"],
        reports_csv=root / directories["reports_csv"],
        reports_html=root / directories["reports_html"],
        state=root / directories["state"],
        database=root / directories["database"],
        latest_summary=root / directories["reports_json"] / "latest.json",
        latest_csv=root / directories["reports_csv"] / "latest.csv",
        latest_html=root / directories["reports_html"] / "index.html",
        current_state=root / directories["state"] / "current_state.json",
        active_profile=root / directories["state"] / "active_profile.json",
        hook_log=root / directories["state"] / "hook-events.log",
    )
    return AppConfig(
        app_name=settings["app_name"],
        poll_interval_seconds=int(os.getenv("POLL_INTERVAL_SECONDS") or settings["poll_interval_seconds"]),
        stable_seconds=int(os.getenv("STABLE_SECONDS") or settings["stable_seconds"]),
        tshark_timeout_seconds=int(
            os.getenv("TSHARK_TIMEOUT_SECONDS") or settings["tshark_timeout_seconds"]
        ),
        hook_timeout_seconds=int(
            os.getenv("HOOK_TIMEOUT_SECONDS") or settings["hook_timeout_seconds"]
        ),
        allowed_extensions=tuple(settings["allowed_extensions"]),
        hook_path=Path(os.getenv("HOOK_PATH") or _default_path(CONTAINER_HOOK_PATH, LOCAL_HOOK_PATH)),
        profile_path=selected_profile,
        config_path=selected_config,
        paths=paths,
        profile=_load_profile(selected_profile),
    )
