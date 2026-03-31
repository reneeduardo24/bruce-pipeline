from __future__ import annotations

import logging
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .configuration import AppConfig
from .database import Database
from .models import CaptureAssessment, CaptureMetrics, ProcessedCapture
from .reports import ensure_placeholder_dashboard, write_state_files, write_summary_files
from .tshark_metrics import TsharkError
from .utils import (
    atomic_write_json,
    capture_basename,
    dated_directory,
    ensure_directory,
    move_file,
    sha256_file,
    utc_now,
    utc_timestamp,
)


LOGGER = logging.getLogger(__name__)


@dataclass
class PendingObservation:
    size: int
    modified_ns: int


class TsharkClient(Protocol):
    def validate_capture(self, capture_path: Path) -> None:
        ...

    def extract_metrics(self, capture_path: Path) -> CaptureMetrics:
        ...

    def export_csv_detail(self, capture_path: Path, destination: Path) -> None:
        ...


def calculate_iaco(metrics: CaptureMetrics, config: AppConfig) -> CaptureAssessment:
    inputs = metrics.to_iaco_inputs()
    normalized = {}
    score = 0.0
    for key, metric_profile in config.profile.metrics.items():
        normalized_key = f"N{key}"
        normalized_value = min(inputs[key] / metric_profile.cap, 1.0)
        normalized[normalized_key] = round(normalized_value, 4)
        score += metric_profile.weight * normalized_value
    final_score = round(score * 100.0, 2)
    band = config.profile.classify(final_score)
    return CaptureAssessment(
        normalized_metrics=normalized,
        score=final_score,
        classification=band.name,
        band_description=band.description,
    )


class BruceAnalyzerService:
    def __init__(self, config: AppConfig, database: Database, tshark: TsharkClient) -> None:
        self.config = config
        self.database = database
        self.tshark = tshark
        self.pending: dict[Path, PendingObservation] = {}

    def prepare_runtime(self) -> None:
        paths = self.config.paths
        ensure_directory(paths.inbox)
        ensure_directory(paths.processed_pcap)
        ensure_directory(paths.quarantine)
        ensure_directory(paths.duplicates)
        ensure_directory(paths.reports_json)
        ensure_directory(paths.reports_csv)
        ensure_directory(paths.reports_html)
        ensure_directory(paths.state)
        ensure_directory(paths.database.parent)
        ensure_placeholder_dashboard(self.config)
        atomic_write_json(
            self.config.paths.active_profile,
            {
                "loaded_at": utc_timestamp(),
                "profile_path": str(self.config.profile_path),
                "profile": self.config.profile.to_dict(),
            },
        )

    def run_forever(self) -> None:
        self.prepare_runtime()
        LOGGER.info("watching inbox: %s", self.config.paths.inbox)
        while True:
            self.scan_once()
            time.sleep(self.config.poll_interval_seconds)

    def scan_once(self) -> None:
        self.prepare_runtime()
        observed: set[Path] = set()
        for entry in sorted(self.config.paths.inbox.iterdir()):
            if not entry.is_file() or entry.name.startswith("."):
                continue
            observed.add(entry)
            stat = entry.stat()
            current = PendingObservation(size=stat.st_size, modified_ns=stat.st_mtime_ns)
            previous = self.pending.get(entry)
            age = time.time() - stat.st_mtime
            if previous and previous == current and age >= self.config.stable_seconds:
                self.pending.pop(entry, None)
                self._process_with_guard(entry)
            else:
                self.pending[entry] = current

        for stale in list(self.pending):
            if stale not in observed or not stale.exists():
                self.pending.pop(stale, None)

    def _process_with_guard(self, inbox_file: Path) -> None:
        try:
            self.process_file(inbox_file)
        except Exception:
            LOGGER.exception("failed to process %s", inbox_file)

    def process_file(self, inbox_file: Path) -> None:
        processed_at = utc_now()
        processed_at_text = utc_timestamp(processed_at)
        source_name = inbox_file.name
        source_path = str(inbox_file)
        sha256 = sha256_file(inbox_file)
        extension = inbox_file.suffix.lower()

        if extension not in self.config.allowed_extensions:
            final_path = self._move_rejected(inbox_file, self.config.paths.quarantine, processed_at, source_name, sha256)
            self._write_sidecar(final_path, source_name, source_path, sha256, processed_at_text, "unsupported extension")
            self.database.insert_file_event(
                sha256=sha256,
                source_name=source_name,
                source_path=source_path,
                final_path=str(final_path),
                status="quarantined",
                processed_at=processed_at_text,
                reason="unsupported extension",
            )
            LOGGER.warning("quarantined unsupported file: %s", source_name)
            return

        try:
            self.tshark.validate_capture(inbox_file)
        except TsharkError as error:
            final_path = self._move_rejected(inbox_file, self.config.paths.quarantine, processed_at, source_name, sha256)
            self._write_sidecar(final_path, source_name, source_path, sha256, processed_at_text, str(error))
            self.database.insert_file_event(
                sha256=sha256,
                source_name=source_name,
                source_path=source_path,
                final_path=str(final_path),
                status="quarantined",
                processed_at=processed_at_text,
                reason=str(error),
            )
            LOGGER.warning("quarantined invalid capture: %s", source_name)
            return

        existing = self.database.capture_by_sha256(sha256)
        if existing:
            final_path = self._move_rejected(inbox_file, self.config.paths.duplicates, processed_at, source_name, sha256)
            self._write_sidecar(
                final_path,
                source_name,
                source_path,
                sha256,
                processed_at_text,
                f"duplicate of {existing['stored_path']}",
            )
            self.database.insert_file_event(
                sha256=sha256,
                source_name=source_name,
                source_path=source_path,
                final_path=str(final_path),
                status="duplicate",
                processed_at=processed_at_text,
                reason=f"duplicate of {existing['stored_path']}",
            )
            LOGGER.info("duplicate capture moved: %s", source_name)
            return

        stored_path = self._move_valid(inbox_file, processed_at, source_name, sha256)
        try:
            metrics = self.tshark.extract_metrics(stored_path)
            assessment = calculate_iaco(metrics, self.config)
            previous_classification = self.database.last_classification()
            state_changed = previous_classification != assessment.classification

            report_base = capture_basename(processed_at, source_name, sha256).rsplit(".", 1)[0]
            json_dir = dated_directory(self.config.paths.reports_json, processed_at)
            csv_dir = dated_directory(self.config.paths.reports_csv, processed_at)
            html_dir = dated_directory(self.config.paths.reports_html, processed_at)
            summary_path = json_dir / f"{report_base}.json"
            detail_csv_path = csv_dir / f"{report_base}.csv"
            html_path = html_dir / f"{report_base}.html"

            self.tshark.export_csv_detail(stored_path, detail_csv_path)
            capture = ProcessedCapture(
                source_name=source_name,
                source_path=source_path,
                stored_path=str(stored_path),
                sha256=sha256,
                capture_format=extension.lstrip("."),
                processed_at=processed_at_text,
                status="processed",
                metrics=metrics,
                assessment=assessment,
                summary_path=str(summary_path),
                detail_csv_path=str(detail_csv_path),
                html_report_path=str(html_path),
                state_changed=state_changed,
                previous_classification=previous_classification,
            )
            summary = write_summary_files(
                capture=capture,
                config=self.config,
                summary_path=summary_path,
                html_path=html_path,
            )
            write_state_files(summary, self.config)

            self.database.insert_capture(
                {
                    "sha256": sha256,
                    "source_name": source_name,
                    "stored_path": str(stored_path),
                    "processed_at": processed_at_text,
                    "capture_format": extension.lstrip("."),
                    "classification": assessment.classification,
                    "iaco": assessment.score,
                    "metrics": metrics.to_dict(),
                    "summary_path": str(summary_path),
                    "detail_csv_path": str(detail_csv_path),
                    "html_report_path": str(html_path),
                }
            )
            self.database.insert_file_event(
                sha256=sha256,
                source_name=source_name,
                source_path=source_path,
                final_path=str(stored_path),
                status="processed",
                processed_at=processed_at_text,
                reason=None,
            )
            if state_changed:
                self.database.insert_state_change(
                    classification=assessment.classification,
                    iaco=assessment.score,
                    source_sha256=sha256,
                    summary_path=str(summary_path),
                    changed_at=processed_at_text,
                )
                self._run_hook(capture)
            LOGGER.info("processed capture: %s -> %s", source_name, stored_path)
        except Exception as error:
            quarantine_path = self._move_existing_to_quarantine(
                stored_path,
                processed_at,
                source_name,
                sha256,
            )
            self._write_sidecar(
                quarantine_path,
                source_name,
                source_path,
                sha256,
                processed_at_text,
                f"processing failure: {error}",
            )
            self.database.insert_file_event(
                sha256=sha256,
                source_name=source_name,
                source_path=source_path,
                final_path=str(quarantine_path),
                status="quarantined",
                processed_at=processed_at_text,
                reason=f"processing failure: {error}",
            )
            raise

    def _move_valid(self, inbox_file: Path, stamp, source_name: str, sha256: str) -> Path:
        destination = dated_directory(self.config.paths.processed_pcap, stamp) / capture_basename(stamp, source_name, sha256)
        return move_file(inbox_file, destination)

    def _move_rejected(self, inbox_file: Path, base: Path, stamp, source_name: str, sha256: str) -> Path:
        destination = dated_directory(base, stamp) / capture_basename(stamp, source_name, sha256)
        return move_file(inbox_file, destination)

    def _move_existing_to_quarantine(self, stored_path: Path, stamp, source_name: str, sha256: str) -> Path:
        destination = dated_directory(self.config.paths.quarantine, stamp) / capture_basename(stamp, source_name, sha256)
        return move_file(stored_path, destination)

    def _write_sidecar(
        self,
        final_path: Path,
        source_name: str,
        source_path: str,
        sha256: str,
        processed_at: str,
        reason: str,
    ) -> None:
        atomic_write_json(
            final_path.with_suffix(final_path.suffix + ".json"),
            {
                "source_name": source_name,
                "source_path": source_path,
                "stored_path": str(final_path),
                "sha256": sha256,
                "processed_at": processed_at,
                "reason": reason,
            },
        )

    def _run_hook(self, capture: ProcessedCapture) -> None:
        hook_path = self.config.hook_path
        if not hook_path.exists():
            LOGGER.info("hook skipped, file not found: %s", hook_path)
            return
        if os.name != "nt" and not os.access(hook_path, os.X_OK):
            LOGGER.info("hook skipped, file is not executable: %s", hook_path)
            return
        env = os.environ.copy()
        env.update(
            {
                "BRUCE_OLD_CLASSIFICATION": capture.previous_classification or "NONE",
                "BRUCE_NEW_CLASSIFICATION": capture.assessment.classification,
                "BRUCE_IACO_SCORE": f"{capture.assessment.score:.2f}",
                "BRUCE_STATE_FILE": str(self.config.paths.current_state),
                "BRUCE_SUMMARY_FILE": capture.summary_path,
                "BRUCE_CAPTURE_NAME": capture.source_name,
                "BRUCE_CAPTURE_SHA256": capture.sha256,
                "BRUCE_CAPTURE_PATH": capture.stored_path,
                "BRUCE_PROCESSED_AT": capture.processed_at,
                "BRUCE_HOOK_LOG_FILE": str(self.config.paths.hook_log),
            }
        )
        command = [str(hook_path)]
        if os.name == "nt" and hook_path.suffix == ".sh":
            LOGGER.info("hook skipped on Windows host: %s", hook_path)
            return
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=self.config.hook_timeout_seconds,
            env=env,
            check=False,
        )
        if completed.returncode != 0:
            message = completed.stderr.strip() or completed.stdout.strip() or "hook failed"
            LOGGER.warning("hook execution failed: %s", message)
