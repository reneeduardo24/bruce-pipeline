from __future__ import annotations

import subprocess
from collections import Counter
from collections.abc import Callable
from pathlib import Path

from .models import CaptureMetrics


class TsharkError(RuntimeError):
    pass


class TsharkRunner:
    def __init__(self, binary: str = "tshark", timeout_seconds: int = 120) -> None:
        self.binary = binary
        self.timeout_seconds = timeout_seconds

    def _run(self, arguments: list[str]) -> subprocess.CompletedProcess[str]:
        command = [self.binary, *arguments]
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except FileNotFoundError as error:
            raise TsharkError(str(error)) from error
        if completed.returncode != 0:
            error = completed.stderr.strip() or completed.stdout.strip() or "unknown tshark error"
            raise TsharkError(error)
        return completed

    def validate_capture(self, capture_path: Path) -> None:
        self._run(["-r", str(capture_path), "-q"])

    def _field_lines(self, capture_path: Path, field: str, display_filter: str | None = None) -> list[str]:
        arguments = ["-r", str(capture_path)]
        if display_filter:
            arguments.extend(["-Y", display_filter])
        arguments.extend(["-T", "fields", "-e", field])
        completed = self._run(arguments)
        lines: list[str] = []
        for raw_line in completed.stdout.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            lines.append(line)
        return lines

    def _count(self, capture_path: Path, display_filter: str, field: str = "frame.number") -> int:
        return len(self._field_lines(capture_path, field, display_filter))

    def _unique_count(
        self,
        capture_path: Path,
        field: str,
        display_filter: str | None = None,
        excluded: set[str] | None = None,
    ) -> int:
        excluded_values = {item.lower() for item in (excluded or set())}
        values = {
            value.lower()
            for value in self._field_lines(capture_path, field, display_filter)
            if value.lower() not in excluded_values
        }
        return len(values)

    def _counter(
        self,
        capture_path: Path,
        field: str,
        display_filter: str | None = None,
        limit: int = 5,
        transform: Callable[[str], str] | None = None,
    ) -> list[dict[str, int | str]]:
        transform_fn = transform or (lambda value: value)
        counter = Counter(
            transform_fn(value)
            for value in self._field_lines(capture_path, field, display_filter)
            if value.strip()
        )
        return [
            {"value": value, "count": count}
            for value, count in counter.most_common(limit)
        ]

    def extract_metrics(self, capture_path: Path) -> CaptureMetrics:
        frame_filter = "wlan"
        timestamps = [
            float(value)
            for value in self._field_lines(capture_path, "frame.time_epoch", frame_filter)
        ]
        duration_seconds = round(max(timestamps) - min(timestamps), 3) if timestamps else 0.0
        return CaptureMetrics(
            frames=self._count(capture_path, frame_filter),
            unique_bssids=self._unique_count(capture_path, "wlan.bssid", "wlan.bssid"),
            unique_clients=self._unique_count(
                capture_path,
                "wlan.sa",
                "wlan.sa",
                {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"},
            ),
            probe_activity=self._count(
                capture_path,
                "wlan.fc.type_subtype == 4 || wlan.fc.type_subtype == 5",
            ),
            disruptive_events=self._count(
                capture_path,
                "wlan.fc.type_subtype == 10 || wlan.fc.type_subtype == 12",
            ),
            unique_ssids=self._unique_count(capture_path, "wlan.ssid", "wlan.ssid"),
            duration_seconds=duration_seconds,
            top_bssids=self._counter(capture_path, "wlan.bssid", "wlan.bssid"),
            top_ssids=self._counter(
                capture_path,
                "wlan.ssid",
                "wlan.ssid",
                transform=lambda value: value or "<hidden>",
            ),
        )

    def export_csv_detail(self, capture_path: Path, destination: Path) -> None:
        completed = self._run(
            [
                "-r",
                str(capture_path),
                "-Y",
                "wlan",
                "-T",
                "fields",
                "-E",
                "header=y",
                "-E",
                "separator=,",
                "-E",
                "quote=d",
                "-e",
                "frame.number",
                "-e",
                "frame.time_epoch",
                "-e",
                "wlan.sa",
                "-e",
                "wlan.da",
                "-e",
                "wlan.bssid",
                "-e",
                "wlan.fc.type_subtype",
                "-e",
                "wlan.ssid",
            ]
        )
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(completed.stdout, encoding="utf-8")
