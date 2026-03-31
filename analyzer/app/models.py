from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class ClassificationBand:
    name: str
    minimum: float
    maximum: float
    description: str


@dataclass(frozen=True)
class MetricProfile:
    key: str
    label: str
    cap: float
    weight: float


@dataclass(frozen=True)
class IACOProfile:
    name: str
    version: str
    description: str
    metrics: dict[str, MetricProfile]
    bands: tuple[ClassificationBand, ...]

    def metric_caps(self) -> dict[str, float]:
        return {key: metric.cap for key, metric in self.metrics.items()}

    def metric_weights(self) -> dict[str, float]:
        return {key: metric.weight for key, metric in self.metrics.items()}

    def classify(self, score: float) -> ClassificationBand:
        for band in self.bands:
            if band.minimum <= score <= band.maximum:
                return band
        return self.bands[-1]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "metrics": {
                key: asdict(metric) for key, metric in self.metrics.items()
            },
            "bands": [asdict(band) for band in self.bands],
        }


@dataclass(frozen=True)
class CaptureMetrics:
    frames: int
    unique_bssids: int
    unique_clients: int
    probe_activity: int
    disruptive_events: int
    unique_ssids: int
    duration_seconds: float
    top_bssids: list[dict[str, Any]]
    top_ssids: list[dict[str, Any]]

    def to_iaco_inputs(self) -> dict[str, float]:
        return {
            "F": float(self.frames),
            "B": float(self.unique_bssids),
            "K": float(self.unique_clients),
            "P": float(self.probe_activity),
            "D": float(self.disruptive_events),
        }

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CaptureAssessment:
    normalized_metrics: dict[str, float]
    score: float
    classification: str
    band_description: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ProcessedCapture:
    source_name: str
    source_path: str
    stored_path: str
    sha256: str
    capture_format: str
    processed_at: str
    status: str
    metrics: CaptureMetrics
    assessment: CaptureAssessment
    summary_path: str
    detail_csv_path: str
    html_report_path: str
    state_changed: bool
    previous_classification: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_name": self.source_name,
            "source_path": self.source_path,
            "stored_path": self.stored_path,
            "sha256": self.sha256,
            "capture_format": self.capture_format,
            "processed_at": self.processed_at,
            "status": self.status,
            "metrics": self.metrics.to_dict(),
            "assessment": self.assessment.to_dict(),
            "summary_path": self.summary_path,
            "detail_csv_path": self.detail_csv_path,
            "html_report_path": self.html_report_path,
            "state_changed": self.state_changed,
            "previous_classification": self.previous_classification,
        }
