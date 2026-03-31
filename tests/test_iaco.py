from __future__ import annotations

import unittest
from pathlib import Path

from analyzer.app.configuration import load_config
from analyzer.app.models import CaptureMetrics
from analyzer.app.pipeline import calculate_iaco


ROOT = Path(__file__).resolve().parents[1]


class IACOTests(unittest.TestCase):
    def test_iaco_classification_matches_thresholds(self) -> None:
        config = load_config(
            config_path=str(ROOT / "config" / "settings.json"),
            profile_path=str(ROOT / "config" / "profiles" / "default.json"),
            data_root=str(ROOT / ".localdata" / "test-iaco"),
        )
        metrics = CaptureMetrics(
            frames=250,
            unique_bssids=25,
            unique_clients=30,
            probe_activity=20,
            disruptive_events=10,
            unique_ssids=8,
            duration_seconds=3.2,
            top_bssids=[],
            top_ssids=[],
        )
        assessment = calculate_iaco(metrics, config)
        self.assertEqual(assessment.score, 100.0)
        self.assertEqual(assessment.classification, "CRITICO")

    def test_low_values_remain_normal(self) -> None:
        config = load_config(
            config_path=str(ROOT / "config" / "settings.json"),
            profile_path=str(ROOT / "config" / "profiles" / "default.json"),
            data_root=str(ROOT / ".localdata" / "test-iaco-low"),
        )
        metrics = CaptureMetrics(
            frames=10,
            unique_bssids=1,
            unique_clients=2,
            probe_activity=0,
            disruptive_events=0,
            unique_ssids=1,
            duration_seconds=1.0,
            top_bssids=[],
            top_ssids=[],
        )
        assessment = calculate_iaco(metrics, config)
        self.assertLess(assessment.score, 35.0)
        self.assertEqual(assessment.classification, "NORMAL")


if __name__ == "__main__":
    unittest.main()
