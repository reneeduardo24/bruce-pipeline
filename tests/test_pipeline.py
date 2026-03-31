from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from analyzer.app.configuration import load_config
from analyzer.app.database import Database
from analyzer.app.models import CaptureMetrics
from analyzer.app.pipeline import BruceAnalyzerService


ROOT = Path(__file__).resolve().parents[1]


class FakeTshark:
    def validate_capture(self, capture_path: Path) -> None:
        if capture_path.suffix.lower() not in {".pcap", ".pcapng"}:
            raise RuntimeError("invalid capture")

    def extract_metrics(self, capture_path: Path) -> CaptureMetrics:
        return CaptureMetrics(
            frames=100,
            unique_bssids=10,
            unique_clients=12,
            probe_activity=3,
            disruptive_events=1,
            unique_ssids=4,
            duration_seconds=2.5,
            top_bssids=[{"value": "aa:bb:cc:dd:ee:ff", "count": 40}],
            top_ssids=[{"value": "BruceLab", "count": 12}],
        )

    def export_csv_detail(self, capture_path: Path, destination: Path) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            "frame.number,frame.time_epoch,wlan.sa,wlan.da,wlan.bssid,wlan.fc.type_subtype,wlan.ssid\n"
            "1,1.0,aa,bb,cc,4,BruceLab\n",
            encoding="utf-8",
        )


class PipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = Path(tempfile.mkdtemp(prefix="bruce-pipeline-tests-"))
        self.config = load_config(
            config_path=str(ROOT / "config" / "settings.json"),
            profile_path=str(ROOT / "config" / "profiles" / "default.json"),
            data_root=str(self.temp_dir / "data"),
        )
        self.database = Database(self.config.paths.database)
        self.service = BruceAnalyzerService(self.config, self.database, FakeTshark())
        self.service.prepare_runtime()

    def tearDown(self) -> None:
        self.database.close()
        shutil.rmtree(self.temp_dir)

    def test_process_file_generates_outputs(self) -> None:
        inbox_file = self.config.paths.inbox / "capture.pcap"
        inbox_file.write_bytes(b"pcap-data")
        self.service.process_file(inbox_file)

        processed_files = list(self.config.paths.processed_pcap.rglob("*.pcap"))
        self.assertEqual(len(processed_files), 1)
        self.assertTrue(self.config.paths.latest_summary.exists())
        self.assertTrue(self.config.paths.latest_csv.exists())
        self.assertTrue(self.config.paths.latest_html.exists())
        self.assertTrue(self.config.paths.current_state.exists())

    def test_duplicate_file_is_separated(self) -> None:
        first = self.config.paths.inbox / "first.pcap"
        second = self.config.paths.inbox / "second.pcap"
        first.write_bytes(b"same-content")
        self.service.process_file(first)
        second.write_bytes(b"same-content")
        self.service.process_file(second)

        duplicates = list(self.config.paths.duplicates.rglob("*.pcap"))
        processed = list(self.config.paths.processed_pcap.rglob("*.pcap"))
        self.assertEqual(len(processed), 1)
        self.assertEqual(len(duplicates), 1)


if __name__ == "__main__":
    unittest.main()
