from __future__ import annotations

import argparse
import logging

from .configuration import load_config
from .database import Database
from .pipeline import BruceAnalyzerService
from .tshark_metrics import TsharkRunner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Bruce Pipeline analyzer")
    parser.add_argument("command", nargs="?", default="run", choices=("run", "scan-once"))
    parser.add_argument("--config", dest="config_path")
    parser.add_argument("--profile", dest="profile_path")
    parser.add_argument("--data-root", dest="data_root")
    parser.add_argument("--log-level", default="INFO")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    config = load_config(
        config_path=args.config_path,
        profile_path=args.profile_path,
        data_root=args.data_root,
    )
    database = Database(config.paths.database)
    tshark = TsharkRunner(timeout_seconds=config.tshark_timeout_seconds)
    service = BruceAnalyzerService(config, database, tshark)

    try:
        if args.command == "scan-once":
            service.scan_once()
            return 0
        service.run_forever()
        return 0
    finally:
        database.close()
