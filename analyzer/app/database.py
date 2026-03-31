from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


class Database:
    def __init__(self, database_path: Path) -> None:
        database_path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(database_path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA journal_mode=WAL")
        self._initialize()

    def _initialize(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS captures (
                sha256 TEXT PRIMARY KEY,
                source_name TEXT NOT NULL,
                stored_path TEXT NOT NULL,
                processed_at TEXT NOT NULL,
                capture_format TEXT NOT NULL,
                classification TEXT NOT NULL,
                iaco REAL NOT NULL,
                metrics_json TEXT NOT NULL,
                summary_path TEXT NOT NULL,
                detail_csv_path TEXT NOT NULL,
                html_report_path TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS file_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sha256 TEXT,
                source_name TEXT NOT NULL,
                source_path TEXT NOT NULL,
                final_path TEXT NOT NULL,
                status TEXT NOT NULL,
                processed_at TEXT NOT NULL,
                reason TEXT
            );

            CREATE TABLE IF NOT EXISTS state_changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                classification TEXT NOT NULL,
                iaco REAL NOT NULL,
                source_sha256 TEXT NOT NULL,
                summary_path TEXT NOT NULL,
                changed_at TEXT NOT NULL
            );
            """
        )
        self.connection.commit()

    def capture_by_sha256(self, sha256: str) -> sqlite3.Row | None:
        cursor = self.connection.execute(
            "SELECT * FROM captures WHERE sha256 = ?",
            (sha256,),
        )
        return cursor.fetchone()

    def insert_capture(self, payload: dict[str, Any]) -> None:
        self.connection.execute(
            """
            INSERT INTO captures (
                sha256,
                source_name,
                stored_path,
                processed_at,
                capture_format,
                classification,
                iaco,
                metrics_json,
                summary_path,
                detail_csv_path,
                html_report_path
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                payload["sha256"],
                payload["source_name"],
                payload["stored_path"],
                payload["processed_at"],
                payload["capture_format"],
                payload["classification"],
                payload["iaco"],
                json.dumps(payload["metrics"], sort_keys=True),
                payload["summary_path"],
                payload["detail_csv_path"],
                payload["html_report_path"],
            ),
        )
        self.connection.commit()

    def insert_file_event(
        self,
        *,
        sha256: str | None,
        source_name: str,
        source_path: str,
        final_path: str,
        status: str,
        processed_at: str,
        reason: str | None,
    ) -> None:
        self.connection.execute(
            """
            INSERT INTO file_events (
                sha256,
                source_name,
                source_path,
                final_path,
                status,
                processed_at,
                reason
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (sha256, source_name, source_path, final_path, status, processed_at, reason),
        )
        self.connection.commit()

    def last_classification(self) -> str | None:
        cursor = self.connection.execute(
            "SELECT classification FROM state_changes ORDER BY id DESC LIMIT 1"
        )
        row = cursor.fetchone()
        return row["classification"] if row else None

    def insert_state_change(
        self,
        *,
        classification: str,
        iaco: float,
        source_sha256: str,
        summary_path: str,
        changed_at: str,
    ) -> None:
        self.connection.execute(
            """
            INSERT INTO state_changes (
                classification,
                iaco,
                source_sha256,
                summary_path,
                changed_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (classification, iaco, source_sha256, summary_path, changed_at),
        )
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()
