"""SQLite persistent state store for glinet-portal (WAL mode, restart hydration)."""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class StateStore:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL;")
            self._conn.execute("PRAGMA synchronous=NORMAL;")
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS device_status (
                    device_id TEXT PRIMARY KEY,
                    payload_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sweeps (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    exit_code INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    summary_json TEXT NOT NULL,
                    output TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_sweeps_device_id ON sweeps(device_id, id DESC);
                CREATE TABLE IF NOT EXISTS meta (
                    key TEXT PRIMARY KEY,
                    value_json TEXT NOT NULL
                );
                """
            )
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def upsert_device_status(self, device_id: str, status: dict) -> None:
        now = _utc_now()
        payload = json.dumps(status)
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO device_status(device_id, payload_json, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(device_id) DO UPDATE SET
                    payload_json = excluded.payload_json,
                    updated_at = excluded.updated_at
                """,
                (device_id, payload, now),
            )
            self._conn.commit()

    def get_all_device_statuses(self) -> dict[str, dict]:
        with self._lock:
            rows = self._conn.execute("SELECT device_id, payload_json, updated_at FROM device_status").fetchall()
        out: dict[str, dict] = {}
        for row in rows:
            data = json.loads(row["payload_json"])
            data.setdefault("updated_at", row["updated_at"])
            out[row["device_id"]] = data
        return out

    def record_sweep(self, device_id: str, sweep: dict) -> int:
        ts = sweep.get("timestamp") or _utc_now()
        exit_code = int(sweep.get("exit_code", -1))
        status = str(sweep.get("status") or ("clean" if exit_code == 0 else "ioc" if exit_code == 1 else "error"))
        verdict = str(sweep.get("verdict") or "")
        summary_json = json.dumps(sweep.get("summary") or {})
        output = str(sweep.get("output") or "")
        with self._lock:
            cur = self._conn.execute(
                """
                INSERT INTO sweeps(device_id, timestamp, exit_code, status, verdict, summary_json, output)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (device_id, ts, exit_code, status, verdict, summary_json, output),
            )
            row_id = int(cur.lastrowid)
            self._conn.execute(
                """
                DELETE FROM sweeps
                WHERE device_id = ?
                  AND id NOT IN (
                      SELECT id FROM sweeps WHERE device_id = ? ORDER BY id DESC LIMIT 20
                  )
                """,
                (device_id, device_id),
            )
            self._conn.commit()
        return row_id

    @staticmethod
    def _row_to_sweep(row: sqlite3.Row) -> dict:
        return {
            "id": row["id"],
            "device_id": row["device_id"],
            "timestamp": row["timestamp"],
            "exit_code": row["exit_code"],
            "status": row["status"],
            "verdict": row["verdict"],
            "summary": json.loads(row["summary_json"]),
            "output": row["output"],
        }

    def get_latest_sweeps(self) -> dict[str, dict]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT s.* FROM sweeps s
                INNER JOIN (
                    SELECT device_id, MAX(id) AS max_id FROM sweeps GROUP BY device_id
                ) latest ON s.id = latest.max_id
                """
            ).fetchall()
        return {row["device_id"]: self._row_to_sweep(row) for row in rows}

    def get_sweep_history(self, device_id: str, limit: int = 10) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM sweeps WHERE device_id = ? ORDER BY id DESC LIMIT ?",
                (device_id, limit),
            ).fetchall()
        return [self._row_to_sweep(r) for r in rows]

    def save_conntrack_alerts(self, alerts: list[dict], checked_at: str) -> None:
        val = json.dumps({"checked_at": checked_at, "alerts": alerts})
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO meta(key, value_json) VALUES ('conntrack', ?)
                ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json
                """,
                (val,),
            )
            self._conn.commit()

    def get_conntrack_snapshot(self) -> dict:
        with self._lock:
            row = self._conn.execute("SELECT value_json FROM meta WHERE key = 'conntrack'").fetchone()
        if not row:
            return {"checked_at": None, "alerts": []}
        return json.loads(row["value_json"])
