from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS scenarios (
    id TEXT PRIMARY KEY,
    parent_id TEXT,
    name TEXT NOT NULL,
    source_feed TEXT NOT NULL,
    abuse_type TEXT NOT NULL,
    cost_model_label TEXT NOT NULL,
    identity_source TEXT NOT NULL,
    mutation_depth INTEGER NOT NULL DEFAULT 0,
    generation INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    requests_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tournament_results (
    run_id TEXT PRIMARY KEY,
    detector_id TEXT NOT NULL,
    scenario_count INTEGER NOT NULL,
    detected_count INTEGER NOT NULL,
    false_positive_count INTEGER NOT NULL,
    cost_blocked REAL NOT NULL,
    cost_missed REAL NOT NULL,
    cost_model_label TEXT NOT NULL,
    win_rate REAL NOT NULL,
    confidence_low REAL NOT NULL,
    confidence_high REAL NOT NULL,
    ran_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS mutation_records (
    mutation_id TEXT PRIMARY KEY,
    parent_scenario_id TEXT NOT NULL,
    child_scenario_id TEXT NOT NULL,
    strategy TEXT NOT NULL,
    depth INTEGER NOT NULL,
    escaped INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
"""


class Database:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path), isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._init_schema()

    def _init_schema(self) -> None:
        with self._cursor() as c:
            c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'")
            row = c.fetchone()
            if row is None:
                c.executescript(SCHEMA)
                c.execute("INSERT INTO schema_version (version) VALUES (?)", (SCHEMA_VERSION,))

    @contextmanager
    def _cursor(self):
        cursor = self._conn.cursor()
        try:
            yield cursor
        finally:
            cursor.close()

    def close(self) -> None:
        self._conn.close()

    def insert_scenario(self, scenario: dict) -> None:
        with self._cursor() as c:
            c.execute(
                """INSERT INTO scenarios
                   (id, parent_id, name, source_feed, abuse_type, cost_model_label,
                    identity_source, mutation_depth, generation, created_at, requests_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (scenario["id"], scenario.get("parent_id"), scenario["name"],
                 scenario["source_feed"], scenario["abuse_type"], scenario["cost_model_label"],
                 scenario["identity_source"], scenario.get("mutation_depth", 0),
                 scenario.get("generation", 0), scenario.get("created_at"),
                 scenario["requests_json"]),
            )

    def get_scenarios(self, parent_id: str | None = None) -> list[dict]:
        with self._cursor() as c:
            if parent_id is None:
                c.execute("SELECT * FROM scenarios")
            else:
                c.execute("SELECT * FROM scenarios WHERE parent_id = ?", (parent_id,))
            cols = [d[0] for d in c.description]
            return [dict(zip(cols, row)) for row in c.fetchall()]

    def get_scenario(self, scenario_id: str) -> dict | None:
        with self._cursor() as c:
            c.execute("SELECT * FROM scenarios WHERE id = ?", (scenario_id,))
            row = c.fetchone()
            if row is None:
                return None
            cols = [d[0] for d in c.description]
            return dict(zip(cols, row))

    def insert_tournament_result(self, result: dict) -> None:
        with self._cursor() as c:
            c.execute(
                """INSERT INTO tournament_results
                   (run_id, detector_id, scenario_count, detected_count, false_positive_count,
                    cost_blocked, cost_missed, cost_model_label, win_rate, confidence_low,
                    confidence_high, ran_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (result["run_id"], result["detector_id"], result["scenario_count"],
                 result["detected_count"], result["false_positive_count"],
                 result["cost_blocked"], result["cost_missed"], result["cost_model_label"],
                 result["win_rate"], result["confidence_low"], result["confidence_high"],
                 result["ran_at"]),
            )

    def get_tournament_results(self, since: int | None = None) -> list[dict]:
        with self._cursor() as c:
            if since is None:
                c.execute("SELECT * FROM tournament_results ORDER BY ran_at DESC")
            else:
                c.execute("SELECT * FROM tournament_results WHERE ran_at >= ? ORDER BY ran_at DESC", (since,))
            cols = [d[0] for d in c.description]
            return [dict(zip(cols, row)) for row in c.fetchall()]

    def insert_mutation(self, record: dict) -> None:
        with self._cursor() as c:
            c.execute(
                """INSERT INTO mutation_records
                   (mutation_id, parent_scenario_id, child_scenario_id, strategy,
                    depth, escaped, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (record["mutation_id"], record["parent_scenario_id"],
                 record["child_scenario_id"], record["strategy"], record["depth"],
                 1 if record["escaped"] else 0, record["created_at"]),
            )

    def audit(self, event_type: str, payload: str) -> None:
        import time
        with self._cursor() as c:
            c.execute(
                "INSERT INTO audit_log (event_type, payload, created_at) VALUES (?, ?, ?)",
                (event_type, payload, int(time.time() * 1000)),
            )
