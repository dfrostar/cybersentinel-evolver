from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path

SCHEMA_VERSION = 2

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

-- v2.0 tables: Self-prompting + Evolution tracking
CREATE TABLE IF NOT EXISTS prompts (
    id TEXT PRIMARY KEY,
    trigger_type TEXT NOT NULL,
    prompt_text TEXT NOT NULL,
    llm_response TEXT,
    scenarios_extracted INTEGER NOT NULL DEFAULT 0,
    accepted INTEGER,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    run_type TEXT NOT NULL,
    status TEXT NOT NULL,
    config TEXT,
    started_at INTEGER NOT NULL,
    finished_at INTEGER
);

CREATE TABLE IF NOT EXISTS run_results (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(id),
    scenario_id TEXT NOT NULL REFERENCES scenarios(id),
    detector_id TEXT NOT NULL,
    verdict TEXT NOT NULL,
    cost REAL NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS gap_analysis (
    id TEXT PRIMARY KEY,
    analysis_type TEXT NOT NULL,
    findings TEXT NOT NULL,
    recommended_prompts TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS cost_models (
    id TEXT PRIMARY KEY,
    label TEXT UNIQUE NOT NULL,
    per_request_base REAL,
    per_1k_requests REAL NOT NULL,
    abuse_type TEXT,
    org_id TEXT,
    source_notes TEXT,
    created_at INTEGER NOT NULL
);
"""


class Database:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path), isolation_level=None, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._lock = threading.Lock()
        self._init_schema()

    def _init_schema(self) -> None:
        with self._cursor() as c:
            c.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name='schema_version'"
            )
            row = c.fetchone()
            if row is None:
                c.executescript(SCHEMA)
                c.execute(
                    "INSERT INTO schema_version (version) VALUES (?)",
                    (SCHEMA_VERSION,),
                )
            else:
                c.execute("SELECT version FROM schema_version")
                ver = c.fetchone()[0]
                self._migrate(c, ver)

    @staticmethod
    def _migrate(cur, from_ver: int) -> None:
        """Sequential migration blocks. Each bumps schema_version."""
        if from_ver < 2:
            cur.executescript("""
                CREATE TABLE IF NOT EXISTS prompts (
                    id TEXT PRIMARY KEY,
                    trigger_type TEXT NOT NULL,
                    prompt_text TEXT NOT NULL,
                    llm_response TEXT,
                    scenarios_extracted INTEGER NOT NULL DEFAULT 0,
                    accepted INTEGER,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS runs (
                    id TEXT PRIMARY KEY,
                    run_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    config TEXT,
                    started_at INTEGER NOT NULL,
                    finished_at INTEGER
                );
                CREATE TABLE IF NOT EXISTS run_results (
                    id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL REFERENCES runs(id),
                    scenario_id TEXT NOT NULL REFERENCES scenarios(id),
                    detector_id TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    cost REAL NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS gap_analysis (
                    id TEXT PRIMARY KEY,
                    analysis_type TEXT NOT NULL,
                    findings TEXT NOT NULL,
                    recommended_prompts TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS cost_models (
                    id TEXT PRIMARY KEY,
                    label TEXT UNIQUE NOT NULL,
                    per_request_base REAL,
                    per_1k_requests REAL NOT NULL,
                    abuse_type TEXT,
                    org_id TEXT,
                    source_notes TEXT,
                    created_at INTEGER NOT NULL
                );
            """)
            cur.execute(
                "UPDATE schema_version SET version = ?",
                (SCHEMA_VERSION,),
            )

    # ── Cursors ────────────────────────────────────────────────────────

    @contextmanager
    def _cursor(self):
        cursor = self._conn.cursor()
        try:
            yield cursor
        finally:
            cursor.close()

    def _rows(self, cur) -> list[dict]:
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    # ── General ─────────────────────────────────────────────────────────

    def close(self) -> None:
        self._conn.close()

    # ── Scenarios ───────────────────────────────────────────────────────

    def insert_scenario(self, scenario: dict) -> None:
        with self._cursor() as c:
            c.execute(
                """INSERT INTO scenarios
                   (id, parent_id, name, source_feed, abuse_type, cost_model_label,
                    identity_source, mutation_depth, generation, created_at, requests_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (scenario["id"], scenario.get("parent_id"), scenario["name"],
                 scenario["source_feed"], scenario["abuse_type"],
                 scenario["cost_model_label"],
                 scenario["identity_source"], scenario.get("mutation_depth", 0),
                 scenario.get("generation", 0), scenario.get("created_at"),
                 scenario["requests_json"]),
            )

    def get_scenarios(
        self,
        parent_id: str | None = None,
        source_feed: str | None = None,
    ) -> list[dict]:
        with self._cursor() as c:
            if parent_id is not None:
                c.execute(
                    "SELECT * FROM scenarios WHERE parent_id = ?",
                    (parent_id,),
                )
            elif source_feed is not None:
                c.execute(
                    "SELECT * FROM scenarios WHERE source_feed = ?",
                    (source_feed,),
                )
            else:
                c.execute("SELECT * FROM scenarios ORDER BY generation, created_at")
            return self._rows(c)

    def get_scenario(self, scenario_id: str) -> dict | None:
        with self._cursor() as c:
            c.execute("SELECT * FROM scenarios WHERE id = ?", (scenario_id,))
            row = c.fetchone()
            if row is None:
                return None
            return dict(zip([d[0] for d in c.description], row))

    # ── Tournaments ─────────────────────────────────────────────────────

    def insert_tournament_result(self, result: dict) -> None:
        with self._cursor() as c:
            c.execute(
                """INSERT INTO tournament_results
                   (run_id, detector_id, scenario_count, detected_count,
                    false_positive_count, cost_blocked, cost_missed,
                    cost_model_label, win_rate, confidence_low,
                    confidence_high, ran_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (result["run_id"], result["detector_id"],
                 result["scenario_count"], result["detected_count"],
                 result["false_positive_count"], result["cost_blocked"],
                 result["cost_missed"], result["cost_model_label"],
                 result["win_rate"], result["confidence_low"],
                 result["confidence_high"], result["ran_at"]),
            )

    def get_tournament_results(
        self, since: int | None = None
    ) -> list[dict]:
        with self._cursor() as c:
            if since is None:
                c.execute(
                    "SELECT * FROM tournament_results ORDER BY ran_at DESC"
                )
            else:
                c.execute(
                    "SELECT * FROM tournament_results "
                    "WHERE ran_at >= ? ORDER BY ran_at DESC",
                    (since,),
                )
            return self._rows(c)

    # ── Mutations ───────────────────────────────────────────────────────

    def insert_mutation(self, record: dict) -> None:
        with self._cursor() as c:
            c.execute(
                """INSERT INTO mutation_records
                   (mutation_id, parent_scenario_id, child_scenario_id,
                    strategy, depth, escaped, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (record["mutation_id"], record["parent_scenario_id"],
                 record["child_scenario_id"], record["strategy"],
                 record["depth"],
                 1 if record["escaped"] else 0, record["created_at"]),
            )

    def get_mutations(
        self, escaped_only: bool = False
    ) -> list[dict]:
        with self._cursor() as c:
            if escaped_only:
                c.execute(
                    "SELECT * FROM mutation_records WHERE escaped = 1"
                )
            else:
                c.execute("SELECT * FROM mutation_records")
            return self._rows(c)

    # ── Self-prompting (v2.0) ──────────────────────────────────────────

    @staticmethod
    def _bool_to_int(v: bool | None) -> int | None:
        if v is None:
            return None
        return 1 if v else 0

    def insert_prompt(self, record: dict) -> None:
        with self._cursor() as c:
            c.execute(
                """INSERT INTO prompts
                   (id, trigger_type, prompt_text, llm_response,
                    scenarios_extracted, accepted, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (record["id"], record["trigger_type"],
                 record["prompt_text"], record.get("llm_response"),
                 record.get("scenarios_extracted", 0),
                 self._bool_to_int(record.get("accepted")),
                 record["created_at"]),
            )

    def get_prompts(
        self, trigger_type: str | None = None
    ) -> list[dict]:
        with self._cursor() as c:
            if trigger_type:
                c.execute(
                    "SELECT * FROM prompts WHERE trigger_type = ? "
                    "ORDER BY created_at DESC",
                    (trigger_type,),
                )
            else:
                c.execute("SELECT * FROM prompts ORDER BY created_at DESC")
            return self._rows(c)

    # ── Runs & Run Results (v2.0) ───────────────────────────────────────

    def insert_run(self, run: dict) -> None:
        with self._cursor() as c:
            c.execute(
                """INSERT INTO runs
                   (id, run_type, status, config, started_at, finished_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (run["id"], run["run_type"], run["status"],
                 run.get("config"), run["started_at"], run.get("finished_at")),
            )

    def update_run_status(
        self, run_id: str, status: str, finished_at: int | None = None
    ) -> None:
        with self._cursor() as c:
            c.execute(
                "UPDATE runs SET status = ?, finished_at = ? WHERE id = ?",
                (status, finished_at, run_id),
            )

    def insert_run_result(self, result: dict) -> None:
        with self._cursor() as c:
            c.execute(
                """INSERT INTO run_results
                   (id, run_id, scenario_id, detector_id, verdict, cost)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (result["id"], result["run_id"], result["scenario_id"],
                 result["detector_id"], result["verdict"],
                 result.get("cost", 0)),
            )

    def get_run_results(self, run_id: str) -> list[dict]:
        with self._cursor() as c:
            c.execute(
                "SELECT * FROM run_results WHERE run_id = ?", (run_id,)
            )
            return self._rows(c)

    # ── Gap Analysis (v2.0) ─────────────────────────────────────────────

    def insert_gap_analysis(self, record: dict) -> None:
        with self._cursor() as c:
            c.execute(
                """INSERT INTO gap_analysis
                   (id, analysis_type, findings, recommended_prompts, created_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (record["id"], record["analysis_type"],
                 record["findings"], record["recommended_prompts"],
                 record["created_at"]),
            )

    def get_gap_analysis(
        self, analysis_type: str | None = None
    ) -> list[dict]:
        with self._cursor() as c:
            if analysis_type:
                c.execute(
                    "SELECT * FROM gap_analysis "
                    "WHERE analysis_type = ? ORDER BY created_at DESC",
                    (analysis_type,),
                )
            else:
                c.execute("SELECT * FROM gap_analysis ORDER BY created_at DESC")
            return self._rows(c)

    # ── Cost Models (v2.0) ──────────────────────────────────────────────

    def insert_cost_model(self, record: dict) -> None:
        with self._cursor() as c:
            c.execute(
                """INSERT INTO cost_models
                   (id, label, per_request_base, per_1k_requests,
                    abuse_type, org_id, source_notes, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (record["id"], record["label"],
                 record.get("per_request_base"),
                 record["per_1k_requests"],
                 record.get("abuse_type"), record.get("org_id"),
                 record.get("source_notes"), record["created_at"]),
            )

    def get_cost_models(self) -> list[dict]:
        with self._cursor() as c:
            c.execute("SELECT * FROM cost_models")
            return self._rows(c)

    # ── Audit ───────────────────────────────────────────────────────────

    def audit(self, event_type: str, payload: str) -> None:
        import time
        with self._cursor() as c:
            c.execute(
                "INSERT INTO audit_log (event_type, payload, created_at) "
                "VALUES (?, ?, ?)",
                (event_type, payload, int(time.time() * 1000)),
            )
