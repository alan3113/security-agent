from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterator

from security_agent.models import Finding, Reachability, Triage


class StateStore:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS findings (
                    finding_key TEXT PRIMARY KEY,
                    advisory_id TEXT NOT NULL,
                    purl TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    priority REAL NOT NULL,
                    disposition TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    notified_at TEXT
                );
                CREATE TABLE IF NOT EXISTS triage_cache (
                    cache_key TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS feed_items (
                    url TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    first_seen TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS email_events (
                    message_id TEXT PRIMARY KEY,
                    thread_id TEXT,
                    sender TEXT,
                    subject TEXT,
                    status TEXT NOT NULL,
                    extraction TEXT,
                    error TEXT,
                    received_at TEXT NOT NULL,
                    processed_at TEXT
                );
            """)

    def upsert(self, finding: Finding) -> bool:
        """Store a finding and return True when it has never been seen before."""
        now = datetime.now(UTC).isoformat()
        with self.connect() as db:
            exists = db.execute("SELECT 1 FROM findings WHERE finding_key = ?", (finding.key,)).fetchone()
            db.execute("""
                INSERT INTO findings(finding_key, advisory_id, purl, first_seen, last_seen,
                                     priority, disposition, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(finding_key) DO UPDATE SET
                    last_seen=excluded.last_seen, priority=excluded.priority,
                    disposition=excluded.disposition, payload=excluded.payload
            """, (finding.key, finding.advisory.id, finding.dependency.purl, now, now,
                  finding.priority, finding.disposition, json.dumps(finding.to_dict())))
        return exists is None

    def mark_notified(self, key: str) -> None:
        with self.connect() as db:
            db.execute("UPDATE findings SET notified_at = ? WHERE finding_key = ?",
                       (datetime.now(UTC).isoformat(), key))

    def pending_digest(self) -> list[tuple[str, dict]]:
        with self.connect() as db:
            rows = db.execute("""
                SELECT finding_key, payload FROM findings
                WHERE disposition = 'digest' AND notified_at IS NULL
                ORDER BY priority DESC
            """).fetchall()
        return [(row["finding_key"], json.loads(row["payload"])) for row in rows]

    def get_triage(self, key: str) -> Triage | None:
        with self.connect() as db:
            row = db.execute("SELECT payload FROM triage_cache WHERE cache_key = ?", (key,)).fetchone()
        if row is None:
            return None
        data = json.loads(row["payload"])
        data["reachability"] = Reachability(data["reachability"])
        return Triage(**data)

    def cache_triage(self, key: str, triage: Triage) -> None:
        payload = {
            "reachability": triage.reachability.value, "impact": triage.impact,
            "fix": triage.fix, "fixed_version": triage.fixed_version,
            "evidence": triage.evidence, "llm_used": triage.llm_used,
        }
        with self.connect() as db:
            db.execute("INSERT OR REPLACE INTO triage_cache(cache_key, payload, created_at) VALUES (?, ?, ?)",
                       (key, json.dumps(payload), datetime.now(UTC).isoformat()))

    def record_feed_item(self, url: str, title: str) -> bool:
        with self.connect() as db:
            exists = db.execute("SELECT 1 FROM feed_items WHERE url = ?", (url,)).fetchone()
            if exists is None:
                db.execute("INSERT INTO feed_items(url, title, first_seen) VALUES (?, ?, ?)",
                           (url, title, datetime.now(UTC).isoformat()))
        return exists is None

    def get_metadata(self, key: str) -> str | None:
        with self.connect() as db:
            row = db.execute("SELECT value FROM metadata WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def set_metadata(self, key: str, value: str) -> None:
        with self.connect() as db:
            db.execute("""
                INSERT INTO metadata(key, value, updated_at) VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
            """, (key, value, datetime.now(UTC).isoformat()))

    def claim_email(self, message_id: str, thread_id: str | None = None) -> bool:
        """Claim an unseen or previously failed email for processing."""
        now = datetime.now(UTC).isoformat()
        with self.connect() as db:
            row = db.execute("SELECT status FROM email_events WHERE message_id = ?", (message_id,)).fetchone()
            if row is None:
                db.execute("""
                    INSERT INTO email_events(message_id, thread_id, status, received_at)
                    VALUES (?, ?, 'processing', ?)
                """, (message_id, thread_id, now))
                return True
            if row["status"] == "error":
                db.execute("UPDATE email_events SET status='processing', error=NULL WHERE message_id=?",
                           (message_id,))
                return True
        return False

    def finish_email(self, message_id: str, status: str, *, sender: str = "", subject: str = "",
                     extraction: dict | None = None, error: str | None = None) -> None:
        with self.connect() as db:
            db.execute("""
                UPDATE email_events
                SET status=?, sender=?, subject=?, extraction=?, error=?, processed_at=?
                WHERE message_id=?
            """, (status, sender, subject, json.dumps(extraction) if extraction is not None else None,
                  error, datetime.now(UTC).isoformat(), message_id))
