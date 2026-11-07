"""SQLite store that remembers which alerts were already reported."""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone


class Store:
    def __init__(self, path: str):
        self.conn = sqlite3.connect(path)
        self.conn.execute(
            """CREATE TABLE IF NOT EXISTS seen (
                   uid TEXT PRIMARY KEY,
                   source TEXT,
                   severity TEXT,
                   title TEXT,
                   url TEXT,
                   first_seen TEXT
               )"""
        )
        self.conn.commit()

    def is_new(self, uid: str) -> bool:
        return self.conn.execute("SELECT 1 FROM seen WHERE uid = ?", (uid,)).fetchone() is None

    def mark(self, alerts) -> None:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self.conn.executemany(
            "INSERT OR IGNORE INTO seen VALUES (?, ?, ?, ?, ?, ?)",
            [(a.uid, a.source, a.severity, a.title, a.url, now) for a in alerts],
        )
        self.conn.commit()
