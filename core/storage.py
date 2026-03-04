"""
AURORA – SQLite Storage Backend
================================
Drop-in replacement for flat JSON file storage.
Provides the EXACT same interface as the JSON-based _load_users / _save_users
functions, but backed by SQLite with WAL mode for concurrent readers.

Design principles:
  - WAL journal mode: multiple concurrent readers, one writer, no blocking.
  - Atomic upserts via INSERT OR REPLACE inside explicit transactions.
  - Connection-per-call pattern — safe for multi-threaded wsgiref/gunicorn.
  - All JSON payloads stored as TEXT (preserves existing encryption/encoding).
  - Schema migration: auto-creates tables on first run, no manual setup.
  - Backward compatible: on first run, migrates any existing .json files.
  - File permissions: 0o600 (same as existing JSON files).
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("aurora.storage")

# ── Connection pool (one connection per thread) ───────────────────────────────
_local = threading.local()
_DB_LOCK = threading.Lock()  # guards schema creation only


def _get_db(db_path: Path) -> sqlite3.Connection:
    """
    Return a per-thread SQLite connection in WAL mode.
    Connections are cached per-thread so they are never shared across threads,
    eliminating the 'objects created in a thread can only be used in that thread'
    SQLite error while still avoiding connection-creation overhead per request.
    """
    attr = f"_aurora_conn_{db_path}"
    conn = getattr(_local, attr, None)
    if conn is None:
        conn = sqlite3.connect(
            str(db_path),
            timeout=30,
            check_same_thread=False,   # we enforce single-thread via _local
            isolation_level=None,      # autocommit; we manage transactions explicitly
        )
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")   # safe + fast with WAL
        conn.execute("PRAGMA foreign_keys=ON")
        conn.row_factory = sqlite3.Row
        setattr(_local, attr, conn)
    return conn


# ── Schema ────────────────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS kv_store (
    namespace   TEXT NOT NULL,
    key         TEXT NOT NULL,
    value       TEXT NOT NULL,
    updated_at  REAL NOT NULL DEFAULT 0,
    PRIMARY KEY (namespace, key)
);
CREATE INDEX IF NOT EXISTS idx_kv_namespace ON kv_store (namespace);
"""


class AuroraDB:
    """
    General-purpose key-value store backed by SQLite.
    Each logical 'namespace' maps to what was previously a separate .json file.

    Namespaces used by AURORA:
      'users'         → users.json
      'messages'      → messages.json
      'reset_tokens'  → reset_tokens.json
      'audit_meta'    → audit chain metadata (prev_hmac, rotation state)
    """

    def __init__(self, db_path: Path):
        self.db_path = db_path
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_schema()
        self._set_permissions()

    def _ensure_schema(self) -> None:
        with _DB_LOCK:
            conn = _get_db(self.db_path)
            conn.executescript(_SCHEMA)

    def _set_permissions(self) -> None:
        try:
            if self.db_path.exists():
                os.chmod(self.db_path, 0o600)
        except OSError:
            pass

    # ── Whole-namespace operations (equivalent to load/save JSON) ─────────────

    def load_namespace(self, namespace: str) -> Dict[str, Any]:
        """Load all keys in a namespace as a dict (mirrors JSON file load)."""
        conn = _get_db(self.db_path)
        rows = conn.execute(
            "SELECT key, value FROM kv_store WHERE namespace = ?",
            (namespace,),
        ).fetchall()
        if not rows:
            return {}
        # If namespace stores a single 'root' key, return its value directly
        if len(rows) == 1 and rows[0]["key"] == "__root__":
            try:
                return json.loads(rows[0]["value"])
            except (json.JSONDecodeError, TypeError):
                return {}
        # Otherwise, reconstruct the dict from individual row keys
        result = {}
        for row in rows:
            try:
                result[row["key"]] = json.loads(row["value"])
            except (json.JSONDecodeError, TypeError):
                result[row["key"]] = row["value"]
        return result

    def save_namespace(self, namespace: str, data: Dict[str, Any]) -> None:
        """Save an entire dict to a namespace atomically (mirrors JSON file save)."""
        conn = _get_db(self.db_path)
        now = time.time()
        with conn:  # BEGIN / COMMIT / ROLLBACK
            conn.execute(
                "DELETE FROM kv_store WHERE namespace = ?", (namespace,)
            )
            for key, value in data.items():
                conn.execute(
                    "INSERT INTO kv_store (namespace, key, value, updated_at) "
                    "VALUES (?, ?, ?, ?)",
                    (namespace, key, json.dumps(value, separators=(",", ":")), now),
                )

    # ── Single-key operations ─────────────────────────────────────────────────

    def get(self, namespace: str, key: str, default: Any = None) -> Any:
        conn = _get_db(self.db_path)
        row = conn.execute(
            "SELECT value FROM kv_store WHERE namespace = ? AND key = ?",
            (namespace, key),
        ).fetchone()
        if row is None:
            return default
        try:
            return json.loads(row["value"])
        except (json.JSONDecodeError, TypeError):
            return row["value"]

    def set(self, namespace: str, key: str, value: Any) -> None:
        conn = _get_db(self.db_path)
        with conn:
            conn.execute(
                "INSERT OR REPLACE INTO kv_store (namespace, key, value, updated_at) "
                "VALUES (?, ?, ?, ?)",
                (namespace, key, json.dumps(value, separators=(",", ":")), time.time()),
            )

    def delete(self, namespace: str, key: str) -> None:
        conn = _get_db(self.db_path)
        with conn:
            conn.execute(
                "DELETE FROM kv_store WHERE namespace = ? AND key = ?",
                (namespace, key),
            )

    def list_keys(self, namespace: str) -> List[str]:
        conn = _get_db(self.db_path)
        rows = conn.execute(
            "SELECT key FROM kv_store WHERE namespace = ?", (namespace,)
        ).fetchall()
        return [r["key"] for r in rows]

    # ── Migration helper ──────────────────────────────────────────────────────

    def migrate_from_json(self, json_path: Path, namespace: str) -> bool:
        """
        One-time migration: if a legacy .json file exists and the namespace
        has no rows yet, import its contents into SQLite then rename the file
        to .json.migrated so it is not re-imported on next startup.
        Returns True if migration happened.
        """
        if not json_path.exists():
            return False
        existing = self.list_keys(namespace)
        if existing:
            return False  # Already migrated
        try:
            with open(json_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                self.save_namespace(namespace, data)
                migrated = json_path.with_suffix(".json.migrated")
                json_path.rename(migrated)
                logger.info(
                    f"[AURORA storage] Migrated {json_path.name} → SQLite "
                    f"({len(data)} records) → {migrated.name}"
                )
                return True
        except Exception as exc:
            logger.warning(f"[AURORA storage] Migration of {json_path} failed: {exc}")
        return False

    def stats(self) -> Dict[str, Any]:
        """Return storage statistics for the health endpoint."""
        conn = _get_db(self.db_path)
        rows = conn.execute(
            "SELECT namespace, COUNT(*) as cnt FROM kv_store GROUP BY namespace"
        ).fetchall()
        ns_counts = {r["namespace"]: r["cnt"] for r in rows}
        size_bytes = self.db_path.stat().st_size if self.db_path.exists() else 0
        return {
            "backend": "sqlite_wal",
            "path": str(self.db_path),
            "size_bytes": size_bytes,
            "namespaces": ns_counts,
            "wal_mode": True,
        }


# ── Module-level singleton ────────────────────────────────────────────────────

_db_instance: Optional[AuroraDB] = None
_db_lock = threading.Lock()


def get_db():
    """
    Return the module-level storage singleton (thread-safe).

    Backend selection (in priority order):
      1. AURORA_STORAGE_BACKEND=postgresql  (env var)
      2. storage_backend: "postgresql"      (aurora_config.json)
      3. Default: SQLite WAL               (no config needed)

    Returns an AuroraDBPostgres instance when PostgreSQL is configured
    and psycopg2 is available; falls back to AuroraDB (SQLite) otherwise.
    Both implement the same interface — callers are unaffected.
    """
    global _db_instance
    if _db_instance is None:
        with _db_lock:
            if _db_instance is None:
                _db_instance = _build_db()
    return _db_instance


def _build_db():
    """Construct the appropriate storage backend."""
    from core.paths import AURORA_HOME

    # Determine requested backend
    backend = os.environ.get("AURORA_STORAGE_BACKEND", "").lower()
    if not backend:
        try:
            from core.config import get_config
            backend = str(get_config().get("storage_backend", "sqlite")).lower()
        except Exception:
            backend = "sqlite"

    if backend == "postgresql":
        from core.storage_pg import try_build_postgres_db
        pg = try_build_postgres_db()
        if pg is not None:
            # Migrate legacy JSON files to PG if needed
            _migrate_legacy(AURORA_HOME, pg)
            return pg
        # Fall through to SQLite on failure (already logged in try_build_postgres_db)

    db_path = AURORA_HOME / "aurora.db"
    db = AuroraDB(db_path)
    _migrate_legacy(AURORA_HOME, db)
    return db


def _migrate_legacy(aurora_home: Path, db: AuroraDB) -> None:
    """Migrate all legacy JSON stores to SQLite on first startup."""
    migrations = [
        (aurora_home / "users.json",         "users"),
        (aurora_home / "messages.json",       "messages"),
        (aurora_home / "reset_tokens.json",   "reset_tokens"),
    ]
    for json_path, namespace in migrations:
        db.migrate_from_json(json_path, namespace)
