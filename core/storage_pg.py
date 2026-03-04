"""
AURORA – PostgreSQL Storage Backend
=====================================
A full, production-ready implementation of the AuroraDB interface backed
by PostgreSQL via psycopg2.  Drop-in replacement for core/storage.py (SQLite).

WHY THIS EXISTS:
  SQLite is excellent for single-node deployments.  When AURORA is scaled
  horizontally (multiple API workers / containers), a shared PostgreSQL
  instance provides:
    - Concurrent writers across processes (SQLite WAL does not cross-process)
    - Connection pooling (SimpleConnectionPool, thread-safe)
    - LISTEN/NOTIFY for future real-time event push
    - Row-level locking and SERIALIZABLE transactions when required

ACTIVATION:
  Set ONE of:
    AURORA_STORAGE_BACKEND=postgresql   (environment variable)
    storage_backend: "postgresql"       (aurora_config.json)

  Then provide connection parameters via any of:
    AURORA_PG_DSN=postgresql://user:pass@host:5432/aurora
    or individually:
    AURORA_PG_HOST / AURORA_PG_PORT / AURORA_PG_USER / AURORA_PG_PASS / AURORA_PG_DB

  If the psycopg2 package is not installed, AURORA falls back to SQLite
  automatically and logs a WARNING — no crash, no data loss.

INTERFACE CONTRACT (identical to AuroraDB in core/storage.py):
  load_namespace(namespace)            → Dict[str, Any]
  save_namespace(namespace, data)      → None  (atomic replace)
  get(namespace, key, default=None)    → Any
  set(namespace, key, value)           → None
  delete(namespace, key)               → None
  list_keys(namespace)                 → List[str]
  migrate_from_json(path, namespace)   → bool
  stats()                              → Dict[str, Any]

SCHEMA:
  Identical to SQLite — a single kv_store table with (namespace, key) PK.
  Auto-created on first connect; safe to run against existing schema.

CONNECTION POOL:
  Uses psycopg2.pool.ThreadedConnectionPool (min=1, max=10).
  Pool size is configurable via AURORA_PG_POOL_MIN / AURORA_PG_POOL_MAX.
  A threading.Lock guards pool borrow/return to prevent race conditions.

SECURITY:
  - Passwords never logged (DSN is masked in stats/logs).
  - All queries use parameterised statements — no string formatting.
  - SSL mode defaults to 'prefer'; set AURORA_PG_SSLMODE=require for strict.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("aurora.storage_pg")

# ─────────────────────────────────────────────────────────────────────────────
# Schema DDL
# ─────────────────────────────────────────────────────────────────────────────

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS aurora_kv_store (
    namespace   TEXT        NOT NULL,
    key         TEXT        NOT NULL,
    value       TEXT        NOT NULL,
    updated_at  DOUBLE PRECISION NOT NULL DEFAULT 0,
    PRIMARY KEY (namespace, key)
);
CREATE INDEX IF NOT EXISTS aurora_idx_kv_namespace
    ON aurora_kv_store (namespace);
"""

# ─────────────────────────────────────────────────────────────────────────────
# DSN helpers
# ─────────────────────────────────────────────────────────────────────────────

def _build_dsn() -> str:
    """
    Build a PostgreSQL DSN from environment variables.
    Priority: AURORA_PG_DSN > individual AURORA_PG_* vars > defaults.
    """
    explicit = os.environ.get("AURORA_PG_DSN", "").strip()
    if explicit:
        return explicit

    host    = os.environ.get("AURORA_PG_HOST", "127.0.0.1")
    port    = os.environ.get("AURORA_PG_PORT", "5432")
    user    = os.environ.get("AURORA_PG_USER", "aurora")
    passwd  = os.environ.get("AURORA_PG_PASS", "")
    dbname  = os.environ.get("AURORA_PG_DB",   "aurora")
    sslmode = os.environ.get("AURORA_PG_SSLMODE", "prefer")

    if passwd:
        return f"postgresql://{user}:{passwd}@{host}:{port}/{dbname}?sslmode={sslmode}"
    return f"postgresql://{user}@{host}:{port}/{dbname}?sslmode={sslmode}"


def _mask_dsn(dsn: str) -> str:
    """Return DSN with password redacted for safe logging."""
    return re.sub(r"(://[^:@/]+:)[^@/]+(@)", r"\1***\2", dsn)


# ─────────────────────────────────────────────────────────────────────────────
# AuroraDBPostgres
# ─────────────────────────────────────────────────────────────────────────────

class AuroraDBPostgres:
    """
    PostgreSQL-backed implementation of the AuroraDB interface.
    Identical public API to AuroraDB (core/storage.py).
    """

    def __init__(
        self,
        dsn:      Optional[str] = None,
        pool_min: int = 1,
        pool_max: int = 10,
    ):
        try:
            import psycopg2                           # type: ignore
            import psycopg2.pool as _pool             # type: ignore
            import psycopg2.extras as _extras         # type: ignore
        except ImportError as exc:
            raise ImportError(
                "psycopg2 is required for the PostgreSQL backend. "
                "Install it with: pip install psycopg2-binary\n"
                f"Original error: {exc}"
            ) from exc

        self._psycopg2   = psycopg2
        self._extras     = _extras
        self._dsn        = dsn or _build_dsn()
        self._pool_lock  = threading.Lock()

        # Validate pool sizes
        pool_min = max(1, int(os.environ.get("AURORA_PG_POOL_MIN", pool_min)))
        pool_max = max(pool_min, int(os.environ.get("AURORA_PG_POOL_MAX", pool_max)))

        logger.info(
            f"[AURORA pg] Connecting to PostgreSQL "
            f"({_mask_dsn(self._dsn)}) pool={pool_min}–{pool_max}"
        )
        self._pool = _pool.ThreadedConnectionPool(
            pool_min, pool_max,
            dsn=self._dsn,
        )
        self._ensure_schema()

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _conn(self):
        """Borrow a connection from the pool (thread-safe)."""
        with self._pool_lock:
            return self._pool.getconn()

    def _put(self, conn) -> None:
        """Return a connection to the pool."""
        with self._pool_lock:
            self._pool.putconn(conn)

    def _ensure_schema(self) -> None:
        """Create tables/indexes if they do not exist."""
        conn = self._conn()
        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute(_SCHEMA_SQL)
            logger.info("[AURORA pg] Schema verified / created.")
        finally:
            self._put(conn)

    # ── Whole-namespace operations ────────────────────────────────────────────

    def load_namespace(self, namespace: str) -> Dict[str, Any]:
        """Load all keys in a namespace as a dict."""
        conn = self._conn()
        try:
            with conn.cursor(cursor_factory=self._extras.DictCursor) as cur:
                cur.execute(
                    "SELECT key, value FROM aurora_kv_store WHERE namespace = %s",
                    (namespace,),
                )
                rows = cur.fetchall()
            if not rows:
                return {}
            # Single '__root__' key → unwrap
            if len(rows) == 1 and rows[0]["key"] == "__root__":
                try:
                    return json.loads(rows[0]["value"])
                except (json.JSONDecodeError, TypeError):
                    return {}
            # Reconstruct dict
            result: Dict[str, Any] = {}
            for row in rows:
                try:
                    result[row["key"]] = json.loads(row["value"])
                except (json.JSONDecodeError, TypeError):
                    result[row["key"]] = row["value"]
            return result
        finally:
            self._put(conn)

    def save_namespace(self, namespace: str, data: Dict[str, Any]) -> None:
        """Atomically replace an entire namespace with new data."""
        conn = self._conn()
        try:
            with conn:   # BEGIN … COMMIT / ROLLBACK
                with conn.cursor() as cur:
                    cur.execute(
                        "DELETE FROM aurora_kv_store WHERE namespace = %s",
                        (namespace,),
                    )
                    now = time.time()
                    for key, value in data.items():
                        cur.execute(
                            "INSERT INTO aurora_kv_store "
                            "(namespace, key, value, updated_at) "
                            "VALUES (%s, %s, %s, %s)",
                            (namespace, key,
                             json.dumps(value, separators=(",", ":")), now),
                        )
        finally:
            self._put(conn)

    # ── Single-key operations ─────────────────────────────────────────────────

    def get(self, namespace: str, key: str, default: Any = None) -> Any:
        conn = self._conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT value FROM aurora_kv_store "
                    "WHERE namespace = %s AND key = %s",
                    (namespace, key),
                )
                row = cur.fetchone()
            if row is None:
                return default
            try:
                return json.loads(row[0])
            except (json.JSONDecodeError, TypeError):
                return row[0]
        finally:
            self._put(conn)

    def set(self, namespace: str, key: str, value: Any) -> None:
        conn = self._conn()
        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "INSERT INTO aurora_kv_store "
                        "(namespace, key, value, updated_at) "
                        "VALUES (%s, %s, %s, %s) "
                        "ON CONFLICT (namespace, key) DO UPDATE "
                        "SET value = EXCLUDED.value, "
                        "    updated_at = EXCLUDED.updated_at",
                        (namespace, key,
                         json.dumps(value, separators=(",", ":")), time.time()),
                    )
        finally:
            self._put(conn)

    def delete(self, namespace: str, key: str) -> None:
        conn = self._conn()
        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "DELETE FROM aurora_kv_store "
                        "WHERE namespace = %s AND key = %s",
                        (namespace, key),
                    )
        finally:
            self._put(conn)

    def list_keys(self, namespace: str) -> List[str]:
        conn = self._conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT key FROM aurora_kv_store WHERE namespace = %s",
                    (namespace,),
                )
                return [row[0] for row in cur.fetchall()]
        finally:
            self._put(conn)

    def migrate_from_json(self, json_path: Path, namespace: str) -> bool:
        """
        One-time migration: import a legacy .json file into PostgreSQL.
        Idempotent — skips if the namespace already has rows.
        """
        if not json_path.exists():
            return False
        existing = self.list_keys(namespace)
        if existing:
            return False
        try:
            with open(json_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                self.save_namespace(namespace, data)
                migrated = json_path.with_suffix(".json.migrated")
                json_path.rename(migrated)
                logger.info(
                    f"[AURORA pg] Migrated {json_path.name} → PostgreSQL "
                    f"({len(data)} records)"
                )
                return True
        except Exception as exc:
            logger.warning(
                f"[AURORA pg] Migration of {json_path} failed: {exc}"
            )
        return False

    def stats(self) -> Dict[str, Any]:
        """Return storage statistics for the health endpoint."""
        conn = self._conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT namespace, COUNT(*) AS cnt "
                    "FROM aurora_kv_store GROUP BY namespace"
                )
                ns_counts = {row[0]: row[1] for row in cur.fetchall()}
                cur.execute(
                    "SELECT pg_database_size(current_database())"
                )
                db_size = cur.fetchone()[0] or 0
            # Pool stats
            with self._pool_lock:
                pool_used = len(self._pool._used)     # type: ignore[attr-defined]
                pool_free = len(self._pool._pool)     # type: ignore[attr-defined]
            return {
                "backend":         "postgresql",
                "dsn_masked":      _mask_dsn(self._dsn),
                "db_size_bytes":   db_size,
                "namespaces":      ns_counts,
                "pool_used":       pool_used,
                "pool_free":       pool_free,
            }
        finally:
            self._put(conn)

    def close(self) -> None:
        """Close all connections in the pool. Call on graceful shutdown."""
        with self._pool_lock:
            self._pool.closeall()
        logger.info("[AURORA pg] Connection pool closed.")


# ─────────────────────────────────────────────────────────────────────────────
# Factory — used by core/storage.py to construct the right backend
# ─────────────────────────────────────────────────────────────────────────────

def try_build_postgres_db() -> Optional["AuroraDBPostgres"]:
    """
    Attempt to construct an AuroraDBPostgres instance.
    Returns None (without raising) if psycopg2 is not installed or
    the connection fails — callers fall back to SQLite transparently.
    """
    try:
        db = AuroraDBPostgres()
        logger.info("[AURORA pg] PostgreSQL backend active.")
        return db
    except ImportError:
        logger.warning(
            "[AURORA pg] psycopg2 not installed — "
            "falling back to SQLite. "
            "Install with: pip install psycopg2-binary"
        )
        return None
    except Exception as exc:
        logger.warning(
            f"[AURORA pg] PostgreSQL connection failed ({exc}) — "
            "falling back to SQLite."
        )
        return None
