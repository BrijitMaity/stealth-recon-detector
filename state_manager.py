"""
state_manager.py — SQLite-Based State Persistence (Industry-Grade)

Replaces in-memory data structures with a durable SQLite database.
Handles graceful restarts, persistence of blocked IPs across reboots,
and tracking of overall SOC metrics.

Industry enhancements:
  - WAL mode for concurrent read/write performance
  - Connection pooling via thread-local storage
  - Schema versioning with migration support
  - Bulk operations for metrics
  - Structured logging
"""
import sqlite3
import threading
import time
from config import cfg
from app_logger import get_logger

log = get_logger(__name__)

# Schema version — increment when tables change
_SCHEMA_VERSION = 3


class StateManager:
    def __init__(self):
        self.db_path = cfg.STATE_DB
        self._lock = threading.Lock()
        self._local = threading.local()  # Thread-local connection storage
        self._init_db()
        log.info("StateManager initialized", extra={"db_path": self.db_path})

    def _get_conn(self) -> sqlite3.Connection:
        """Get a thread-local database connection (connection pooling pattern).

        Instead of opening/closing a connection per operation, each thread
        reuses its own long-lived connection. This dramatically reduces
        SQLite lock contention under the 10-thread worker pool.
        """
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            # WAL mode — allows concurrent reads while writing
            conn.execute("PRAGMA journal_mode=WAL")
            # Synchronous NORMAL — good balance of speed vs durability
            conn.execute("PRAGMA synchronous=NORMAL")
            # Busy timeout — wait up to 5s if DB is locked by another connection
            conn.execute("PRAGMA busy_timeout=5000")
            self._local.conn = conn
        return conn

    def _init_db(self):
        with self._lock:
            conn = self._get_conn()
            cursor = conn.cursor()

            # Schema version tracking
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS schema_info (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            ''')

            # Check current schema version
            cursor.execute("SELECT value FROM schema_info WHERE key = 'version'")
            row = cursor.fetchone()
            current_version = int(row['value']) if row else 0

            # Blocked IPs table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    ip TEXT PRIMARY KEY,
                    reason TEXT,
                    blocked_at REAL,
                    expires_at REAL
                )
            ''')

            # System Metrics table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS system_metrics (
                    key TEXT PRIMARY KEY,
                    value_int INTEGER DEFAULT 0,
                    value_text TEXT
                )
            ''')

            # ── Migration: v1 → v2 (add audit_log table) ────────────────
            if current_version < 2:
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS audit_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp REAL NOT NULL,
                        action TEXT NOT NULL,
                        target TEXT,
                        details TEXT,
                        actor TEXT DEFAULT 'system'
                    )
                ''')
                # Create index for time-range queries
                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_audit_timestamp
                    ON audit_log(timestamp)
                ''')
                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_blocked_expires
                    ON blocked_ips(expires_at)
                ''')
                cursor.execute("INSERT OR REPLACE INTO schema_info (key, value) VALUES ('version', '2')")
                log.info("Database schema migrated to v2")

            # ── Migration: v2 → v3 (add users table) ────────────────
            if current_version < 3:
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        role TEXT DEFAULT 'analyst'
                    )
                ''')
                cursor.execute("INSERT OR REPLACE INTO schema_info (key, value) VALUES ('version', '3')")
                log.info("Database schema migrated to v3")

            # Update schema version
            cursor.execute(
                "INSERT OR REPLACE INTO schema_info (key, value) VALUES ('version', ?)",
                (str(_SCHEMA_VERSION),)
            )

            # Seed default metrics if not exist
            cursor.execute("INSERT OR IGNORE INTO system_metrics (key, value_int) VALUES ('total_scanned', 0)")
            cursor.execute("INSERT OR IGNORE INTO system_metrics (key, value_int) VALUES ('total_blocked', 0)")
            cursor.execute("INSERT OR IGNORE INTO system_metrics (key, value_int) VALUES ('total_threats', 0)")
            cursor.execute("INSERT OR IGNORE INTO system_metrics (key, value_int) VALUES ('total_safe', 0)")

            conn.commit()

    def create_user(self, username: str, password_hash: str, role: str = 'analyst') -> bool:
        """Create a new user. Returns True if successful, False if username exists."""
        try:
            with self._lock:
                conn = self._get_conn()
                conn.execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                    (username, password_hash, role)
                )
                conn.commit()
            log.info(f"New user registered: {username} (Role: {role})")
            return True
        except sqlite3.IntegrityError:
            return False
            
    def get_user(self, username: str) -> dict:
        """Retrieve a user by username."""
        conn = self._get_conn()
        cursor = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None

    # ── IP Block Management ──────────────────────────────────────────
    def save_blocked_ip(self, ip, reason, expires_at):
        with self._lock:
            conn = self._get_conn()
            conn.execute(
                "INSERT OR REPLACE INTO blocked_ips (ip, reason, blocked_at, expires_at) VALUES (?, ?, ?, ?)",
                (ip, reason, time.time(), expires_at)
            )
            conn.commit()
            self._write_audit("block_ip", ip, f"reason={reason}, ttl={expires_at - time.time():.0f}s")

    def remove_blocked_ip(self, ip):
        with self._lock:
            conn = self._get_conn()
            conn.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
            conn.commit()
            self._write_audit("unblock_ip", ip, "TTL expired or manual unblock")

    def get_all_blocked_ips(self):
        with self._lock:
            conn = self._get_conn()
            cursor = conn.execute("SELECT ip, expires_at FROM blocked_ips")
            rows = cursor.fetchall()
            # Return dict of {ip: expires_at}
            return {row['ip']: row['expires_at'] for row in rows}

    def get_blocked_ip_count(self) -> int:
        """Fast count without loading all IPs into memory."""
        with self._lock:
            conn = self._get_conn()
            cursor = conn.execute("SELECT COUNT(*) as cnt FROM blocked_ips")
            return cursor.fetchone()['cnt']

    # ── Metrics Management ───────────────────────────────────────────
    def increment_metric(self, key, amount=1):
        with self._lock:
            conn = self._get_conn()
            conn.execute(
                "UPDATE system_metrics SET value_int = value_int + ? WHERE key = ?",
                (amount, key)
            )
            conn.commit()

    def get_metric(self, key):
        with self._lock:
            conn = self._get_conn()
            cursor = conn.execute("SELECT value_int FROM system_metrics WHERE key = ?", (key,))
            row = cursor.fetchone()
            return row['value_int'] if row else 0

    def get_all_metrics(self) -> dict:
        """Fetch all metrics in a single query (bulk operation)."""
        with self._lock:
            conn = self._get_conn()
            cursor = conn.execute("SELECT key, value_int FROM system_metrics")
            return {row['key']: row['value_int'] for row in cursor.fetchall()}

    # ── Audit Log ────────────────────────────────────────────────────
    def _write_audit(self, action: str, target: str, details: str = "",
                     actor: str = "system"):
        """Write an entry to the audit trail (called within lock)."""
        try:
            conn = self._get_conn()
            conn.execute(
                "INSERT INTO audit_log (timestamp, action, target, details, actor) "
                "VALUES (?, ?, ?, ?, ?)",
                (time.time(), action, target, details, actor)
            )
            conn.commit()
        except Exception as e:
            log.warning(f"Audit log write failed: {e}")

    def get_recent_audit(self, limit: int = 50) -> list[dict]:
        """Retrieve recent audit log entries."""
        with self._lock:
            conn = self._get_conn()
            cursor = conn.execute(
                "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            )
            return [dict(row) for row in cursor.fetchall()]

    def close(self):
        """Close thread-local connections gracefully."""
        conn = getattr(self._local, "conn", None)
        if conn:
            try:
                conn.close()
            except Exception:
                pass
            self._local.conn = None


# Singleton instance
state = StateManager()
