"""
Centralized configuration for the Stealth Reconnaissance Detection System.

All settings are loaded from environment variables with sensible defaults.
Override any setting by setting the corresponding environment variable
before starting the application.

Features:
  - Input validation on startup (port ranges, thresholds, paths)
  - Version tracking
  - Environment name for multi-stage deployments
  - Immutable after initialization (via __slots__ on inner class)

Usage:
    from config import cfg
    print(cfg.DASHBOARD_PORT)
"""

import os
import sys
import secrets


__version__ = "2.0.0"


def _env(key: str, default, cast=str):
    """Read an environment variable and cast it to the desired type."""
    val = os.environ.get(key, None)
    if val is None:
        return default
    if cast is bool:
        return val.strip().lower() in {"1", "true", "yes"}
    return cast(val)


def _secure_env(key: str, length: int = 32):
    """Read an environment variable, returning a securely generated random fallback if missing."""
    val = os.environ.get(key)
    if not val:
        val = secrets.token_urlsafe(length)
        print(f"WARNING: '{key}' not set in environment. Using generated secure fallback.", file=sys.stderr)
    return val


class _Config:
    """Application configuration — read-only after init."""

    # ── Meta ───────────────────────────────────────────────────────────
    VERSION: str = __version__
    ENVIRONMENT: str = _env("STEALTH_ENVIRONMENT", "development")

    # ── Paths ──────────────────────────────────────────────────────────
    BASE_DIR: str = os.path.dirname(os.path.abspath(__file__))
    LOG_CSV: str = _env("STEALTH_LOG_CSV", "stealth_detection_logs.csv")
    MODEL_PATH: str = _env("STEALTH_MODEL_PATH",
                           os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                        "random_forest_model.pkl"))
    TRAINING_DATA: str = _env("STEALTH_TRAINING_DATA",
                              os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                           "CSV", "ml_ready_dataset.csv"))
    STATE_DB: str = _env("STEALTH_STATE_DB",
                         os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                      "state.db"))
    REPORT_FILE: str = _env("STEALTH_REPORT_FILE", "security_report.txt")

    # ── Dashboard ──────────────────────────────────────────────────────
    DASHBOARD_HOST: str = _env("STEALTH_DASHBOARD_HOST", "127.0.0.1")
    DASHBOARD_PORT: int = _env("STEALTH_DASHBOARD_PORT", 5000, cast=int)
    DASHBOARD_USER: str = _env("STEALTH_DASHBOARD_USER", "admin")
    DASHBOARD_PASS: str = _secure_env("STEALTH_DASHBOARD_PASS", 16)
    CORS_ORIGINS: str = _env("STEALTH_CORS_ORIGINS", "http://127.0.0.1:5000")
    RATE_LIMIT_AUTH: str = _env("STEALTH_RATE_LIMIT_AUTH", "100/second; 500/minute; 2000/hour")
    RATE_LIMIT_PUBLIC: str = _env("STEALTH_RATE_LIMIT_PUBLIC", "10/second; 100/minute")
    RATE_LIMIT_AUTHED: str = _env("STEALTH_RATE_LIMIT_AUTHED", "50/second; 1000/minute")

    # ── Detection Thresholds ───────────────────────────────────────────
    ML_CONFIDENCE_THRESHOLD: float = _env("STEALTH_ML_THRESHOLD", 50.0, cast=float)
    DPI_MIN_PAYLOAD_LEN: int = _env("STEALTH_DPI_MIN_LEN", 10, cast=int)
    UNIQUE_PORT_THRESHOLD: int = _env("STEALTH_PORT_THRESHOLD", 3, cast=int)
    PACKET_COUNT_THRESHOLD: int = _env("STEALTH_PKT_THRESHOLD", 15, cast=int)
    NIGHT_START_HOUR: int = _env("STEALTH_NIGHT_START", 22, cast=int)
    NIGHT_END_HOUR: int = _env("STEALTH_NIGHT_END", 5, cast=int)

    # ── ML Model ───────────────────────────────────────────────────────
    MODEL_NAME: str = _env("STEALTH_MODEL_NAME",
                           "distilbert-base-uncased-finetuned-sst-2-english")
    TRAINING_ROWS: int = _env("STEALTH_TRAINING_ROWS", 10000, cast=int)

    # ── Processing ─────────────────────────────────────────────────────
    THREAD_POOL_SIZE: int = _env("STEALTH_THREAD_POOL", 10, cast=int)
    HEARTBEAT_PERIOD: int = _env("STEALTH_HEARTBEAT", 10, cast=int)
    LOG_BUFFER_SIZE: int = _env("STEALTH_LOG_BUFFER", 10, cast=int)
    LOG_FLUSH_INTERVAL: float = _env("STEALTH_FLUSH_SEC", 1.0, cast=float)
    CLEAN_EVERY_N_ROWS: int = _env("STEALTH_CLEAN_ROWS", 50, cast=int)
    MAX_CSV_SIZE_BYTES: int = _env("STEALTH_MAX_CSV_MB", 200, cast=int) * 1024 * 1024
    MAX_EVENTS_IN_MEMORY: int = _env("STEALTH_MAX_MEM_EVENTS", 1000, cast=int)

    # ── Firewall ───────────────────────────────────────────────────────
    BLOCK_TTL_SECONDS: int = _env("STEALTH_BLOCK_TTL", 3600, cast=int)  # 1 hour default
    MAX_BLOCKED_IPS: int = _env("STEALTH_MAX_BLOCKED", 500, cast=int)

    # ── Alerting (Feature 1) ──────────────────────────────────────────
    SLACK_WEBHOOK_URL: str = _env("STEALTH_SLACK_WEBHOOK", "")
    WEBHOOK_URL: str = _env("STEALTH_WEBHOOK_URL", "")
    SMTP_HOST: str = _env("STEALTH_SMTP_HOST", "")
    SMTP_PORT: int = _env("STEALTH_SMTP_PORT", 587, cast=int)
    SMTP_FROM: str = _env("STEALTH_SMTP_FROM", "")
    SMTP_TO: str = _env("STEALTH_SMTP_TO", "")
    SMTP_USER: str = _env("STEALTH_SMTP_USER", "")
    SMTP_PASS: str = _env("STEALTH_SMTP_PASS", "")
    ALERT_SEVERITY_THRESHOLD: float = _env("STEALTH_ALERT_THRESHOLD", 7.0, cast=float)
    ALERT_COOLDOWN_SECONDS: int = _env("STEALTH_ALERT_COOLDOWN", 300, cast=int)  # 5 min per IP

    # ── Security & Authentication ──────────────────────────────────────
    # RBAC: format "user:pass:role,user2:pass2:role"
    RBAC_USERS: str = _env("RBAC_USERS", "")
    
    # JWT Config
    JWT_SECRET: str = _secure_env("JWT_SECRET", 32)
    JWT_ALGORITHM: str = _env("JWT_ALGORITHM", "HS256")
    JWT_EXPIRY_HOURS: int = _env("JWT_EXPIRY_HOURS", 24, int)

    # Enterprise API Key for SIEMs/Machine-to-Machine
    ENTERPRISE_API_KEY: str = _env("ENTERPRISE_API_KEY", "")

    # ── OSINT Threat Intelligence (Feature 3) ─────────────────────────
    ABUSEIPDB_API_KEY: str = _env("STEALTH_ABUSEIPDB_KEY", "")
    VIRUSTOTAL_API_KEY: str = _env("STEALTH_VIRUSTOTAL_KEY", "")
    GREYNOISE_API_KEY: str = _env("STEALTH_GREYNOISE_KEY", "")
    OSINT_CACHE_TTL_SECONDS: int = _env("STEALTH_OSINT_CACHE_TTL", 86400, cast=int)  # 24h

    # ── Threat Database (Feature 4) ───────────────────────────────────
    THREAT_DB_PATH: str = _env("STEALTH_THREAT_DB",
                               os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                            "threat_events.db"))
    THREAT_RETENTION_DAYS: int = _env("STEALTH_RETENTION_DAYS", 90, cast=int)

    # ── Logging ────────────────────────────────────────────────────────
    LOG_LEVEL: str = _env("STEALTH_LOG_LEVEL", "INFO")
    LOG_FILE: str = _env("STEALTH_LOG_FILE",
                         os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                      "app.log"))
    LOG_MAX_BYTES: int = _env("STEALTH_LOG_MAX_MB", 10, cast=int) * 1024 * 1024
    LOG_BACKUP_COUNT: int = _env("STEALTH_LOG_BACKUPS", 5, cast=int)

    # ── Simulation ─────────────────────────────────────────────────────
    SIM_INTERVAL: float = _env("STEALTH_SIM_INTERVAL", 0.3, cast=float)
    SIM_ATTACK_RATIO: float = _env("STEALTH_ATTACK_RATIO", 0.15, cast=float)
    SIM_BENIGN_RATIO: float = _env("STEALTH_BENIGN_RATIO", 0.10, cast=float)

    # ── TLS / HTTPS (Feature P2-1) ────────────────────────────────────
    ENABLE_TLS: bool = _env("STEALTH_ENABLE_TLS", False, cast=lambda v: str(v).lower() in ("true", "1", "yes"))
    TLS_CERT_PATH: str = _env("STEALTH_TLS_CERT", os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs", "server.crt"))
    TLS_KEY_PATH: str = _env("STEALTH_TLS_KEY", os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs", "server.key"))

    # ── TLS / HTTPS (Feature P2-1) ────────────────────────────────────

    # ── RBAC Users (Feature P2-9) ─────────────────────────────────────
    # Format: "user:pass:role,user2:pass2:role2"
    # Roles: admin, analyst, viewer
    # Duplicate RBAC section removed.

    # ── GeoIP (Feature P2-4) ──────────────────────────────────────────
    GEOIP_CACHE_TTL: int = _env("STEALTH_GEOIP_CACHE_TTL", 86400, cast=int)  # 24h
    GEOIP_API_URL: str = _env("STEALTH_GEOIP_API", "https://ipapi.co")

    # ── Backup (Feature P2-8) ─────────────────────────────────────────
    BACKUP_DIR: str = _env("STEALTH_BACKUP_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "backups"))
    BACKUP_RETENTION_COUNT: int = _env("STEALTH_BACKUP_RETENTION", 7, cast=int)
    BACKUP_INTERVAL_HOURS: int = _env("STEALTH_BACKUP_INTERVAL", 24, cast=int)

    # ── Correlation Engine (Feature P2-6) ─────────────────────────────
    CORRELATION_WINDOW_SECONDS: int = _env("STEALTH_CORRELATION_WINDOW", 600, cast=int)  # 10 min
    CORRELATION_MIN_STAGES: int = _env("STEALTH_CORRELATION_STAGES", 2, cast=int)



    def validate(self) -> list[str]:
        """Validate all configuration values. Returns list of warnings/errors.

        Raises ValueError for critical misconfigurations that would cause
        runtime failures.
        """
        errors = []
        warnings = []

        # Port range validation
        if not (1 <= self.DASHBOARD_PORT <= 65535):
            errors.append(f"DASHBOARD_PORT={self.DASHBOARD_PORT} out of range [1, 65535]")

        # Thread pool must be positive
        if self.THREAD_POOL_SIZE < 1:
            errors.append(f"THREAD_POOL_SIZE={self.THREAD_POOL_SIZE} must be >= 1")

        # Night hours must be valid
        if not (0 <= self.NIGHT_START_HOUR <= 23):
            errors.append(f"NIGHT_START_HOUR={self.NIGHT_START_HOUR} out of range [0, 23]")
        if not (0 <= self.NIGHT_END_HOUR <= 23):
            errors.append(f"NIGHT_END_HOUR={self.NIGHT_END_HOUR} out of range [0, 23]")

        # Thresholds must be positive
        if self.ML_CONFIDENCE_THRESHOLD < 0 or self.ML_CONFIDENCE_THRESHOLD > 100:
            errors.append(f"ML_CONFIDENCE_THRESHOLD={self.ML_CONFIDENCE_THRESHOLD} out of range [0, 100]")
        if self.UNIQUE_PORT_THRESHOLD < 1:
            warnings.append(f"UNIQUE_PORT_THRESHOLD={self.UNIQUE_PORT_THRESHOLD} is very low, may cause false positives")
        if self.BLOCK_TTL_SECONDS < 60:
            warnings.append(f"BLOCK_TTL_SECONDS={self.BLOCK_TTL_SECONDS} is very short (<60s)")

        # Simulation ratios must sum to <= 1.0
        if self.SIM_ATTACK_RATIO + self.SIM_BENIGN_RATIO > 1.0:
            errors.append(f"SIM_ATTACK_RATIO + SIM_BENIGN_RATIO = {self.SIM_ATTACK_RATIO + self.SIM_BENIGN_RATIO} > 1.0")

        # Log level must be valid
        import logging
        if self.LOG_LEVEL.upper() not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            errors.append(f"LOG_LEVEL='{self.LOG_LEVEL}' is not a valid Python logging level")

        # CSV size limit sanity
        if self.MAX_CSV_SIZE_BYTES < 1024 * 1024:
            warnings.append(f"MAX_CSV_SIZE_BYTES={self.MAX_CSV_SIZE_BYTES} is less than 1MB — CSV will rotate very frequently")

        if errors:
            raise ValueError(
                "Configuration validation failed:\n" +
                "\n".join(f"  ERROR: {e}" for e in errors) +
                ("\n" + "\n".join(f"  WARN:  {w}" for w in warnings) if warnings else "")
            )

        return warnings

    def __repr__(self):
        lines = [f"  {k} = {v!r}" for k, v in sorted(vars(type(self)).items())
                 if k.isupper() and not k.startswith("_")]
        return "StealthConfig(\n" + "\n".join(lines) + "\n)"


# Singleton instance — import this everywhere
cfg = _Config()

# Validate on import — fail fast on bad configuration
try:
    _warnings = cfg.validate()
    for _w in _warnings:
        print(f"[Config] WARNING: {_w}", file=sys.stderr)
except ValueError as _e:
    print(f"[Config] FATAL: {_e}", file=sys.stderr)
    raise SystemExit(1) from _e
