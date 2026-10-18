"""
app/config.py — Environment-based configuration.

All secrets are loaded exclusively from environment variables.
No secret is ever hardcoded here.
"""

from __future__ import annotations

import os
from datetime import timedelta


class BaseConfig:
    """Shared settings across all environments."""

    SECRET_KEY: str = os.environ.get("SECRET_KEY", "")  # Validated in ProductionConfig
    TESTING: bool = False
    DEBUG: bool = False

    # ── SQLAlchemy ────────────────────────────────────────────────────────────
    SQLALCHEMY_DATABASE_URI: str = os.environ.get("DATABASE_URL", "")
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False
    SQLALCHEMY_ENGINE_OPTIONS: dict = {
        "pool_pre_ping": True,          # Detect stale connections
        "pool_recycle": 300,            # Recycle every 5 minutes
    }

    # ── Session security ──────────────────────────────────────────────────────
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SECURE: bool = True          # Override to False in dev
    SESSION_COOKIE_SAMESITE: str = "Lax"
    PERMANENT_SESSION_LIFETIME: timedelta = timedelta(
        seconds=int(os.environ.get("SESSION_LIFETIME_SECONDS", 3600))
    )
    SESSION_COOKIE_NAME: str = "cslab_session"

    # ── CSRF ──────────────────────────────────────────────────────────────────
    WTF_CSRF_ENABLED: bool = True
    WTF_CSRF_TIME_LIMIT: int = 3600             # 1 hour

    # ── External-target mode ──────────────────────────────────────────────────
    EXTERNAL_TARGETS_ENABLED: bool = (
        os.environ.get("EXTERNAL_TARGETS_ENABLED", "false").lower() == "true"
    )

    # ── Reports ───────────────────────────────────────────────────────────────
    REPORT_OUTPUT_DIR: str = os.environ.get("REPORT_OUTPUT_DIR", "instance/reports")

    # ── Logging ───────────────────────────────────────────────────────────────
    LOG_LEVEL: str = os.environ.get("LOG_LEVEL", "INFO")

    # ── Execution timeouts (seconds per test module) ──────────────────────────
    EXECUTION_TIMEOUT_DEFAULT: int = 30
    EXECUTION_TIMEOUT_HTTPS: int = 15          # Network-dependent test


class DevelopmentConfig(BaseConfig):
    """Local development — relaxed session security, verbose logging."""

    DEBUG: bool = True
    SESSION_COOKIE_SECURE: bool = False         # Allow HTTP in dev
    LOG_LEVEL: str = os.environ.get("LOG_LEVEL", "DEBUG")

    # Allow missing SECRET_KEY in dev with a default (never used in prod)
    SECRET_KEY: str = os.environ.get(
        "SECRET_KEY", "dev-insecure-key-do-not-use-in-production"
    )

    # Use postgresql+psycopg2 driver explicitly for psycopg2-binary compatibility.
    # If DATABASE_URL is not provided and local Postgres is unreachable, fallback to SQLite.
    @staticmethod
    def _resolve_db_uri() -> str:
        if "DATABASE_URL" in os.environ:
            raw = os.environ["DATABASE_URL"]
            return (
                raw.replace("postgresql://", "postgresql+psycopg2://", 1)
                if raw.startswith("postgresql://")
                else raw
            )
        import socket
        try:
            with socket.create_connection(("localhost", 5432), timeout=0.2):
                return "postgresql+psycopg2://postgres:postgres@localhost:5432/cybersec_lab_dev"
        except OSError:
            os.makedirs("instance", exist_ok=True)
            abs_path = os.path.abspath("instance/dev.db").replace("\\", "/")
            return f"sqlite:///{abs_path}"

    SQLALCHEMY_DATABASE_URI: str = _resolve_db_uri.__func__()


class ProductionConfig(BaseConfig):
    """Render / production — strict settings, no debug."""

    SESSION_COOKIE_SECURE: bool = True

    @classmethod
    def validate(cls) -> None:
        """Called at startup — raises if required production variables are missing."""
        required = ["SECRET_KEY", "DATABASE_URL"]
        missing = [k for k in required if not os.environ.get(k)]
        if missing:
            raise EnvironmentError(
                f"Missing required production environment variables: {missing}"
            )


class TestingConfig(BaseConfig):
    """Automated tests — in-memory SQLite not permitted; use a test PostgreSQL DB."""

    TESTING: bool = True
    DEBUG: bool = True
    WTF_CSRF_ENABLED: bool = False              # Disable CSRF for test clients
    SESSION_COOKIE_SECURE: bool = False

    SECRET_KEY: str = "testing-secret-key-not-for-production"

    _raw_test_url: str = os.environ.get(
        "TEST_DATABASE_URL",
        "postgresql://postgres:postgres@localhost:5432/cybersec_lab_test",
    )
    SQLALCHEMY_DATABASE_URI: str = (
        _raw_test_url.replace("postgresql://", "postgresql+psycopg2://", 1)
        if _raw_test_url.startswith("postgresql://")
        else _raw_test_url
    )

    EXTERNAL_TARGETS_ENABLED: bool = False      # Always disabled in tests
    EXECUTION_TIMEOUT_DEFAULT: int = 5          # Fast timeouts in tests


# ── Config registry ───────────────────────────────────────────────────────────
config_map: dict[str, type[BaseConfig]] = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
}


def get_config(env: str | None = None) -> type[BaseConfig]:
    """Return the config class for the given environment name."""
    env = env or os.environ.get("FLASK_ENV", "development")
    cfg = config_map.get(env)
    if cfg is None:
        raise ValueError(f"Unknown FLASK_ENV '{env}'. Valid: {list(config_map)}")
    return cfg
