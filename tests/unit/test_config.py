"""tests/unit/test_config.py — Phase 1: Configuration unit tests."""

from __future__ import annotations

import os

import pytest


class TestConfigLoading:
    def test_testing_config_loads(self, app):
        assert app.config["TESTING"] is True
        assert app.config["WTF_CSRF_ENABLED"] is False

    def test_secret_key_present(self, app):
        assert app.config["SECRET_KEY"]
        assert app.config["SECRET_KEY"] != ""

    def test_external_targets_disabled_by_default(self, app):
        assert app.config["EXTERNAL_TARGETS_ENABLED"] is False

    def test_session_cookie_httponly(self, app):
        assert app.config["SESSION_COOKIE_HTTPONLY"] is True

    def test_session_cookie_samesite(self, app):
        assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"

    def test_no_sqlalchemy_track_modifications(self, app):
        assert app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] is False

    def test_database_url_is_postgresql(self):
        from app.config import DevelopmentConfig
        assert DevelopmentConfig.SQLALCHEMY_DATABASE_URI.startswith(("postgresql://", "postgresql+psycopg2://")), (
            f"Database URL must be PostgreSQL, got: {DevelopmentConfig.SQLALCHEMY_DATABASE_URI}"
        )


class TestConfigMap:
    def test_unknown_env_raises(self):
        from app.config import get_config
        with pytest.raises(ValueError, match="Unknown FLASK_ENV"):
            get_config("nonexistent_env")

    def test_testing_config_class(self):
        from app.config import TestingConfig
        assert TestingConfig.TESTING is True
        assert TestingConfig.WTF_CSRF_ENABLED is False

    def test_development_config_insecure_cookie(self):
        from app.config import DevelopmentConfig
        assert DevelopmentConfig.SESSION_COOKIE_SECURE is False

    def test_production_config_secure_cookie(self):
        from app.config import ProductionConfig
        assert ProductionConfig.SESSION_COOKIE_SECURE is True


class TestLoggingSanitization:
    def test_password_redacted(self):
        from app.logging_config import _sanitize
        result = _sanitize("Login attempted with password=supersecret123")
        assert "supersecret123" not in result
        assert "[REDACTED]" in result

    def test_token_redacted(self):
        from app.logging_config import _sanitize
        result = _sanitize("token=abc123xyz")
        assert "abc123xyz" not in result

    def test_db_dsn_password_redacted(self):
        from app.logging_config import _sanitize
        result = _sanitize("postgresql://user:mypassword@host:5432/db")
        assert "mypassword" not in result

    def test_safe_content_unchanged(self):
        from app.logging_config import _sanitize
        safe = "User logged in successfully from 127.0.0.1"
        assert _sanitize(safe) == safe
