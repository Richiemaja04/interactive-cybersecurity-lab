"""
tests/unit/test_evidence_sanitization.py — Phase 2: Evidence sanitization unit tests.
"""

from __future__ import annotations

import pytest

from app.evidence.sanitizer import (
    sanitize_evidence_detail,
    sanitize_string,
    sanitize_value,
)


class TestEvidenceSanitization:
    """Verifies that secrets, internal paths, and stack traces are redacted before storage."""

    def test_sensitive_dict_keys_redacted(self):
        raw = {
            "username": "alice",
            "password": "SuperSecretPassword123!",
            "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            "api_key": "sk-1234567890abcdef",
            "cookie": "session_id=abcdef123456",
            "authorization": "Bearer secret-token-xyz",
        }
        sanitized = sanitize_evidence_detail(raw)

        assert sanitized["username"] == "alice"
        assert sanitized["password"] == "[REDACTED]"
        assert sanitized["token"] == "[REDACTED]"
        assert sanitized["api_key"] == "[REDACTED]"
        assert sanitized["cookie"] == "[REDACTED]"
        assert sanitized["authorization"] == "[REDACTED]"

    def test_sensitive_inline_substrings_redacted(self):
        text = "Request sent with password=MyPass99! and token=abcde12345"
        sanitized = sanitize_string(text)
        assert "MyPass99!" not in sanitized
        assert "abcde12345" not in sanitized
        assert "password=[REDACTED]" in sanitized
        assert "token=[REDACTED]" in sanitized

    def test_database_url_passwords_redacted(self):
        dsn = "postgresql://dbuser:supersecretpass@db.example.internal:5432/lab"
        sanitized = sanitize_string(dsn)
        assert "supersecretpass" not in sanitized
        assert "postgresql://dbuser:[REDACTED]@db.example.internal:5432/lab" in sanitized

    def test_stack_traces_redacted(self):
        trace = (
            "Traceback (most recent call last):\n"
            "  File \"/var/www/app/routes.py\", line 42, in my_view\n"
            "ZeroDivisionError: division by zero"
        )
        sanitized = sanitize_string(trace)
        assert "Traceback (most recent call last):" not in sanitized
        assert "[STACK_TRACE_REDACTED]" in sanitized

    def test_internal_paths_redacted(self):
        win_path = "Failed opening file at C:\\Users\\Administrator\\secrets\\keys.json"
        sanitized_win = sanitize_string(win_path)
        assert "C:\\Users\\Administrator" not in sanitized_win
        assert "[PATH_REDACTED]" in sanitized_win

        unix_path = "Log wrote to /var/log/application/sensitive.log"
        sanitized_unix = sanitize_string(unix_path)
        assert "/var/log/application/sensitive.log" not in sanitized_unix
        assert "[PATH_REDACTED]" in sanitized_unix

    def test_nested_structures_recursively_sanitized(self):
        nested = {
            "status": "ok",
            "headers": {
                "Authorization": "Bearer secret123",
                "Content-Type": "application/json",
            },
            "records": [
                {"id": 1, "secret_notes": "sensitive admin data", "token": "xyz789"},
                {"id": 2, "secret_notes": "safe public notes", "token": "abc123"},
            ],
        }
        sanitized = sanitize_evidence_detail(nested)
        assert sanitized["headers"]["Authorization"] == "[REDACTED]"
        assert sanitized["headers"]["Content-Type"] == "application/json"
        assert sanitized["records"][0]["token"] == "[REDACTED]"
        assert sanitized["records"][1]["token"] == "[REDACTED]"

    def test_safe_data_preserved_accurately(self):
        safe = {
            "url": "/robots.txt",
            "status_code": 200,
            "paths_checked": ["/admin/", "/backup/"],
            "is_vulnerable": True,
        }
        sanitized = sanitize_evidence_detail(safe)
        assert sanitized == safe
