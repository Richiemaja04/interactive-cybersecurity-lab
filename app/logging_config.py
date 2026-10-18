"""
app/logging_config.py — Sanitizing log filter.

Redacts passwords, tokens, secrets, and session values from all log records
before they are written to any handler.
"""

from __future__ import annotations

import logging
import re

# Patterns that should never appear in logs
_REDACT_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'(password\s*[=:]\s*)\S+', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'(secret\s*[=:]\s*)\S+', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'(token\s*[=:]\s*)\S+', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'(api[_-]?key\s*[=:]\s*)\S+', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'(authorization:\s*)(Bearer\s+)\S+', re.IGNORECASE), r'\1\2[REDACTED]'),
    (re.compile(r'(session\s*[=:]\s*)\S+', re.IGNORECASE), r'\1[REDACTED]'),
    # PostgreSQL DSN passwords
    (re.compile(r'(postgresql://[^:]+:)[^@]+(@)', re.IGNORECASE), r'\1[REDACTED]\2'),
]


class SanitizingFilter(logging.Filter):
    """Strip sensitive values from log messages before emission."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = _sanitize(str(record.msg))
        record.args = _sanitize_args(record.args)
        return True


def _sanitize(text: str) -> str:
    for pattern, replacement in _REDACT_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def _sanitize_args(args):
    """Recursively sanitize log format arguments."""
    if isinstance(args, dict):
        return {k: _sanitize(str(v)) if isinstance(v, str) else v for k, v in args.items()}
    if isinstance(args, (list, tuple)):
        return type(args)(_sanitize(str(a)) if isinstance(a, str) else a for a in args)
    if isinstance(args, str):
        return _sanitize(args)
    return args
