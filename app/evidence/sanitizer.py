"""
app/evidence/sanitizer.py — Evidence sanitization pipeline.

Invariants:
- Raw HTTP request/response bodies are NEVER stored.
- Passwords, authorization headers, API tokens, session cookies are REDACTED.
- Internal operating system file paths and stack traces are REDACTED.
- Operates recursively on strings, dictionaries, lists, and JSON structures.
"""

from __future__ import annotations

import re
from typing import Any

# Pattern matching sensitive dictionary key names
_SENSITIVE_KEY_PATTERN = re.compile(
    r"^(password|passwd|secret|token|api_?key|auth(orization)?|cookie|session(id)?|credential|private_?key|jwt)$",
    re.IGNORECASE,
)

# Pattern matching sensitive substrings in values (e.g. token=xyz, password=xyz)
_SENSITIVE_VALUE_PATTERN = re.compile(
    r"(password|token|secret|api_key|bearer)\s*[=:]\s*['\"]?([^\s,'\"&]+)['\"]?",
    re.IGNORECASE,
)

# Pattern matching database URLs with credentials
_DB_URL_PATTERN = re.compile(
    r"(postgres(ql)?|mysql|sqlite)://([^:]+):([^@]+)@([^\s/]+)",
    re.IGNORECASE,
)

# Pattern matching stack trace headers & file frames
_STACK_TRACE_PATTERN = re.compile(
    r"(Traceback \(most recent call last\):|File\s+[\"'][^\"']+[\"'],\s+line\s+\d+)",
    re.IGNORECASE,
)

# Pattern matching internal absolute OS paths
_INTERNAL_PATH_PATTERN = re.compile(
    r"([a-zA-Z]:\\[^ \t\r\n\(\)\<\>]+|/(home|var|tmp|etc|Users|usr)/[^ \t\r\n\(\)\<\>]+)",
)


def sanitize_string(text: str) -> str:
    """Sanitize a string value by redacting secrets, stack traces, and internal paths."""
    if not isinstance(text, str):
        return text

    # Redact DB credentials
    text = _DB_URL_PATTERN.sub(r"\1://\3:[REDACTED]@\5", text)

    # Redact sensitive key=value pairs in text
    text = _SENSITIVE_VALUE_PATTERN.sub(r"\1=[REDACTED]", text)

    # Redact stack trace indicators
    text = _STACK_TRACE_PATTERN.sub("[STACK_TRACE_REDACTED]", text)

    # Redact internal paths
    text = _INTERNAL_PATH_PATTERN.sub("[PATH_REDACTED]", text)

    return text


def sanitize_value(val: Any, key_name: str | None = None) -> Any:
    """Recursively sanitize any value (dict, list, string, scalar)."""
    if key_name and _SENSITIVE_KEY_PATTERN.match(str(key_name).strip()):
        return "[REDACTED]"

    if isinstance(val, dict):
        return {k: sanitize_value(v, key_name=str(k)) for k, v in val.items()}
    elif isinstance(val, list):
        return [sanitize_value(item) for item in val]
    elif isinstance(val, tuple):
        return tuple(sanitize_value(item) for item in val)
    elif isinstance(val, str):
        return sanitize_string(val)
    return val


def sanitize_evidence_detail(detail: dict[str, Any]) -> dict[str, Any]:
    """Sanitize an entire evidence detail dictionary for storage."""
    if not isinstance(detail, dict):
        return {}
    return sanitize_value(detail)
