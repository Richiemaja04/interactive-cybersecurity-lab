"""
app/audit/service.py — Audit event recording service.

Writes immutable AuditEvent rows.
Redacts secrets before storage.
Never raises — audit failures are logged but do not break the calling operation.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from flask import current_app, request

if TYPE_CHECKING:
    from app.models.user import User

# Patterns to redact from audit detail values
_SECRET_PATTERN = re.compile(
    r'(password|secret|token|api.?key|authorization)',
    re.IGNORECASE,
)


def write_audit_event(
    action: str,
    user_id: int | None = None,
    detail: dict | None = None,
) -> None:
    """Convenience helper accepting user_id directly."""
    try:
        from app.extensions import db
        from app.models.audit import AuditEvent

        sanitized = _sanitize_detail(detail or {})
        event = AuditEvent(
            user_id=user_id,
            action=action,
            detail=sanitized,
            ip_address=_get_ip(),
            user_agent=request.user_agent.string[:256] if request else None,
        )
        db.session.add(event)
        db.session.commit()
    except Exception as exc:
        try:
            current_app.logger.error("Audit write failed for action=%s: %s", action, exc)
        except RuntimeError:
            pass


def record_audit_event(
    action: str,
    user: "User | None",
    detail: dict | None = None,
) -> None:
    """
    Write a sanitized audit event.
    Safe to call from any request context.
    """
    try:
        from app.extensions import db
        from app.models.audit import AuditEvent

        sanitized = _sanitize_detail(detail or {})

        event = AuditEvent(
            user_id=user.id if user else None,
            action=action,
            detail=sanitized,
            ip_address=_get_ip(),
            user_agent=request.user_agent.string[:256] if request else None,
        )
        db.session.add(event)
        db.session.commit()
    except Exception as exc:
        # Audit failure must never crash the calling operation
        try:
            current_app.logger.error("Audit write failed for action=%s: %s", action, exc)
        except RuntimeError:
            pass  # No app context available


def _sanitize_detail(detail: dict) -> dict:
    """Remove secret-looking keys from audit detail dict."""
    return {
        k: "[REDACTED]" if _SECRET_PATTERN.search(str(k)) else v
        for k, v in detail.items()
    }


def _get_ip() -> str | None:
    """Extract client IP, respecting X-Forwarded-For from trusted proxies."""
    try:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()[:45]
        return request.remote_addr
    except RuntimeError:
        return None
