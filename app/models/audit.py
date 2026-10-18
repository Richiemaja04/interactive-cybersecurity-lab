"""app/models/audit.py — Immutable security audit event log."""

from __future__ import annotations

from datetime import datetime, timezone

from app.extensions import db


class AuditEvent(db.Model):
    """
    Immutable security audit record.

    No UPDATE or DELETE routes are provided for this table.
    Admin-only read access is enforced at the route level.
    Secrets and unnecessary payloads are redacted before insertion.
    """

    __tablename__ = "audit_events"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    action = db.Column(db.String(128), nullable=False, index=True)
    # Sanitized detail — never contains credentials, tokens, or session values
    detail = db.Column(db.JSON, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)    # IPv4 or IPv6
    user_agent = db.Column(db.String(256), nullable=True)
    timestamp = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    user = db.relationship("User", back_populates="audit_events")

    def __repr__(self) -> str:
        return f"<AuditEvent action={self.action!r} user={self.user_id} ts={self.timestamp}>"
