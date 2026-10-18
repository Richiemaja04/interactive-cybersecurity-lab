"""app/models/external.py — External target approvals."""

from __future__ import annotations

from datetime import datetime, timezone

from app.extensions import db


class ExternalTargetApproval(db.Model):
    """
    Administrator-approved external hostname for optional external-target mode.
    Feature is disabled by default. Only HTTPS port 443 is permitted.
    """

    __tablename__ = "external_target_approvals"

    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(253), nullable=False, unique=True, index=True)
    approved_by_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    approval_notes = db.Column(db.Text, nullable=True)
    is_active = db.Column(db.Boolean, nullable=False, default=True, index=True)
    valid_from = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    valid_until = db.Column(db.DateTime(timezone=True), nullable=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    approved_by = db.relationship("User")

    def __repr__(self) -> str:
        return f"<ExternalTargetApproval hostname={self.hostname!r} active={self.is_active}>"
