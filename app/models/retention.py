"""app/models/retention.py — Retention job tracking."""

from __future__ import annotations

from datetime import datetime, timezone

from app.extensions import db


class RetentionJob(db.Model):
    """
    Records each execution of the 90-day retention cleanup.
    Admin-triggered only; every execution is audited.
    """

    __tablename__ = "retention_jobs"

    id = db.Column(db.Integer, primary_key=True)
    triggered_by_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    scope = db.Column(db.String(128), nullable=False)    # e.g. "execution_history", "reports"
    cutoff_date = db.Column(db.DateTime(timezone=True), nullable=False)
    records_deleted = db.Column(db.Integer, nullable=False, default=0)
    notes = db.Column(db.Text, nullable=True)
    executed_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    triggered_by = db.relationship("User")

    def __repr__(self) -> str:
        return f"<RetentionJob scope={self.scope!r} deleted={self.records_deleted}>"
