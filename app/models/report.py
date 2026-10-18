"""app/models/report.py — Report export tracking."""

from __future__ import annotations

import enum
from datetime import datetime, timezone

from app.extensions import db


class ReportFormat(str, enum.Enum):
    PDF = "pdf"
    JSON = "json"


class ReportExport(db.Model):
    """
    Tracks every report export for audit and retention.
    The file_ref is a path within REPORT_OUTPUT_DIR, never a public URL.
    """

    __tablename__ = "report_exports"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    run_id = db.Column(
        db.Integer, db.ForeignKey("execution_runs.id", ondelete="SET NULL"), nullable=True
    )
    format = db.Column(
        db.Enum(ReportFormat, name="report_format_enum"),
        nullable=False,
    )
    file_ref = db.Column(db.String(512), nullable=True)    # Relative path within REPORT_OUTPUT_DIR
    file_size_bytes = db.Column(db.Integer, nullable=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    user = db.relationship("User", back_populates="report_exports")
    run = db.relationship("ExecutionRun")

    def __repr__(self) -> str:
        return f"<ReportExport user={self.user_id} format={self.format.value}>"
