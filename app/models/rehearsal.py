"""app/models/rehearsal.py — Rehearsal sessions and fault injection."""

from __future__ import annotations

import enum
from datetime import datetime, timezone

from app.extensions import db


class FaultType(str, enum.Enum):
    DEMO_SERVICE_UNAVAILABLE = "demo_service_unavailable"
    CONTROLLED_TIMEOUT = "controlled_timeout"
    SIMULATED_DB_UNAVAILABLE = "simulated_db_unavailable"
    REPORT_EXPORT_FAILURE = "report_export_failure"


class RehearsalSession(db.Model):
    """
    An isolated rehearsal run.
    Results are kept completely separate from regular execution history.
    """

    __tablename__ = "rehearsal_sessions"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    preset_id = db.Column(
        db.Integer, db.ForeignKey("presets.id", ondelete="SET NULL"), nullable=True
    )
    sequence_id = db.Column(
        db.Integer, db.ForeignKey("presentation_sequences.id", ondelete="SET NULL"), nullable=True
    )
    is_active = db.Column(db.Boolean, nullable=False, default=True, index=True)
    started_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    ended_at = db.Column(db.DateTime(timezone=True), nullable=True)

    user = db.relationship("User", back_populates="rehearsal_sessions")
    preset = db.relationship("Preset")
    faults = db.relationship(
        "FaultInjection",
        back_populates="rehearsal_session",
        cascade="all, delete-orphan",
        lazy="joined",
    )

    def __repr__(self) -> str:
        return f"<RehearsalSession id={self.id} user={self.user_id} active={self.is_active}>"


class FaultInjection(db.Model):
    """
    Predefined simulated fault in an isolated lab component.
    All faults are disabled by default and visibly labeled [SIMULATED FAULT].
    Auto-cleared when the rehearsal session ends.
    """

    __tablename__ = "fault_injections"

    id = db.Column(db.Integer, primary_key=True)
    rehearsal_session_id = db.Column(
        db.Integer,
        db.ForeignKey("rehearsal_sessions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    fault_type = db.Column(
        db.Enum(FaultType, name="fault_type_enum"),
        nullable=False,
    )
    is_enabled = db.Column(db.Boolean, nullable=False, default=False)
    config_json = db.Column(db.JSON, nullable=True)     # E.g., {"timeout_seconds": 10}
    activated_at = db.Column(db.DateTime(timezone=True), nullable=True)
    deactivated_at = db.Column(db.DateTime(timezone=True), nullable=True)

    rehearsal_session = db.relationship("RehearsalSession", back_populates="faults")

    def __repr__(self) -> str:
        return f"<FaultInjection type={self.fault_type.value} enabled={self.is_enabled}>"
