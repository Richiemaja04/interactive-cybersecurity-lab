"""app/models/remediation.py — Remediation actions and audit trail."""

from __future__ import annotations

import enum
from datetime import datetime, timezone

from app.extensions import db


class OutcomeEnum(str, enum.Enum):
    RESOLVED = "resolved"
    PERSISTS = "persists"
    INCONCLUSIVE = "inconclusive"


class RemediationAction(db.Model):
    """
    A fix applied to a finding with before/after state capture.

    Optimistic locking: scenario_version_at_action must match the current
    scenario version at apply time. Stale actions are rejected.
    """

    __tablename__ = "remediation_actions"

    id = db.Column(db.Integer, primary_key=True)
    finding_id = db.Column(
        db.Integer,
        db.ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    fix_name = db.Column(db.String(128), nullable=False)
    description = db.Column(db.Text, nullable=True)
    scenario_version_at_action = db.Column(db.Integer, nullable=False)
    before_state = db.Column(db.JSON, nullable=False)
    after_state = db.Column(db.JSON, nullable=True)
    outcome = db.Column(
        db.Enum(OutcomeEnum, name="outcome_enum"),
        nullable=True,
    )
    verification_notes = db.Column(db.Text, nullable=True)
    is_reversal = db.Column(db.Boolean, nullable=False, default=False)
    reversed_action_id = db.Column(
        db.Integer,
        db.ForeignKey("remediation_actions.id", ondelete="SET NULL"),
        nullable=True,
    )
    applied_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    finding = db.relationship("Finding", back_populates="remediation_actions")
    user = db.relationship("User", back_populates="remediation_actions")

    def __repr__(self) -> str:
        return f"<RemediationAction {self.fix_name!r} outcome={self.outcome}>"


class RemediationAudit(db.Model):
    """Immutable audit log entry for every remediation event."""

    __tablename__ = "remediation_audits"

    id = db.Column(db.Integer, primary_key=True)
    action_id = db.Column(
        db.Integer,
        db.ForeignKey("remediation_actions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    event_type = db.Column(db.String(64), nullable=False)   # "applied", "reversed", "verified"
    detail = db.Column(db.Text, nullable=True)              # Sanitized detail only
    timestamp = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    action = db.relationship("RemediationAction")
    user = db.relationship("User")

    def __repr__(self) -> str:
        return f"<RemediationAudit action={self.action_id} event={self.event_type}>"
