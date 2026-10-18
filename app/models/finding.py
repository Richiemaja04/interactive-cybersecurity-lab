"""
app/models/finding.py — Findings, annotations, and run comparisons.

Key invariants:
- Severity and confidence are separate fields — no combined score.
- VerificationStatus is independent of ExecutionState.
- Simulated evidence → VerificationStatus.SIMULATED (never Confirmed).
- Annotations are private to their owning tester.
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone

from app.extensions import db


class SeverityEnum(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"
    NONE = "none"


class ConfidenceEnum(str, enum.Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class VerificationStatus(str, enum.Enum):
    CONFIRMED = "confirmed"
    POTENTIAL = "potential"
    INCONCLUSIVE = "inconclusive"
    SIMULATED = "simulated"       # Never represents a verified live vulnerability


class Finding(db.Model):
    """
    Security finding produced by classification of collected evidence.

    No overall security score is computed.
    No "certified secure" claim is ever made.
    """

    __tablename__ = "findings"

    id = db.Column(db.Integer, primary_key=True)
    run_id = db.Column(
        db.Integer,
        db.ForeignKey("execution_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    title = db.Column(db.String(256), nullable=False)
    description = db.Column(db.Text, nullable=True)
    severity = db.Column(
        db.Enum(SeverityEnum, name="severity_enum"),
        nullable=False,
        default=SeverityEnum.INFORMATIONAL,
        index=True,
    )
    confidence = db.Column(
        db.Enum(ConfidenceEnum, name="confidence_enum"),
        nullable=False,
        default=ConfidenceEnum.UNKNOWN,
    )
    verification_status = db.Column(
        db.Enum(VerificationStatus, name="verification_status_enum"),
        nullable=False,
        default=VerificationStatus.INCONCLUSIVE,
        index=True,
    )
    remediation_summary = db.Column(db.Text, nullable=True)
    verification_steps = db.Column(db.JSON, nullable=True)   # List of step strings
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    run = db.relationship("ExecutionRun", back_populates="findings")
    annotations = db.relationship(
        "FindingAnnotation",
        back_populates="finding",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )
    remediation_actions = db.relationship(
        "RemediationAction",
        back_populates="finding",
        lazy="dynamic",
    )

    def __repr__(self) -> str:
        return (
            f"<Finding {self.title!r} "
            f"severity={self.severity.value} "
            f"status={self.verification_status.value}>"
        )


class FindingAnnotation(db.Model):
    """
    Private tester note on a finding.
    Ownership is enforced at the service layer — no cross-tester access.
    """

    __tablename__ = "finding_annotations"

    id = db.Column(db.Integer, primary_key=True)
    finding_id = db.Column(
        db.Integer,
        db.ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    text = db.Column(db.Text, nullable=False)
    include_in_export = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    finding = db.relationship("Finding", back_populates="annotations")
    user = db.relationship("User", back_populates="annotations")

    def __repr__(self) -> str:
        return f"<FindingAnnotation finding={self.finding_id} user={self.user_id}>"


class RunComparison(db.Model):
    """Side-by-side comparison of two execution runs by the same tester."""

    __tablename__ = "run_comparisons"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    run_a_id = db.Column(
        db.Integer, db.ForeignKey("execution_runs.id", ondelete="CASCADE"), nullable=False
    )
    run_b_id = db.Column(
        db.Integer, db.ForeignKey("execution_runs.id", ondelete="CASCADE"), nullable=False
    )
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    user = db.relationship("User")
    run_a = db.relationship("ExecutionRun", foreign_keys=[run_a_id])
    run_b = db.relationship("ExecutionRun", foreign_keys=[run_b_id])

    def __repr__(self) -> str:
        return f"<RunComparison user={self.user_id} a={self.run_a_id} b={self.run_b_id}>"
