"""
app/models/execution.py — ExecutionRun and ExecutionEvent.

IMPORTANT: ExecutionState (run lifecycle) and FindingVerificationStatus
(finding quality) are separate dimensions. They must never be conflated.
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone

from app.extensions import db


class ExecutionState(str, enum.Enum):
    NOT_STARTED = "not_started"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    BLOCKED = "blocked"          # Scope violation or safety gate triggered


class ExecutionRun(db.Model):
    """
    One execution attempt of one test module against one scenario.

    A completed run may produce zero findings.
    A failed run does not establish any security conclusion.
    is_rehearsal=True: results are stored separately from regular history.
    """

    __tablename__ = "execution_runs"

    id = db.Column(db.Integer, primary_key=True)
    test_id = db.Column(
        db.Integer,
        db.ForeignKey("test_definitions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    scenario_id = db.Column(
        db.Integer,
        db.ForeignKey("scenarios.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    # Snapshot the scenario version at execution time for conflict detection
    scenario_version_at_run = db.Column(db.Integer, nullable=True)

    state = db.Column(
        db.Enum(ExecutionState, name="execution_state_enum"),
        nullable=False,
        default=ExecutionState.NOT_STARTED,
        index=True,
    )
    is_rehearsal = db.Column(db.Boolean, nullable=False, default=False, index=True)

    started_at = db.Column(db.DateTime(timezone=True), nullable=True)
    completed_at = db.Column(db.DateTime(timezone=True), nullable=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # Human-readable reason for failures, cancellations, or blocks
    state_reason = db.Column(db.String(512), nullable=True)

    # Cancellation flag polled by execution loop
    cancel_requested = db.Column(db.Boolean, nullable=False, default=False)

    # ── Relationships ──────────────────────────────────────────────────────────
    test_definition = db.relationship("TestDefinition", back_populates="execution_runs")
    user = db.relationship("User", back_populates="execution_runs")
    scenario = db.relationship("Scenario")
    events = db.relationship(
        "ExecutionEvent",
        back_populates="run",
        order_by="ExecutionEvent.timestamp",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )
    evidence_records = db.relationship(
        "EvidenceRecord",
        back_populates="run",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )
    findings = db.relationship(
        "Finding",
        back_populates="run",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )

    @property
    def duration_seconds(self) -> float | None:
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None

    def __repr__(self) -> str:
        return f"<ExecutionRun id={self.id} state={self.state.value} rehearsal={self.is_rehearsal}>"


class ExecutionEvent(db.Model):
    """Stage-based progress events within an execution run (replaces WebSockets)."""

    __tablename__ = "execution_events"

    id = db.Column(db.Integer, primary_key=True)
    run_id = db.Column(
        db.Integer,
        db.ForeignKey("execution_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    timestamp = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    event_type = db.Column(db.String(64), nullable=False)   # e.g. "stage_start", "progress", "error"
    detail = db.Column(db.Text, nullable=True)              # Sanitized detail only

    run = db.relationship("ExecutionRun", back_populates="events")

    def __repr__(self) -> str:
        return f"<ExecutionEvent run={self.run_id} type={self.event_type}>"
