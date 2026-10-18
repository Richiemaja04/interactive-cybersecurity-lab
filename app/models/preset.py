"""app/models/preset.py — Presets and presentation sequences."""

from __future__ import annotations

from datetime import datetime, timezone

from app.extensions import db


class Preset(db.Model):
    """
    Administrator-managed deterministic scenario configuration.
    Testers can load (read-only); only admins can create/modify.
    """

    __tablename__ = "presets"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), unique=True, nullable=False, index=True)
    description = db.Column(db.Text, nullable=True)
    version = db.Column(db.Integer, nullable=False, default=1)
    created_by_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    config_json = db.Column(db.JSON, nullable=False, default=dict)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    external_id = db.Column(db.String(64), nullable=True, unique=True)  # For import/export dedup
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

    created_by = db.relationship("User")
    sequence_steps = db.relationship("SequenceStep", back_populates="preset", lazy="dynamic")

    def __repr__(self) -> str:
        return f"<Preset {self.name!r} v{self.version}>"


class PresentationSequence(db.Model):
    """Ordered collection of test steps for a guided presentation."""

    __tablename__ = "presentation_sequences"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False, index=True)
    description = db.Column(db.Text, nullable=True)
    version = db.Column(db.Integer, nullable=False, default=1)
    created_by_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    is_default = db.Column(db.Boolean, nullable=False, default=False)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
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

    created_by = db.relationship("User")
    steps = db.relationship(
        "SequenceStep",
        back_populates="sequence",
        order_by="SequenceStep.step_order",
        cascade="all, delete-orphan",
        lazy="joined",
    )

    def __repr__(self) -> str:
        return f"<PresentationSequence {self.name!r} v{self.version}>"


class SequenceStep(db.Model):
    """One step in a presentation sequence — links a test to an optional preset."""

    __tablename__ = "sequence_steps"
    __table_args__ = (
        db.UniqueConstraint("sequence_id", "step_order", name="uq_sequence_step_order"),
    )

    id = db.Column(db.Integer, primary_key=True)
    sequence_id = db.Column(
        db.Integer,
        db.ForeignKey("presentation_sequences.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    step_order = db.Column(db.Integer, nullable=False)
    test_id = db.Column(
        db.Integer,
        db.ForeignKey("test_definitions.id", ondelete="CASCADE"),
        nullable=False,
    )
    preset_id = db.Column(
        db.Integer,
        db.ForeignKey("presets.id", ondelete="SET NULL"),
        nullable=True,
    )
    presenter_notes_override = db.Column(db.Text, nullable=True)

    sequence = db.relationship("PresentationSequence", back_populates="steps")
    test_definition = db.relationship("TestDefinition")
    preset = db.relationship("Preset", back_populates="sequence_steps")

    def __repr__(self) -> str:
        return f"<SequenceStep seq={self.sequence_id} order={self.step_order} test={self.test_id}>"
