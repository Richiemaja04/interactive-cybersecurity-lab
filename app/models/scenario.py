"""
app/models/scenario.py — Test definitions, scenarios, and versioned scenario history.

ScenarioVersion provides a linear, immutable history of mutations.
Parallel branches are out of scope for v1.
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone

from app.extensions import db


class ScenarioState(str, enum.Enum):
    VULNERABLE = "vulnerable"
    SECURE = "secure"


class TestDefinition(db.Model):
    """
    Static definition of each of the ten security tests.
    Populated via initial migration seed data.
    """

    __tablename__ = "test_definitions"
    __test__ = False  # Not a pytest test class

    id = db.Column(db.Integer, primary_key=True)
    number = db.Column(db.String(2), unique=True, nullable=False)   # "01" – "10"
    name = db.Column(db.String(128), nullable=False)
    slug = db.Column(db.String(64), unique=True, nullable=False, index=True)
    category = db.Column(db.String(64), nullable=False)
    objective = db.Column(db.Text, nullable=False)
    concept = db.Column(db.Text, nullable=False)
    presenter_notes = db.Column(db.Text, nullable=True)

    scenarios = db.relationship("Scenario", back_populates="test_definition", lazy="dynamic")
    execution_runs = db.relationship("ExecutionRun", back_populates="test_definition", lazy="dynamic")

    def __repr__(self) -> str:
        return f"<TestDefinition {self.number}: {self.name}>"


class Scenario(db.Model):
    """
    A named, versioned scenario for a test (e.g., 'robots_txt_vulnerable').
    Current version is tracked; mutations create a new ScenarioVersion.
    """

    __tablename__ = "scenarios"

    id = db.Column(db.Integer, primary_key=True)
    test_id = db.Column(
        db.Integer, db.ForeignKey("test_definitions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name = db.Column(db.String(128), nullable=False)
    description = db.Column(db.Text, nullable=True)
    current_version = db.Column(db.Integer, nullable=False, default=1)
    state = db.Column(
        db.Enum(ScenarioState, name="scenario_state_enum"),
        nullable=False,
        default=ScenarioState.VULNERABLE,
    )
    config_json = db.Column(db.JSON, nullable=False, default=dict)
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

    test_definition = db.relationship("TestDefinition", back_populates="scenarios")
    versions = db.relationship(
        "ScenarioVersion",
        back_populates="scenario",
        order_by="ScenarioVersion.version",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<Scenario {self.name!r} v{self.current_version} state={self.state.value}>"


class ScenarioVersion(db.Model):
    """
    Immutable snapshot of a scenario at a specific version.
    Linear history only — no parallel branches.
    """

    __tablename__ = "scenario_versions"
    __table_args__ = (
        db.UniqueConstraint("scenario_id", "version", name="uq_scenario_version"),
    )

    id = db.Column(db.Integer, primary_key=True)
    scenario_id = db.Column(
        db.Integer, db.ForeignKey("scenarios.id", ondelete="CASCADE"), nullable=False, index=True
    )
    version = db.Column(db.Integer, nullable=False)
    snapshot_json = db.Column(db.JSON, nullable=False)
    change_description = db.Column(db.String(255), nullable=True)
    changed_by_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    changed_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    scenario = db.relationship("Scenario", back_populates="versions")
    changed_by = db.relationship("User")

    def __repr__(self) -> str:
        return f"<ScenarioVersion scenario={self.scenario_id} v{self.version}>"
