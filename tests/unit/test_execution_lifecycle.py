"""
tests/unit/test_execution_lifecycle.py — Phase 2: Execution lifecycle manager unit tests.
"""

from __future__ import annotations

import time
import pytest

from app.models.execution import ExecutionEvent, ExecutionRun, ExecutionState
from app.models.scenario import Scenario, ScenarioState, TestDefinition
from app.services.execution_service import (
    ExecutionService,
    ScopeViolation,
)
from app.tests._base import (
    ExecutionResult,
    PreconditionResult,
    PresenterNotes,
    RemediationGuidance,
    SecurityTestModule,
    SimulatedResult,
)


class MockSuccessModule(SecurityTestModule):
    test_id = "01"
    name = "Mock Success Module"
    slug = "mock-success"
    category = "Testing"

    def validate_preconditions(self, scenario):
        return PreconditionResult(ok=True)

    def execute(self, run, scenario, config):
        return ExecutionResult(state="completed", summary="Success", evidence=[])

    def collect_evidence(self, run): return []
    def sanitize_evidence(self, evidence): return evidence
    def classify_finding(self, evidence): return None
    def get_remediation(self, finding): return RemediationGuidance(description="", rationale="", fix_name="", code_diff="")
    def get_verification_steps(self, finding): return []
    def get_presenter_notes(self): return PresenterNotes(objective="", test_steps=[], evidence_interpretation="", talking_points=[], remediation_takeaway="")
    def simulate(self, scenario): return SimulatedResult(summary="", evidence_records=[])


class MockTimeoutModule(MockSuccessModule):
    def execute(self, run, scenario, config):
        time.sleep(2.0)
        return ExecutionResult(state="completed", summary="Success", evidence=[])


class MockScopeViolationModule(MockSuccessModule):
    def execute(self, run, scenario, config):
        raise ScopeViolation("Attempted request to private IP 192.168.1.1 is prohibited")


class MockCancelledModule(MockSuccessModule):
    def execute(self, run, scenario, config):
        return ExecutionResult(state="cancelled", summary="Cancelled", evidence=[], state_reason="User clicked cancel")


@pytest.fixture
def test_def_fixture(db_session):
    test_def = TestDefinition(
        number="99",
        name="Lifecycle Test",
        slug="lifecycle-test",
        category="Testing",
        objective="Verify lifecycle",
        concept="State machine",
    )
    db_session.add(test_def)
    db_session.commit()
    return test_def


class TestExecutionLifecycle:
    """Tests lifecycle states: Completed, Failed, Blocked, Cancelled, Timeout."""

    def test_successful_execution_transitions_to_completed(self, db_session, test_def_fixture, app):
        run = ExecutionRun(test_id=test_def_fixture.id, user_id=None, scenario_version_at_run=1)
        db_session.add(run)
        db_session.commit()

        scenario = Scenario(test_id=test_def_fixture.id, name="Test Scenario", current_version=1, state=ScenarioState.VULNERABLE)
        service = ExecutionService(run, MockSuccessModule(), timeout=5)
        service.execute(scenario, {})

        assert run.state == ExecutionState.COMPLETED
        assert run.completed_at is not None

    def test_timeout_transitions_to_failed(self, db_session, test_def_fixture, app):
        run = ExecutionRun(test_id=test_def_fixture.id, user_id=None, scenario_version_at_run=1)
        db_session.add(run)
        db_session.commit()

        scenario = Scenario(test_id=test_def_fixture.id, name="Test Scenario", current_version=1, state=ScenarioState.VULNERABLE)
        # Timeout set to 0.1s while module sleeps 2s
        service = ExecutionService(run, MockTimeoutModule(), timeout=0.1)
        service.execute(scenario, {})

        assert run.state == ExecutionState.FAILED
        assert "exceeded" in run.state_reason.lower() or "timeout" in run.state_reason.lower()

    def test_scope_violation_transitions_to_blocked(self, db_session, test_def_fixture, app):
        run = ExecutionRun(test_id=test_def_fixture.id, user_id=None, scenario_version_at_run=1)
        db_session.add(run)
        db_session.commit()

        scenario = Scenario(test_id=test_def_fixture.id, name="Test Scenario", current_version=1, state=ScenarioState.VULNERABLE)
        service = ExecutionService(run, MockScopeViolationModule(), timeout=5)
        service.execute(scenario, {})

        assert run.state == ExecutionState.BLOCKED
        assert "192.168.1.1" in run.state_reason

    def test_cooperative_cancellation_transitions_to_cancelled(self, db_session, test_def_fixture, app):
        run = ExecutionRun(test_id=test_def_fixture.id, user_id=None, scenario_version_at_run=1)
        db_session.add(run)
        db_session.commit()

        scenario = Scenario(test_id=test_def_fixture.id, name="Test Scenario", current_version=1, state=ScenarioState.VULNERABLE)
        service = ExecutionService(run, MockCancelledModule(), timeout=5)
        service.execute(scenario, {})

        assert run.state == ExecutionState.CANCELLED
        assert "cancel" in run.state_reason.lower()
