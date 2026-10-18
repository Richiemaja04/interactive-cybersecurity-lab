"""
tests/integration/test_remediation_flow.py — Remediation workflow and optimistic lock tests.
"""

import pytest

from app.models.execution import ExecutionRun, ExecutionState
from app.models.finding import ConfidenceEnum, Finding, SeverityEnum, VerificationStatus
from app.models.remediation import OutcomeEnum, RemediationAction, RemediationAudit
from app.models.scenario import Scenario, ScenarioState, TestDefinition
from app.remediation.service import RemediationService, StaleActionError


@pytest.fixture
def remediation_scenario(db_session, tester_user):
    td = TestDefinition(
        number="04",
        name="Cookie Inspection",
        slug="cookies",
        category="Session",
        objective="Inspect cookie flags",
        concept="HttpOnly and Secure",
    )
    db_session.add(td)
    db_session.flush()

    scenario = Scenario(
        test_id=td.id,
        name="cookies_default",
        state=ScenarioState.VULNERABLE,
        current_version=1,
        config_json={},
    )
    db_session.add(scenario)
    db_session.flush()

    run = ExecutionRun(
        test_id=td.id,
        user_id=tester_user.id,
        scenario_id=scenario.id,
        state=ExecutionState.COMPLETED,
        scenario_version_at_run=1,
    )
    db_session.add(run)
    db_session.flush()

    finding = Finding(
        run_id=run.id,
        title="Session Cookie Missing HttpOnly Flag",
        description="Session cookie is exposed to JavaScript.",
        severity=SeverityEnum.MEDIUM,
        confidence=ConfidenceEnum.HIGH,
        verification_status=VerificationStatus.CONFIRMED,
    )
    db_session.add(finding)
    db_session.commit()
    return scenario, finding, run


def test_remediation_apply_and_reversal(remediation_scenario, tester_user, db_session):
    scenario, finding, run = remediation_scenario

    # 1. Apply fix with matching version (v1)
    action = RemediationService.apply_fix(
        finding_id=finding.id,
        user_id=tester_user.id,
        fix_name="set_httponly_and_secure",
        expected_scenario_version=1,
    )
    assert action.outcome == OutcomeEnum.RESOLVED
    assert scenario.state == ScenarioState.SECURE
    assert scenario.current_version == 2

    # Verify audit record
    audit = RemediationAudit.query.filter_by(action_id=action.id).first()
    assert audit is not None
    assert audit.event_type == "applied"

    # 2. Reverse fix with matching version (v2)
    reversal = RemediationService.reverse_fix(
        action_id=action.id,
        user_id=tester_user.id,
        expected_scenario_version=2,
    )
    assert reversal.is_reversal is True
    assert reversal.outcome == OutcomeEnum.PERSISTS
    assert scenario.state == ScenarioState.VULNERABLE
    assert scenario.current_version == 3


def test_remediation_stale_action_rejected(remediation_scenario, tester_user):
    scenario, finding, run = remediation_scenario

    # Attempt fix with mismatched expected version (e.g. expected 99 instead of 1)
    with pytest.raises(StaleActionError, match="Scenario state has changed"):
        RemediationService.apply_fix(
            finding_id=finding.id,
            user_id=tester_user.id,
            fix_name="set_httponly_and_secure",
            expected_scenario_version=99,
        )
    # Scenario state remains unmodified
    assert scenario.state == ScenarioState.VULNERABLE
    assert scenario.current_version == 1
