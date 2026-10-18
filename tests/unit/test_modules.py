"""
tests/unit/test_modules.py — Unit tests for all ten security test modules.

Verifies:
- All 10 modules implement SecurityTestModule contract.
- Vulnerable vs secure scenario execution.
- Finding classification, severity, confidence, and verification status.
- Evidence record provenance tagging.
- Simulation methods produce explicitly labeled simulated evidence.
- Presenter notes, verification steps, and remediation guidance exist and are non-empty.
"""

import pytest

from app.models.evidence import EvidenceType, ProvenanceEnum
from app.models.execution import ExecutionRun, ExecutionState
from app.models.finding import ConfidenceEnum, SeverityEnum, VerificationStatus
from app.models.scenario import Scenario, ScenarioState, TestDefinition
from app.tests.registry import get_all_modules, get_module_by_number, get_module_by_slug


@pytest.fixture
def mock_scenario_vuln(db_session):
    td = TestDefinition(
        number="99",
        name="Mock Test",
        slug="mock-test",
        category="Test Category",
        objective="Test Objective",
        concept="Test Concept",
    )
    db_session.add(td)
    db_session.flush()

    scenario = Scenario(
        test_id=td.id,
        name="mock_vuln",
        state=ScenarioState.VULNERABLE,
        current_version=1,
        config_json={},
    )
    db_session.add(scenario)
    db_session.flush()
    return scenario


@pytest.fixture
def mock_scenario_secure(db_session):
    td = TestDefinition(
        number="98",
        name="Mock Secure Test",
        slug="mock-secure-test",
        category="Test Category",
        objective="Test Objective",
        concept="Test Concept",
    )
    db_session.add(td)
    db_session.flush()

    scenario = Scenario(
        test_id=td.id,
        name="mock_secure",
        state=ScenarioState.SECURE,
        current_version=1,
        config_json={},
    )
    db_session.add(scenario)
    db_session.flush()
    return scenario


@pytest.fixture
def test_run(db_session, tester_user, mock_scenario_vuln):
    run = ExecutionRun(
        test_id=mock_scenario_vuln.test_id,
        user_id=tester_user.id,
        state=ExecutionState.RUNNING,
        scenario_version_at_run=1,
    )
    db_session.add(run)
    db_session.flush()
    return run


def test_registry_contains_all_ten_modules():
    modules = get_all_modules()
    assert len(modules) == 10

    expected_slugs = {
        "robots-txt",
        "idor",
        "forced-browsing",
        "cookies",
        "https-certificate",
        "input-validation",
        "source-inspection",
        "network-api",
        "weak-credentials",
        "error-analysis",
    }
    assert set(modules.keys()) == expected_slugs

    for num in [f"{i:02d}" for i in range(1, 11)]:
        mod = get_module_by_number(num)
        assert mod is not None, f"Module {num} missing from registry"
        assert mod.test_id == num


@pytest.mark.parametrize("slug", [
    "robots-txt",
    "idor",
    "forced-browsing",
    "cookies",
    "https-certificate",
    "input-validation",
    "source-inspection",
    "network-api",
    "weak-credentials",
    "error-analysis",
])
def test_all_modules_contract_metadata(slug):
    mod = get_module_by_slug(slug)
    assert mod is not None
    assert len(mod.test_id) == 2
    assert mod.name
    assert mod.slug == slug
    assert mod.category

    notes = mod.get_presenter_notes()
    assert notes.objective
    assert len(notes.demonstration_steps) > 0
    assert len(notes.talking_points) > 0

    remediation = mod.get_remediation(None)
    assert remediation.summary
    assert len(remediation.steps) > 0

    steps = mod.get_verification_steps(None)
    assert len(steps) > 0


@pytest.mark.parametrize("slug", [
    "robots-txt",
    "idor",
    "forced-browsing",
    "cookies",
    "https-certificate",
    "input-validation",
    "source-inspection",
    "network-api",
    "weak-credentials",
    "error-analysis",
])
def test_module_vulnerable_execution(slug, db_session, test_run, mock_scenario_vuln):
    mod = get_module_by_slug(slug)
    res = mod.execute(test_run, mock_scenario_vuln, {})

    assert res.state == "completed"
    assert len(res.evidence) > 0
    assert res.finding is not None
    assert res.finding.verification_status in (
        VerificationStatus.CONFIRMED,
        VerificationStatus.POTENTIAL,
    )
    assert res.finding.severity in (
        SeverityEnum.CRITICAL,
        SeverityEnum.HIGH,
        SeverityEnum.MEDIUM,
        SeverityEnum.LOW,
        SeverityEnum.INFORMATIONAL,
    )
    assert res.finding.confidence in (ConfidenceEnum.HIGH, ConfidenceEnum.MEDIUM)

    # Check evidence provenance: should be CONTROLLED_SCENARIO
    for ev in res.evidence:
        assert ev.provenance == ProvenanceEnum.CONTROLLED_SCENARIO
        assert ev.is_simulated is False


@pytest.mark.parametrize("slug", [
    "robots-txt",
    "idor",
    "forced-browsing",
    "cookies",
    "https-certificate",
    "input-validation",
    "source-inspection",
    "network-api",
    "weak-credentials",
    "error-analysis",
])
def test_module_secure_execution(slug, db_session, test_run, mock_scenario_secure):
    mod = get_module_by_slug(slug)
    res = mod.execute(test_run, mock_scenario_secure, {})

    assert res.state == "completed"
    assert len(res.evidence) > 0
    # In secure scenario, finding should be None
    assert res.finding is None


@pytest.mark.parametrize("slug", [
    "cookies",
    "https-certificate",
    "input-validation",
    "source-inspection",
    "network-api",
    "weak-credentials",
    "error-analysis",
])
def test_module_simulation_labeled_correctly(slug, mock_scenario_vuln):
    mod = get_module_by_slug(slug)
    sim_res = mod.simulate(mock_scenario_vuln)

    assert sim_res.summary
    assert len(sim_res.simulated_evidence) > 0
    for ev in sim_res.simulated_evidence:
        assert ev.is_simulated is True
        assert ev.provenance == ProvenanceEnum.SIMULATED
        assert "[SIMULATED" in ev.title
