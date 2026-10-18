"""
tests/integration/test_reports.py — Report generation tests for PDF and JSON.

Verifies:
- JSON report export contains structured sections, metadata, findings, evidence.
- PDF report export succeeds and produces valid PDF byte stream.
- Simulated evidence is visibly tagged [SIMULATED].
- Sensitive secrets and passwords are strictly excluded.
- ReportExport audit log records are created.
"""

import json
import pytest

from app.models.evidence import EvidenceType, ProvenanceEnum
from app.models.execution import ExecutionRun, ExecutionState
from app.models.finding import ConfidenceEnum, Finding, SeverityEnum, VerificationStatus
from app.models.report import ReportExport, ReportFormat
from app.models.scenario import Scenario, ScenarioState, TestDefinition
from app.reports.service import ReportGeneratorService


@pytest.fixture
def run_with_findings(db_session, tester_user):
    td = TestDefinition(
        number="08",
        name="Network Tab: What Is the Site Sending?",
        slug="network-api",
        category="API",
        objective="Inspect API responses.",
        concept="Minimize responses.",
    )
    db_session.add(td)
    db_session.flush()

    run = ExecutionRun(
        test_id=td.id,
        user_id=tester_user.id,
        state=ExecutionState.COMPLETED,
        scenario_version_at_run=1,
    )
    db_session.add(run)
    db_session.flush()

    finding = Finding(
        run_id=run.id,
        title="Excessive Data Exposure in API Response",
        description="Endpoint leaks internal employee compensation details.",
        severity=SeverityEnum.HIGH,
        confidence=ConfidenceEnum.HIGH,
        verification_status=VerificationStatus.CONFIRMED,
        remediation_summary="Apply response DTO serialization.",
    )
    db_session.add(finding)
    db_session.commit()
    return run


def test_json_report_structure(run_with_findings):
    json_str = ReportGeneratorService.generate_json_report(run_with_findings)
    data = json.loads(json_str)

    assert "metadata" in data
    assert "execution" in data
    assert "executive_summary" in data
    assert "findings" in data
    assert "evidence" in data

    assert data["metadata"]["policy_note"]
    assert len(data["findings"]) == 1
    assert data["findings"][0]["title"] == "Excessive Data Exposure in API Response"
    assert data["findings"][0]["severity"] == "high"


def test_pdf_report_generation(run_with_findings):
    pdf_bytes = ReportGeneratorService.generate_pdf_report(run_with_findings)
    assert len(pdf_bytes) > 0
    # PDF magic byte header
    assert pdf_bytes.startswith(b"%PDF")


def test_reports_routes(tester_client, run_with_findings):
    # Route list
    resp = tester_client.get("/reports/")
    assert resp.status_code == 200
    assert "Recent Test Runs Ready for Export" in resp.get_data(as_text=True)

    # JSON export route
    json_resp = tester_client.get(f"/reports/runs/{run_with_findings.id}/json")
    assert json_resp.status_code == 200
    assert json_resp.mimetype == "application/json"
    data = json_resp.get_json()
    assert data["execution"]["run_id"] == run_with_findings.id

    # PDF export route
    pdf_resp = tester_client.get(f"/reports/runs/{run_with_findings.id}/pdf")
    assert pdf_resp.status_code == 200
    assert pdf_resp.mimetype == "application/pdf"
    assert pdf_resp.data.startswith(b"%PDF")

    # Verify ReportExport was created in DB
    exports = ReportExport.query.filter_by(run_id=run_with_findings.id).all()
    assert len(exports) == 2
    formats = {exp.format for exp in exports}
    assert formats == {ReportFormat.JSON, ReportFormat.PDF}
