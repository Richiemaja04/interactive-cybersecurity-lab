"""
app/tests/network_api/module.py — Test 08: Network Tab & API Over-fetching

Source: Web Security Testing presentation, Test 08.
Category: Excessive Data Exposure & Broken Object Property Level Authorization.

Demonstrates how API endpoints often return entire database records or internal
object fields to the client, relying on the frontend to filter or hide sensitive
attributes (salary, SSN, internal role, private contact information).
Audited directly by inspecting HTTP response payloads in browser DevTools Network tab.
"""

from __future__ import annotations

from app.models.evidence import EvidenceRecord, EvidenceType, ProvenanceEnum
from app.models.finding import ConfidenceEnum, Finding, SeverityEnum, VerificationStatus
from app.tests._base import (
    ExecutionResult,
    PreconditionResult,
    PresenterNotes,
    RemediationGuidance,
    SecurityTestModule,
    SimulatedResult,
)


class NetworkApiModule(SecurityTestModule):
    test_id = "08"
    name = "Network Tab: What Is the Site Sending?"
    slug = "network-api"
    category = "Excessive Data Exposure"

    def validate_preconditions(self, scenario) -> PreconditionResult:
        if not scenario or not scenario.is_active:
            return PreconditionResult(ok=False, reason="Scenario is not active")
        return PreconditionResult(ok=True)

    def execute(self, run, scenario, config: dict) -> ExecutionResult:
        from app.extensions import db

        is_vulnerable = scenario.state.value == "vulnerable"
        evidence: list[EvidenceRecord] = []

        if is_vulnerable:
            api_detail = {
                "endpoint": "/api/lab/employees/101",
                "method": "GET",
                "status_code": 200,
                "returned_fields": [
                    "id",
                    "full_name",
                    "department",
                    "email",
                    "salary",
                    "ssn",
                    "internal_clearance",
                    "home_address",
                ],
                "sensitive_fields_exposed": [
                    "salary",
                    "ssn",
                    "internal_clearance",
                    "home_address",
                ],
                "ui_displayed_fields": ["id", "full_name", "department"],
                "data_minimization_applied": False,
            }
            obs = (
                "API endpoint /api/lab/employees/101 returns full internal database record. "
                "Sensitive fields (salary, ssn, clearance, address) are transmitted to the browser "
                "even though the UI only displays name and department."
            )
        else:
            api_detail = {
                "endpoint": "/api/lab/employees/101",
                "method": "GET",
                "status_code": 200,
                "returned_fields": ["id", "full_name", "department"],
                "sensitive_fields_exposed": [],
                "ui_displayed_fields": ["id", "full_name", "department"],
                "data_minimization_applied": True,
            }
            obs = (
                "API endpoint /api/lab/employees/101 enforces strict data minimization via response DTO. "
                "Only public profile fields required by the user interface are serialized."
            )

        api_evidence = EvidenceRecord(
            run_id=run.id,
            provenance=ProvenanceEnum.CONTROLLED_SCENARIO,
            evidence_type=EvidenceType.API_RESPONSE_FIELDS,
            title="API Response Payload Over-fetching Audit",
            sanitized_detail=api_detail,
            observation=obs,
            is_simulated=False,
        )
        db.session.add(api_evidence)
        evidence.append(api_evidence)

        finding = self.classify_finding(evidence)
        if finding:
            finding.run_id = run.id
            db.session.add(finding)

        db.session.flush()

        return ExecutionResult(
            state="completed",
            summary=(
                f"Network API inspection completed. Scenario is {scenario.state.value}. "
                f"{'Excessive sensitive data exposure detected in API response.' if is_vulnerable else 'API response strictly minimized.'}"
            ),
            evidence=evidence,
            finding=finding,
        )

    def collect_evidence(self, run) -> list:
        return list(run.evidence_records)

    def sanitize_evidence(self, evidence: list) -> list:
        return evidence

    def classify_finding(self, evidence: list) -> Finding | None:
        if not evidence:
            return None

        has_overfetching = False
        exposed_fields: list[str] = []

        for e in evidence:
            if e.evidence_type == EvidenceType.API_RESPONSE_FIELDS and isinstance(e.sanitized_detail, dict):
                exposed = e.sanitized_detail.get("sensitive_fields_exposed", [])
                if exposed:
                    has_overfetching = True
                    exposed_fields.extend(exposed)

        if not has_overfetching:
            return None

        return Finding(
            title="Excessive Data Exposure in API Response (Over-fetching)",
            description=(
                f"The API endpoint exposes sensitive entity fields ({', '.join(set(exposed_fields))}) "
                "to the browser that are not required by the user interface. Relying on frontend code "
                "to conceal or omit attributes creates a severe information disclosure vulnerability."
            ),
            severity=SeverityEnum.HIGH,
            confidence=ConfidenceEnum.HIGH,
            verification_status=VerificationStatus.CONFIRMED,
        )

    def get_remediation(self, finding: Finding) -> RemediationGuidance:
        return RemediationGuidance(
            summary="Implement server-side Data Transfer Objects (DTOs) with strict allowlists to minimize API responses.",
            steps=[
                "Never serialize raw ORM model entities directly into JSON responses.",
                "Define explicit response schemas (e.g. Marshmallow, Pydantic, or dataclasses) that whitelist allowed fields.",
                "Enforce object-property level authorization: restrict sensitive properties to authenticated administrators.",
                "Conduct regular API contract reviews comparing UI presentation requirements with backend payloads.",
            ],
            references=[
                "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
                "https://cwe.mitre.org/data/definitions/213.html",
            ],
            has_one_click_fix=True,
            fix_name="apply_api_response_minimization",
        )

    def get_verification_steps(self, finding: Finding) -> list[str]:
        return [
            "Open browser DevTools -> Network tab.",
            "Trigger the API request for the target resource.",
            "Select the request in the network list and click the 'Response' or 'Preview' tab.",
            "Verify that sensitive attributes (salary, ssn, clearance, address) are completely absent from the JSON payload.",
            "Verify the frontend interface still renders correctly without broken UI elements.",
        ]

    def get_presenter_notes(self) -> PresenterNotes:
        return PresenterNotes(
            objective="Show that what the user sees in the UI is only a subset of what the server actually sends.",
            demonstration_steps=[
                "Navigate to the lab directory view — show the innocent-looking employee profile card.",
                "Open browser DevTools -> Network tab and reload the profile card.",
                "Click on the GET /api/lab/employees/101 request and open the 'Preview' tab.",
                "Point out the unmasked SSN, salary, and home address returned in the JSON response.",
                "Toggle to secure scenario — re-run request to demonstrate minimized schema payload.",
            ],
            evidence_meaning=(
                "Even if frontend JavaScript or CSS does not display a field, any data sent "
                "over the wire is readable by anyone using browser inspection tools."
            ),
            talking_points=[
                "Frontend hiding is not security: the browser DevTools sees every byte sent across HTTP.",
                "Over-fetching increases network payload size and creates severe privacy/compliance violations (GDPR, HIPAA).",
                "APIs should be designed with the Principle of Least Privilege regarding data exposure.",
            ],
            remediation_takeaway=(
                "Filter and shape API responses on the server using strict DTO schemas before transmission."
            ),
        )

    def simulate(self, scenario) -> SimulatedResult:
        ev = EvidenceRecord(
            run_id=0,
            provenance=ProvenanceEnum.SIMULATED,
            evidence_type=EvidenceType.API_RESPONSE_FIELDS,
            title="[SIMULATED] API Over-fetching Audit",
            sanitized_detail={
                "endpoint": "/api/lab/employees/101",
                "sensitive_fields_exposed": ["salary", "ssn"],
                "data_minimization_applied": False,
            },
            observation="[SIMULATED REPLAY] Replay of API over-fetching response audit.",
            is_simulated=True,
        )
        return SimulatedResult(
            summary="[SIMULATED] API over-fetching inspection replay.",
            simulated_evidence=[ev],
        )
