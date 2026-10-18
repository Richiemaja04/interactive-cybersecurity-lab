"""
app/tests/idor/module.py — Test 02: URL Parameter Tampering & IDOR

Source: Web Security Testing presentation, Test 02.
Category: Broken Object Level Authorization (BOLA / IDOR).

Demonstrates that changing URL parameters or request identifiers (e.g. account_id, doc_id)
can allow unauthorized access to records belonging to other users if server-side authorization is absent.
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


class IdorModule(SecurityTestModule):
    test_id = "02"
    name = "URL Parameter Tampering & IDOR"
    slug = "idor"
    category = "Broken Access Control"

    def validate_preconditions(self, scenario) -> PreconditionResult:
        if not scenario or not scenario.is_active:
            return PreconditionResult(ok=False, reason="Scenario is not active")
        return PreconditionResult(ok=True)

    def execute(self, run, scenario, config: dict) -> ExecutionResult:
        from app.extensions import db

        is_vulnerable = scenario.state.value == "vulnerable"
        evidence: list[EvidenceRecord] = []

        if is_vulnerable:
            idor_detail = {
                "authenticated_user_id": 42,
                "requested_record_id": 105,
                "record_actual_owner_id": 99,
                "record_title": "Executive Compensation Review 2026 (Confidential)",
                "authorization_enforced": False,
                "status_code": 200,
                "url": "/api/lab/records?id=105",
            }
            obs = (
                "User 42 tampered with the 'id' parameter (requesting id=105 belonging to User 99). "
                "The server returned the record with status 200 without checking ownership."
            )
        else:
            idor_detail = {
                "authenticated_user_id": 42,
                "requested_record_id": 105,
                "record_actual_owner_id": 99,
                "record_title": None,
                "authorization_enforced": True,
                "status_code": 403,
                "url": "/api/lab/records?id=105",
            }
            obs = (
                "User 42 requested id=105 belonging to User 99. "
                "The server enforced ownership validation and rejected the request with 403 Forbidden."
            )

        idor_evidence = EvidenceRecord(
            run_id=run.id,
            provenance=ProvenanceEnum.CONTROLLED_SCENARIO,
            evidence_type=EvidenceType.URL_PARAMETER,
            title="Object Reference Authorization Verification",
            sanitized_detail=idor_detail,
            observation=obs,
            is_simulated=False,
        )
        db.session.add(idor_evidence)
        evidence.append(idor_evidence)

        finding = self.classify_finding(evidence)
        if finding:
            finding.run_id = run.id
            db.session.add(finding)

        db.session.flush()

        return ExecutionResult(
            state="completed",
            summary=(
                f"IDOR check completed. Scenario is {scenario.state.value}. "
                f"{'Unauthorized horizontal data access confirmed.' if is_vulnerable else 'Server-side authorization enforced.'}"
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

        unauthorized_access = False
        for e in evidence:
            if e.evidence_type == EvidenceType.URL_PARAMETER and isinstance(e.sanitized_detail, dict):
                detail = e.sanitized_detail
                if detail.get("status_code") == 200 and not detail.get("authorization_enforced"):
                    unauthorized_access = True

        if not unauthorized_access:
            return None

        return Finding(
            title="Insecure Direct Object Reference (IDOR) Permits Cross-Tenant Data Access",
            description=(
                "The application retrieves sensitive records directly using user-supplied primary keys "
                "without verifying whether the authenticated user has permission to access the target entity. "
                "Attackers can iterate IDs to harvest private data across all tenant accounts."
            ),
            severity=SeverityEnum.CRITICAL,
            confidence=ConfidenceEnum.HIGH,
            verification_status=VerificationStatus.CONFIRMED,
        )

    def get_remediation(self, finding: Finding) -> RemediationGuidance:
        return RemediationGuidance(
            summary="Scope all database queries to the current authenticated user's organization or ID, and use unguessable UUIDs.",
            steps=[
                "Always filter queries by the authenticated user ID: query.filter_by(id=target_id, owner_id=current_user.id).",
                "Implement an authorization policy / decorator checking relationship ownership before data loading.",
                "Replace sequential auto-increment integer IDs in public APIs with version 4 UUIDs or nanoids.",
                "Return 404 (Not Found) rather than 403 on IDOR attempts to prevent object existence enumeration.",
            ],
            references=[
                "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
                "https://portswigger.net/web-security/access-control/idor",
            ],
            has_one_click_fix=True,
            fix_name="enforce_object_level_authorization",
        )

    def get_verification_steps(self, finding: Finding) -> list[str]:
        return [
            "Log in as Test User A and record the ID of a private document (e.g., ID 101).",
            "Log in as Test User B and attempt to retrieve ID 101 via URL parameter or API request.",
            "Confirm the server returns 403 Forbidden or 404 Not Found.",
            "Confirm no metadata or document body belonging to User A is returned in the response payload.",
        ]

    def get_presenter_notes(self) -> PresenterNotes:
        return PresenterNotes(
            objective="Demonstrate how easily horizontal privilege escalation occurs when servers trust client-provided IDs.",
            demonstration_steps=[
                "Open profile page showing record '?id=42'.",
                "Change query parameter in browser address bar to '?id=99' and press Enter.",
                "Show that confidential record of User 99 is displayed without any password check.",
                "Toggle to secure scenario — repeat tampering — show immediate 403 access denial.",
            ],
            evidence_meaning=(
                "A 200 OK containing data owned by User B when requested by User A is definitive proof of an authorization flaw."
            ),
            talking_points=[
                "Authentication proves WHO you are; authorization decides WHAT you can touch.",
                "IDOR has ranked as the #1 API security vulnerability for multiple years (BOLA).",
                "Frontend hiding (disabling buttons) is useless: requests can be generated directly.",
            ],
            remediation_takeaway=(
                "Enforce tenant and ownership checks on the server for every single database fetch."
            ),
        )

    def simulate(self, scenario) -> SimulatedResult:
        ev = EvidenceRecord(
            run_id=0,
            provenance=ProvenanceEnum.SIMULATED,
            evidence_type=EvidenceType.URL_PARAMETER,
            title="[SIMULATED] IDOR Check",
            sanitized_detail={"status_code": 200, "authorization_enforced": False},
            observation="[SIMULATED REPLAY] Replay of IDOR unauthorized record retrieval.",
            is_simulated=True,
        )
        return SimulatedResult(
            summary="[SIMULATED] IDOR tampering check replay.",
            evidence_records=[ev],
        )
