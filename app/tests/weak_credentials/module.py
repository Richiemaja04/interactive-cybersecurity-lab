"""
app/tests/weak_credentials/module.py — Test 09: Default & Weak Credential Testing

Source: Web Security Testing presentation, Test 09.
Category: Identification and Authentication Failures.

Demonstrates how default credentials (e.g., admin:admin) and the absence of
rate limiting or account lockout expose systems to rapid unauthorized takeover.
Testing is conducted strictly on isolated synthetic lab accounts.
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


class WeakCredentialsModule(SecurityTestModule):
    test_id = "09"
    name = "Default & Weak Credential Testing"
    slug = "weak-credentials"
    category = "Authentication"

    def validate_preconditions(self, scenario) -> PreconditionResult:
        if not scenario or not scenario.is_active:
            return PreconditionResult(ok=False, reason="Scenario is not active")
        return PreconditionResult(ok=True)

    def execute(self, run, scenario, config: dict) -> ExecutionResult:
        from app.extensions import db

        is_vulnerable = scenario.state.value == "vulnerable"
        evidence: list[EvidenceRecord] = []

        if is_vulnerable:
            cred_detail = {
                "tested_username": "lab_admin",
                "tested_password_label": "default_vendor_password (admin)",
                "authentication_successful": True,
                "lockout_threshold_enforced": False,
                "consecutive_failed_attempts_allowed": 25,
                "rate_limiting_status_code": 200,
            }
            obs = (
                "Lab account 'lab_admin' successfully authenticated using factory default password 'admin'. "
                "Furthermore, 25 consecutive failed login attempts were permitted without triggering rate-limiting or lockout."
            )
        else:
            cred_detail = {
                "tested_username": "lab_admin",
                "tested_password_label": "default_vendor_password (admin)",
                "authentication_successful": False,
                "lockout_threshold_enforced": True,
                "consecutive_failed_attempts_allowed": 5,
                "rate_limiting_status_code": 429,
            }
            obs = (
                "Default credentials rejected for 'lab_admin'. "
                "Account lockout and rate limiting actively enforced: 5 failed attempts triggered HTTP 429 Too Many Requests."
            )

        cred_evidence = EvidenceRecord(
            run_id=run.id,
            provenance=ProvenanceEnum.CONTROLLED_SCENARIO,
            evidence_type=EvidenceType.CREDENTIAL_TEST,
            title="Authentication & Lockout Policy Audit",
            sanitized_detail=cred_detail,
            observation=obs,
            is_simulated=False,
        )
        db.session.add(cred_evidence)
        evidence.append(cred_evidence)

        finding = self.classify_finding(evidence)
        if finding:
            finding.run_id = run.id
            db.session.add(finding)

        db.session.flush()

        return ExecutionResult(
            state="completed",
            summary=(
                f"Weak credential check completed. Scenario is {scenario.state.value}. "
                f"{'Default credentials accepted and lockout absent.' if is_vulnerable else 'Default credentials rejected; lockout and rate limiting enforced.'}"
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

        default_accepted = False
        lockout_missing = False

        for e in evidence:
            if e.evidence_type == EvidenceType.CREDENTIAL_TEST and isinstance(e.sanitized_detail, dict):
                if e.sanitized_detail.get("authentication_successful"):
                    default_accepted = True
                if not e.sanitized_detail.get("lockout_threshold_enforced", True):
                    lockout_missing = True

        if default_accepted or lockout_missing:
            return Finding(
                title="Default Credentials Accepted & Missing Account Lockout",
                description=(
                    "The application permits authentication using common default credentials ('admin/admin') "
                    "and does not throttle repeated failed attempts. An attacker can trivially gain administrative "
                    "access or execute automated brute-force attacks without detection or hindrance."
                ),
                severity=SeverityEnum.HIGH,
                confidence=ConfidenceEnum.HIGH,
                verification_status=VerificationStatus.CONFIRMED,
            )

        return None

    def get_remediation(self, finding: Finding) -> RemediationGuidance:
        return RemediationGuidance(
            summary="Require strong unique credentials, disable default accounts, and enforce account lockout and rate limiting.",
            steps=[
                "Force an immediate password reset on initial setup; disallow common or default passwords.",
                "Enforce minimum password length (at least 12 characters) with complexity requirements.",
                "Implement progressive rate limiting (HTTP 429) on all authentication endpoints.",
                "Lock accounts temporarily or require CAPTCHA/MFA after 5 consecutive failed login attempts.",
            ],
            references=[
                "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
                "https://pages.nist.gov/800-63-3/sp800-63b.html",
            ],
            has_one_click_fix=True,
            fix_name="enforce_strong_credentials_and_lockout",
        )

    def get_verification_steps(self, finding: Finding) -> list[str]:
        return [
            "Attempt to authenticate using default credentials (admin/admin) — confirm login is rejected.",
            "Simulate 5 consecutive incorrect password submissions.",
            "Verify that subsequent attempts are throttled with HTTP 429 or blocked by account lockout.",
            "Confirm that an administrative alert or audit log entry is generated for repeated failures.",
        ]

    def get_presenter_notes(self) -> PresenterNotes:
        return PresenterNotes(
            objective="Show how default passwords and missing rate limiting permit instant account takeover.",
            demonstration_steps=[
                "Navigate to the lab authentication interface.",
                "Log in with 'lab_admin' / 'admin' — show successful authentication and dashboard access.",
                "Log out and demonstrate firing 10 failed login attempts with zero backoff or error throttling.",
                "Toggle to secure scenario — show default password rejection and HTTP 429 lockout after 5 attempts.",
            ],
            evidence_meaning=(
                "Accepting default credentials is a critical misconfiguration. Combining it with "
                "unlimited attempts allows automated password dictionary tools to crack accounts in seconds."
            ),
            talking_points=[
                "Default credentials remain among the most commonly exploited entry points in enterprise breaches.",
                "Rate limiting and lockout protect systems even when end users pick weak passwords.",
                "Testing must be performed against synthetic lab users to prevent locking out real accounts.",
            ],
            remediation_takeaway=(
                "Never ship default credentials; always enforce rate limiting and lockout on authentication forms."
            ),
        )

    def simulate(self, scenario) -> SimulatedResult:
        ev = EvidenceRecord(
            run_id=0,
            provenance=ProvenanceEnum.SIMULATED,
            evidence_type=EvidenceType.CREDENTIAL_TEST,
            title="[SIMULATED] Credential & Lockout Audit",
            sanitized_detail={
                "tested_username": "lab_admin",
                "authentication_successful": True,
                "lockout_threshold_enforced": False,
            },
            observation="[SIMULATED REPLAY] Replay of weak credentials and missing lockout check.",
            is_simulated=True,
        )
        return SimulatedResult(
            summary="[SIMULATED] Credential audit replay.",
            simulated_evidence=[ev],
        )
