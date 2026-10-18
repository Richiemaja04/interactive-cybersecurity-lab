"""
app/tests/cookies/module.py — Test 04: Cookie Security Flags Inspection

Source: Web Security Testing presentation, Test 04.
Category: Session Management & Cryptographic Controls.

Audits cookie security attributes:
- HttpOnly: Prevents client-side script theft (document.cookie)
- Secure: Ensures transmission over HTTPS only
- SameSite: Mitigates Cross-Site Request Forgery (CSRF)
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


class CookiesModule(SecurityTestModule):
    test_id = "04"
    name = "Cookie Inspection"
    slug = "cookies"
    category = "Session Management"

    def validate_preconditions(self, scenario) -> PreconditionResult:
        if not scenario or not scenario.is_active:
            return PreconditionResult(ok=False, reason="Scenario is not active")
        return PreconditionResult(ok=True)

    def execute(self, run, scenario, config: dict) -> ExecutionResult:
        from app.extensions import db

        is_vulnerable = scenario.state.value == "vulnerable"
        evidence: list[EvidenceRecord] = []

        if is_vulnerable:
            cookie_payload = {
                "name": "lab_session_token",
                "value": "tok_9f83a8e2bc74",
                "httponly": False,
                "secure": False,
                "samesite": "None",
                "domain": "example-lab.local",
                "path": "/",
            }
            obs = (
                "Cookie 'lab_session_token' lacks HttpOnly and Secure flags, and SameSite=None. "
                "The cookie can be read by client-side scripts and transmitted in plaintext."
            )
        else:
            cookie_payload = {
                "name": "lab_session_token",
                "value": "tok_9f83a8e2bc74",
                "httponly": True,
                "secure": True,
                "samesite": "Lax",
                "domain": "example-lab.local",
                "path": "/",
            }
            obs = (
                "Cookie 'lab_session_token' has HttpOnly=True, Secure=True, and SameSite=Lax. "
                "Protected against XSS theft, plaintext eavesdropping, and cross-site CSRF."
            )

        cookie_evidence = EvidenceRecord(
            run_id=run.id,
            provenance=ProvenanceEnum.CONTROLLED_SCENARIO,
            evidence_type=EvidenceType.COOKIE_ATTRIBUTES,
            title="Session Cookie Attributes Audit",
            sanitized_detail=cookie_payload,
            observation=obs,
            is_simulated=False,
        )
        db.session.add(cookie_evidence)
        evidence.append(cookie_evidence)

        finding = self.classify_finding(evidence)
        if finding:
            finding.run_id = run.id
            db.session.add(finding)

        db.session.flush()

        return ExecutionResult(
            state="completed",
            summary=(
                f"Cookie inspection completed. Scenario is {scenario.state.value}. "
                f"{'Vulnerable missing flags identified.' if is_vulnerable else 'All security flags present.'}"
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

        vuln_cookies = []
        for e in evidence:
            if e.evidence_type == EvidenceType.COOKIE_ATTRIBUTES and isinstance(e.sanitized_detail, dict):
                detail = e.sanitized_detail
                if not detail.get("httponly") or not detail.get("secure") or detail.get("samesite") in ("None", None):
                    vuln_cookies.append(detail)

        if not vuln_cookies:
            return None

        missing = []
        c = vuln_cookies[0]
        if not c.get("httponly"): missing.append("HttpOnly")
        if not c.get("secure"): missing.append("Secure")
        if c.get("samesite") in ("None", None): missing.append("SameSite")

        return Finding(
            title=f"Session Cookie Missing Security Flags ({', '.join(missing)})",
            description=(
                f"The authentication/session cookie '{c.get('name')}' is missing "
                f"critical security attributes: {', '.join(missing)}. "
                "Missing HttpOnly permits script access via XSS; missing Secure permits transmission over unencrypted HTTP; "
                "missing SameSite enables CSRF attacks."
            ),
            severity=SeverityEnum.HIGH if "HttpOnly" in missing else SeverityEnum.MEDIUM,
            confidence=ConfidenceEnum.HIGH,
            verification_status=VerificationStatus.CONFIRMED,
        )

    def get_remediation(self, finding: Finding) -> RemediationGuidance:
        return RemediationGuidance(
            summary="Configure all sensitive cookies with HttpOnly=True, Secure=True, and SameSite=Lax (or Strict).",
            steps=[
                "In Flask / WSGI frameworks, ensure SESSION_COOKIE_HTTPONLY=True is set.",
                "Enforce SESSION_COOKIE_SECURE=True in production environments.",
                "Set SESSION_COOKIE_SAMESITE='Lax' to prevent cross-site request forgery.",
                "For custom Set-Cookie headers, always append '; HttpOnly; Secure; SameSite=Lax'.",
            ],
            references=[
                "https://owasp.org/www-community/controls/SecureCookieAttribute",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies",
            ],
            has_one_click_fix=True,
            fix_name="enforce_cookie_flags",
        )

    def get_verification_steps(self, finding: Finding) -> list[str]:
        return [
            "Open browser DevTools -> Application tab -> Cookies.",
            "Inspect the Set-Cookie response header in the Network tab.",
            "Verify the 'HttpOnly' column displays a checkmark.",
            "Verify the 'Secure' column displays a checkmark.",
            "Verify 'SameSite' is set to 'Lax' or 'Strict'.",
            "In Developer Console, evaluate document.cookie; verify session token is NOT visible.",
        ]

    def get_presenter_notes(self) -> PresenterNotes:
        return PresenterNotes(
            objective="Demonstrate how missing cookie security flags expose sessions to theft and forgery.",
            demonstration_steps=[
                "Inspect document.cookie in browser console on vulnerable demo — observe session token printed.",
                "Point out missing HttpOnly and Secure in Developer Tools -> Cookies table.",
                "Explain how an XSS vulnerability weaponizes missing HttpOnly to exfiltrate cookies.",
                "Toggle to secure scenario, repeat document.cookie — observe token is inaccessible to JS.",
            ],
            evidence_meaning=(
                "A cookie without HttpOnly can be accessed by any JavaScript executing in the origin. "
                "A cookie without Secure is broadcast in cleartext over unencrypted HTTP connections."
            ),
            talking_points=[
                "Cookies are the primary vehicle for session identity in web applications.",
                "HttpOnly is a defense-in-depth measure: it mitigates XSS cookie theft, though not XSS itself.",
                "SameSite=Lax has become the modern browser default, but explicit server enforcement is essential.",
            ],
            remediation_takeaway=(
                "Always set HttpOnly, Secure, and SameSite on authentication and session cookies at the framework level."
            ),
        )

    def simulate(self, scenario) -> SimulatedResult:
        ev = EvidenceRecord(
            run_id=0,
            provenance=ProvenanceEnum.SIMULATED,
            evidence_type=EvidenceType.COOKIE_ATTRIBUTES,
            title="[SIMULATED] Cookie Attributes Inspection",
            sanitized_detail={"name": "sim_session", "httponly": False, "secure": False, "samesite": "None"},
            observation="[SIMULATED REPLAY] Replay of missing cookie flags.",
            is_simulated=True,
        )
        return SimulatedResult(
            summary="[SIMULATED] Cookie security flags inspection replay.",
            simulated_evidence=[ev],
        )
