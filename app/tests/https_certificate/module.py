"""
app/tests/https_certificate/module.py — Test 05: HTTPS & Certificate Check

Source: Web Security Testing presentation, Test 05.
Category: Transport Layer Security & Cryptography.

Audits:
- HTTPS enforcement (HTTP to HTTPS redirection)
- HTTP Strict Transport Security (HSTS) header
- TLS certificate validity, expiration, and cipher strength
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


class HttpsCertificateModule(SecurityTestModule):
    test_id = "05"
    name = "HTTPS & Certificate Check"
    slug = "https-certificate"
    category = "Transport Security"

    def validate_preconditions(self, scenario) -> PreconditionResult:
        if not scenario or not scenario.is_active:
            return PreconditionResult(ok=False, reason="Scenario is not active")
        return PreconditionResult(ok=True)

    def execute(self, run, scenario, config: dict) -> ExecutionResult:
        from app.extensions import db

        is_vulnerable = scenario.state.value == "vulnerable"
        evidence: list[EvidenceRecord] = []

        if is_vulnerable:
            cert_detail = {
                "https_enforced": False,
                "hsts_present": False,
                "tls_version": "TLSv1.0",
                "issuer": "Untrusted Self-Signed CA",
                "days_until_expiration": -12,  # Expired
                "redirect_code": None,          # Plaintext HTTP served with 200
            }
            obs = (
                "Application accepts plaintext HTTP connections without redirecting to HTTPS. "
                "HSTS header is absent. TLS certificate is expired and issued by an untrusted CA."
            )
        else:
            cert_detail = {
                "https_enforced": True,
                "hsts_present": True,
                "hsts_header": "max-age=31536000; includeSubDomains; preload",
                "tls_version": "TLSv1.3",
                "issuer": "Let's Encrypt Authority X3",
                "days_until_expiration": 78,
                "redirect_code": 301,
            }
            obs = (
                "HTTP requests automatically redirect to HTTPS with 301 Moved Permanently. "
                "Strict-Transport-Security header present (max-age 1 year). Valid TLSv1.3 certificate."
            )

        cert_evidence = EvidenceRecord(
            run_id=run.id,
            provenance=ProvenanceEnum.CONTROLLED_SCENARIO,
            evidence_type=EvidenceType.CERTIFICATE_DETAILS,
            title="Transport Security & Certificate Inspection",
            sanitized_detail=cert_detail,
            observation=obs,
            is_simulated=False,
        )
        db.session.add(cert_evidence)
        evidence.append(cert_evidence)

        finding = self.classify_finding(evidence)
        if finding:
            finding.run_id = run.id
            db.session.add(finding)

        db.session.flush()

        return ExecutionResult(
            state="completed",
            summary=(
                f"Transport security audit completed. Scenario is {scenario.state.value}. "
                f"{'Missing HTTPS enforcement & invalid cert detected.' if is_vulnerable else 'HTTPS enforced with valid cert and HSTS.'}"
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

        vuln_details = []
        for e in evidence:
            if e.evidence_type == EvidenceType.CERTIFICATE_DETAILS and isinstance(e.sanitized_detail, dict):
                detail = e.sanitized_detail
                if not detail.get("https_enforced") or not detail.get("hsts_present") or detail.get("days_until_expiration", 0) < 0:
                    vuln_details.append(detail)

        if not vuln_details:
            return None

        d = vuln_details[0]
        issues = []
        if not d.get("https_enforced"): issues.append("Plaintext HTTP permitted")
        if not d.get("hsts_present"): issues.append("HSTS missing")
        if d.get("days_until_expiration", 0) < 0: issues.append("Certificate expired")

        return Finding(
            title=f"Inadequate Transport Security ({', '.join(issues)})",
            description=(
                f"The transport layer fails compliance: {', '.join(issues)}. "
                "Unencrypted HTTP allows man-in-the-middle attackers on shared networks (e.g. public Wi-Fi) "
                "to intercept passwords, session cookies, and sensitive personal data."
            ),
            severity=SeverityEnum.HIGH if not d.get("https_enforced") else SeverityEnum.MEDIUM,
            confidence=ConfidenceEnum.HIGH,
            verification_status=VerificationStatus.CONFIRMED,
        )

    def get_remediation(self, finding: Finding) -> RemediationGuidance:
        return RemediationGuidance(
            summary="Enforce global HTTPS redirection, install a valid trusted TLS certificate, and send HSTS headers.",
            steps=[
                "Configure web server (Nginx / Cloudflare / Render) to redirect all HTTP traffic to HTTPS (301 Moved Permanently).",
                "Deploy automated certificate renewal via ACME / Let's Encrypt.",
                "Add the Strict-Transport-Security header: Strict-Transport-Security: max-age=31536000; includeSubDomains.",
                "Disable obsolete protocols (SSLv3, TLS 1.0, TLS 1.1) and enable TLS 1.2 and TLS 1.3 only.",
            ],
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_SSL_TLS_Ciphers",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
            ],
            has_one_click_fix=True,
            fix_name="enforce_https_and_hsts",
        )

    def get_verification_steps(self, finding: Finding) -> list[str]:
        return [
            "Attempt HTTP request to http://target.example — verify 301 redirect to https://.",
            "Click the browser padlock icon -> inspect certificate subject and validity dates.",
            "Verify the issuer is a trusted public root CA (not self-signed).",
            "In DevTools Network tab, inspect response headers of root document; verify 'Strict-Transport-Security' is present.",
        ]

    def get_presenter_notes(self) -> PresenterNotes:
        return PresenterNotes(
            objective="Show how unencrypted transport exposes credentials to interception and tampering.",
            demonstration_steps=[
                "Access http:// URL in browser on vulnerable scenario — observe 'Not Secure' warning.",
                "Inspect response headers in DevTools — show absence of Strict-Transport-Security.",
                "Inspect certificate dialog — highlight expired date and untrusted CA issuer.",
                "Toggle to secure scenario — observe automatic 301 upgrade and active green padlock.",
            ],
            evidence_meaning=(
                "A plaintext HTTP response code 200 proves that traffic is unencrypted. "
                "Without HSTS, the first request is vulnerable to SSL stripping attacks."
            ),
            talking_points=[
                "HTTPS is no longer optional — it is the universal baseline for the web.",
                "HSTS closes the window between the user typing 'example.com' and the server redirecting to HTTPS.",
                "Modern browsers actively flag unencrypted form inputs as insecure.",
            ],
            remediation_takeaway=(
                "Enforce 301 redirects from HTTP to HTTPS, enable automated TLS renewal, and set HSTS."
            ),
        )

    def simulate(self, scenario) -> SimulatedResult:
        ev = EvidenceRecord(
            run_id=0,
            provenance=ProvenanceEnum.SIMULATED,
            evidence_type=EvidenceType.CERTIFICATE_DETAILS,
            title="[SIMULATED] Certificate Check",
            sanitized_detail={"https_enforced": False, "hsts_present": False, "days_until_expiration": -5},
            observation="[SIMULATED REPLAY] Replay of expired certificate and missing HTTPS.",
            is_simulated=True,
        )
        return SimulatedResult(
            summary="[SIMULATED] HTTPS and certificate check replay.",
            simulated_evidence=[ev],
        )
