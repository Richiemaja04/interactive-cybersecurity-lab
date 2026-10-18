"""
app/tests/source_inspection/module.py — Test 07: Inspect Page Source & Client-Side Code

Source: Web Security Testing presentation, Test 07.
Category: Information Disclosure & Code Quality.

Demonstrates that all client-side code (HTML, JavaScript, comments, inline configs)
is completely public. Hardcoding keys, tokens, or internal endpoints is a severe vulnerability.
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


class SourceInspectionModule(SecurityTestModule):
    test_id = "07"
    name = "Inspect Source & Client Code"
    slug = "source-inspection"
    category = "Code Inspection"

    def validate_preconditions(self, scenario) -> PreconditionResult:
        if not scenario or not scenario.is_active:
            return PreconditionResult(ok=False, reason="Scenario is not active")
        return PreconditionResult(ok=True)

    def execute(self, run, scenario, config: dict) -> ExecutionResult:
        from app.extensions import db

        is_vulnerable = scenario.state.value == "vulnerable"
        evidence: list[EvidenceRecord] = []

        if is_vulnerable:
            source_detail = {
                "source_file": "app.bundle.js",
                "exposed_keys": [
                    {"variable": "STRIPE_SECRET_KEY", "value": "sk_test_[REDACTED]", "line": 42},
                    {"variable": "INTERNAL_ADMIN_ENDPOINT", "value": "/api/v1/internal-debug-dump", "line": 108},
                ],
                "developer_comments": [
                    "// TODO: Remove this bypass before production deployment (Alice - 2026)",
                ],
                "has_sensitive_data": True,
            }
            obs = (
                "Page source and bundled JavaScript contain hardcoded synthetic API keys, "
                "developer comments referencing security bypasses, and unlisted internal diagnostic endpoints."
            )
        else:
            source_detail = {
                "source_file": "app.bundle.js",
                "exposed_keys": [],
                "developer_comments": [],
                "has_sensitive_data": False,
            }
            obs = (
                "Client-side scripts contain zero hardcoded secrets. "
                "Environment variables and credentials remain strictly server-side. "
                "Only public initialization parameters (e.g., public keys) are provided."
            )

        source_evidence = EvidenceRecord(
            run_id=run.id,
            provenance=ProvenanceEnum.CONTROLLED_SCENARIO,
            evidence_type=EvidenceType.PAGE_SOURCE_EXCERPT,
            title="Client Source Code Audit",
            sanitized_detail=source_detail,
            observation=obs,
            is_simulated=False,
        )
        db.session.add(source_evidence)
        evidence.append(source_evidence)

        finding = self.classify_finding(evidence)
        if finding:
            finding.run_id = run.id
            db.session.add(finding)

        db.session.flush()

        return ExecutionResult(
            state="completed",
            summary=(
                f"Source inspection completed. Scenario is {scenario.state.value}. "
                f"{'Exposed secrets and debug comments found in client assets.' if is_vulnerable else 'No secrets exposed in client-side code.'}"
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

        exposed = []
        for e in evidence:
            if e.evidence_type == EvidenceType.PAGE_SOURCE_EXCERPT and isinstance(e.sanitized_detail, dict):
                if e.sanitized_detail.get("has_sensitive_data"):
                    exposed.append(e.sanitized_detail)

        if not exposed:
            return None

        return Finding(
            title="Hardcoded Secrets & Internal Endpoints in Client Source",
            description=(
                "Client-side JavaScript and HTML contain embedded credentials, developer bypass comments, "
                "or unpublished API endpoints. Anything delivered to a browser can be read by anyone inspecting "
                "page source or network assets."
            ),
            severity=SeverityEnum.HIGH,
            confidence=ConfidenceEnum.HIGH,
            verification_status=VerificationStatus.CONFIRMED,
        )

    def get_remediation(self, finding: Finding) -> RemediationGuidance:
        return RemediationGuidance(
            summary="Extract all credentials to server-side environment variables and strip debug comments during bundling.",
            steps=[
                "Move all secret keys, database credentials, and service tokens to server-side environment variables.",
                "Ensure client code only consumes publishable keys (e.g. Stripe publishable key, Firebase public config).",
                "Configure production bundler (Vite / Webpack / esbuild) to strip comments and console.log calls.",
                "Implement pre-commit secret scanners (TruffleHog / GitGuardian) to block commits containing keys.",
            ],
            references=[
                "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
                "https://cwe.mitre.org/data/definitions/798.html",
            ],
            has_one_click_fix=True,
            fix_name="remove_hardcoded_secrets",
        )

    def get_verification_steps(self, finding: Finding) -> list[str]:
        return [
            "Open browser DevTools -> Sources tab.",
            "Use Ctrl+Shift+F (global search) to query for 'key', 'secret', 'token', or 'password'.",
            "Verify that zero private keys or server-side credentials match.",
            "Inspect HTML comments (<!-- ... -->) to ensure no internal implementation details remain.",
        ]

    def get_presenter_notes(self) -> PresenterNotes:
        return PresenterNotes(
            objective="Show that JavaScript running in the browser is completely transparent to the user.",
            demonstration_steps=[
                "Open 'View Page Source' in browser — show inline script with API_KEY variable.",
                "Open DevTools -> Sources -> bundled script — point out internal debug endpoints in comments.",
                "Explain the critical distinction between client-side public keys vs. server-side private secrets.",
                "Toggle to secure scenario — demonstrate clean client bundle and externalized config.",
            ],
            evidence_meaning=(
                "Any string embedded in HTML or JS bundle is accessible to 100% of visitors. "
                "Obfuscation or minification does not prevent extraction by attackers."
            ),
            talking_points=[
                "Client-side secrets are an oxymoron: if the browser can read it, the user can read it.",
                "Minification and transpilation compress code, but do not encrypt it.",
                "API keys with write or administrative permissions must never touch client code.",
            ],
            remediation_takeaway=(
                "Keep secrets strictly server-side. Use server endpoints as proxies for sensitive third-party APIs."
            ),
        )

    def simulate(self, scenario) -> SimulatedResult:
        ev = EvidenceRecord(
            run_id=0,
            provenance=ProvenanceEnum.SIMULATED,
            evidence_type=EvidenceType.PAGE_SOURCE_EXCERPT,
            title="[SIMULATED] Source Inspection",
            sanitized_detail={"exposed_keys": [{"variable": "SIM_KEY", "value": "[REDACTED]"}], "has_sensitive_data": True},
            observation="[SIMULATED REPLAY] Replay of exposed secrets in source code.",
            is_simulated=True,
        )
        return SimulatedResult(
            summary="[SIMULATED] Page source inspection replay.",
            simulated_evidence=[ev],
        )
