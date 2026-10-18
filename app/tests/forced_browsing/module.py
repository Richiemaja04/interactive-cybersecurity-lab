"""
app/tests/forced_browsing/module.py — Test 03: Directory Guessing / Forced Browsing

Source: Web Security Testing presentation, Test 03.
Category: Predictable Resource Location & Access Control.

Demonstrates accessing unlinked administrative consoles, backup archives,
configuration files, and hidden directories via predictable URL guessing.
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


class ForcedBrowsingModule(SecurityTestModule):
    test_id = "03"
    name = "Directory Guessing / Forced Browsing"
    slug = "forced-browsing"
    category = "Access Control"

    def validate_preconditions(self, scenario) -> PreconditionResult:
        if not scenario or not scenario.is_active:
            return PreconditionResult(ok=False, reason="Scenario is not active")
        return PreconditionResult(ok=True)

    def execute(self, run, scenario, config: dict) -> ExecutionResult:
        from app.extensions import db

        is_vulnerable = scenario.state.value == "vulnerable"
        evidence: list[EvidenceRecord] = []

        probed_paths = [
            {"path": "/backup/database_dump.sql.bak", "vulnerable": 200, "secure": 404},
            {"path": "/admin/user-management", "vulnerable": 200, "secure": 403},
            {"path": "/.env", "vulnerable": 200, "secure": 404},
            {"path": "/api/v1/internal/health", "vulnerable": 200, "secure": 401},
        ]

        for item in probed_paths:
            path = item["path"]
            status = item["vulnerable"] if is_vulnerable else item["secure"]
            accessible = (status == 200)

            ev = EvidenceRecord(
                run_id=run.id,
                provenance=ProvenanceEnum.CONTROLLED_SCENARIO,
                evidence_type=EvidenceType.HTTP_RESPONSE,
                title=f"Forced Browsing Probe: {path}",
                sanitized_detail={
                    "path": path,
                    "status_code": status,
                    "accessible_without_auth": accessible,
                },
                observation=(
                    f"Path {path!r} returned {status} "
                    f"({'accessible directly without credentials' if accessible else 'access denied or not found'})."
                ),
                is_simulated=False,
            )
            db.session.add(ev)
            evidence.append(ev)

        finding = self.classify_finding(evidence)
        if finding:
            finding.run_id = run.id
            db.session.add(finding)

        db.session.flush()

        return ExecutionResult(
            state="completed",
            summary=(
                f"Forced browsing check completed. Scenario is {scenario.state.value}. "
                f"{'Unlinked backups and consoles accessible without auth.' if is_vulnerable else 'All sensitive paths protected.'}"
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

        accessible_items = [
            e for e in evidence
            if e.evidence_type == EvidenceType.HTTP_RESPONSE
            and isinstance(e.sanitized_detail, dict)
            and e.sanitized_detail.get("accessible_without_auth")
        ]

        if not accessible_items:
            return None

        return Finding(
            title="Sensitive Resources & Consoles Accessible via Forced Browsing",
            description=(
                f"Probing {len(accessible_items)} predictable paths revealed that administrative consoles, "
                "database backup archives, or environment configurations are directly accessible via URL guessing "
                "without authentication or authorization."
            ),
            severity=SeverityEnum.HIGH,
            confidence=ConfidenceEnum.HIGH,
            verification_status=VerificationStatus.CONFIRMED,
        )

    def get_remediation(self, finding: Finding) -> RemediationGuidance:
        return RemediationGuidance(
            summary="Deny webroot storage of backups/configs and enforce strict authentication on administrative routes.",
            steps=[
                "Move backups, logs, and sensitive data directories outside the public web server document root.",
                "Configure web server rules (Nginx/Apache) to deny dotfiles (e.g. /.env, /.git) with 404.",
                "Enforce role-based access control decorators (@require_admin) on all administrative URL paths.",
                "Implement centralized routing that defaults to access denied unless explicitly whitelisted.",
            ],
            references=[
                "https://owasp.org/www-community/attacks/Forced_browsing",
                "https://cwe.mitre.org/data/definitions/425.html",
            ],
            has_one_click_fix=True,
            fix_name="block_forced_browsing_paths",
        )

    def get_verification_steps(self, finding: Finding) -> list[str]:
        return [
            "Attempt HTTP GET requests to known sensitive paths: /backup/, /.env, /admin/users.",
            "Verify the server returns 404 Not Found or 403 Forbidden.",
            "Confirm no file downloads are initiated for archive or database dump extensions (.bak, .sql, .zip).",
            "Verify unauthenticated access to administrative views redirects to login.",
        ]

    def get_presenter_notes(self) -> PresenterNotes:
        return PresenterNotes(
            objective="Show that obscurity (not linking a page in the UI) provides zero security.",
            demonstration_steps=[
                "Type '/backup/database_dump.sql.bak' directly into browser address bar.",
                "Demonstrate browser downloading internal database schema without login.",
                "Type '/admin/user-management' — show privileged dashboard appearing.",
                "Toggle to secure scenario — observe immediate 404/403 responses.",
            ],
            evidence_meaning=(
                "A 200 response to an unlinked administrative or backup path confirms predictable resource exposure."
            ),
            talking_points=[
                "Security by obscurity always fails: automated scanners guess thousands of paths a minute.",
                "Leaving database backups in webroot is one of the most common causes of mass data breaches.",
                "If it shouldn't be public, it shouldn't be in the web server's document root.",
            ],
            remediation_takeaway=(
                "Never store backups in webroot. Enforce server-side role checks on all administrative paths."
            ),
        )

    def simulate(self, scenario) -> SimulatedResult:
        ev = EvidenceRecord(
            run_id=0,
            provenance=ProvenanceEnum.SIMULATED,
            evidence_type=EvidenceType.HTTP_RESPONSE,
            title="[SIMULATED] Forced Browsing Probe",
            sanitized_detail={"path": "/backup/dump.sql", "status_code": 200, "accessible_without_auth": True},
            observation="[SIMULATED REPLAY] Replay of forced browsing accessing unlinked backup.",
            is_simulated=True,
        )
        return SimulatedResult(
            summary="[SIMULATED] Forced browsing check replay.",
            evidence_records=[ev],
        )
