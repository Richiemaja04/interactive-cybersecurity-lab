"""
app/tests/robots_txt/module.py — Test 01: Robots.txt Enumeration

Demonstrates that robots.txt is publicly readable and does not enforce
access control. Paths listed as Disallow are still reachable.

Source: Web Security Testing presentation, Test 01.
Category: Information disclosure.
"""

from __future__ import annotations

from app.models.evidence import EvidenceRecord, EvidenceType, ProvenanceEnum
from app.models.finding import Finding, SeverityEnum, VerificationStatus, ConfidenceEnum
from app.tests._base import (
    ExecutionResult,
    PresenterNotes,
    PreconditionResult,
    RemediationGuidance,
    SecurityTestModule,
    SimulatedResult,
)

# Lab robots.txt content for the vulnerable scenario
_VULNERABLE_ROBOTS_TXT = """\
User-agent: *
Disallow: /admin/
Disallow: /backup/
Disallow: /api/internal/
Disallow: /config/
Allow: /
Sitemap: https://example-lab.local/sitemap.xml
"""

# Secure scenario: no sensitive paths disclosed
_SECURE_ROBOTS_TXT = """\
User-agent: *
Disallow: /
Sitemap: https://example-lab.local/sitemap.xml
"""

# Lab path responses for demonstration
_LAB_PATHS = {
    "/admin/": {"vulnerable": 200, "secure": 403},
    "/backup/": {"vulnerable": 200, "secure": 403},
    "/api/internal/": {"vulnerable": 200, "secure": 404},
    "/config/": {"vulnerable": 200, "secure": 403},
}


class RobotsTxtModule(SecurityTestModule):
    test_id = "01"
    name = "Robots.txt Enumeration"
    slug = "robots-txt"
    category = "Information disclosure"

    def validate_preconditions(self, scenario) -> PreconditionResult:
        if not scenario or not scenario.is_active:
            return PreconditionResult(ok=False, reason="Scenario is not active")
        return PreconditionResult(ok=True)

    def execute(self, run, scenario, config: dict) -> ExecutionResult:
        from app.extensions import db

        is_vulnerable = scenario.state.value == "vulnerable"
        robots_content = _VULNERABLE_ROBOTS_TXT if is_vulnerable else _SECURE_ROBOTS_TXT

        evidence = []

        # Evidence 1: robots.txt content
        robots_evidence = EvidenceRecord(
            run_id=run.id,
            provenance=ProvenanceEnum.CONTROLLED_SCENARIO,
            evidence_type=EvidenceType.HTTP_RESPONSE,
            title="robots.txt Content",
            sanitized_detail={
                "url": "/robots.txt",
                "status_code": 200,
                "content_preview": robots_content[:500],
                "disallowed_paths": self._extract_disallowed(robots_content),
            },
            observation=(
                "robots.txt is publicly accessible and lists restricted paths."
                if is_vulnerable
                else "robots.txt does not disclose specific application paths."
            ),
            is_simulated=False,
        )
        db.session.add(robots_evidence)
        evidence.append(robots_evidence)

        # Evidence 2: Check if listed paths are actually accessible
        if is_vulnerable:
            for path, responses in _LAB_PATHS.items():
                status = responses["vulnerable"]
                path_evidence = EvidenceRecord(
                    run_id=run.id,
                    provenance=ProvenanceEnum.CONTROLLED_SCENARIO,
                    evidence_type=EvidenceType.HTTP_RESPONSE,
                    title=f"Path Accessibility: {path}",
                    sanitized_detail={
                        "path": path,
                        "status_code": status,
                        "listed_in_robots": True,
                        "authorization_enforced": status == 403,
                    },
                    observation=(
                        f"Path {path!r} is listed in robots.txt AND returns {status} "
                        f"({'accessible without authorization' if status == 200 else 'access controlled'})."
                    ),
                    is_simulated=False,
                )
                db.session.add(path_evidence)
                evidence.append(path_evidence)

        db.session.flush()

        finding = self.classify_finding(evidence)
        if finding:
            db.session.add(finding)
            finding.run_id = run.id
            finding.verification_steps = self.get_verification_steps(finding)
            finding.remediation_summary = self.get_remediation(finding).summary

        db.session.flush()

        return ExecutionResult(
            state="completed",
            summary=(
                f"robots.txt {'disclosed sensitive paths' if is_vulnerable else 'did not disclose sensitive paths'}. "
                f"{len(evidence)} evidence item(s) collected."
            ),
            evidence=evidence,
            finding=finding,
        )

    def collect_evidence(self, run) -> list:
        return list(run.evidence_records.filter_by())

    def sanitize_evidence(self, evidence: list) -> list:
        """robots.txt content is inherently public — no sensitive data to strip."""
        return evidence

    def classify_finding(self, evidence: list) -> Finding | None:
        if not evidence:
            return None

        # Check if any path was accessible without authorization
        accessible_paths = [
            e for e in evidence
            if e.evidence_type == EvidenceType.HTTP_RESPONSE
            and isinstance(e.sanitized_detail, dict)
            and e.sanitized_detail.get("status_code") == 200
            and e.sanitized_detail.get("listed_in_robots")
            and not e.sanitized_detail.get("authorization_enforced")
        ]

        has_disclosure = any(
            e.title == "robots.txt Content"
            and isinstance(e.sanitized_detail, dict)
            and len(e.sanitized_detail.get("disallowed_paths", [])) > 0
            for e in evidence
        )

        if not has_disclosure:
            return None  # No paths disclosed — no finding

        if accessible_paths:
            # Path disclosure + accessible without auth = Confirmed (controlled scenario)
            return Finding(
                title="robots.txt Discloses Accessible Restricted Paths",
                description=(
                    f"robots.txt lists {len(accessible_paths)} path(s) as restricted, "
                    "but those paths are accessible without authentication. "
                    "robots.txt is not an access control mechanism."
                ),
                severity=SeverityEnum.LOW,
                confidence=ConfidenceEnum.HIGH,
                verification_status=VerificationStatus.CONFIRMED,
            )
        else:
            # Path disclosure only — paths are actually protected
            return Finding(
                title="robots.txt Discloses Application Path Structure",
                description=(
                    "robots.txt lists application paths, providing a map of the "
                    "application structure. The listed paths are access-controlled, "
                    "but the disclosure itself reduces obscurity."
                ),
                severity=SeverityEnum.INFORMATIONAL,
                confidence=ConfidenceEnum.HIGH,
                verification_status=VerificationStatus.POTENTIAL,
            )

    def get_remediation(self, finding: Finding) -> RemediationGuidance:
        return RemediationGuidance(
            summary="Remove sensitive path listings from robots.txt and enforce authorization on all restricted resources.",
            steps=[
                "Remove specific application paths from robots.txt Disallow entries.",
                "Use a generic Disallow: / or list only non-sensitive public paths.",
                "Ensure all restricted resources enforce server-side authorization, independent of robots.txt.",
                "Consider whether a sitemap serves the intended SEO purpose without the security implication.",
            ],
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/",
                "https://developers.google.com/search/docs/crawling-indexing/robots/intro",
            ],
            has_one_click_fix=True,
            fix_name="remove_sensitive_paths",
        )

    def get_verification_steps(self, finding: Finding) -> list[str]:
        return [
            "Fetch /robots.txt and confirm sensitive paths are no longer listed.",
            "Attempt to access previously listed paths without authentication.",
            "Confirm restricted paths return 403 or redirect to login — not 200.",
            "Confirm paths not in robots.txt are still access-controlled.",
        ]

    def get_presenter_notes(self) -> PresenterNotes:
        return PresenterNotes(
            objective="Show that robots.txt is public and does not enforce access control.",
            demonstration_steps=[
                "Navigate to /robots.txt — it loads without authentication.",
                "Point out the Disallow entries listing admin, backup, and API paths.",
                "Attempt to access /admin/ directly — observe the response.",
                "Toggle to the secure scenario and repeat — paths are not listed.",
            ],
            evidence_meaning=(
                "A 200 response to a path listed as Disallow confirms that robots.txt "
                "provides zero access control. The paths are reachable by anyone. "
                "Listing them in robots.txt is essentially a directory of interesting targets."
            ),
            talking_points=[
                "robots.txt is a courtesy to well-behaved crawlers, not a security control.",
                "Malicious actors read robots.txt specifically to find interesting paths.",
                "The fix is both to clean up robots.txt AND to enforce authorization on every resource.",
                "An observation (path listed) does not confirm a vulnerability — the path must also be accessible.",
            ],
            remediation_takeaway=(
                "Remove specific paths from robots.txt. Enforce server-side authorization "
                "on every restricted resource regardless of whether it is listed anywhere."
            ),
        )

    def _extract_disallowed(self, content: str) -> list[str]:
        paths = []
        for line in content.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:"):
                path = line[9:].strip()
                if path and path != "/":
                    paths.append(path)
        return paths
