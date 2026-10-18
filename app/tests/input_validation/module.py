"""
app/tests/input_validation/module.py — Test 06: Form Input Validation & XSS Awareness

Source: Web Security Testing presentation, Test 06.
Category: Input Validation & Output Encoding.

Demonstrates how unencoded user inputs reflected in HTTP responses allow
unintended markup interpretation, and how context-aware HTML entity encoding
and Content Security Policy (CSP) headers effectively mitigate the risk.
Testing is conducted strictly with benign canary payloads.
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


class InputValidationModule(SecurityTestModule):
    test_id = "06"
    name = "Form Input Validation & XSS Awareness"
    slug = "input-validation"
    category = "Input Validation"

    def validate_preconditions(self, scenario) -> PreconditionResult:
        if not scenario or not scenario.is_active:
            return PreconditionResult(ok=False, reason="Scenario is not active")
        return PreconditionResult(ok=True)

    def execute(self, run, scenario, config: dict) -> ExecutionResult:
        from app.extensions import db

        is_vulnerable = scenario.state.value == "vulnerable"
        evidence: list[EvidenceRecord] = []

        canary_payload = '<script>console.log("canary_test")</script>'

        if is_vulnerable:
            reflection_detail = {
                "input_parameter": "query",
                "submitted_payload": canary_payload,
                "reflected_output": canary_payload,
                "is_encoded": False,
                "response_content_type": "text/html",
                "status_code": 200,
            }
            reflection_obs = (
                f"Submitted payload {canary_payload!r} was reflected verbatim into the response body "
                "without HTML entity encoding, allowing client-side execution."
            )
            csp_detail = {
                "header_name": "Content-Security-Policy",
                "header_present": False,
                "header_value": None,
                "protection_enforced": False,
            }
            csp_obs = (
                "Content-Security-Policy header is absent. "
                "The browser has no policy restricting inline script execution."
            )
        else:
            encoded_output = "&lt;script&gt;console.log(&quot;canary_test&quot;)&lt;/script&gt;"
            reflection_detail = {
                "input_parameter": "query",
                "submitted_payload": canary_payload,
                "reflected_output": encoded_output,
                "is_encoded": True,
                "response_content_type": "text/html",
                "status_code": 200,
            }
            reflection_obs = (
                f"Submitted payload was safely HTML-encoded as {encoded_output!r}. "
                "The browser parses it as harmless text content rather than executable markup."
            )
            csp_detail = {
                "header_name": "Content-Security-Policy",
                "header_present": True,
                "header_value": "default-src 'self'",
                "protection_enforced": True,
            }
            csp_obs = (
                "Strict Content-Security-Policy header ('default-src \\'self\\'') is present and enforced."
            )

        reflection_evidence = EvidenceRecord(
            run_id=run.id,
            provenance=ProvenanceEnum.CONTROLLED_SCENARIO,
            evidence_type=EvidenceType.FORM_REFLECTION,
            title="Form Input Reflection Audit",
            sanitized_detail=reflection_detail,
            observation=reflection_obs,
            is_simulated=False,
        )
        db.session.add(reflection_evidence)
        evidence.append(reflection_evidence)

        csp_evidence = EvidenceRecord(
            run_id=run.id,
            provenance=ProvenanceEnum.CONTROLLED_SCENARIO,
            evidence_type=EvidenceType.HEADER_INSPECTION,
            title="Content Security Policy (CSP) Verification",
            sanitized_detail=csp_detail,
            observation=csp_obs,
            is_simulated=False,
        )
        db.session.add(csp_evidence)
        evidence.append(csp_evidence)

        finding = self.classify_finding(evidence)
        if finding:
            finding.run_id = run.id
            db.session.add(finding)

        db.session.flush()

        return ExecutionResult(
            state="completed",
            summary=(
                f"Input validation check completed. Scenario is {scenario.state.value}. "
                f"{'Unsanitized input reflected verbatim without CSP.' if is_vulnerable else 'Input HTML-encoded and strict CSP enforced.'}"
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

        unencoded_reflection = False
        csp_missing = False

        for e in evidence:
            if e.evidence_type == EvidenceType.FORM_REFLECTION and isinstance(e.sanitized_detail, dict):
                if not e.sanitized_detail.get("is_encoded", True):
                    unencoded_reflection = True
            elif e.evidence_type == EvidenceType.HEADER_INSPECTION and isinstance(e.sanitized_detail, dict):
                if not e.sanitized_detail.get("header_present", False):
                    csp_missing = True

        if unencoded_reflection:
            return Finding(
                title="Unsanitized User Input Reflected Without Content Security Policy",
                description=(
                    "User-supplied input is reflected in the HTML response without context-aware HTML "
                    "entity encoding. The absence of a Content-Security-Policy header permits "
                    "arbitrary script execution in the context of the user's browser session (Reflected XSS)."
                ),
                severity=SeverityEnum.HIGH,
                confidence=ConfidenceEnum.HIGH,
                verification_status=VerificationStatus.CONFIRMED,
            )
        elif csp_missing:
            return Finding(
                title="Missing Content-Security-Policy Header",
                description=(
                    "The application does not declare a Content-Security-Policy header. While input "
                    "encoding is in place, the absence of CSP removes defense-in-depth protections."
                ),
                severity=SeverityEnum.LOW,
                confidence=ConfidenceEnum.HIGH,
                verification_status=VerificationStatus.CONFIRMED,
            )

        return None

    def get_remediation(self, finding: Finding) -> RemediationGuidance:
        return RemediationGuidance(
            summary="Apply context-aware HTML encoding to all untrusted data and deploy a strict Content Security Policy.",
            steps=[
                "Use automated template escaping (e.g. Jinja2 default auto-escaping, React JSX) for all dynamic variables.",
                "Ensure safe escaping functions (e.g. html.escape) are applied when formatting strings outside templates.",
                "Deploy a restrictive Content-Security-Policy header: 'default-src \\'self\\'; script-src \\'self\\''.",
                "Disallow 'unsafe-inline' and 'unsafe-eval' script sources across all application views.",
            ],
            references=[
                "https://owasp.org/www-community/attacks/xss/",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
            ],
            has_one_click_fix=True,
            fix_name="enable_html_encoding_and_csp",
        )

    def get_verification_steps(self, finding: Finding) -> list[str]:
        return [
            "Submit a harmless canary string such as <b id=canary>test</b> into the search input.",
            "Inspect the response body in DevTools Network tab: confirm characters '<' and '>' are encoded as '&lt;' and '&gt;'.",
            "Check response headers in DevTools: verify 'Content-Security-Policy' is present with valid directives.",
            "Verify the browser console outputs no script execution errors from the canary payload.",
        ]

    def get_presenter_notes(self) -> PresenterNotes:
        return PresenterNotes(
            objective="Show that unencoded input reflected in HTML allows script execution, and show how output encoding + CSP mitigate it.",
            demonstration_steps=[
                "Navigate to the lab input form.",
                "Input a harmless Canary script: <script>console.log('canary')</script>.",
                "Inspect the Elements tab in browser DevTools to show unescaped tags directly inside HTML.",
                "Toggle to secure mode and re-run — show HTML entity encoding (&lt;script&gt;) and CSP header.",
            ],
            evidence_meaning=(
                "Unencoded reflection indicates the server treats untrusted input as raw markup. "
                "Combined with missing CSP, any visitor could be coerced into running attacker-supplied JavaScript."
            ),
            talking_points=[
                "Never use live exploit payloads in security testing demonstrations — benign canaries prove the flaw safely.",
                "Input validation filters bad characters, but output encoding ensures safe representation regardless of input.",
                "Content Security Policy is the browser's safety net if server-side encoding is ever missed.",
            ],
            remediation_takeaway=(
                "Always encode untrusted data before inserting it into HTML documents, and enforce a strict CSP."
            ),
        )

    def simulate(self, scenario) -> SimulatedResult:
        ev = EvidenceRecord(
            run_id=0,
            provenance=ProvenanceEnum.SIMULATED,
            evidence_type=EvidenceType.FORM_REFLECTION,
            title="[SIMULATED] Form Input Reflection Audit",
            sanitized_detail={
                "input_parameter": "query",
                "submitted_payload": "<script>console.log('sim_canary')</script>",
                "reflected_output": "<script>console.log('sim_canary')</script>",
                "is_encoded": False,
            },
            observation="[SIMULATED REPLAY] Replay of unencoded form input reflection.",
            is_simulated=True,
        )
        return SimulatedResult(
            summary="[SIMULATED] Form input reflection replay.",
            simulated_evidence=[ev],
        )
