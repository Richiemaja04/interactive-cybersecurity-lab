"""
app/tests/error_analysis/module.py — Test 10: Error Message Analysis

Source: Web Security Testing presentation, Test 10.
Category: Information Disclosure & Exception Handling.

Evaluates whether application failure states leak implementation details,
such as database schemas, unhandled stack traces, framework versions, or internal file paths.
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


class ErrorAnalysisModule(SecurityTestModule):
    test_id = "10"
    name = "Error Message Analysis"
    slug = "error-analysis"
    category = "Information Disclosure"

    def validate_preconditions(self, scenario) -> PreconditionResult:
        if not scenario or not scenario.is_active:
            return PreconditionResult(ok=False, reason="Scenario is not active")
        return PreconditionResult(ok=True)

    def execute(self, run, scenario, config: dict) -> ExecutionResult:
        from app.extensions import db

        is_vulnerable = scenario.state.value == "vulnerable"
        evidence: list[EvidenceRecord] = []

        if is_vulnerable:
            error_detail = {
                "status_code": 500,
                "response_body_sample": (
                    "InternalServerError: [STACK_TRACE_REDACTED]\n"
                    "psycopg2.errors.UndefinedTable: relation 'users_v2' does not exist\n"
                    "QUERY: SELECT * FROM users_v2 WHERE id = 1\n"
                    "File: [PATH_REDACTED]/app/models/user.py, line 88"
                ),
                "leaks_stack_trace": True,
                "leaks_sql_query": True,
                "leaks_internal_paths": True,
                "correlation_id_provided": False,
            }
            obs = (
                "Triggered 500 response returns raw Python stack trace, internal PostgreSQL relation names, "
                "exact SQL queries, and local filesystem directory paths directly to the client."
            )
        else:
            error_detail = {
                "status_code": 500,
                "response_body_sample": (
                    '{"error": "An internal server error occurred.", "correlation_id": "err_c9f28a1"}'
                ),
                "leaks_stack_trace": False,
                "leaks_sql_query": False,
                "leaks_internal_paths": False,
                "correlation_id_provided": True,
            }
            obs = (
                "Triggered 500 response returns a sanitized, user-friendly JSON message with an incident correlation ID. "
                "Zero internal stack traces, SQL syntax, or filesystem paths reach the browser."
            )

        error_evidence = EvidenceRecord(
            run_id=run.id,
            provenance=ProvenanceEnum.CONTROLLED_SCENARIO,
            evidence_type=EvidenceType.ERROR_MESSAGE,
            title="Unhandled Exception Response Analysis",
            sanitized_detail=error_detail,
            observation=obs,
            is_simulated=False,
        )
        db.session.add(error_evidence)
        evidence.append(error_evidence)

        finding = self.classify_finding(evidence)
        if finding:
            finding.run_id = run.id
            db.session.add(finding)

        db.session.flush()

        return ExecutionResult(
            state="completed",
            summary=(
                f"Error analysis completed. Scenario is {scenario.state.value}. "
                f"{'Verbose diagnostic details leaked in response.' if is_vulnerable else 'Error response properly sanitized with correlation ID.'}"
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

        leaking_errors = []
        for e in evidence:
            if e.evidence_type == EvidenceType.ERROR_MESSAGE and isinstance(e.sanitized_detail, dict):
                detail = e.sanitized_detail
                if detail.get("leaks_stack_trace") or detail.get("leaks_sql_query") or detail.get("leaks_internal_paths"):
                    leaking_errors.append(detail)

        if not leaking_errors:
            return None

        return Finding(
            title="Verbose Error Messages Disclosing Internal Implementation",
            description=(
                "The server returns detailed diagnostic messages, stack traces, or database queries "
                "to users upon error. Attackers leverage these disclosures to identify software versions, "
                "database structure, and file locations for targeted exploitation."
            ),
            severity=SeverityEnum.MEDIUM,
            confidence=ConfidenceEnum.HIGH,
            verification_status=VerificationStatus.CONFIRMED,
        )

    def get_remediation(self, finding: Finding) -> RemediationGuidance:
        return RemediationGuidance(
            summary="Configure production error handlers to return generic messages with unique correlation IDs, logging full traces privately.",
            steps=[
                "Disable debug mode (DEBUG=False) in production and staging environments.",
                "Implement custom @app.errorhandler(500) that renders a friendly template or sanitized JSON.",
                "Generate a UUID / correlation ID per error to return to the user for support tickets.",
                "Log the full stack trace and request context securely to server logs or an APM tool (e.g. Sentry).",
            ],
            references=[
                "https://owasp.org/www-community/Improper_Error_Handling",
                "https://cwe.mitre.org/data/definitions/209.html",
            ],
            has_one_click_fix=True,
            fix_name="sanitize_error_handlers",
        )

    def get_verification_steps(self, finding: Finding) -> list[str]:
        return [
            "Trigger a safe synthetic server exception (e.g., malformed parameter or invalid route).",
            "Verify the HTTP response status is 500 Internal Server Error.",
            "Inspect the response body: confirm no 'Traceback', 'File \"', SQL queries, or file paths appear.",
            "Verify a correlation ID or reference code is provided to the client.",
            "Inspect server logs to confirm full technical diagnostic details were preserved internally.",
        ]

    def get_presenter_notes(self) -> PresenterNotes:
        return PresenterNotes(
            objective="Show how verbose error messages inadvertently assist attackers by mapping the application.",
            demonstration_steps=[
                "Trigger a failure condition on vulnerable demo — display stack trace in browser.",
                "Highlight leaked database query, table names, and local disk paths.",
                "Explain how this information saves attackers hours of blind reconnaissance.",
                "Toggle to secure scenario — trigger same error — show clean user error with incident reference ID.",
            ],
            evidence_meaning=(
                "A response containing framework exception traces proves debug mode is active or global error handlers are missing."
            ),
            talking_points=[
                "Errors are inevitable; how an application fails determines its resilience.",
                "A correlation ID connects the user's experience with the engineer's private log file.",
                "Never let the database speak directly to the browser.",
            ],
            remediation_takeaway=(
                "Turn off DEBUG in production, catch unhandled exceptions, and return clean error pages with correlation IDs."
            ),
        )

    def simulate(self, scenario) -> SimulatedResult:
        ev = EvidenceRecord(
            run_id=0,
            provenance=ProvenanceEnum.SIMULATED,
            evidence_type=EvidenceType.ERROR_MESSAGE,
            title="[SIMULATED] Error Message Analysis",
            sanitized_detail={"leaks_stack_trace": True, "leaks_sql_query": True},
            observation="[SIMULATED REPLAY] Replay of verbose error disclosing internal stack trace.",
            is_simulated=True,
        )
        return SimulatedResult(
            summary="[SIMULATED] Error message analysis replay.",
            simulated_evidence=[ev],
        )
