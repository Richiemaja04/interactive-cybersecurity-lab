"""
app/tests/error_analysis/routes.py — Routes for Test 10: Error Message Analysis.
"""

from __future__ import annotations

from flask import Blueprint, jsonify
from flask_login import login_required

from app.auth.decorators import require_tester
from app.models.scenario import Scenario, ScenarioState, TestDefinition
from app.tests.controller import (
    execute_test_run,
    render_run_detail,
    render_test_detail,
    toggle_test_scenario,
)

error_bp = Blueprint("error_analysis", __name__)
SLUG = "error-analysis"


@error_bp.route("/")
@login_required
@require_tester
def detail():
    return render_test_detail(SLUG, "error_analysis", lab_url="/tests/error-analysis/lab/trigger-error")


@error_bp.route("/run", methods=["POST"])
@login_required
@require_tester
def run_test():
    return execute_test_run(SLUG, "error_analysis")


@error_bp.route("/runs/<int:run_id>")
@login_required
@require_tester
def view_run(run_id: int):
    return render_run_detail(SLUG, "error_analysis", run_id)


@error_bp.route("/scenario", methods=["POST"])
@login_required
@require_tester
def toggle_scenario():
    return toggle_test_scenario(SLUG, "error_analysis")


# ── Interactive Lab Endpoints ─────────────────────────────────────────────────

@error_bp.route("/lab/trigger-error")
def lab_trigger_error():
    """Demonstrates verbose unhandled exception dump vs sanitized generic error response."""
    test_def = TestDefinition.query.filter_by(slug=SLUG).first()
    scenario = Scenario.query.filter_by(test_id=test_def.id).first() if test_def else None
    is_vulnerable = not scenario or scenario.state == ScenarioState.VULNERABLE

    if is_vulnerable:
        # Returns verbose unhandled stack trace and internal database query
        return jsonify({
            "status": "vulnerable",
            "error_type": "InternalServerError",
            "exception": "psycopg2.errors.UndefinedTable: relation 'users_v2' does not exist",
            "sql_query": "SELECT * FROM users_v2 WHERE id = 1",
            "file": "/var/www/lab/app/models/user.py",
            "line": 88,
            "stack_trace": [
                'File "/var/www/lab/app/routes.py", line 42, in trigger_error',
                'File "/var/www/lab/app/models/user.py", line 88, in get_user',
            ],
        }), 500
    else:
        # Sanitized user-facing error with opaque correlation ID
        return jsonify({
            "status": "secure",
            "error": "An unexpected error occurred while processing your request.",
            "correlation_id": "err_c9f28a11-b45a",
            "message": "Please contact support if the issue persists.",
        }), 500
