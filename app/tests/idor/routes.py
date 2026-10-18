"""
app/tests/idor/routes.py — Routes for Test 02: URL Parameter Tampering & IDOR.
"""

from __future__ import annotations

from flask import Blueprint, jsonify, request
from flask_login import login_required

from app.auth.decorators import require_tester
from app.models.scenario import Scenario, ScenarioState, TestDefinition
from app.tests.controller import (
    execute_test_run,
    render_run_detail,
    render_test_detail,
    toggle_test_scenario,
)

idor_bp = Blueprint("idor", __name__)
SLUG = "idor"


@idor_bp.route("/")
@login_required
@require_tester
def detail():
    return render_test_detail(SLUG, "idor", lab_url="/tests/idor/lab/record?id=105")


@idor_bp.route("/run", methods=["POST"])
@login_required
@require_tester
def run_test():
    return execute_test_run(SLUG, "idor")


@idor_bp.route("/runs/<int:run_id>")
@login_required
@require_tester
def view_run(run_id: int):
    return render_run_detail(SLUG, "idor", run_id)


@idor_bp.route("/scenario", methods=["POST"])
@login_required
@require_tester
def toggle_scenario():
    return toggle_test_scenario(SLUG, "idor")


# ── Interactive Lab Endpoints ─────────────────────────────────────────────────

_SYNTHETIC_RECORDS = {
    101: {"id": 101, "owner_id": 42, "title": "My Quarterly Objectives (User 42)", "confidential": False},
    105: {"id": 105, "owner_id": 99, "title": "Executive Compensation Review 2026 (Confidential)", "confidential": True},
}


@idor_bp.route("/lab/record")
def lab_record():
    """Demonstrates object-level authorization vs. missing ownership check."""
    record_id = request.args.get("id", type=int, default=101)
    record = _SYNTHETIC_RECORDS.get(record_id)
    if not record:
        return jsonify({"error": "Record not found"}), 404

    test_def = TestDefinition.query.filter_by(slug=SLUG).first()
    scenario = Scenario.query.filter_by(test_id=test_def.id).first() if test_def else None
    is_vulnerable = not scenario or scenario.state == ScenarioState.VULNERABLE

    current_user_sim_id = 42

    if is_vulnerable:
        # No ownership check: returns record regardless of owner
        return jsonify({
            "status": "vulnerable",
            "message": "Record retrieved without ownership verification.",
            "record": record,
        }), 200
    else:
        # Secure: enforces ownership check
        if record["owner_id"] != current_user_sim_id:
            return jsonify({
                "error": "Forbidden: You do not have permission to view this record.",
                "status": "secure",
            }), 403
        return jsonify({"status": "secure", "record": record}), 200
