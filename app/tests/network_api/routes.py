"""
app/tests/network_api/routes.py — Routes for Test 08: Network Tab & API Over-fetching.
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

network_bp = Blueprint("network_api", __name__)
SLUG = "network-api"


@network_bp.route("/")
@login_required
@require_tester
def detail():
    return render_test_detail(SLUG, "network_api", lab_url="/tests/network-api/lab/employees/101")


@network_bp.route("/run", methods=["POST"])
@login_required
@require_tester
def run_test():
    return execute_test_run(SLUG, "network_api")


@network_bp.route("/runs/<int:run_id>")
@login_required
@require_tester
def view_run(run_id: int):
    return render_run_detail(SLUG, "network_api", run_id)


@network_bp.route("/scenario", methods=["POST"])
@login_required
@require_tester
def toggle_scenario():
    return toggle_test_scenario(SLUG, "network_api")


# ── Interactive Lab Endpoints ─────────────────────────────────────────────────

_SYNTHETIC_EMPLOYEES = {
    101: {
        "id": 101,
        "full_name": "Alex Taylor",
        "department": "Security Architecture",
        "email": "alex.taylor@example-lab.local",
        "salary": 140000,
        "ssn": "999-XX-0101",
        "internal_clearance": "TopSecret",
        "home_address": "42 Cyber Way, Suite 300, Neo City",
    }
}


@network_bp.route("/lab/employees/<int:emp_id>")
def lab_employee(emp_id: int):
    """Demonstrates API over-fetching: raw entity return vs minimized DTO schema."""
    emp = _SYNTHETIC_EMPLOYEES.get(emp_id)
    if not emp:
        return jsonify({"error": "Employee not found"}), 404

    test_def = TestDefinition.query.filter_by(slug=SLUG).first()
    scenario = Scenario.query.filter_by(test_id=test_def.id).first() if test_def else None
    is_vulnerable = not scenario or scenario.state == ScenarioState.VULNERABLE

    if is_vulnerable:
        # Returns all fields including sensitive compensation & PII
        return jsonify(emp), 200
    else:
        # Data minimization applied: only public profile attributes
        return jsonify({
            "id": emp["id"],
            "full_name": emp["full_name"],
            "department": emp["department"],
        }), 200
