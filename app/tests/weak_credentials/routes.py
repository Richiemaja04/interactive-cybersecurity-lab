"""
app/tests/weak_credentials/routes.py — Routes for Test 09: Default & Weak Credential Testing.
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

weak_creds_bp = Blueprint("weak_credentials", __name__)
SLUG = "weak-credentials"


@weak_creds_bp.route("/")
@login_required
@require_tester
def detail():
    return render_test_detail(SLUG, "weak_credentials", lab_url="/tests/weak-credentials/lab/login")


@weak_creds_bp.route("/run", methods=["POST"])
@login_required
@require_tester
def run_test():
    return execute_test_run(SLUG, "weak_credentials")


@weak_creds_bp.route("/runs/<int:run_id>")
@login_required
@require_tester
def view_run(run_id: int):
    return render_run_detail(SLUG, "weak_credentials", run_id)


@weak_creds_bp.route("/scenario", methods=["POST"])
@login_required
@require_tester
def toggle_scenario():
    return toggle_test_scenario(SLUG, "weak_credentials")


# ── Interactive Lab Endpoints ─────────────────────────────────────────────────

@weak_creds_bp.route("/lab/login", methods=["GET", "POST"])
def lab_login():
    """Demonstrates weak default credentials acceptance vs lockout & password strength enforcement."""
    test_def = TestDefinition.query.filter_by(slug=SLUG).first()
    scenario = Scenario.query.filter_by(test_id=test_def.id).first() if test_def else None
    is_vulnerable = not scenario or scenario.state == ScenarioState.VULNERABLE

    if request.method == "GET":
        return jsonify({
            "endpoint": "/tests/weak-credentials/lab/login",
            "instruction": "Send POST with JSON or form data: username and password.",
            "synthetic_lab_account": "lab_admin",
            "default_password": "admin",
            "scenario": "vulnerable" if is_vulnerable else "secure",
        })

    data = request.get_json(silent=True) or request.form
    username = data.get("username", "")
    password = data.get("password", "")

    if is_vulnerable:
        # Accepts default admin/admin with zero lockout
        if username == "lab_admin" and password == "admin":
            return jsonify({
                "status": "vulnerable",
                "authenticated": True,
                "message": "Authenticated with default password 'admin'. No lockout policy enforced.",
            }), 200
        return jsonify({"authenticated": False, "error": "Invalid credentials"}), 401
    else:
        # Secure: default password rejected, complexity & lockout required
        if password == "admin":
            return jsonify({
                "status": "secure",
                "authenticated": False,
                "error": "Authentication failed. Default password rejected by security policy.",
            }), 401
        return jsonify({
            "status": "secure",
            "message": "Authentication endpoint protected with lockout and rate limiting.",
        }), 401
