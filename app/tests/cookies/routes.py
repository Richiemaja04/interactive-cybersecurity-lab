"""
app/tests/cookies/routes.py — Routes for Test 04: Cookie Security Flags Inspection.
"""

from __future__ import annotations

from flask import Blueprint, jsonify, make_response
from flask_login import login_required

from app.auth.decorators import require_tester
from app.models.scenario import Scenario, ScenarioState, TestDefinition
from app.tests.controller import (
    execute_test_run,
    render_run_detail,
    render_test_detail,
    toggle_test_scenario,
)

cookies_bp = Blueprint("cookies", __name__)
SLUG = "cookies"


@cookies_bp.route("/")
@login_required
@require_tester
def detail():
    return render_test_detail(SLUG, "cookies", lab_url="/tests/cookies/lab/cookie-check")


@cookies_bp.route("/run", methods=["POST"])
@login_required
@require_tester
def run_test():
    return execute_test_run(SLUG, "cookies")


@cookies_bp.route("/runs/<int:run_id>")
@login_required
@require_tester
def view_run(run_id: int):
    return render_run_detail(SLUG, "cookies", run_id)


@cookies_bp.route("/scenario", methods=["POST"])
@login_required
@require_tester
def toggle_scenario():
    return toggle_test_scenario(SLUG, "cookies")


# ── Interactive Lab Endpoints ─────────────────────────────────────────────────

@cookies_bp.route("/lab/cookie-check")
def lab_cookie():
    """Sets a demonstration session cookie reflecting the active scenario state."""
    test_def = TestDefinition.query.filter_by(slug=SLUG).first()
    scenario = Scenario.query.filter_by(test_id=test_def.id).first() if test_def else None
    is_vulnerable = not scenario or scenario.state == ScenarioState.VULNERABLE

    resp = make_response(jsonify({
        "status": "vulnerable" if is_vulnerable else "secure",
        "cookie_name": "lab_session_token",
        "description": "Inspect Set-Cookie header in DevTools Network tab or document.cookie in Console.",
        "httponly": not is_vulnerable,
        "secure": not is_vulnerable,
        "samesite": "Lax" if not is_vulnerable else "None",
    }))

    if is_vulnerable:
        # Vulnerable: missing flags
        resp.set_cookie(
            "lab_session_token",
            "tok_9f83a8e2bc74",
            httponly=False,
            secure=False,
            samesite=None,
        )
    else:
        # Secure: all flags strictly applied
        resp.set_cookie(
            "lab_session_token",
            "tok_9f83a8e2bc74",
            httponly=True,
            secure=True,
            samesite="Lax",
        )

    return resp
