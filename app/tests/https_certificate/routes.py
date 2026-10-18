"""
app/tests/https_certificate/routes.py — Routes for Test 05: HTTPS & Certificate Check.
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

https_bp = Blueprint("https_certificate", __name__)
SLUG = "https-certificate"


@https_bp.route("/")
@login_required
@require_tester
def detail():
    return render_test_detail(SLUG, "https_certificate", lab_url="/tests/https-certificate/lab/cert-info")


@https_bp.route("/run", methods=["POST"])
@login_required
@require_tester
def run_test():
    return execute_test_run(SLUG, "https_certificate")


@https_bp.route("/runs/<int:run_id>")
@login_required
@require_tester
def view_run(run_id: int):
    return render_run_detail(SLUG, "https_certificate", run_id)


@https_bp.route("/scenario", methods=["POST"])
@login_required
@require_tester
def toggle_scenario():
    return toggle_test_scenario(SLUG, "https_certificate")


# ── Interactive Lab Endpoints ─────────────────────────────────────────────────

@https_bp.route("/lab/cert-info")
def lab_cert_info():
    """Provides TLS and transport certificate status for the demonstration."""
    test_def = TestDefinition.query.filter_by(slug=SLUG).first()
    scenario = Scenario.query.filter_by(test_id=test_def.id).first() if test_def else None
    is_vulnerable = not scenario or scenario.state == ScenarioState.VULNERABLE

    if is_vulnerable:
        return jsonify({
            "status": "vulnerable",
            "tls_enforced": False,
            "hsts_present": False,
            "certificate_status": "untrusted_or_expired_simulation",
            "message": "Cleartext HTTP accepted without redirect to HTTPS.",
        }), 200
    else:
        return jsonify({
            "status": "secure",
            "tls_enforced": True,
            "hsts_present": True,
            "hsts_header": "max-age=31536000; includeSubDomains; preload",
            "certificate_status": "valid",
            "message": "HTTPS strictly enforced with valid certificate and HSTS preload.",
        }), 200
