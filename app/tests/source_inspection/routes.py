"""
app/tests/source_inspection/routes.py — Routes for Test 07: Inspect Page Source & Client Code.
"""

from __future__ import annotations

from flask import Blueprint, Response
from flask_login import login_required

from app.auth.decorators import require_tester
from app.models.scenario import Scenario, ScenarioState, TestDefinition
from app.tests.controller import (
    execute_test_run,
    render_run_detail,
    render_test_detail,
    toggle_test_scenario,
)

source_bp = Blueprint("source_inspection", __name__)
SLUG = "source-inspection"


@source_bp.route("/")
@login_required
@require_tester
def detail():
    return render_test_detail(SLUG, "source_inspection", lab_url="/tests/source-inspection/lab/bundle.js")


@source_bp.route("/run", methods=["POST"])
@login_required
@require_tester
def run_test():
    return execute_test_run(SLUG, "source_inspection")


@source_bp.route("/runs/<int:run_id>")
@login_required
@require_tester
def view_run(run_id: int):
    return render_run_detail(SLUG, "source_inspection", run_id)


@source_bp.route("/scenario", methods=["POST"])
@login_required
@require_tester
def toggle_scenario():
    return toggle_test_scenario(SLUG, "source_inspection")


# ── Interactive Lab Endpoints ─────────────────────────────────────────────────

@source_bp.route("/lab/bundle.js")
def lab_bundle():
    """Serves client-side bundle demonstrating synthetic secret exposure vs clean asset."""
    test_def = TestDefinition.query.filter_by(slug=SLUG).first()
    scenario = Scenario.query.filter_by(test_id=test_def.id).first() if test_def else None
    is_vulnerable = not scenario or scenario.state == ScenarioState.VULNERABLE

    if is_vulnerable:
        content = """// Application Bundle v1.4.0 (Vulnerable Lab Configuration)
const API_BASE = "https://api.example-lab.local";

// TODO: Remove this bypass before production deployment (Alice - 2026)
const STRIPE_SECRET_KEY = "sk_test_synthetic_key_exposed_in_client_bundle_9921";
const INTERNAL_ADMIN_ENDPOINT = "/api/v1/internal-debug-dump";

console.log("Client bundle initialized with synthetic secret exposure.");
"""
    else:
        content = """// Application Bundle v1.4.0 (Secure Lab Configuration)
const API_BASE = "https://api.example-lab.local";
const STRIPE_PUBLISHABLE_KEY = "pk_test_synthetic_public_publishable_key";

console.log("Client bundle initialized securely without secret exposure.");
"""

    return Response(content, mimetype="application/javascript")
