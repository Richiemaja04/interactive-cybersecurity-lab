"""
app/tests/input_validation/routes.py — Routes for Test 06: Form Input Validation & XSS Awareness.
"""

from __future__ import annotations

import html
from flask import Blueprint, Response, request
from flask_login import login_required

from app.auth.decorators import require_tester
from app.models.scenario import Scenario, ScenarioState, TestDefinition
from app.tests.controller import (
    execute_test_run,
    render_run_detail,
    render_test_detail,
    toggle_test_scenario,
)

input_validation_bp = Blueprint("input_validation", __name__)
SLUG = "input-validation"


@input_validation_bp.route("/")
@login_required
@require_tester
def detail():
    return render_test_detail(
        SLUG,
        "input_validation",
        lab_url="/tests/input-validation/lab/search?query=%3Cscript%3Econsole.log('canary')%3C%2Fscript%3E",
    )


@input_validation_bp.route("/run", methods=["POST"])
@login_required
@require_tester
def run_test():
    return execute_test_run(SLUG, "input_validation")


@input_validation_bp.route("/runs/<int:run_id>")
@login_required
@require_tester
def view_run(run_id: int):
    return render_run_detail(SLUG, "input_validation", run_id)


@input_validation_bp.route("/scenario", methods=["POST"])
@login_required
@require_tester
def toggle_scenario():
    return toggle_test_scenario(SLUG, "input_validation")


# ── Interactive Lab Endpoints ─────────────────────────────────────────────────

@input_validation_bp.route("/lab/search")
def lab_search():
    """Demonstrates input reflection: unencoded vs. context-aware HTML escaped + CSP."""
    query = request.args.get("query", "harmless_canary")
    test_def = TestDefinition.query.filter_by(slug=SLUG).first()
    scenario = Scenario.query.filter_by(test_id=test_def.id).first() if test_def else None
    is_vulnerable = not scenario or scenario.state == ScenarioState.VULNERABLE

    if is_vulnerable:
        # Reflected raw, unencoded, no CSP
        body = f"""<!DOCTYPE html>
<html>
<head><title>Search Results (Vulnerable Lab)</title></head>
<body style="font-family: sans-serif; padding: 2rem; background: #0a0e1a; color: #fff;">
  <h2>Lab Search Query Result</h2>
  <p>Search results for query: <span id="query-output">{query}</span></p>
  <p style="color: #ff4444;">⚠️ Notice: The input was reflected unescaped into the HTML document with no CSP.</p>
</body>
</html>"""
        resp = Response(body, mimetype="text/html")
    else:
        # Secure: safely HTML encoded and strict CSP applied
        safe_query = html.escape(query)
        body = f"""<!DOCTYPE html>
<html>
<head><title>Search Results (Secure Lab)</title></head>
<body style="font-family: sans-serif; padding: 2rem; background: #0a0e1a; color: #fff;">
  <h2>Lab Search Query Result</h2>
  <p>Search results for query: <span id="query-output">{safe_query}</span></p>
  <p style="color: #00ff88;">🛡️ Notice: The input is safely entity-encoded and Content-Security-Policy is enforced.</p>
</body>
</html>"""
        resp = Response(body, mimetype="text/html")
        resp.headers["Content-Security-Policy"] = "default-src 'self'"

    return resp
