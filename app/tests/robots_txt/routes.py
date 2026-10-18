"""
app/tests/robots_txt/routes.py — Routes for Test 01: Robots.txt Enumeration.
"""

from __future__ import annotations

from flask import Blueprint, Response, jsonify
from flask_login import login_required

from app.auth.decorators import require_tester
from app.models.scenario import Scenario, ScenarioState, TestDefinition
from app.tests.controller import (
    execute_test_run,
    render_run_detail,
    render_test_detail,
    toggle_test_scenario,
)

robots_bp = Blueprint("robots_txt", __name__)
SLUG = "robots-txt"


@robots_bp.route("/")
@login_required
@require_tester
def detail():
    return render_test_detail(SLUG, "robots_txt", lab_url="/tests/robots-txt/lab/robots.txt")


@robots_bp.route("/run", methods=["POST"])
@login_required
@require_tester
def run_test():
    return execute_test_run(SLUG, "robots_txt")


@robots_bp.route("/runs/<int:run_id>")
@login_required
@require_tester
def view_run(run_id: int):
    return render_run_detail(SLUG, "robots_txt", run_id)


@robots_bp.route("/scenario", methods=["POST"])
@login_required
@require_tester
def toggle_scenario():
    return toggle_test_scenario(SLUG, "robots_txt")


# ── Interactive Lab Endpoints ─────────────────────────────────────────────────

@robots_bp.route("/lab/robots.txt")
def lab_robots_txt():
    """Serves controlled robots.txt based on active scenario state."""
    test_def = TestDefinition.query.filter_by(slug=SLUG).first()
    scenario = Scenario.query.filter_by(test_id=test_def.id).first() if test_def else None
    is_vulnerable = not scenario or scenario.state == ScenarioState.VULNERABLE

    if is_vulnerable:
        content = (
            "User-agent: *\n"
            "Disallow: /tests/robots-txt/lab/admin/\n"
            "Disallow: /tests/robots-txt/lab/backup/\n"
            "Disallow: /tests/robots-txt/lab/api/internal/\n"
            "Disallow: /tests/robots-txt/lab/config/\n"
            "Allow: /\n"
            "Sitemap: https://example-lab.local/sitemap.xml\n"
        )
    else:
        content = (
            "User-agent: *\n"
            "Disallow: /\n"
            "Sitemap: https://example-lab.local/sitemap.xml\n"
        )

    return Response(content, mimetype="text/plain")


@robots_bp.route("/lab/admin/")
def lab_admin():
    test_def = TestDefinition.query.filter_by(slug=SLUG).first()
    scenario = Scenario.query.filter_by(test_id=test_def.id).first() if test_def else None
    if not scenario or scenario.state == ScenarioState.VULNERABLE:
        return jsonify({"status": "vulnerable", "endpoint": "/admin/", "message": "Admin control panel reached without authentication."}), 200
    return jsonify({"error": "Forbidden: Authentication required"}), 403


@robots_bp.route("/lab/backup/")
def lab_backup():
    test_def = TestDefinition.query.filter_by(slug=SLUG).first()
    scenario = Scenario.query.filter_by(test_id=test_def.id).first() if test_def else None
    if not scenario or scenario.state == ScenarioState.VULNERABLE:
        return jsonify({"status": "vulnerable", "endpoint": "/backup/", "files": ["db_backup_2026.sql.gz", "config.bak"]}), 200
    return jsonify({"error": "Forbidden: Authentication required"}), 403
