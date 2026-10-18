"""
app/tests/forced_browsing/routes.py — Routes for Test 03: Directory Guessing / Forced Browsing.
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

forced_browsing_bp = Blueprint("forced_browsing", __name__)
SLUG = "forced-browsing"


@forced_browsing_bp.route("/")
@login_required
@require_tester
def detail():
    return render_test_detail(SLUG, "forced_browsing", lab_url="/tests/forced-browsing/lab/admin/user-management")


@forced_browsing_bp.route("/run", methods=["POST"])
@login_required
@require_tester
def run_test():
    return execute_test_run(SLUG, "forced_browsing")


@forced_browsing_bp.route("/runs/<int:run_id>")
@login_required
@require_tester
def view_run(run_id: int):
    return render_run_detail(SLUG, "forced_browsing", run_id)


@forced_browsing_bp.route("/scenario", methods=["POST"])
@login_required
@require_tester
def toggle_scenario():
    return toggle_test_scenario(SLUG, "forced_browsing")


# ── Interactive Lab Endpoints ─────────────────────────────────────────────────

@forced_browsing_bp.route("/lab/admin/user-management")
def lab_admin_users():
    test_def = TestDefinition.query.filter_by(slug=SLUG).first()
    scenario = Scenario.query.filter_by(test_id=test_def.id).first() if test_def else None
    if not scenario or scenario.state == ScenarioState.VULNERABLE:
        return jsonify({"status": "vulnerable", "endpoint": "/admin/user-management", "users": ["alice", "bob", "root"]}), 200
    return jsonify({"error": "Forbidden: Administrator role required"}), 403


@forced_browsing_bp.route("/lab/backup/database_dump.sql.bak")
def lab_backup_dump():
    test_def = TestDefinition.query.filter_by(slug=SLUG).first()
    scenario = Scenario.query.filter_by(test_id=test_def.id).first() if test_def else None
    if not scenario or scenario.state == ScenarioState.VULNERABLE:
        return jsonify({"status": "vulnerable", "file": "database_dump.sql.bak", "size": "14.2MB"}), 200
    return jsonify({"error": "Not Found"}), 404
