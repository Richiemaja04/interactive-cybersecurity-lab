"""
app/tests/controller.py — Shared test execution controller and view helper.

Coordinates TestDefinition retrieval, Scenario state management, ExecutionService
invocation, and view rendering across all 10 security test modules.
"""

from __future__ import annotations

from flask import abort, flash, redirect, render_template, request, url_for, jsonify
from flask_login import current_user

from app.extensions import db
from app.models.execution import ExecutionRun, ExecutionState
from app.models.scenario import Scenario, ScenarioState, ScenarioVersion, TestDefinition
from app.services.execution_service import ExecutionService
from app.tests.registry import get_module_by_slug
from scripts.seed_test_definitions import TEST_DEFINITIONS


def ensure_test_scenario(slug: str) -> tuple[TestDefinition, Scenario]:
    """
    Ensure TestDefinition and active Scenario exist for the given slug.
    Creates them idempotently if not already present.
    """
    test_def = TestDefinition.query.filter_by(slug=slug).first()
    if not test_def:
        # Match from TEST_DEFINITIONS
        matching = next((item for item in TEST_DEFINITIONS if item["slug"] == slug), None)
        if not matching:
            abort(404, f"Test definition for slug '{slug}' not found.")
        test_def = TestDefinition(**matching)
        db.session.add(test_def)
        db.session.flush()

    scenario = Scenario.query.filter_by(test_id=test_def.id).first()
    if not scenario:
        scenario = Scenario(
            test_id=test_def.id,
            name=f"{slug}_default",
            state=ScenarioState.VULNERABLE,
            current_version=1,
            config_json={},
            is_active=True,
        )
        db.session.add(scenario)
        db.session.flush()

        # Initial scenario version snapshot
        sv = ScenarioVersion(
            scenario_id=scenario.id,
            version=1,
            snapshot_json={"state": ScenarioState.VULNERABLE.value, "config": {}},
            change_description="Initial scenario creation",
        )
        db.session.add(sv)
        db.session.commit()

    return test_def, scenario


def render_test_detail(slug: str, blueprint_name: str, lab_url: str | None = None):
    """Render the standard test detail page for a module."""
    test_def, scenario = ensure_test_scenario(slug)
    module = get_module_by_slug(slug)
    if not module:
        abort(404, f"Test module '{slug}' not registered.")

    presenter_notes = module.get_presenter_notes()
    verification_steps = module.get_verification_steps(None)
    remediation = module.get_remediation(None)

    # Fetch recent runs for this test owned by current user
    recent_runs = (
        ExecutionRun.query.filter_by(test_id=test_def.id, user_id=current_user.id)
        .order_by(ExecutionRun.id.desc())
        .limit(10)
        .all()
    )

    return render_template(
        "tests/detail.html",
        test_def=test_def,
        scenario=scenario,
        presenter_notes=presenter_notes,
        verification_steps=verification_steps,
        remediation=remediation,
        recent_runs=recent_runs,
        test_slug_url=blueprint_name,
        lab_url=lab_url,
    )


def execute_test_run(slug: str, blueprint_name: str):
    """Execute a test run and redirect or return results."""
    test_def, scenario = ensure_test_scenario(slug)
    module = get_module_by_slug(slug)
    if not module:
        abort(404, f"Test module '{slug}' not registered.")

    run = ExecutionRun(
        test_id=test_def.id,
        user_id=current_user.id,
        scenario_id=scenario.id,
        state=ExecutionState.QUEUED,
        scenario_version_at_run=scenario.current_version,
        is_rehearsal=False,
    )
    db.session.add(run)
    db.session.commit()

    # Execute synchronously via ExecutionService
    service = ExecutionService(run=run, module=module, timeout=10)
    service.execute(scenario=scenario, config={})

    if request.is_json or request.headers.get("Accept") == "application/json":
        return jsonify({
            "run_id": run.id,
            "state": run.state.value,
            "scenario_version": run.scenario_version_at_run,
            "findings_count": run.findings.count(),
            "evidence_count": run.evidence_records.count(),
        })

    flash(f"Test run #{run.id} completed with state: {run.state.value.capitalize()}.", "success")
    return redirect(url_for(f"{blueprint_name}.view_run", run_id=run.id))


def render_run_detail(slug: str, blueprint_name: str, run_id: int):
    """Render the results of a specific execution run."""
    test_def, _ = ensure_test_scenario(slug)
    run = ExecutionRun.query.filter_by(id=run_id, test_id=test_def.id).first_or_404()

    # Enforce tester ownership or administrator access
    if run.user_id != current_user.id and not current_user.is_administrator:
        abort(403, "Access denied: you do not own this execution run.")

    findings = run.findings.all()
    evidence_records = run.evidence_records.all()
    events = run.events.all()

    return render_template(
        "tests/run_detail.html",
        test_def=test_def,
        run=run,
        findings=findings,
        evidence_records=evidence_records,
        events=events,
        test_slug_url=blueprint_name,
    )


def toggle_test_scenario(slug: str, blueprint_name: str):
    """Toggle scenario state between vulnerable and secure."""
    _, scenario = ensure_test_scenario(slug)

    new_state = (
        ScenarioState.SECURE
        if scenario.state == ScenarioState.VULNERABLE
        else ScenarioState.VULNERABLE
    )
    scenario.state = new_state
    scenario.current_version += 1

    # Record linear scenario version snapshot
    version_snapshot = ScenarioVersion(
        scenario_id=scenario.id,
        version=scenario.current_version,
        snapshot_json={"state": new_state.value, "config": scenario.config_json},
        change_description=f"Tester toggled scenario to {new_state.value}",
        changed_by_id=current_user.id,
    )
    db.session.add(version_snapshot)
    db.session.commit()

    flash(f"Scenario configuration toggled to {new_state.value.upper()} (v{scenario.current_version}).", "info")
    return redirect(url_for(f"{blueprint_name}.detail"))
