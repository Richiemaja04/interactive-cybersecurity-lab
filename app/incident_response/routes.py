"""
app/incident_response/routes.py — 5-Step Incident Response interactive walkthrough.

Features:
- Structured 5-stage workflow: Identify → Inspect → Assess → Remediate → Verify
- Strictly labeled as [SIMULATED INCIDENT] throughout
- Educational interactive walkthrough of live triage and remediation verification
"""

from __future__ import annotations

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import login_required

from app.auth.decorators import require_tester

ir_bp = Blueprint("ir", __name__)

_INCIDENT_STAGES = [
    {"step": 1, "name": "Identify", "title": "Detect & Characterize Anomaly"},
    {"step": 2, "name": "Inspect", "title": "Examine Technical Evidence"},
    {"step": 3, "name": "Assess", "title": "Determine Impact & Scope"},
    {"step": 4, "name": "Remediate", "title": "Apply Targeted Containment & Fix"},
    {"step": 5, "name": "Verify", "title": "Validate Recovery & Residual Risk"},
]


@ir_bp.route("/")
@login_required
@require_tester
def index():
    step = request.args.get("step", 1, type=int)
    step = max(1, min(step, 5))
    return render_template(
        "incident_response/index.html",
        current_step=step,
        stages=_INCIDENT_STAGES,
    )
