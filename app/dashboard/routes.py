"""
app/dashboard/routes.py — Dashboard and landing page routes.
"""

from __future__ import annotations

from flask import Blueprint, render_template
from flask_login import login_required

from app.auth.decorators import require_tester

dashboard_bp = Blueprint("dashboard", __name__, template_folder="../templates/dashboard")
landing_bp = Blueprint("landing", __name__, template_folder="../templates")


@landing_bp.route("/")
def index():
    """Public landing page."""
    return render_template("landing.html", title="Interactive Cybersecurity Lab")


@dashboard_bp.route("/")
@login_required
@require_tester
def index():
    """Main dashboard — all ten tests, statuses, and summaries."""
    return render_template("dashboard/index.html", title="Dashboard")
