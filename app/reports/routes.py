"""
app/reports/routes.py — Report management, PDF generation, and JSON download routes.
"""

from __future__ import annotations

import os
from flask import (
    Blueprint,
    Response,
    abort,
    current_app,
    flash,
    render_template,
    send_file,
)
from flask_login import current_user, login_required

from app.auth.decorators import require_tester
from app.models.execution import ExecutionRun
from app.models.report import ReportExport, ReportFormat
from app.reports.service import ReportGeneratorService

reports_bp = Blueprint("reports", __name__)


@reports_bp.route("/")
@login_required
@require_tester
def index():
    """List available test runs and historical report exports."""
    # Runs for the current user
    runs = (
        ExecutionRun.query.filter_by(user_id=current_user.id)
        .order_by(ExecutionRun.id.desc())
        .limit(25)
        .all()
    )
    exports = (
        ReportExport.query.filter_by(user_id=current_user.id)
        .order_by(ReportExport.id.desc())
        .limit(25)
        .all()
    )
    return render_template("reports/index.html", runs=runs, exports=exports)


@reports_bp.route("/runs/<int:run_id>/json")
@login_required
@require_tester
def export_json(run_id: int):
    """Generate, record, and stream JSON report."""
    run = ExecutionRun.query.get_or_404(run_id)
    if run.user_id != current_user.id and not current_user.is_administrator:
        abort(403, "Access denied")

    json_str = ReportGeneratorService.generate_json_report(run)
    filename = f"report_run_{run.id}_{run.test_definition.slug}.json"

    # Record export audit
    ReportGeneratorService.record_export(
        user_id=current_user.id,
        run_id=run.id,
        report_format=ReportFormat.JSON,
        content=json_str,
        filename=filename,
    )

    return Response(
        json_str,
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@reports_bp.route("/runs/<int:run_id>/pdf")
@login_required
@require_tester
def export_pdf(run_id: int):
    """Generate, record, and stream PDF report."""
    run = ExecutionRun.query.get_or_404(run_id)
    if run.user_id != current_user.id and not current_user.is_administrator:
        abort(403, "Access denied")

    try:
        pdf_bytes = ReportGeneratorService.generate_pdf_report(run)
    except Exception as e:
        flash(f"PDF generation failed: {e}. Downloading JSON format instead.", "warning")
        return export_json(run_id)

    filename = f"report_run_{run.id}_{run.test_definition.slug}.pdf"

    # Record export audit
    ReportGeneratorService.record_export(
        user_id=current_user.id,
        run_id=run.id,
        report_format=ReportFormat.PDF,
        content=pdf_bytes,
        filename=filename,
    )

    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@reports_bp.route("/exports/<int:export_id>/download")
@login_required
@require_tester
def download_export(export_id: int):
    """Download an existing archived report file."""
    export = ReportExport.query.get_or_404(export_id)
    if export.user_id != current_user.id and not current_user.is_administrator:
        abort(403, "Access denied")

    out_dir = current_app.config["REPORT_OUTPUT_DIR"]
    file_path = os.path.join(out_dir, export.file_ref)
    if not os.path.exists(file_path):
        abort(404, "Report file not found on disk")

    return send_file(file_path, as_attachment=True, download_name=export.file_ref)
