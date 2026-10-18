"""
app/retention/service.py — 90-day data retention cleanup engine.

Enforces:
- Automatic or on-demand purging of transient execution records and reports older than 90 days
- Immutable RetentionJob record creation
- Audit logging of all deletion operations
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from flask import current_app

from app.audit.service import write_audit_event
from app.extensions import db
from app.models.execution import ExecutionRun
from app.models.report import ReportExport
from app.models.retention import RetentionJob


class RetentionService:
    @classmethod
    def execute_retention_job(cls, triggered_by_id: int | None = None) -> RetentionJob:
        """Purge execution runs and reports older than RETENTION_DAYS (default 90)."""
        retention_days = current_app.config.get("RETENTION_DAYS", 90)
        cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)

        # 1. Old Execution Runs
        runs_to_delete = ExecutionRun.query.filter(ExecutionRun.created_at < cutoff).all()
        run_count = len(runs_to_delete)
        for r in runs_to_delete:
            db.session.delete(r)

        # 2. Old Report Exports
        reports_to_delete = ReportExport.query.filter(ReportExport.created_at < cutoff).all()
        report_count = len(reports_to_delete)
        for rep in reports_to_delete:
            db.session.delete(rep)

        total_deleted = run_count + report_count

        job = RetentionJob(
            triggered_by_id=triggered_by_id,
            scope="execution_runs_and_reports",
            cutoff_date=cutoff,
            records_deleted=total_deleted,
            notes=f"Purged {run_count} runs and {report_count} report exports older than {retention_days} days.",
        )
        db.session.add(job)
        db.session.commit()

        write_audit_event(
            action="DATA_RETENTION_PURGE",
            user_id=triggered_by_id,
            detail={
                "retention_days": retention_days,
                "cutoff_date": cutoff.isoformat(),
                "records_deleted": total_deleted,
            },
        )

        return job
