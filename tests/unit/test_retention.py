"""
tests/unit/test_retention.py — Data retention cleanup job tests.
"""

from datetime import datetime, timedelta, timezone

from app.models.execution import ExecutionRun, ExecutionState
from app.models.report import ReportExport, ReportFormat
from app.models.retention import RetentionJob
from app.models.scenario import TestDefinition
from app.retention.service import RetentionService


def test_retention_purges_only_aged_records(app, db_session, tester_user):
    with app.app_context():
        td = TestDefinition(
            number="01",
            name="Robots.txt Enumeration",
            slug="robots-txt-ret",
            category="Info",
            objective="obj",
            concept="concept",
        )
        db_session.add(td)
        db_session.flush()

        now = datetime.now(timezone.utc)
        old_date = now - timedelta(days=95)
        recent_date = now - timedelta(days=10)

        # 1. Old run (95 days old -> should be purged)
        old_run = ExecutionRun(
            test_id=td.id,
            user_id=tester_user.id,
            state=ExecutionState.COMPLETED,
            created_at=old_date,
        )
        # 2. Recent run (10 days old -> should be kept)
        recent_run = ExecutionRun(
            test_id=td.id,
            user_id=tester_user.id,
            state=ExecutionState.COMPLETED,
            created_at=recent_date,
        )
        # 3. Old report export
        old_report = ReportExport(
            user_id=tester_user.id,
            format=ReportFormat.JSON,
            created_at=old_date,
        )

        db_session.add_all([old_run, recent_run, old_report])
        db_session.commit()

        # Execute retention job
        job = RetentionService.execute_retention_job(triggered_by_id=tester_user.id)

        assert job.records_deleted == 2  # old_run + old_report

        # Verify old run is gone
        assert db_session.get(ExecutionRun, old_run.id) is None
        # Verify recent run is preserved
        assert db_session.get(ExecutionRun, recent_run.id) is not None
        # Verify old report is gone
        assert db_session.get(ReportExport, old_report.id) is None
