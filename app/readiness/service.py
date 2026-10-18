"""
app/readiness/service.py — Pre-sequence readiness verification gate.

Conducts automated health and configuration checks before a live presentation
sequence is started, ensuring deterministic delivery:
- Application & database connectivity
- Availability of all 10 security test scenarios
- Account provisioning (Tester & Admin exist)
- PDF/JSON reporting engine readiness
"""

from __future__ import annotations

import dataclasses
from sqlalchemy import text

from app.extensions import db
from app.models.scenario import Scenario, TestDefinition
from app.models.user import RoleEnum, User
from app.tests.registry import get_all_modules
from scripts.seed_test_definitions import TEST_DEFINITIONS


@dataclasses.dataclass
class CheckResult:
    name: str
    status: str      # "pass", "warning", "fail"
    detail: str
    essential: bool = True


@dataclasses.dataclass
class ReadinessReport:
    overall_status: str     # "Ready", "Warning", "Blocked"
    checks: list[CheckResult]
    can_proceed: bool


class ReadinessService:
    @staticmethod
    def run_all_checks() -> ReadinessReport:
        checks: list[CheckResult] = []

        # 1. Database Health Check
        db_pass = False
        try:
            db.session.execute(text("SELECT 1"))
            db_pass = True
            checks.append(CheckResult(
                name="Database Connectivity",
                status="pass",
                detail="PostgreSQL/SQLite database is responsive and accepting queries.",
                essential=True,
            ))
        except Exception as e:
            checks.append(CheckResult(
                name="Database Connectivity",
                status="fail",
                detail=f"Database unreachable: {e}",
                essential=True,
            ))

        # 2. Test Modules Registry
        modules = get_all_modules()
        if len(modules) == 10:
            checks.append(CheckResult(
                name="Module Registration",
                status="pass",
                detail="All 10 security test modules successfully loaded in registry.",
                essential=True,
            ))
        else:
            checks.append(CheckResult(
                name="Module Registration",
                status="fail",
                detail=f"Expected 10 modules in registry, found {len(modules)}.",
                essential=True,
            ))

        # 3. Test Definitions & Scenario Seed Status
        if db_pass:
            defs_count = TestDefinition.query.count()
            if defs_count >= 10:
                checks.append(CheckResult(
                    name="Test Definitions",
                    status="pass",
                    detail=f"{defs_count} test definitions loaded in database.",
                    essential=True,
                ))
            else:
                checks.append(CheckResult(
                    name="Test Definitions",
                    status="warning",
                    detail=f"Only {defs_count}/10 test definitions seeded in database. Auto-seeding available.",
                    essential=False,
                ))
        else:
            checks.append(CheckResult(
                name="Test Definitions",
                status="fail",
                detail="Skipped due to database unavailability.",
                essential=True,
            ))

        # 4. User Account Provisioning
        if db_pass:
            has_tester = User.query.filter_by(role=RoleEnum.TESTER, is_active=True).first() is not None
            has_admin = User.query.filter_by(role=RoleEnum.ADMINISTRATOR, is_active=True).first() is not None
            if has_tester and has_admin:
                checks.append(CheckResult(
                    name="Account Provisioning",
                    status="pass",
                    detail="Tester and Administrator roles are provisioned and active.",
                    essential=True,
                ))
            else:
                checks.append(CheckResult(
                    name="Account Provisioning",
                    status="warning",
                    detail="Missing active Tester or Admin user account.",
                    essential=False,
                ))
        else:
            checks.append(CheckResult(
                name="Account Provisioning",
                status="fail",
                detail="Skipped due to database unavailability.",
                essential=True,
            ))

        # 5. Reporting Engine Readiness
        try:
            import reportlab
            checks.append(CheckResult(
                name="Reporting Engine",
                status="pass",
                detail="JSON and PDF export engines available.",
                essential=False,
            ))
        except ImportError:
            checks.append(CheckResult(
                name="Reporting Engine",
                status="warning",
                detail="ReportLab not installed; PDF export will use JSON fallback.",
                essential=False,
            ))

        # Evaluate Overall Status
        has_essential_fail = any(c.status == "fail" and c.essential for c in checks)
        has_warning = any(c.status == "warning" for c in checks)

        if has_essential_fail:
            overall = "Blocked"
            can_proceed = False
        elif has_warning:
            overall = "Warning"
            can_proceed = True
        else:
            overall = "Ready"
            can_proceed = True

        return ReadinessReport(
            overall_status=overall,
            checks=checks,
            can_proceed=can_proceed,
        )
