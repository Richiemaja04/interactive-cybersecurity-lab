"""
tests/unit/test_models.py — Phase 1: Database model unit tests.

Note: These tests use the db_session fixture which requires PostgreSQL.
"""

from __future__ import annotations

import pytest


class TestUserModel:
    def test_create_user(self, db_session, app):
        from app.extensions import bcrypt
        from app.models.user import RoleEnum, User

        with app.app_context():
            user = User(
                username="modeltest_user",
                email="modeltest@test.local",
                password_hash=bcrypt.generate_password_hash("Password1!").decode(),
                role=RoleEnum.TESTER,
            )
            db_session.add(user)
            db_session.flush()
            assert user.id is not None
            assert user.is_active is True
            assert user.created_at is not None

    def test_admin_role_satisfies_tester_check(self, admin_user, app):
        with app.app_context():
            from app.models.user import RoleEnum
            assert admin_user.has_role(RoleEnum.TESTER) is True
            assert admin_user.has_role(RoleEnum.ADMINISTRATOR) is True
            assert admin_user.is_administrator is True

    def test_tester_cannot_satisfy_admin_check(self, tester_user, app):
        with app.app_context():
            from app.models.user import RoleEnum
            assert tester_user.has_role(RoleEnum.ADMINISTRATOR) is False
            assert tester_user.is_tester is True

    def test_password_hash_not_plaintext(self, db_session, app):
        from app.extensions import bcrypt
        from app.models.user import RoleEnum, User

        with app.app_context():
            pw = "SecretPassword99!"
            user = User(
                username="hashtest_user",
                email="hashtest@test.local",
                password_hash=bcrypt.generate_password_hash(pw).decode(),
                role=RoleEnum.TESTER,
            )
            assert pw not in user.password_hash
            assert bcrypt.check_password_hash(user.password_hash, pw)


class TestExecutionStateModel:
    def test_all_states_defined(self):
        from app.models.execution import ExecutionState
        states = {s.value for s in ExecutionState}
        required = {"not_started", "queued", "running", "completed", "failed", "cancelled", "blocked"}
        assert required == states

    def test_execution_state_not_finding_status(self):
        """Verify these two enums are distinct — they must never be conflated."""
        from app.models.execution import ExecutionState
        from app.models.finding import VerificationStatus
        exec_values = {s.value for s in ExecutionState}
        finding_values = {s.value for s in VerificationStatus}
        assert not exec_values.intersection(finding_values), (
            "ExecutionState and VerificationStatus share values — they must remain distinct"
        )


class TestFindingVerificationStatus:
    def test_all_statuses_defined(self):
        from app.models.finding import VerificationStatus
        statuses = {s.value for s in VerificationStatus}
        assert "confirmed" in statuses
        assert "potential" in statuses
        assert "inconclusive" in statuses
        assert "simulated" in statuses


class TestEvidenceProvenance:
    def test_all_provenances_defined(self):
        from app.models.evidence import ProvenanceEnum
        values = {p.value for p in ProvenanceEnum}
        assert "observed_live" in values
        assert "controlled_scenario" in values
        assert "simulated" in values
        assert "manually_verified" in values
