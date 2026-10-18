"""
tests/integration/test_auth.py — Authentication integration tests.

Tests:
- Login success with valid credentials
- Timing-safe / anti-enumeration failure for invalid password & unknown username
- Inactive user login rejection
- Safe redirect validation (prevents open redirect)
- POST-only logout requirement
- Audit event creation on login success, failure, and logout
"""

from __future__ import annotations

import pytest

from app.models.audit import AuditEvent
from app.models.user import RoleEnum, User


class TestLoginFlow:
    """Authentication and session establishment."""

    def test_login_page_renders_get(self, client):
        resp = client.get("/auth/login")
        assert resp.status_code == 200
        assert b"Sign In" in resp.data or b"username" in resp.data.lower()

    def test_login_success(self, client, tester_user):
        resp = client.post(
            "/auth/login",
            data={
                "username": "test_tester",
                "password": "TestTester1!",
                "remember_me": False,
            },
            follow_redirects=False,
        )
        assert resp.status_code in (302, 303)
        assert "/dashboard" in resp.headers["Location"]

        # Audit event recorded
        audit = (
            AuditEvent.query.filter_by(action="login_success")
            .order_by(AuditEvent.id.desc())
            .first()
        )
        assert audit is not None
        assert audit.user_id == tester_user.id

    def test_login_invalid_password_returns_generic_error(self, client, tester_user):
        resp = client.post(
            "/auth/login",
            data={
                "username": "test_tester",
                "password": "WrongPassword999!",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"Invalid username or password" in resp.data

        # Failure audit event recorded
        audit = (
            AuditEvent.query.filter_by(action="login_failure")
            .order_by(AuditEvent.id.desc())
            .first()
        )
        assert audit is not None

    def test_login_unknown_username_returns_same_error(self, client):
        resp = client.post(
            "/auth/login",
            data={
                "username": "completely_unknown_user_123",
                "password": "AnyPassword123!",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"Invalid username or password" in resp.data

    def test_inactive_user_cannot_login(self, client, db_session):
        from app.extensions import bcrypt

        inactive = User(
            username="inactive_tester",
            email="inactive@test.local",
            password_hash=bcrypt.generate_password_hash("Pass123!").decode(),
            role=RoleEnum.TESTER,
            is_active=False,
        )
        db_session.add(inactive)
        db_session.commit()

        resp = client.post(
            "/auth/login",
            data={
                "username": "inactive_tester",
                "password": "Pass123!",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"Invalid username or password" in resp.data

    def test_login_rejects_external_redirect(self, client, tester_user):
        resp = client.post(
            "/auth/login?next=https://evil.attacker.com",
            data={"username": "test_tester", "password": "TestTester1!"},
            follow_redirects=False,
        )
        assert resp.status_code in (302, 303)
        assert "evil.attacker.com" not in resp.headers["Location"]
        assert "/dashboard" in resp.headers["Location"]

    def test_login_rejects_protocol_relative_redirect(self, client, tester_user):
        resp = client.post(
            "/auth/login?next=//evil.attacker.com",
            data={"username": "test_tester", "password": "TestTester1!"},
            follow_redirects=False,
        )
        assert resp.status_code in (302, 303)
        assert "evil.attacker.com" not in resp.headers["Location"]
        assert "/dashboard" in resp.headers["Location"]

    def test_login_honors_valid_relative_redirect(self, client, tester_user):
        resp = client.post(
            "/auth/login?next=/reports/",
            data={"username": "test_tester", "password": "TestTester1!"},
            follow_redirects=False,
        )
        assert resp.status_code in (302, 303)
        assert resp.headers["Location"].endswith("/reports/")


class TestLogoutFlow:
    """Logout endpoint behavior."""

    def test_logout_get_rejected(self, tester_client):
        resp = tester_client.get("/auth/logout")
        assert resp.status_code == 405

    def test_logout_post_success(self, tester_client):
        resp = tester_client.post("/auth/logout", follow_redirects=False)
        assert resp.status_code in (302, 303)
        assert "/auth/login" in resp.headers["Location"]

        audit = (
            AuditEvent.query.filter_by(action="logout")
            .order_by(AuditEvent.id.desc())
            .first()
        )
        assert audit is not None
