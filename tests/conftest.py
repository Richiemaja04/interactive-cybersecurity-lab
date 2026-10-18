"""
tests/conftest.py — Shared pytest fixtures for all test types.

Uses TestingConfig which requires TEST_DATABASE_URL environment variable.
PostgreSQL in staging/production/CI; local file-based SQLite fallback when
PostgreSQL server is not reachable locally.
"""

from __future__ import annotations

import os
import socket

import pytest

# Configure test environment before importing app
os.environ.setdefault("SECRET_KEY", "testing-secret-key-not-for-production")
if "TEST_DATABASE_URL" not in os.environ:
    postgres_up = False
    try:
        with socket.create_connection(("localhost", 5432), timeout=0.2):
            postgres_up = True
    except OSError:
        postgres_up = False

    if postgres_up:
        os.environ["TEST_DATABASE_URL"] = "postgresql://postgres:postgres@localhost:5432/cybersec_lab_test"
    else:
        # File-based SQLite ensures all client connections share the same test DB
        os.makedirs("instance", exist_ok=True)
        abs_db_path = os.path.abspath("instance/test.db").replace("\\", "/")
        os.environ["TEST_DATABASE_URL"] = f"sqlite:///{abs_db_path}"

from app import create_app
from app.extensions import db as _db


@pytest.fixture(scope="session")
def app():
    """Create application using TestingConfig for the test session."""
    application = create_app("testing")
    yield application


@pytest.fixture(scope="session")
def db(app):
    """Create all tables once per test session; drop after."""
    with app.app_context():
        _db.create_all()
        yield _db
        _db.drop_all()


@pytest.fixture(scope="function")
def db_session(db, app):
    """
    Provide a clean DB session per test.
    Rolls back and cleans tables after each test to keep tests isolated.
    """
    with app.app_context():
        _db.session.expire_on_commit = False
        yield _db.session
        _db.session.rollback()
        # Clean all table rows between tests
        for table in reversed(_db.metadata.sorted_tables):
            _db.session.execute(table.delete())
        _db.session.commit()
        _db.session.remove()


@pytest.fixture(scope="function")
def client(app, db):
    """Flask test client."""
    with app.test_client() as c:
        yield c


@pytest.fixture(scope="function")
def admin_user(db_session, app):
    """Create a test Administrator account."""
    from app.extensions import bcrypt
    from app.models.user import RoleEnum, User

    user = User(
        username="test_admin",
        email="admin@test.local",
        password_hash=bcrypt.generate_password_hash("TestAdmin1!").decode(),
        role=RoleEnum.ADMINISTRATOR,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture(scope="function")
def tester_user(db_session, app):
    """Create a test Tester account."""
    from app.extensions import bcrypt
    from app.models.user import RoleEnum, User

    user = User(
        username="test_tester",
        email="tester@test.local",
        password_hash=bcrypt.generate_password_hash("TestTester1!").decode(),
        role=RoleEnum.TESTER,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture(scope="function")
def tester_client(client, tester_user, app):
    """Test client authenticated as a Tester."""
    user_id = str(tester_user.id)
    with client.session_transaction() as sess:
        sess["_user_id"] = user_id
        sess["_fresh"] = True
    return client


@pytest.fixture(scope="function")
def admin_client(client, admin_user, app):
    """Test client authenticated as an Administrator."""
    user_id = str(admin_user.id)
    with client.session_transaction() as sess:
        sess["_user_id"] = user_id
        sess["_fresh"] = True
    return client
