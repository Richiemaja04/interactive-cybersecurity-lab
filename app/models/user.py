"""
app/models/user.py — User and role models.

Security notes:
- Passwords are NEVER stored in plaintext. Only bcrypt hashes are persisted.
- The role field is server-side only — never trust client-supplied role values.
- No public registration: accounts created only via scripts/provision_accounts.py.
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone

from flask_login import UserMixin

from app.extensions import db, login_manager


class RoleEnum(str, enum.Enum):
    GUEST = "guest"
    TESTER = "tester"
    ADMINISTRATOR = "administrator"


class User(UserMixin, db.Model):
    """Platform user with role-based access control."""

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(
        db.Enum(RoleEnum, name="role_enum"),
        nullable=False,
        default=RoleEnum.TESTER,
        index=True,
    )
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    last_login_at = db.Column(db.DateTime(timezone=True), nullable=True)

    # ── Relationships ──────────────────────────────────────────────────────────
    execution_runs = db.relationship(
        "ExecutionRun", back_populates="user", lazy="dynamic", cascade="save-update"
    )
    annotations = db.relationship(
        "FindingAnnotation", back_populates="user", lazy="dynamic", cascade="all, delete-orphan"
    )
    remediation_actions = db.relationship(
        "RemediationAction", back_populates="user", lazy="dynamic"
    )
    audit_events = db.relationship("AuditEvent", back_populates="user", lazy="dynamic")
    rehearsal_sessions = db.relationship(
        "RehearsalSession", back_populates="user", lazy="dynamic"
    )
    report_exports = db.relationship("ReportExport", back_populates="user", lazy="dynamic")

    def __repr__(self) -> str:
        return f"<User {self.username!r} role={self.role.value}>"

    # ── Role helpers (server-side) ─────────────────────────────────────────────
    @property
    def is_administrator(self) -> bool:
        return self.role == RoleEnum.ADMINISTRATOR

    @property
    def is_tester(self) -> bool:
        return self.role in (RoleEnum.TESTER, RoleEnum.ADMINISTRATOR)

    def has_role(self, role: RoleEnum) -> bool:
        """Check minimum role. Admin satisfies any role requirement."""
        if self.role == RoleEnum.ADMINISTRATOR:
            return True
        if role == RoleEnum.TESTER:
            return self.role == RoleEnum.TESTER
        return self.role == role

    # ── Flask-Login interface ──────────────────────────────────────────────────
    def get_id(self) -> str:
        return str(self.id)


@login_manager.user_loader
def load_user(user_id: str) -> User | None:
    """Load user by ID for Flask-Login session management."""
    try:
        return db.session.get(User, int(user_id))
    except (ValueError, TypeError):
        return None
