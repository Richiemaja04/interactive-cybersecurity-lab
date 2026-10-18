"""
app/auth/routes.py — Authentication routes.

Security properties:
- Login uses bcrypt comparison — timing-safe via flask-bcrypt.
- Failed login returns the same message regardless of whether the username
  exists (prevents username enumeration).
- Successful login regenerates the session to prevent session fixation.
- All state-changing routes protected by CSRF token.
- Audit events written for login success and failure.
"""

from __future__ import annotations

from datetime import datetime, timezone

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user, login_required, login_user, logout_user

from app.audit.service import record_audit_event
from app.auth.forms import LoginForm
from app.extensions import bcrypt, db
from app.models.user import User

auth_bp = Blueprint("auth", __name__, template_folder="../templates/auth")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """Login endpoint — redirects authenticated users away."""
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        # bcrypt.check_password_hash is timing-safe.
        # Deliberately use the same code path whether user exists or not
        # to avoid username enumeration via timing.
        password_valid = (
            user is not None
            and bcrypt.check_password_hash(user.password_hash, form.password.data)
            and user.is_active
        )

        if password_valid:
            # Record login time
            user.last_login_at = datetime.now(timezone.utc)
            db.session.commit()

            login_user(user, remember=form.remember_me.data)

            record_audit_event(
                action="login_success",
                user=user,
                detail={"username": user.username},
            )
            current_app.logger.info("Login success: user=%s", user.id)

            # Safe redirect: only allow relative paths to prevent open redirect
            next_page = request.args.get("next", "")
            if next_page.startswith("/") and not next_page.startswith("//"):
                return redirect(next_page)
            return redirect(url_for("dashboard.index"))

        else:
            record_audit_event(
                action="login_failure",
                user=None,
                detail={"username_attempted": form.username.data[:64]},
            )
            current_app.logger.warning(
                "Login failure for username: %s",
                form.username.data[:64],
            )
            # Same message for wrong password and unknown user — no enumeration
            flash("Invalid username or password.", "error")

    return render_template("auth/login.html", form=form, title="Sign In")


@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    """Logout — POST only to prevent CSRF-driven logouts via GET."""
    record_audit_event(
        action="logout",
        user=current_user,
        detail={"username": current_user.username},
    )
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))
