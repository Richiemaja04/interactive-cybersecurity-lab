"""
app/__init__.py — Application factory.

Usage:
    from app import create_app
    app = create_app()          # uses FLASK_ENV env var
    app = create_app("testing") # explicit config
"""

from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler

from flask import Flask, jsonify

from app.config import get_config
from app.extensions import bcrypt, csrf, db, login_manager, migrate
from app.logging_config import SanitizingFilter


def create_app(config_name: str | None = None) -> Flask:
    """Application factory — returns a fully configured Flask app."""

    app = Flask(__name__, instance_relative_config=False)

    # ── 1. Load configuration ─────────────────────────────────────────────────
    config_class = get_config(config_name)
    app.config.from_object(config_class)

    # Allow dynamic environment variables to override database URI at runtime
    if app.config.get("TESTING") and os.environ.get("TEST_DATABASE_URL"):
        test_url = os.environ["TEST_DATABASE_URL"]
        app.config["SQLALCHEMY_DATABASE_URI"] = (
            test_url.replace("postgresql://", "postgresql+psycopg2://", 1)
            if test_url.startswith("postgresql://")
            else test_url
        )
    elif os.environ.get("DATABASE_URL") and not app.config.get("TESTING"):
        db_url = os.environ["DATABASE_URL"]
        if db_url.startswith("postgres://"):
            db_url = db_url.replace("postgres://", "postgresql+psycopg2://", 1)
        elif db_url.startswith("postgresql://") and "+psycopg2" not in db_url:
            db_url = db_url.replace("postgresql://", "postgresql+psycopg2://", 1)
        app.config["SQLALCHEMY_DATABASE_URI"] = db_url

    # Validate production config on startup
    if config_name == "production" or os.environ.get("FLASK_ENV") == "production":
        if hasattr(config_class, "validate"):
            config_class.validate()

    # ── 2. Ensure instance folder exists ──────────────────────────────────────
    os.makedirs(app.instance_path, exist_ok=True)
    os.makedirs(app.config["REPORT_OUTPUT_DIR"], exist_ok=True)

    # ── 3. Configure logging ──────────────────────────────────────────────────
    _configure_logging(app)

    # ── 4. Initialize extensions ──────────────────────────────────────────────
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    csrf.init_app(app)
    bcrypt.init_app(app)

    # ── 5. Import models (so Alembic can detect them) ─────────────────────────
    with app.app_context():
        from app.models import (  # noqa: F401
            audit,
            evidence,
            execution,
            finding,
            preset,
            remediation,
            report,
            rehearsal,
            retention,
            scenario,
            user,
        )

    # ── 6. Register blueprints ────────────────────────────────────────────────
    _register_blueprints(app)

    # ── 7. Register error handlers ────────────────────────────────────────────
    _register_error_handlers(app)

    # ── 8. Health check endpoint ──────────────────────────────────────────────
    @app.route("/health")
    def health():  # type: ignore[return]
        """
        Public health endpoint — returns DB availability.
        Used by Render health checks and readiness gate.
        """
        db_ok = _check_db()
        status = "ok" if db_ok else "degraded"
        code = 200 if db_ok else 503
        return jsonify({"status": status, "db": db_ok}), code

    app.logger.info("Interactive Cybersecurity Lab started (env=%s)", config_name or os.environ.get("FLASK_ENV", "development"))
    return app


# ── Private helpers ────────────────────────────────────────────────────────────

def _configure_logging(app: Flask) -> None:
    """Set up structured, sanitized application logging."""
    sanitizer = SanitizingFilter()

    formatter = logging.Formatter(
        "[%(asctime)s] %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console handler
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    handler.addFilter(sanitizer)

    level = getattr(logging, app.config.get("LOG_LEVEL", "INFO").upper(), logging.INFO)
    app.logger.setLevel(level)
    app.logger.addHandler(handler)

    # Rotating file handler (write to instance/ directory)
    log_path = os.path.join(app.instance_path, "app.log")
    try:
        file_handler = RotatingFileHandler(log_path, maxBytes=5_000_000, backupCount=3)
        file_handler.setFormatter(formatter)
        file_handler.addFilter(sanitizer)
        app.logger.addHandler(file_handler)
    except OSError:
        app.logger.warning("Could not create log file at %s", log_path)


def _register_blueprints(app: Flask) -> None:
    """Register all application blueprints."""
    from app.auth.routes import auth_bp
    from app.dashboard.routes import dashboard_bp
    from app.admin.routes import admin_bp
    from app.reports.routes import reports_bp
    from app.audit.routes import audit_bp
    from app.presets.routes import presets_bp
    from app.presentation_sequences.routes import sequences_bp
    from app.rehearsal.routes import rehearsal_bp
    from app.remediation.routes import remediation_bp
    from app.incident_response.routes import ir_bp
    from app.external_targets.routes import external_bp
    from app.retention.routes import retention_bp
    from app.readiness.routes import readiness_bp

    # Test module blueprints
    from app.tests.robots_txt.routes import robots_bp
    from app.tests.idor.routes import idor_bp
    from app.tests.forced_browsing.routes import forced_browsing_bp
    from app.tests.cookies.routes import cookies_bp
    from app.tests.https_certificate.routes import https_bp
    from app.tests.input_validation.routes import input_validation_bp
    from app.tests.source_inspection.routes import source_bp
    from app.tests.network_api.routes import network_bp
    from app.tests.weak_credentials.routes import weak_creds_bp
    from app.tests.error_analysis.routes import error_bp

    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(dashboard_bp, url_prefix="/dashboard")
    app.register_blueprint(admin_bp, url_prefix="/admin")
    app.register_blueprint(reports_bp, url_prefix="/reports")
    app.register_blueprint(audit_bp, url_prefix="/audit")
    app.register_blueprint(presets_bp, url_prefix="/presets")
    app.register_blueprint(sequences_bp, url_prefix="/sequences")
    app.register_blueprint(rehearsal_bp, url_prefix="/rehearsal")
    app.register_blueprint(remediation_bp, url_prefix="/remediation")
    app.register_blueprint(ir_bp, url_prefix="/incident-response")
    app.register_blueprint(external_bp, url_prefix="/external-targets")
    app.register_blueprint(retention_bp, url_prefix="/retention")
    app.register_blueprint(readiness_bp, url_prefix="/readiness")

    # Tests under /tests/<slug>/
    app.register_blueprint(robots_bp, url_prefix="/tests/robots-txt")
    app.register_blueprint(idor_bp, url_prefix="/tests/idor")
    app.register_blueprint(forced_browsing_bp, url_prefix="/tests/forced-browsing")
    app.register_blueprint(cookies_bp, url_prefix="/tests/cookies")
    app.register_blueprint(https_bp, url_prefix="/tests/https-certificate")
    app.register_blueprint(input_validation_bp, url_prefix="/tests/input-validation")
    app.register_blueprint(source_bp, url_prefix="/tests/source-inspection")
    app.register_blueprint(network_bp, url_prefix="/tests/network-api")
    app.register_blueprint(weak_creds_bp, url_prefix="/tests/weak-credentials")
    app.register_blueprint(error_bp, url_prefix="/tests/error-analysis")

    # Public landing page
    from app.dashboard.routes import landing_bp
    app.register_blueprint(landing_bp)


def _register_error_handlers(app: Flask) -> None:
    """Register sanitized error handlers — never leak internals."""

    @app.errorhandler(400)
    def bad_request(e):
        return jsonify({"error": "Bad request"}), 400

    @app.errorhandler(401)
    def unauthorized(e):
        return jsonify({"error": "Authentication required"}), 401

    @app.errorhandler(403)
    def forbidden(e):
        return jsonify({"error": "Access denied"}), 403

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Resource not found"}), 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        return jsonify({"error": "Method not allowed"}), 405

    @app.errorhandler(500)
    def internal_error(e):
        # Log internally but never expose details to client
        app.logger.error("Internal server error: %s", e, exc_info=True)
        return jsonify({"error": "An internal error occurred"}), 500


def _check_db() -> bool:
    """Return True if the database is reachable; False otherwise."""
    try:
        from sqlalchemy import text
        db.session.execute(text("SELECT 1"))
        return True
    except Exception:
        return False
