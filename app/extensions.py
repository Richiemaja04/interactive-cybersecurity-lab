"""
app/extensions.py — Flask extension instances.

Initialized here without an app; bound to the app in create_app().
Import from here in blueprints to avoid circular imports.
"""

from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect

# ── Core extensions ───────────────────────────────────────────────────────────
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
csrf = CSRFProtect()
bcrypt = Bcrypt()

# ── Login manager config ──────────────────────────────────────────────────────
login_manager.login_view = "auth.login"
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "warning"
# Refresh the session on every request so the lifetime resets on activity
login_manager.refresh_view = "auth.login"
login_manager.needs_refresh_message = "Session expired. Please log in again."
login_manager.needs_refresh_message_category = "warning"
