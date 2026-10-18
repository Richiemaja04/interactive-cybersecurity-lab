#!/usr/bin/env bash
set -e

echo "==> Initializing database tables..."
python -c "from app import create_app; from app.extensions import db; app = create_app(); with app.app_context(): db.create_all()"

echo "==> Seeding test definitions..."
python scripts/seed_test_definitions.py

echo "==> Starting Gunicorn web server..."
exec gunicorn "app:create_app()" --workers 2 --timeout 120 --bind 0.0.0.0:$PORT
