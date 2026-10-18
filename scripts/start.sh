#!/usr/bin/env bash
set -e

echo "==> Interactive Cybersecurity Lab: Booting service..."

python scripts/init_db.py

echo "==> Seeding test definitions..."
python scripts/seed_test_definitions.py || true

echo "==> Starting Gunicorn on port ${PORT:-5000}..."
exec gunicorn "app:create_app()" --workers 2 --timeout 120 --bind 0.0.0.0:${PORT:-5000}
