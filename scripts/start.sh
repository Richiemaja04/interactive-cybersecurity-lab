#!/usr/bin/env bash
set -e

echo "==> Interactive Cybersecurity Lab: Starting up..."

# Wait for database to accept connections and initialize tables
python - << 'EOF'
import time
import sys

for attempt in range(1, 31):
    try:
        from app import create_app
        from app.extensions import db
        app = create_app()
        with app.app_context():
            db.create_all()
        print(f"==> Database connected and tables verified on attempt {attempt}.")
        sys.exit(0)
    except Exception as exc:
        print(f"==> Waiting for database (attempt {attempt}/30): {exc}")
        time.sleep(2)

print("==> Database connection failed after 60s timeout.", file=sys.stderr)
sys.exit(1)
EOF

echo "==> Seeding test definitions..."
python scripts/seed_test_definitions.py || true

echo "==> Starting Gunicorn on port ${PORT:-5000}..."
exec gunicorn "app:create_app()" --workers 2 --timeout 120 --bind 0.0.0.0:${PORT:-5000}
