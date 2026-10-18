# Production Dockerfile for Interactive Cybersecurity Lab
FROM python:3.11-slim

# Prevent Python from writing .pyc files and buffer stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_ENV=production

# Install system dependencies needed for compiling and running
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . .

# Ensure instance directory for reports and temporary database exists
RUN mkdir -p instance/reports

# Run as non-privileged user for container security
RUN useradd -u 1001 -m labuser && chown -R labuser:labuser /app
USER labuser

EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:5000/health || exit 1

# Launch with Gunicorn WSGI server
CMD ["gunicorn", "app:create_app()", "--workers", "2", "--timeout", "120", "--bind", "0.0.0.0:5000"]
