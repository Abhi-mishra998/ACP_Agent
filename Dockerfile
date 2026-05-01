# ─────────────────────────────────────────
# STAGE 1: Builder
# ─────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
RUN pip install --no-cache-dir --prefix=/install .

# ─────────────────────────────────────────
# STAGE 2: Final
# ─────────────────────────────────────────
FROM python:3.11-slim AS final

WORKDIR /app

# Staff Engineer Fix: Install curl for robust health checks
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -g 999 appuser && \
    useradd -r -u 999 -g appuser appuser && \
    chown -R appuser:appuser /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

COPY --chown=appuser:appuser services/ ./services/
COPY --chown=appuser:appuser sdk/ ./sdk/
COPY --chown=appuser:appuser seed_admin.py .

USER appuser
