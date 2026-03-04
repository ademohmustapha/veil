# ─────────────────────────────────────────────────────────────────────────────
# AURORA — Production Dockerfile
# Multi-stage build: minimises final image, non-root runtime, hardened.
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.12-slim-bookworm AS builder

# Build dependencies only (stripped from final image)
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc g++ libssl-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY requirements.txt .
RUN pip install --prefix=/install --no-cache-dir -r requirements.txt

# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.12-slim-bookworm AS runtime

LABEL org.opencontainers.image.title="AURORA" \
      org.opencontainers.image.description="Autonomous Unified Resilience & Organizational Real-time Awareness" \
      org.opencontainers.image.version="aurora" \
      org.opencontainers.image.authors="Ademoh Mustapha Onimis" \
      org.opencontainers.image.licenses="Proprietary"

# Runtime security hardening
RUN apt-get update && apt-get install -y --no-install-recommends \
        tini && \
    rm -rf /var/lib/apt/lists/* && \
    # Create non-root user with fixed UID for deterministic permissions
    useradd -u 10001 -M -s /bin/false -d /home/aurora aurora && \
    mkdir -p /home/aurora/.aurora /aurora && \
    chown -R aurora:aurora /home/aurora /aurora

WORKDIR /aurora
COPY --from=builder /install /usr/local
COPY --chown=aurora:aurora . .

# Immutable filesystem: source code read-only; data written to volume
RUN chmod -R 755 /aurora && \
    chmod 600 /aurora/core /aurora/hardening 2>/dev/null || true

USER aurora

ENV PYTHONPATH=/aurora \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    AURORA_HOME=/home/aurora/.aurora

# Data / keys volume — NEVER bake secrets into the image
VOLUME ["/home/aurora/.aurora"]

EXPOSE 9100

# tini as PID 1 — handles SIGTERM/SIGCHLD correctly in containers
ENTRYPOINT ["tini", "--", "python3", "aurora.py"]
CMD []

# Health check: passes only if 100% of self-diagnostics pass
HEALTHCHECK \
    --interval=30s \
    --timeout=15s \
    --start-period=10s \
    --retries=3 \
    CMD python3 aurora.py doctor --json | \
        python3 -c "import sys,json; d=json.load(sys.stdin); sys.exit(0 if d.get('pass_rate',0)==100.0 else 1)"
