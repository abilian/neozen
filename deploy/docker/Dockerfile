# NeoZen production image
#
# Multi-stage build:
#   1. builder — installs build deps and produces the wheel
#   2. runtime — minimal slim image with the wheel installed
#
# Usage:
#   docker build -t neozen:dev -f deploy/docker/Dockerfile .
#   docker run --rm -p 8000:8000 \
#     -e NEOZEN_SECRET_KEY=dev-secret-change-me \
#     -e NEOZEN_DATABASE_URL=sqlite+aiosqlite:///data/neozen.db \
#     neozen:dev

# ============================================================================
# Builder stage
# ============================================================================
FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build

# Install build prerequisites only
RUN pip install --no-cache-dir build

# Copy only the files needed to build a wheel
COPY pyproject.toml README.md ./
COPY src/ ./src/

# Build the wheel
RUN python -m build --wheel --outdir /wheels


# ============================================================================
# Runtime stage
# ============================================================================
FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="NeoZen" \
      org.opencontainers.image.description="Framework-agnostic Python auth toolkit and lightweight self-hosted IAM" \
      org.opencontainers.image.source="https://github.com/abilian/neozen" \
      org.opencontainers.image.licenses="Apache-2.0"

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    NEOZEN_BIND_HOST=0.0.0.0 \
    NEOZEN_BIND_PORT=8000

# Non-root user for the runtime
RUN useradd --create-home --uid 1000 --shell /bin/bash neozen

# Install the wheel built in the previous stage. The `[all]` extras
# pull every optional integration so the operator audience has a
# batteries-included image; for size-sensitive deployments, build a
# slimmer variant locally with a narrower extra set.
COPY --from=builder /wheels/*.whl /tmp/
RUN pip install --no-cache-dir "$(ls /tmp/*.whl)[all]" && rm -rf /tmp/*.whl

USER neozen
WORKDIR /home/neozen
RUN mkdir -p /home/neozen/data

EXPOSE 8000

# Healthcheck hits /healthz (liveness). Readiness is /readyz; orchestrators
# typically configure readiness separately, so we keep the HEALTHCHECK
# liveness-only.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/healthz').status==200 else 1)" \
      || exit 1

ENTRYPOINT ["neozen", "serve"]
