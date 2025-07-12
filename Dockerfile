# Multi-stage build for production-ready container
FROM python:3.11-slim as builder

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies for building
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create and activate virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Production stage
FROM python:3.11-slim as production

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

# Install runtime system dependencies
RUN apt-get update && apt-get install -y \
    libpq5 \
    opensc \
    opensc-pkcs11 \
    softhsm2 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy virtual environment from builder stage
COPY --from=builder /opt/venv /opt/venv

# Create non-root user
RUN groupadd -r hsm && useradd -r -g hsm -d /app -s /bin/bash hsm

# Create app directory and set ownership
RUN mkdir -p /app /var/log/hsm_edwards_api && \
    chown -R hsm:hsm /app /var/log/hsm_edwards_api

# Set working directory
WORKDIR /app

# Copy application code
COPY --chown=hsm:hsm . .

# Create SoftHSM configuration directory
RUN mkdir -p /app/softhsm2 && \
    chown -R hsm:hsm /app/softhsm2

# Switch to non-root user
USER hsm

# Create SoftHSM token for development/testing
RUN echo "directories.tokendir = /app/softhsm2/tokens" > /app/softhsm2.conf && \
    echo "objectstore.backend = file" >> /app/softhsm2.conf && \
    echo "log.level = INFO" >> /app/softhsm2.conf && \
    export SOFTHSM2_CONF=/app/softhsm2.conf && \
    softhsm2-util --init-token --slot 0 --label "HSM_TOKEN" --pin 1234 --so-pin 1234 || true

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health/liveness || exit 1

# Set environment variables for SoftHSM
ENV SOFTHSM2_CONF=/app/softhsm2.conf \
    HSM_LIBRARY_PATH=/usr/lib/softhsm/libsofthsm2.so \
    HSM_SLOT_ID=0 \
    HSM_PIN=1234

# Command to run the application
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]