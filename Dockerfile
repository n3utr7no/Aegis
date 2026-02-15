# ── Stage 1: Builder ──────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc g++ && \
    rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml requirements.txt ./
COPY aegis/ ./aegis/

# Install the package with all optional dependencies (except dev)
RUN pip install --no-cache-dir --prefix=/install \
    -e ".[ocr,guardrail-groq]" \
    python-dotenv>=1.0 \
    spacy>=3.7

# Download the spaCy English model
RUN /install/bin/python -m spacy download en_core_web_sm 2>/dev/null || true


# ── Stage 2: Runtime ──────────────────────────────────────
FROM python:3.11-slim

LABEL maintainer="n3utr7no"
LABEL description="Aegis — Self-Evolving Security Sidecar for LLM Applications"

WORKDIR /app

# Install runtime system dependencies
#   - tesseract-ocr: for Lens OCR scanning
#   - libgl1: sometimes needed by Pillow
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        tesseract-ocr \
        tesseract-ocr-eng && \
    rm -rf /var/lib/apt/lists/*

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY aegis/ ./aegis/
COPY pyproject.toml requirements.txt ./

# Re-install in editable mode (links the package)
RUN pip install --no-cache-dir -e "."

# Copy remaining project files
COPY .env.example ./
COPY playground/ ./playground/

# Default environment (can be overridden at runtime)
ENV AEGIS_HOST=0.0.0.0
ENV AEGIS_PORT=8080
ENV AEGIS_LOG_LEVEL=INFO
ENV AEGIS_GUARDRAIL_BACKEND=groq

EXPOSE 8080

# Health check — hit the proxy root
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/')" || exit 1

# Run the proxy
CMD ["python", "-m", "aegis"]
