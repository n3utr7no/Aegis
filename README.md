<p align="center">
  <h1 align="center">🛡️ Aegis</h1>
  <p align="center"><strong>The Self-Evolving Security Sidecar for LLM Applications</strong></p>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.11+-blue?style=flat-square&logo=python&logoColor=white" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/version-0.1.0-green?style=flat-square" alt="Version 0.1.0">
  <img src="https://img.shields.io/badge/license-MIT-orange?style=flat-square" alt="License MIT">
</p>

---

Aegis is a **transparent security proxy** that sits between your application and any LLM provider. It intercepts API calls to automatically **detect and swap PII**, **inject canary tokens**, **classify prompt injections & jailbreaks**, and **moderate LLM outputs** — all without changing a single line in your application code.

## ✨ Features

| Module | What It Does |
|--------|--------------|
| **Shield** | PII detection & semantic swapping, canary token injection/detection, structural isolation tagging, prompt-injection & jailbreak classification (Groq / ONNX / HuggingFace), output moderation |
| **Lens** | OCR-based text extraction from images, Unicode homoglyph & confusable normalization, obfuscated code flattening |
| **Forge** | Automated red-team attack generation, response judging, iterative prompt optimization |
| **Oracle** | Scheduled vulnerability scanning, security briefing reports |
| **Proxy** | Async reverse-proxy (aiohttp), middleware pipeline, OpenAI-compatible API routing |

## 📋 Minimum Requirements

| Requirement | Version |
|-------------|---------|
| **Python** | `>= 3.11` |
| **OS** | Windows, macOS, or Linux |
| **RAM** | 2 GB minimum (8 GB+ recommended if using local guardrail models) |
| **Disk** | ~500 MB for core + venv (3 GB+ if downloading guardrail models locally) |

### Optional System Dependencies

| Dependency | Required For |
|------------|-------------|
| [Tesseract OCR](https://github.com/tesseract-ocr/tesseract) | `aegis.lens` OCR scanning (`enable_ocr = true`) |
| CUDA-capable GPU | Accelerated guardrail inference with PyTorch (not required — CPU works) |

## 🚀 Quick Start

### 1. Clone & Create Virtual Environment

```bash
git clone https://github.com/n3utr7no/Aegis.git
cd Aegis
python -m venv .venv
```

Activate the virtual environment:

```bash
# Windows
.venv\Scripts\activate

# macOS / Linux
source .venv/bin/activate
```

### 2. Install Dependencies

```bash
# Core dependencies
pip install -e .

# With OCR support
pip install -e ".[ocr]"

# With guardrail (HuggingFace / PyTorch)
pip install -e ".[guardrail]"

# With guardrail (ONNX — lighter, faster on CPU)
pip install -e ".[guardrail-onnx]"

# With Groq-powered guardrail (cloud-based, no local model needed)
pip install -e ".[guardrail-groq]"

# Development & testing
pip install -e ".[dev]"
```

### 3. Configure Environment

```bash
cp .env.example .env
```

Edit `.env` and fill in your values:

```ini
# Required
AEGIS_UPSTREAM_URL=https://api.openai.com   # or any OpenAI-compatible endpoint
AEGIS_VAULT_KEY=                             # generate with command below

# Generate an encryption key for the PII vault
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

See [`.env.example`](.env.example) for all available configuration options.

### 4. Start the Proxy

```bash
python -m aegis --host 127.0.0.1 --port 8080
```

Or use the defaults from your `.env`:

```bash
python -m aegis
```

### 5. Point Your App at Aegis

Replace your LLM provider's base URL with `http://127.0.0.1:8080` in your application — that's it. Aegis proxies requests transparently.

## 🐳 Docker

The quickest way to run Aegis without installing anything locally.

### Using Docker Compose (recommended)

```bash
# 1. Copy and configure your environment
cp .env.example .env   # then edit .env with your keys

# 2. Build and start
docker compose up -d

# 3. Check health
docker compose ps
```

### Using Docker Directly

```bash
# Build the image
docker build -t aegis .

# Run the container
docker run -d \
  --name aegis-proxy \
  -p 8080:8080 \
  --env-file .env \
  -e AEGIS_HOST=0.0.0.0 \
  --restart unless-stopped \
  aegis
```

### Key Notes

- The `.env` file is **not** baked into the image (for security); it is loaded at runtime via `--env-file` or `env_file` in Compose.
- The default exposed port is **8080** — override with `AEGIS_PORT` in `.env`.
- A built-in **health check** pings `http://localhost:8080/` every 30 seconds.
- Tesseract OCR is pre-installed in the image for Lens OCR scanning.

## 🏗️ Architecture

```
Your App ──► Aegis Proxy (port 8080) ──► LLM Provider
                  │
                  ├── Shield (ingress/egress pipeline)
                  │     ├── PII Detector + Semantic Swapper
                  │     ├── Structural Tagger
                  │     ├── Canary Injector / Detector
                  │     ├── Guardrail Classifier
                  │     └── Output Moderator
                  │
                  ├── Lens (content analysis)
                  │     ├── OCR Scanner
                  │     ├── Unicode Normalizer
                  │     └── Code Flattener
                  │
                  ├── Forge (red-team engine)
                  │     ├── Red-Hat Attack Generator
                  │     ├── Response Judge
                  │     └── Prompt Optimizer
                  │
                  └── Oracle (scheduled ops)
                        ├── Vulnerability Scanner
                        ├── Scheduler
                        └── Security Briefer
```

## 📁 Project Structure

```
aegis/
├── aegis/
│   ├── main.py              # CLI entry point
│   ├── config.py             # Centralized configuration (env vars)
│   ├── proxy/                # Async reverse-proxy server
│   │   ├── server.py         # aiohttp server setup
│   │   ├── routes.py         # API route handlers
│   │   ├── middleware.py      # Request/response middleware
│   │   └── models.py         # Pydantic request/response models
│   ├── shield/               # Core security pipeline
│   │   ├── pipeline.py       # Ingress/egress orchestrator
│   │   ├── pii/              # PII detection, swapping, vault
│   │   ├── canary/           # Canary token generation & detection
│   │   ├── guardrail/        # Prompt injection/jailbreak classifier
│   │   └── tagger/           # Structural isolation tags
│   ├── lens/                 # Content analysis tools
│   │   ├── ocr_scanner.py    # Image-to-text via Tesseract
│   │   ├── unicode_normalizer.py  # Homoglyph & confusable detection
│   │   └── code_flattener.py     # Obfuscated code normalization
│   ├── forge/                # Red-team testing engine
│   │   ├── red_hat.py        # Attack generation
│   │   ├── judge.py          # Response evaluation
│   │   ├── optimizer.py      # Iterative prompt refinement
│   │   └── runner.py         # Forge execution orchestrator
│   ├── oracle/               # Scheduled security operations
│   │   ├── scanner.py        # Vulnerability scanner
│   │   ├── scheduler.py      # Periodic task scheduler
│   │   ├── briefer.py        # Security report generator
│   │   └── templates.py      # Report templates
│   └── utils/                # Shared utilities
│       ├── crypto.py         # Encryption helpers
│       ├── logging.py        # Structured logging
│       └── text.py           # Text processing utilities
├── tests/                    # Comprehensive test suite (322+ tests)
├── playground/               # Demo scripts & dashboard
│   ├── dashboard.html        # Security monitoring dashboard
│   ├── run_e2e.py            # End-to-end test runner
│   └── start_server.py       # Quick server launcher
├── pyproject.toml            # Build config & dependency specification
├── requirements.txt          # Pinned core dependencies
└── .env.example              # Environment variable template
```

## 🧪 Running Tests

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run the full test suite
pytest

# Run with coverage
pytest --cov=aegis

# Run a specific module's tests
pytest tests/test_shield/
```

## ⚙️ Configuration Reference

All configuration is via environment variables (or `.env` file). Key settings:

| Variable | Default | Description |
|----------|---------|-------------|
| `AEGIS_HOST` | `127.0.0.1` | Proxy bind address |
| `AEGIS_PORT` | `8080` | Proxy bind port |
| `AEGIS_UPSTREAM_URL` | `https://api.groq.com/openai/v1` | Target LLM API base URL |
| `AEGIS_VAULT_KEY` | — | Fernet key for PII vault encryption |
| `AEGIS_LOG_LEVEL` | `INFO` | Logging verbosity (`DEBUG`, `INFO`, `WARN`, `ERROR`) |
| `AEGIS_GUARDRAIL_BACKEND` | `auto` | Guardrail backend: `auto`, `groq`, `onnx`, `huggingface` |
| `AEGIS_GUARDRAIL_MODEL` | `meta-llama/Prompt-Guard-86M` | HuggingFace model for guardrail |
| `AEGIS_INJECTION_THRESHOLD` | `0.90` | Score threshold for prompt-injection detection |
| `AEGIS_JAILBREAK_THRESHOLD` | `0.85` | Score threshold for jailbreak detection |
| `AEGIS_ENABLE_OCR` | `false` | Enable Lens OCR scanning |
| `AEGIS_ENABLE_FORGE` | `false` | Enable Forge red-team engine |
| `AEGIS_ENABLE_ORACLE` | `false` | Enable Oracle scheduled scanning |

## 📄 License

MIT
