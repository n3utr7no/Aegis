"""
Aegis configuration module.

Loads configuration from environment variables with sensible defaults.
Single source of truth for all configurable values.
"""

import os
from dataclasses import dataclass, field

from dotenv import load_dotenv

# Auto-load .env from project root (no-op if already loaded or missing)
load_dotenv()


@dataclass
class AegisConfig:
    """Central configuration for the Aegis sidecar."""

    # ── Proxy ──────────────────────────────────────────────
    host: str = "127.0.0.1"
    port: int = 8080
    upstream_url: str = "https://api.groq.com/openai/v1"
    upstream_api_key: str = ""              # Auth key for upstream LLM

    # ── Vault ──────────────────────────────────────────────
    vault_key: str = ""
    vault_db_path: str = "aegis_vault.db"

    # ── Logging ────────────────────────────────────────────
    log_level: str = "INFO"

    # ── Canary ─────────────────────────────────────────────
    canary_prefix: str = "AEGIS-CANARY"

    # ── Guardrail ──────────────────────────────────────────
    guardrail_backend: str = "auto"       # auto | groq | onnx | huggingface
    guardrail_model: str = "meta-llama/Prompt-Guard-86M"
    guardrail_groq_key: str = ""          # Falls back to GROQ_API_KEY
    guardrail_hf_token: str = ""          # Falls back to HUGGINGFACEHUB_API_TOKEN
    injection_threshold: float = 0.90
    jailbreak_threshold: float = 0.85

    # ── Feature flags ─────────────────────────────────────
    enable_ocr: bool = False
    enable_forge: bool = False
    enable_oracle: bool = False

    @classmethod
    def from_env(cls) -> "AegisConfig":
        """Load configuration from environment variables.

        Environment variables are prefixed with AEGIS_ and uppercased.
        Example: AEGIS_PORT=9090 sets port=9090.
        """
        return cls(
            host=os.getenv("AEGIS_HOST", cls.host),
            port=int(os.getenv("AEGIS_PORT", str(cls.port))),
            upstream_url=os.getenv("AEGIS_UPSTREAM_URL", cls.upstream_url),
            upstream_api_key=(
                os.getenv("AEGIS_UPSTREAM_API_KEY")
                or os.getenv("GROQ_API_KEY")
                or os.getenv("API_KEY", "")
            ),
            vault_key=os.getenv("AEGIS_VAULT_KEY", cls.vault_key),
            vault_db_path=os.getenv("AEGIS_VAULT_DB_PATH", cls.vault_db_path),
            log_level=os.getenv("AEGIS_LOG_LEVEL", cls.log_level),
            canary_prefix=os.getenv("AEGIS_CANARY_PREFIX", cls.canary_prefix),
            # Guardrail — backend, model, keys, thresholds
            guardrail_backend=os.getenv(
                "AEGIS_GUARDRAIL_BACKEND", cls.guardrail_backend,
            ),
            guardrail_model=os.getenv(
                "AEGIS_GUARDRAIL_MODEL", cls.guardrail_model,
            ),
            guardrail_groq_key=(
                os.getenv("AEGIS_GUARDRAIL_GROQ_KEY")
                or os.getenv("GROQ_API_KEY", "")
            ),
            guardrail_hf_token=(
                os.getenv("AEGIS_GUARDRAIL_HF_TOKEN")
                or os.getenv("HUGGINGFACEHUB_API_TOKEN", "")
            ),
            injection_threshold=float(os.getenv(
                "AEGIS_INJECTION_THRESHOLD",
                str(cls.injection_threshold),
            )),
            jailbreak_threshold=float(os.getenv(
                "AEGIS_JAILBREAK_THRESHOLD",
                str(cls.jailbreak_threshold),
            )),
            enable_ocr=os.getenv("AEGIS_ENABLE_OCR", "false").lower() == "true",
            enable_forge=os.getenv("AEGIS_ENABLE_FORGE", "false").lower() == "true",
            enable_oracle=os.getenv("AEGIS_ENABLE_ORACLE", "false").lower() == "true",
        )


# Global config instance — initialized lazily
_config: AegisConfig | None = None


def get_config() -> AegisConfig:
    """Return the global config, creating it from env vars on first call."""
    global _config
    if _config is None:
        _config = AegisConfig.from_env()
    return _config


def reset_config() -> None:
    """Reset the global config (useful for testing)."""
    global _config
    _config = None
