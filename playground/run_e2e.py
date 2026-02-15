"""
Aegis E2E Test Runner — Automated integration tests against live Groq API.

Starts a local Aegis proxy (in-process via TestClient) and fires a battery
of attack vectors through the full pipeline. Rate-limited to 1 request
per 10 seconds to respect API quotas.

Usage:
    python playground/run_e2e.py
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from pathlib import Path

# Ensure project root is on sys.path
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

# Load .env
from dotenv import load_dotenv
load_dotenv(project_root / ".env")

import httpx

from aegis.config import get_config, reset_config
from aegis.proxy.server import create_app

# ── Config ────────────────────────────────────────────────────────────────

RATE_LIMIT_SECONDS = 10  # Minimum seconds between API requests
ATTACKS_FILE = Path(__file__).parent / "attacks.json"
UPSTREAM_MODEL = "llama-3.1-8b-instant"  # Groq model for test requests


# ── Colorized output ─────────────────────────────────────────────────────

class Colors:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


def print_banner():
    print(f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════╗
║            ⚔️  AEGIS E2E TEST RUNNER                         ║
║            Testing against live Groq LLM                     ║
║            Rate limit: {RATE_LIMIT_SECONDS}s between requests                  ║
╚══════════════════════════════════════════════════════════════╝
{Colors.RESET}""")


def print_category(name: str, count: int):
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'═' * 60}")
    print(f"  📂 {name.upper()} ({count} tests)")
    print(f"{'═' * 60}{Colors.RESET}\n")


def print_test_result(
    name: str,
    passed: bool,
    verdict: str,
    expected: str,
    details: dict,
    duration: float,
):
    status = f"{Colors.GREEN}✅ PASS" if passed else f"{Colors.RED}❌ FAIL"
    print(f"  {status}{Colors.RESET}  {Colors.BOLD}{name}{Colors.RESET}")
    print(f"       Verdict: {verdict} (expected: {expected})")
    print(f"       Guardrail: {details.get('label', 'n/a')} "
          f"(score: {details.get('score', 0):.3f})")
    if details.get('pii_swapped', 0) > 0:
        print(f"       PII swapped: {details['pii_swapped']}")
    if details.get('lens_invisible', 0) > 0:
        print(f"       Lens invisible chars: {details['lens_invisible']}")
    if details.get('moderation_flagged'):
        print(f"       Output moderation: FLAGGED "
              f"(score={details.get('moderation_score', 0)})")
    print(f"       Duration: {duration:.1f}s")
    print()


def print_summary(total: int, passed: int, failed: int, duration: float):
    color = Colors.GREEN if failed == 0 else Colors.RED
    print(f"\n{Colors.BOLD}{'═' * 60}")
    print(f"  RESULTS: {color}{passed} passed{Colors.RESET}{Colors.BOLD}, "
          f"{Colors.RED if failed > 0 else Colors.DIM}{failed} failed"
          f"{Colors.RESET}{Colors.BOLD} "
          f"({total} total in {duration:.0f}s)")
    print(f"{'═' * 60}{Colors.RESET}\n")


# ── Test runner ───────────────────────────────────────────────────────────


async def run_single_test(
    client: httpx.AsyncClient,
    attack: dict,
    model: str,
) -> tuple[bool, str, dict, float]:
    """Run a single test and return (passed, verdict, details, duration)."""
    start = time.time()

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": attack["prompt"]},
        ],
        "temperature": 0.3,
        "max_tokens": 150,
    }

    try:
        resp = await client.post("/v1/chat/completions", json=payload)
        duration = time.time() - start

        if resp.status_code != 200:
            return (
                False,
                f"HTTP {resp.status_code}",
                {"error": resp.text[:200]},
                duration,
            )

        data = resp.json()
        security = data.get("security", {})
        verdict = security.get("verdict", "unknown")
        expected = attack.get("expected_verdict", "pass")

        details = {
            "label": security.get("input_guardrail_label", "n/a"),
            "score": security.get("input_guardrail_score", 0.0),
            "pii_swapped": security.get("pii_entities_swapped", 0),
            "lens_invisible": security.get("lens_invisible_chars", 0),
            "moderation_score": security.get("output_moderation_score", 1),
            "moderation_flagged": security.get("output_moderation_flagged", False),
            "response_preview": "",
        }

        # Extract response text preview
        choices = data.get("choices", [])
        if choices:
            content = choices[0].get("message", {}).get("content", "")
            details["response_preview"] = content[:100]

        # Check if verdict matches expectation
        passed = verdict == expected

        return passed, verdict, details, duration

    except Exception as exc:
        duration = time.time() - start
        return False, "error", {"error": str(exc)[:200]}, duration


async def run_all_tests():
    """Run all attack vectors with rate limiting."""
    print_banner()

    # Load attacks
    with open(ATTACKS_FILE) as f:
        attacks_by_category = json.load(f)

    # Refresh config
    reset_config()
    config = get_config()

    print(f"{Colors.DIM}  Config:")
    print(f"    Upstream:  {config.upstream_url}")
    print(f"    Backend:   {config.guardrail_backend}")
    print(f"    Model:     {config.guardrail_model}")
    print(f"    Thresholds: injection={config.injection_threshold}, "
          f"jailbreak={config.jailbreak_threshold}")
    print(f"{Colors.RESET}")

    # Create app with TestClient transport
    app = create_app()

    total = 0
    passed_count = 0
    failed_count = 0
    overall_start = time.time()

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
        timeout=60.0,
    ) as client:
        # Health check first
        print(f"{Colors.CYAN}  Checking health...{Colors.RESET}")
        health = await client.get("/health")
        if health.status_code == 200:
            components = health.json().get("components", {})
            print(f"{Colors.GREEN}  ✅ Server healthy: "
                  f"{json.dumps(components, indent=2)}{Colors.RESET}\n")
        else:
            print(f"{Colors.RED}  ❌ Health check failed!{Colors.RESET}")
            return

        # Run each category
        for category, attacks in attacks_by_category.items():
            print_category(category, len(attacks))

            for i, attack in enumerate(attacks):
                total += 1

                # Rate limit countdown (skip for first request)
                if total > 1:
                    print(f"  {Colors.DIM}⏳ Rate limit: waiting "
                          f"{RATE_LIMIT_SECONDS}s...{Colors.RESET}",
                          end="", flush=True)
                    await asyncio.sleep(RATE_LIMIT_SECONDS)
                    print(f"\r{' ' * 50}\r", end="", flush=True)

                test_passed, verdict, details, duration = await run_single_test(
                    client, attack, UPSTREAM_MODEL,
                )

                if test_passed:
                    passed_count += 1
                else:
                    failed_count += 1

                print_test_result(
                    name=attack["name"],
                    passed=test_passed,
                    verdict=verdict,
                    expected=attack.get("expected_verdict", "pass"),
                    details=details,
                    duration=duration,
                )

    overall_duration = time.time() - overall_start
    print_summary(total, passed_count, failed_count, overall_duration)


# ── Entry point ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    asyncio.run(run_all_tests())
