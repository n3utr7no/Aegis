"""
Start the Aegis proxy server with .env configuration.

Usage:
    python playground/start_server.py
"""

import sys
from pathlib import Path

# Ensure project root is on sys.path
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

# Load .env from project root
from dotenv import load_dotenv
load_dotenv(project_root / ".env")

from aegis.config import get_config
from aegis.proxy.server import run_server


def main():
    config = get_config()

    banner = f"""
╔══════════════════════════════════════════════════════════╗
║                 ⚔️  AEGIS SECURITY PROXY                 ║
╠══════════════════════════════════════════════════════════╣
║  Host:       {config.host:<42} ║
║  Port:       {config.port:<42} ║
║  Upstream:   {config.upstream_url:<42} ║
║  Guardrail:  {config.guardrail_backend:<42} ║
║  Model:      {config.guardrail_model:<42} ║
╠══════════════════════════════════════════════════════════╣
║  Dashboard:  Open playground/dashboard.html in browser   ║
║  E2E Tests:  python playground/run_e2e.py                ║
╚══════════════════════════════════════════════════════════╝
"""
    print(banner)
    run_server(host=config.host, port=config.port)


if __name__ == "__main__":
    main()
