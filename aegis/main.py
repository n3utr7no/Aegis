"""
Aegis Main Entry Point — CLI for starting the proxy server.
"""

import argparse
import sys

from aegis.proxy.server import run_server
from aegis.utils.logging import log


def main() -> None:
    """Parse CLI arguments and start the Aegis proxy."""
    parser = argparse.ArgumentParser(
        prog="aegis",
        description="Aegis — Self-Evolving Security Sidecar for LLM Applications",
    )
    parser.add_argument(
        "--host",
        type=str,
        default=None,
        help="Host to bind to (default: from AEGIS_HOST env or 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Port to bind to (default: from AEGIS_PORT env or 8080)",
    )

    args = parser.parse_args()

    log.info("main", "=" * 50)
    log.info("main", "  Aegis Security Sidecar v0.1.0")
    log.info("main", "=" * 50)

    try:
        run_server(host=args.host, port=args.port)
    except KeyboardInterrupt:
        log.info("main", "Shutting down...")
        sys.exit(0)
    except Exception as exc:
        log.error("main", f"Fatal error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
