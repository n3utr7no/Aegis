"""
Canary Generator — Creates high-entropy canary tokens for prompt leak detection.

Canaries are unique strings injected into system prompts. If they appear
in the LLM's output, it indicates a system prompt leak attack succeeded.
"""

import uuid

from aegis.utils.logging import log


# Default prefix makes canaries easily identifiable in logs
_DEFAULT_PREFIX = "AEGIS-CANARY"


class CanaryGenerator:
    """Generates high-entropy canary tokens for prompt leak detection.

    Each canary is a UUID4-based string with a recognizable prefix,
    making it both unique and easy to search for programmatically.

    Usage:
        gen = CanaryGenerator()
        canary = gen.generate()
        # "AEGIS-CANARY-a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    """

    def __init__(self, prefix: str = _DEFAULT_PREFIX):
        """Initialize the canary generator.

        Args:
            prefix: String prefix for generated canaries.
                    Defaults to 'AEGIS-CANARY'.
        """
        self._prefix = prefix
        log.debug("canary.generator", f"Initialized with prefix='{prefix}'")

    def generate(self) -> str:
        """Generate a new high-entropy canary token.

        Returns:
            A canary string in the format '{prefix}-{uuid4}'.
        """
        token = f"{self._prefix}-{uuid.uuid4()}"
        log.info("canary.generator", f"Generated canary: {token[:30]}...")
        return token

    def validate_format(self, canary: str) -> bool:
        """Check if a string looks like a valid canary token.

        Args:
            canary: The string to validate.

        Returns:
            True if the string matches the expected canary format.
        """
        if not canary.startswith(self._prefix + "-"):
            return False

        # Extract the UUID part after the prefix
        uuid_part = canary[len(self._prefix) + 1:]
        try:
            uuid.UUID(uuid_part)
            return True
        except ValueError:
            return False

    @property
    def prefix(self) -> str:
        """Return the configured canary prefix."""
        return self._prefix
