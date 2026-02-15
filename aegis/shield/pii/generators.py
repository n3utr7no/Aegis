"""
Synthetic Data Generators — Produces realistic fake data for PII swapping.

Uses the Faker library to generate contextually appropriate replacement
values. Supports deterministic seeding for reproducible swaps within
a session.
"""

from faker import Faker

from aegis.utils.logging import log


class SyntheticGenerator:
    """Generates realistic synthetic data for each PII entity type.

    The generator maintains a Faker instance that can be seeded for
    deterministic output (useful for testing and reproducible swaps).

    Usage:
        gen = SyntheticGenerator(seed=42)
        name = gen.generate("EMAIL")  # "john.doe@example.com" -> consistent fake
    """

    # Mapping of entity types to Faker provider methods
    _GENERATOR_MAP: dict[str, str] = {
        "EMAIL": "email",
        "PHONE": "phone_number",
        "SSN": "ssn",
        "CREDIT_CARD": "credit_card_number",
        "IP_ADDRESS": "ipv4",
        "DATE_OF_BIRTH": "date_of_birth",
        "NAME": "name",
        "ADDRESS": "address",
        # NER entity types (from spaCy)
        "PERSON": "name",
        "ORG": "company",
        "GPE": "city",
    }

    def __init__(self, seed: int | None = None, locale: str = "en_US"):
        """Initialize the synthetic data generator.

        Args:
            seed: Optional seed for deterministic output.
            locale: Faker locale for region-specific data.
        """
        self._faker = Faker(locale)
        if seed is not None:
            self._faker.seed_instance(seed)
            log.debug("pii.generators", f"Seeded generator with seed={seed}")

        log.debug(
            "pii.generators",
            f"Initialized SyntheticGenerator (locale={locale})",
        )

    def generate(self, entity_type: str) -> str:
        """Generate a synthetic replacement value for the given entity type.

        Args:
            entity_type: The PII entity type (e.g., 'EMAIL', 'PHONE', 'SSN').

        Returns:
            A realistic synthetic value matching the entity type.

        Raises:
            ValueError: If entity_type is not recognized.
        """
        faker_method = self._GENERATOR_MAP.get(entity_type)

        if faker_method is None:
            raise ValueError(
                f"Unknown entity type: '{entity_type}'. "
                f"Supported types: {list(self._GENERATOR_MAP.keys())}"
            )

        provider = getattr(self._faker, faker_method)
        value = str(provider())

        log.debug("pii.generators", f"Generated {entity_type}: {value[:20]}...")
        return value

    def generate_batch(self, entity_type: str, count: int) -> list[str]:
        """Generate multiple synthetic values of the same type.

        Args:
            entity_type: The PII entity type.
            count: Number of values to generate.

        Returns:
            A list of synthetic values.
        """
        return [self.generate(entity_type) for _ in range(count)]

    @property
    def supported_types(self) -> list[str]:
        """Return the list of supported entity types."""
        return list(self._GENERATOR_MAP.keys())
