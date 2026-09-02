"""Ecosystem plugin layer.

Public surface is deliberately small: everything downstream talks to adapters
through :mod:`supplyguard.ecosystems.base`.
"""

from supplyguard.ecosystems.base import (
    EcosystemAdapter,
    ManifestParseError,
    adapter_for_manifest,
    all_adapters,
    ecosystem_names,
    get_adapter,
    register,
)

__all__ = [
    "EcosystemAdapter",
    "ManifestParseError",
    "adapter_for_manifest",
    "all_adapters",
    "ecosystem_names",
    "get_adapter",
    "register",
]
