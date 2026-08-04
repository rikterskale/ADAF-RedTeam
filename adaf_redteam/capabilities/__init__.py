"""Capability model. Phase 0 ships descriptors only — no executable adapters."""

from .base import Capability, CapabilityResult
from .registry import CapabilityDescriptor, get_descriptor, list_descriptors

__all__ = [
    "Capability",
    "CapabilityDescriptor",
    "CapabilityResult",
    "get_descriptor",
    "list_descriptors",
]
