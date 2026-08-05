"""Capability model. Every registered capability has an adapter; live primitives
remain lab_certified=False until certified per docs/CERTIFICATION.md."""

from .base import Capability, CapabilityResult
from .registry import CapabilityDescriptor, get_descriptor, list_descriptors

__all__ = [
    "Capability",
    "CapabilityDescriptor",
    "CapabilityResult",
    "get_descriptor",
    "list_descriptors",
]
