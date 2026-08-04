"""Adversary-emulation / purple-team capabilities.

These run authorized evasion / payload-reliability TTPs and their proof is
DETECTION evidence: what was attempted, what fired, what did not. They require an
ROE detection-notification (enforced by the gate) and always emit a detection
block — there is no 'succeed silently' path. The novel evasion primitives are the
lab-certification boundary and raise.
"""

from .evasion import AdversaryEmulationEvasionCapability
from .reliability import PayloadReliabilityCapability

__all__ = ["AdversaryEmulationEvasionCapability", "PayloadReliabilityCapability"]
