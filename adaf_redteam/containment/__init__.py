"""Lab-containment probe. Gates every state-changing action."""

from .probe import ContainmentProbe, probe_domain

__all__ = ["ContainmentProbe", "probe_domain"]
