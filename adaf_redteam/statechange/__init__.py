"""State-changing runtime: cleanup latch.

When a state-changing capability's cleanup fails to verify (a mutation was not
proven reversed), the run is *latched*: further state-changing actions sharing the
same output directory are refused until an operator clears it. This is the
cleanup-latch the design mandates for the state-changing tier.
"""

from .latch import LATCH_FILENAME, clear_latch, is_latched, set_latch

__all__ = ["LATCH_FILENAME", "clear_latch", "is_latched", "set_latch"]
