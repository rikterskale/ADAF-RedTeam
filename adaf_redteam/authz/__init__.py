"""Engagement authorization: parsing, schema validation, and the runtime gate."""

from .engagement import Engagement, load_engagement
from .gates import GateError, authorize

__all__ = ["Engagement", "GateError", "authorize", "load_engagement"]
