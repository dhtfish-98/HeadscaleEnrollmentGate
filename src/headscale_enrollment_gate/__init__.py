"""Operator-side Headscale enrollment admission gate."""

from .gate import EnrollmentGate, GateError, HeadscaleCLI, MintedKey

__version__ = "0.1.0"
__all__ = ["EnrollmentGate", "GateError", "HeadscaleCLI", "MintedKey"]
