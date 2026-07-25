"""
security package
=================

Security Gateway module for InputGuard -- Member B's deliverable per
docs/Rules.md, Section 8.

The one import every other module needs is the locked entry point:

    from security.gateway import process_request

This __init__ additionally re-exports the most useful public names
(detectors, sanitizers, the logger's read/write functions) purely for
convenience -- e.g. direct access when unit testing. `app/routes.py`
should keep using the import path above; that's the one guaranteed by
the team contract.
"""
from .gateway import process_request, settings
from .logger import get_threats, log_threat
from .sanitizers import (
    ATTACK_CMDI,
    ATTACK_NONE,
    ATTACK_SQLI,
    ATTACK_XSS,
    detect_cmdi,
    detect_sqli,
    detect_xss,
    inspect_value,
    sanitize_data,
    sanitize_value,
)

__all__ = [
    "process_request",
    "settings",
    "log_threat",
    "get_threats",
    "detect_sqli",
    "detect_xss",
    "detect_cmdi",
    "inspect_value",
    "sanitize_data",
    "sanitize_value",
    "ATTACK_SQLI",
    "ATTACK_XSS",
    "ATTACK_CMDI",
    "ATTACK_NONE",
]
