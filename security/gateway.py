"""
security/gateway.py
====================

The Security Gateway -- the single entry point the backend (Member A)
calls before trusting any user-submitted form data.

Implements the locked contract in docs/Rules.md, Section 2:

    from security.gateway import process_request
    result = process_request(data={"username": "admin", "password": "' OR '1'='1"})

`process_request` always returns a dict with exactly these four keys --
sanitized_data, is_blocked, reason, attack_type -- per the Return
Contract table in Section 2. Nothing is ever printed to stdout (Section
2's "Implementation Note for Member B"); blocked requests are written
to the threat log file instead, via security.logger.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from pydantic_settings import BaseSettings

from .logger import log_threat
from .sanitizers import ATTACK_NONE, inspect_value, sanitize_data

_log = logging.getLogger(__name__)


class _GatewaySettings(BaseSettings):
    """
    Local instance of the team-wide settings pattern (docs/Rules.md,
    Section 4). Each module that needs configuration reads the same
    `.env` file independently rather than importing a shared object
    from `app.config`, so `security/` has no import-time coupling to
    `app/` and stays independently importable and testable.
    """

    SECURITY_ENABLED: bool = True
    DATABASE_URL: str = "sqlite:///./inputguard.db"
    LOG_FILE: str = "threats.log"

    class Config:
        env_file = ".env"


settings = _GatewaySettings()

# Human-readable block reasons, keyed by the locked attack_type values.
# The "sqli" text matches the example in Rules.md Section 2 verbatim.
_BLOCK_REASONS = {
    "sqli": "SQL Injection detected",
    "xss": "Cross-Site Scripting (XSS) detected",
    "cmdi": "Command Injection detected",
}


def process_request(data: Dict[str, Any], ip: str = "unknown") -> Dict[str, Any]:
    """
    Inspect a request's form data for SQL Injection, XSS, and OS Command
    Injection, per docs/Rules.md Section 2.

    Parameters
    ----------
    data:
        The raw field -> value mapping submitted by the client, e.g.
        ``{"username": "admin", "password": "' OR '1'='1"}``. Required,
        and the only argument the locked contract's call site passes.
    ip:
        Client IP address, used only for the threat log entry (Section
        6). Optional and keyword-friendly so the documented call
        ``process_request(data={...})`` keeps working unmodified;
        callers that have the real client IP (e.g. FastAPI's
        ``request.client.host``) should pass it for accurate logging.

    Returns
    -------
    dict with exactly the four keys required by the Return Contract:
        sanitized_data (dict), is_blocked (bool),
        reason (str | None), attack_type (str)
    """
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise TypeError(
            f"process_request() expects 'data' to be a dict, got {type(data).__name__}"
        )

    sanitized = sanitize_data(data)

    if not settings.SECURITY_ENABLED:
        # Gateway explicitly bypassed (Rules.md Section 4 toggle behaviour
        # -- "Attacks succeed, for demo purposes"). Sanitization still
        # runs since it's harmless hygiene, not a security control;
        # detection is what's skipped.
        return {
            "sanitized_data": sanitized,
            "is_blocked": False,
            "reason": None,
            "attack_type": ATTACK_NONE,
        }

    attack_type: Optional[str] = None
    offending_value: Any = None

    for field_value in data.values():
        hit = inspect_value(field_value)
        if hit is not None:
            attack_type = hit
            offending_value = field_value
            break  # fail-fast: first flagged field wins

    if attack_type is None:
        return {
            "sanitized_data": sanitized,
            "is_blocked": False,
            "reason": None,
            "attack_type": ATTACK_NONE,
        }

    # Section 6: payload is the raw blocked input, not the sanitized copy.
    log_threat(attack_type=attack_type, payload=str(offending_value), ip=ip)

    return {
        "sanitized_data": sanitized,
        "is_blocked": True,
        "reason": _BLOCK_REASONS[attack_type],
        "attack_type": attack_type,
    }
