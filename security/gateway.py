"""Temporary stub for Member B's Security Gateway.

This module will be replaced by the real security implementation.
It exists only so the backend can start and be tested while Member B is working.
"""


def process_request(data: dict) -> dict:
    """Return the contract shape defined in Rules.md Section 2.

    Always returns non-blocked because this is a pass-through stub.
    """
    return {
        "sanitized_data": data,
        "is_blocked": False,
        "reason": None,
        "attack_type": "none",
    }
