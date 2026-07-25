"""
security/logger.py
===================

Threat-event logging for InputGuard.

Owns the on-disk log format locked in docs/Rules.md, Section 6: one
JSON object per line, appended to the file named by the LOG_FILE
setting (default "threats.log"):

    {"timestamp": "2026-07-24T14:30:00", "attack_type": "sqli",
     "payload": "' OR '1'='1", "ip": "127.0.0.1"}

`log_threat` is the write side, called by security.gateway.process_request
whenever a request is blocked. `get_threats` is the read side: a small
convenience so whoever implements the backend's `GET /api/threat-log`
endpoint (Section 6) doesn't have to re-implement JSONL parsing -- the
module that owns the format also owns reading it back.

Per Section 2's implementation note ("Do not print to stdout"), nothing
here ever prints. Internal I/O failures (e.g. an unwritable log path)
go through the standard `logging` module at WARNING/ERROR level, which
is an operator-facing diagnostic channel, distinct from the threat
event log this module writes for the app.
"""
from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic_settings import BaseSettings

_log = logging.getLogger(__name__)

_VALID_ATTACK_TYPES = {"sqli", "xss", "cmdi"}

# Section 6: "payload -- truncate to 500 chars if needed".
MAX_PAYLOAD_LENGTH = 500

# Serializes writes/reads from concurrent requests handled in the same
# process. A multi-process deployment would need an OS-level file lock
# (e.g. fcntl.flock) or a database-backed log instead; out of scope for
# this project's single-worker docker-compose setup.
_LOG_LOCK = threading.Lock()


class _LoggerSettings(BaseSettings):
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


settings = _LoggerSettings()


def _now_iso() -> str:
    """
    UTC timestamp formatted as YYYY-MM-DDTHH:MM:SS (Section 6's exact
    format, no offset suffix). Logging in UTC avoids ambiguity across
    deployments/timezones; strftime is used instead of .isoformat() so
    the offset suffix a timezone-aware datetime would normally add is
    never included.
    """
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def log_threat(
    attack_type: str,
    payload: str,
    ip: str = "unknown",
    log_file: Optional[str] = None,
) -> None:
    """
    Append one threat event to the log file, in the exact schema from
    docs/Rules.md Section 6.

    Parameters
    ----------
    attack_type: one of "sqli", "xss", "cmdi".
    payload: the raw offending input; truncated to 500 chars.
    ip: client IP address; defaults to "unknown" if the caller doesn't have it.
    log_file: override path; defaults to the LOG_FILE setting.
    """
    if attack_type not in _VALID_ATTACK_TYPES:
        raise ValueError(
            f"attack_type must be one of {sorted(_VALID_ATTACK_TYPES)}, got {attack_type!r}"
        )

    entry = {
        "timestamp": _now_iso(),
        "attack_type": attack_type,
        "payload": str(payload)[:MAX_PAYLOAD_LENGTH],
        "ip": ip,
    }
    line = json.dumps(entry, ensure_ascii=False)
    path = Path(log_file or settings.LOG_FILE)

    with _LOG_LOCK:
        try:
            with path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError:
            _log.exception("Failed to write threat log entry to %s", path)


def get_threats(limit: Optional[int] = None, log_file: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Read back logged threat events, oldest first -- the same shape
    Member A's `GET /api/threat-log` endpoint returns under the
    `"threats"` key (Section 6).

    Malformed lines are skipped (and noted via the logging module)
    rather than raising, so one corrupted entry can't take the whole
    endpoint down. If `limit` is given, only the most recent `limit`
    entries are returned.
    """
    path = Path(log_file or settings.LOG_FILE)
    if not path.exists():
        return []

    threats: List[Dict[str, Any]] = []
    with _LOG_LOCK:
        try:
            with path.open("r", encoding="utf-8") as fh:
                for line_no, raw_line in enumerate(fh, start=1):
                    raw_line = raw_line.strip()
                    if not raw_line:
                        continue
                    try:
                        threats.append(json.loads(raw_line))
                    except json.JSONDecodeError:
                        _log.warning("Skipping malformed threat log line %d in %s", line_no, path)
        except OSError:
            _log.exception("Failed to read threat log from %s", path)
            return []

    if limit is not None:
        threats = threats[-limit:]
    return threats
