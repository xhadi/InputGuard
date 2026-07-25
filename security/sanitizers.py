"""
security/sanitizers.py
=======================

Pure, side-effect-free input inspection utilities for the InputGuard
Security Gateway. Everything in this module is a plain function over
strings/dicts/lists -- no file I/O, no logging, no config -- so it can
be unit tested in isolation and reused outside the gateway if needed.

This module owns two independent responsibilities that security/gateway.py
composes together:

1. Sanitization -- light, format-preserving hygiene applied to *every*
   field, regardless of whether an attack is detected: strip control /
   NUL bytes, trim padding whitespace, cap length. This is deliberately
   NOT an attempt to neutralize attack syntax (stripping quotes, angle
   brackets, etc.) -- that would silently rewrite what the user typed.
   Neutralizing attacks is the detection + blocking job below instead.
   Per docs/Rules.md Section 2, `sanitized_data` is returned even when
   `is_blocked` is True, so callers must treat it as display/storage-
   ready ONLY once they've checked `is_blocked is False`.

2. Detection -- signature-based heuristics that flag SQL Injection,
   Cross-Site Scripting, and OS Command Injection, the three attack
   categories locked in docs/Rules.md Section 2 (`attack_type` must be
   exactly one of "sqli", "xss", "cmdi", "none").

Design notes
------------
* All detection regexes are pre-compiled once at import time.
* Every pattern avoids nested/unbounded quantifiers over attacker-
  controlled content (no `(x+)+`-style constructs), and any "match
  anything in between" pattern is length-bounded. Combined with the
  MAX_SCAN_LENGTH cap in `inspect_value`, worst-case matching cost
  stays linear in input size -- this is a deliberate ReDoS mitigation,
  since these patterns run directly against attacker-controlled input.
* Detection favours precision on fields where false positives would be
  most disruptive (e.g. the SQLi tautology rule requires matching
  operands via a backreference -- `OR 1=1` -- rather than flagging any
  "word = word" comparison, which would misfire on ordinary sentences).
  Command-injection rules never fire on a bare `; | &` alone, since
  those characters are common and even encouraged in strong passwords;
  they only fire when a metacharacter is directly chained with a known
  command/binary or a dangerous construct (backticks, `$( )`, etc).
"""
from __future__ import annotations

import re
from typing import Any, List, Optional, Pattern

# --------------------------------------------------------------------------
# Attack type constants -- must match docs/Rules.md, Section 2 exactly
# (lowercase, exactly "sqli" | "xss" | "cmdi" | "none").
# --------------------------------------------------------------------------
ATTACK_SQLI = "sqli"
ATTACK_XSS = "xss"
ATTACK_CMDI = "cmdi"
ATTACK_NONE = "none"


# --------------------------------------------------------------------------
# Sanitization
# --------------------------------------------------------------------------
# ASCII control characters and the NUL byte. Ordinary printable text and
# meaningful whitespace are left untouched -- this is hygiene, not a
# content filter.
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

DEFAULT_MAX_FIELD_LENGTH = 2000


def sanitize_value(value: Any, max_length: int = DEFAULT_MAX_FIELD_LENGTH) -> Any:
    """
    Apply light, format-preserving hygiene to a single value.

    - str: strip control/NUL bytes, trim surrounding whitespace, cap length.
    - dict / list: recurse element-wise.
    - anything else (int, bool, float, None, ...): returned unchanged.

    This never strips attack syntax (quotes, angle brackets, shell
    metacharacters) -- see the module docstring for why. Detection +
    blocking in `inspect_value` / security.gateway is what actually
    stops an attack; this function only normalizes formatting.
    """
    if isinstance(value, str):
        cleaned = _CONTROL_CHARS_RE.sub("", value).strip()
        return cleaned[:max_length]
    if isinstance(value, dict):
        return {key: sanitize_value(val, max_length) for key, val in value.items()}
    if isinstance(value, list):
        return [sanitize_value(item, max_length) for item in value]
    return value


def sanitize_data(data: dict) -> dict:
    """Sanitize every value in a top-level request dict. See sanitize_value."""
    return {key: sanitize_value(val) for key, val in data.items()}


# --------------------------------------------------------------------------
# Detection
# --------------------------------------------------------------------------
# Hard ceiling on how much of a single value detection regexes run against.
# Every pattern above is already length-bounded / free of nested quantifiers
# (see module docstring), so search() cost is linear in input size, not
# exponential -- confirmed by benchmarking the full pattern set up to 5M
# characters. Because of that, values are scanned in FULL up to this
# ceiling; there is deliberately no small "scan window" an attacker could
# evade by padding a field with junk before the real payload (an earlier,
# smaller cap here had exactly that bug: a short attack string placed
# after enough padding sailed through undetected). This ceiling exists
# only as a last-resort circuit breaker for pathological, multi-megabyte
# submissions -- far beyond any real username/password -- so a single
# request can't tie up the worker for seconds of regex time. Request-body
# size limits at the web-server/ASGI layer are the right place to reject
# oversized submissions outright; that's outside security/'s scope.
MAX_SCAN_LENGTH = 1_000_000


def _compile(patterns: List[str]) -> List[Pattern[str]]:
    return [re.compile(p, re.IGNORECASE) for p in patterns]


_SQLI_PATTERNS = _compile([
    # Tautology with matching operands, e.g. OR 1=1 / OR '1'='1' / AND 'a'='a'
    # (backreference \1 requires both sides to be equal -- keeps this precise
    # instead of matching any "word = word" comparison in ordinary text).
    r"\b(?:or|and)\b\s*['\"]?\s*(\w+)\s*['\"]?\s*=\s*['\"]?\s*\1\b",
    # String-literal breakout immediately followed by a boolean keyword,
    # e.g. `' OR`, `" AND` -- a strong structural signal on its own.
    r"['\"]\s*(?:or|and)\b",
    # Inline / end-of-line SQL comment markers used to truncate a query.
    r"(?:--|#)(?:\s|$)",
    r"/\*[\s\S]{0,300}?\*/",
    # UNION-based injection.
    r"\bunion\b(?:\s+\ball\b)?\s+\bselect\b",
    # Stacked / batched queries.
    r";\s*(?:drop|delete|update|insert|select|exec|create|alter|truncate)\b",
    # Dangerous built-in functions / stored procedures.
    r"\bxp_cmdshell\b",
    r"\bsp_executesql\b",
    r"\bwaitfor\s+delay\b",
    r"\bsleep\s*\(\s*\d+\s*\)",
    r"\bbenchmark\s*\(",
    r"\bpg_sleep\s*\(",
    # Schema / metadata enumeration.
    r"\binformation_schema\b",
    r"\bsqlite_master\b",
    # CAST-based injection (word-boundaried, so "forecast(" etc. is safe).
    r"\bcast\s*\([\s\S]{1,100}\bas\b",
])

_XSS_PATTERNS = _compile([
    r"<\s*script\b[^>]{0,200}>",
    r"<\s*/\s*script\s*>",
    r"javascript\s*:",
    r"\bon(?:error|load|click|mouseover|focus|blur|change|submit|input|key\w*|drag\w*)\s*=\s*['\"]",
    r"<\s*(?:iframe|object|embed|svg|body|img)\b[^>]{0,200}\bon\w+\s*=",
    r"<\s*img\b[^>]{0,200}\bsrc\s*=\s*['\"]?\s*javascript:",
    r"document\s*\.\s*(?:cookie|location|write)\b",
    r"\beval\s*\(",
    r"expression\s*\(",
    r"data\s*:\s*text/html",
])

_CMDI_PATTERNS = _compile([
    # Command substitution -- rare in legitimate input regardless of context.
    r"`[^`]{1,200}`",
    r"\$\([^)]{1,200}\)",
    # Shell metacharacter directly chained with a known command/binary.
    # (A bare `; | &` never matches on its own -- see module docstring.)
    r"[;&|]{1,2}\s*(?:ls|cat|rm|whoami|id|pwd|wget|curl|nc|ncat|bash|sh|python\d?|"
    r"perl|chmod|chown|kill|ping|nslookup|netstat|ifconfig|ipconfig|dir|type|del|"
    r"echo|powershell|cmd(?:\.exe)?)\b",
    # Sensitive file / path targets.
    r"/etc/passwd",
    r"/etc/shadow",
    r"c:\\windows\\system32",
    # Reverse-shell indicators.
    r"\bnc\s+-e\b",
    r"/dev/tcp/",
    r"\bbash\s+-i\b",
    r"\bpowershell\b",
    r"\bcmd\.exe\b",
])


def _matches_any(patterns: List[Pattern[str]], value: str) -> bool:
    scoped = value[:MAX_SCAN_LENGTH]
    return any(pattern.search(scoped) for pattern in patterns)


def detect_sqli(value: Any) -> bool:
    """Return True if `value` contains a SQL Injection signature."""
    if not isinstance(value, str) or not value:
        return False
    return _matches_any(_SQLI_PATTERNS, value)


def detect_xss(value: Any) -> bool:
    """Return True if `value` contains a Cross-Site Scripting signature."""
    if not isinstance(value, str) or not value:
        return False
    return _matches_any(_XSS_PATTERNS, value)


def detect_cmdi(value: Any) -> bool:
    """Return True if `value` contains an OS Command Injection signature."""
    if not isinstance(value, str) or not value:
        return False
    return _matches_any(_CMDI_PATTERNS, value)


def inspect_value(value: Any) -> Optional[str]:
    """
    Classify a single value against all three attack categories.

    Checks run in a fixed priority order -- sqli, then cmdi, then xss --
    so that if a value happens to match more than one category, the
    classification with the greater server-side blast radius wins.
    Returns the attack type string, or None if nothing matched.

    Recurses into dict/list values so nested/JSON-shaped fields are
    covered too, not just flat strings.
    """
    if isinstance(value, str):
        if detect_sqli(value):
            return ATTACK_SQLI
        if detect_cmdi(value):
            return ATTACK_CMDI
        if detect_xss(value):
            return ATTACK_XSS
        return None
    if isinstance(value, dict):
        for nested in value.values():
            hit = inspect_value(nested)
            if hit is not None:
                return hit
        return None
    if isinstance(value, list):
        for item in value:
            hit = inspect_value(item)
            if hit is not None:
                return hit
        return None
    return None
