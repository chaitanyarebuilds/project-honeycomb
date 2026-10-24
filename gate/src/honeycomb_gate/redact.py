"""Secret redaction applied before anything is written to the event log (F2).

Redaction is key-based (a field named like a secret) and value-based (a string that looks
like a credential). It errs towards hiding: a false redaction loses a little detail, a miss
leaks a secret into a log. Strings are capped before any pattern runs, because arguments are
chosen by an untrusted agent and must not be able to make the scan slow.
"""

import re
from typing import Any

REDACTED = "[REDACTED]"
MAX_SCAN_CHARS = 8192
MAX_NAME_CHARS = 128

# A key is split into lower-case words (camelCase, snake_case, dashes, dots), then checked
# against these words and against adjacent pairs joined together ("api" + "key").
_SECRET_WORDS = {
    "password", "passwd", "pwd", "passphrase", "secret", "token", "apikey", "authorization",
    "auth", "credential", "credentials", "cookie", "privatekey", "bearer",
}  # fmt: skip
_WORD = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")

_SECRET_VALUE = [
    re.compile(r"\b(?:sk|pk|rk)-[A-Za-z0-9_\-]{16,}\b"),  # generic provider-style keys
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),  # cloud access key id shape
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),  # code-host tokens
    re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}\b"),  # chat tokens
    re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"),  # JWT
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-~+/]{16,}=*"),
    re.compile(r"(?i)\b[a-z][a-z0-9+.\-]{0,30}://[^/\s:@]{1,128}:[^/\s@]{1,128}@"),  # user:pass@
    re.compile(r"-----BEGIN [A-Z ]{0,30}PRIVATE KEY-----"),
]


def is_secret_key(key: str) -> bool:
    words = [w.lower() for w in _WORD.findall(key)]
    if any(w in _SECRET_WORDS for w in words):
        return True
    return any(a + b in _SECRET_WORDS for a, b in zip(words, words[1:], strict=False))


def redact_string(value: str) -> str:
    if len(value) > MAX_SCAN_CHARS:
        value = value[:MAX_SCAN_CHARS] + f"...[{len(value) - MAX_SCAN_CHARS} more chars not stored]"
    for pattern in _SECRET_VALUE:
        value = pattern.sub(REDACTED, value)
    return value


_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f  ]")


def sanitize_name(value: object) -> str:
    """Make an agent-supplied name safe to log and print: redacted, no control characters, short."""
    text = redact_string(str(value)[: MAX_NAME_CHARS * 4])
    text = _CONTROL.sub("?", text)
    return text if len(text) <= MAX_NAME_CHARS else text[:MAX_NAME_CHARS] + "..."


def redact(value: Any, *, max_depth: int = 8) -> Any:
    """Return a copy of ``value`` with secrets replaced by ``[REDACTED]``."""
    if max_depth <= 0:
        return "[TRUNCATED]"
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if isinstance(key, str) and is_secret_key(key):
                out[key] = REDACTED
            else:
                out[sanitize_name(key)] = redact(item, max_depth=max_depth - 1)
        return out
    if isinstance(value, list | tuple):
        return [redact(item, max_depth=max_depth - 1) for item in value[:1000]]
    if isinstance(value, str):
        return redact_string(value)
    return value
