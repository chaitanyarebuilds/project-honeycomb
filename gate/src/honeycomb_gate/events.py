"""Append-only JSONL event log (F2, M0 subset: no SQLite, no redaction yet)."""

import hashlib
import json
import os
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
_MAX_PAYLOAD_BYTES = 4096


def _ulid_like() -> str:
    # 48-bit ms timestamp + 80 random bits, Crockford base32: sortable, ULID-shaped.
    alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    n = (int(time.time() * 1000) << 80) | int.from_bytes(os.urandom(10))
    return "".join(alphabet[(n >> (5 * i)) & 31] for i in range(25, -1, -1))


def digest(payload: Any) -> str:
    raw = json.dumps(payload, sort_keys=True, default=str).encode()
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class EventLog:
    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, kind: str, *, severity: str = "info", **fields: Any) -> dict[str, Any]:
        event: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "event_id": _ulid_like(),
            "ts": datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "kind": kind,
            "severity": severity,
            **fields,
        }
        line = json.dumps(event, default=str)
        if len(line.encode()) > _MAX_PAYLOAD_BYTES:
            event.pop("args_redacted", None)
            event["truncated"] = True
            line = json.dumps(event, default=str)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
        return event
