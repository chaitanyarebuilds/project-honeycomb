"""Tool registry: definition pinning, quarantine and description flags (F3).

A tool's definition is hashed per upstream over everything the agent will see: name, title,
description, input and output schemas, annotations and execution hints. Only ``_meta`` and
icons are left out, and the gate does not forward those. The first definition seen is pinned
in learning mode (trust on first use); in strict mode a tool must be approved by an operator
before it is visible. Any later change quarantines the tool until the operator approves the
exact pending hash with ``honeycomb-gate tools approve --hash``. Annotations are hashed but
never used to grant anything: they are untrusted hints.
"""

import difflib
import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from honeycomb_gate.events import canonical_json
from honeycomb_gate.locking import JsonStore
from honeycomb_gate.walk import strings_of

APPROVED = "approved"
QUARANTINED = "quarantined"
UNAPPROVED = "unapproved"  # strict mode: seen, never approved

_NOT_PINNED = {"meta", "_meta", "icons"}
MAX_SCAN_CHARS = 20000


def definition_of(tool: Any) -> dict[str, Any]:
    """The pinned view of an MCP tool: every model-visible field except metadata and icons."""
    dump: dict[str, Any] = tool.model_dump(by_alias=True, exclude_none=True)
    return {k: v for k, v in dump.items() if k not in _NOT_PINNED}


def definition_hash(definition: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(definition)).hexdigest()


@dataclass
class PinResult:
    status: str  # approved | quarantined | unapproved
    event: str | None = None  # tool.pinned | tool.definition_changed | tool.unapproved | ...
    previous_hash: str | None = None
    current_hash: str = ""
    details: dict[str, str] = field(default_factory=dict)
    earlier: list[tuple[str, dict[str, str]]] = field(default_factory=list)  # events to log first


class PinStore(JsonStore):
    """JSON file of pins, safe to share between the running gate and the operator's CLI."""

    sort_keys = True  # a pin file diffs cleanly

    def entries(self) -> dict[str, dict[str, dict[str, Any]]]:
        with self._lock:
            return self._read()

    def check(
        self,
        upstream: str,
        tool: str,
        definition: dict[str, Any],
        *,
        strict: bool,
    ) -> PinResult:
        """Compare a live definition with its pin, updating the store as needed."""
        current = definition_hash(definition)
        with self._lock:
            data = self._read()
            entry = data.get(upstream, {}).get(tool)

            def put(new: dict[str, Any]) -> None:
                data.setdefault(upstream, {})[tool] = new
                self._write(data)

            if entry is None:
                if strict:
                    put({"status": UNAPPROVED, "pending_hash": current, "pending": definition})
                    return PinResult(UNAPPROVED, "tool.unapproved", None, current)
                put({"status": APPROVED, "hash": current, "definition": definition})
                return PinResult(APPROVED, "tool.pinned", None, current)

            earlier: list[tuple[str, dict[str, str]]] = []
            if entry["status"] == APPROVED:
                announce = entry.pop("announce", None)
                if announce:  # approved by the CLI while the gate ran: record it exactly once
                    earlier.append(
                        ("tool.approved", {**json.loads(announce), "hash": entry["hash"]})
                    )
                    put(entry)
                if entry["hash"] == current:
                    event, details = earlier[0] if earlier else (None, {})
                    return PinResult(APPROVED, event, entry["hash"], current, details)
                # Approved definition differs from the live one: quarantine, even right after
                # an approval (the upstream may have changed again in between).
                put(
                    {
                        "status": QUARANTINED,
                        "hash": entry["hash"],
                        "definition": entry.get("definition", {}),
                        "pending_hash": current,
                        "pending": definition,
                    }
                )
                return PinResult(
                    QUARANTINED, "tool.definition_changed", entry["hash"], current, earlier=earlier
                )

            # Already quarantined or unapproved: track the newest definition. Revert-to-original
            # does not un-quarantine; only an operator approval does.
            changed_again = entry.get("pending_hash") != current
            if changed_again:
                entry = {**entry, "pending_hash": current, "pending": definition}
                put(entry)
            return PinResult(
                entry["status"],
                "tool.definition_changed"
                if changed_again and entry["status"] == QUARANTINED
                else None,
                entry.get("hash"),
                current,
            )

    def approve(self, upstream: str, tool: str, approver: str, expected_hash: str) -> str:
        """Approve the pending definition if it is the one the operator reviewed.

        Returns ``"ok"``, ``"unknown"`` (no such tool or nothing pending) or ``"stale"``
        (the pending hash is not the one given, so the definition changed after review).
        The running gate records ``tool.approved`` the next time it sees the tool, so the CLI
        never writes to the hash-chained log itself (two writers would break the chain).
        """
        with self._lock:
            data = self._read()
            entry = data.get(upstream, {}).get(tool)
            if entry is None:
                return "unknown"
            pending = entry.get("pending_hash")
            if not pending:
                return "unknown"
            wanted = expected_hash.removeprefix("sha256:")
            if len(wanted) < 12 or not pending.removeprefix("sha256:").startswith(wanted):
                return "stale"
            now = datetime.now(UTC).isoformat(timespec="seconds")
            stamp = {"approver": approver, "approved_at": now}
            data[upstream][tool] = {
                "status": APPROVED,
                "hash": pending,
                "definition": entry.get("pending", {}),
                "announce": json.dumps(stamp),
            }
            self._write(data)
            return "ok"

    def diff(self, upstream: str, tool: str) -> str | None:
        """Unified diff between the approved definition and the pending one, if any."""
        entry = self.entries().get(upstream, {}).get(tool)
        if entry is None or "pending" not in entry:
            return None

        def render(d: dict[str, Any]) -> list[str]:
            return json.dumps(d, indent=2, sort_keys=True, ensure_ascii=True).splitlines()

        return "\n".join(
            difflib.unified_diff(
                render(entry.get("definition", {})),
                render(entry["pending"]),
                "approved",
                "pending",
                lineterm="",
            )
        )


@dataclass
class DescriptionFinding:
    suspicious: bool
    score: int
    reasons: list[str] = field(default_factory=list)


# (reason, pattern, weight). A weight of 2 or more is enough on its own; weak signals such as
# a single URL only count when combined, so ordinary documentation links do not raise alarms.
_PATTERNS: list[tuple[str, re.Pattern[str], int]] = [
    (
        "override_instructions",
        re.compile(
            r"(?i)\b(ignore|disregard|forget)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all)\b"
            r"[^.\n]{0,30}\b(instructions?|rules?|prompts?)\b"
        ),
        2,
    ),
    (
        "conceal_from_user",
        re.compile(
            r"(?i)\b(do not|don't|never)\s+(tell|inform|mention|show|reveal)\b[^.\n]{0,30}\buser\b"
        ),
        2,
    ),
    ("hidden_block", re.compile(r"(?i)<\s*(important|system|instructions?|hidden)\s*>"), 2),
    ("system_prompt", re.compile(r"(?i)\bsystem prompt\b"), 1),
    (
        "sensitive_file_reference",
        re.compile(
            r"(?i)(~/\.ssh|id_rsa|\.env\b(?!\.(?:example|sample|template))|/etc/passwd|"
            r"credentials\.json|mcp\.json)"
        ),
        2,
    ),
    ("exfiltration_wording", re.compile(r"(?i)\b(exfiltrate|send (it|them|this) to)\b"), 2),
    ("url", re.compile(r"(?i)\bhttps?://\S+"), 1),
    ("encoded_blob", re.compile(r"[A-Za-z0-9+/]{48,}={0,2}"), 1),
    (
        "invisible_characters",
        re.compile("[​‌‍⁠﻿‪-‮⁦-⁩]"),
        2,
    ),
]


def scan_description(text: str | None) -> DescriptionFinding:
    """Heuristic scan for instruction-like text. A hit is a signal, never proof."""
    if not text:
        return DescriptionFinding(False, 0)
    text = text[:MAX_SCAN_CHARS]
    score = 0
    reasons: list[str] = []
    strong = False
    for reason, pattern, weight in _PATTERNS:
        if pattern.search(text):
            score += weight
            reasons.append(reason)
            strong = strong or weight >= 2
    return DescriptionFinding(strong or score >= 2, score, reasons)


def scan_definition(definition: dict[str, Any]) -> DescriptionFinding:
    """Scan every model-visible string in a tool definition, not just its description."""
    findings = [scan_description(s) for s in strings_of(definition)]
    reasons = sorted({r for f in findings for r in f.reasons})
    return DescriptionFinding(
        any(f.suspicious for f in findings), max((f.score for f in findings), default=0), reasons
    )
