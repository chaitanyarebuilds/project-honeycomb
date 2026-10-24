"""Approvals (F10): a person says yes before a risky call goes through.

A request is bound to the exact call: the run, the tool and the digest of its arguments. It needs
``quorum`` different people to approve it, one "no" ends it, and a request nobody answers in time
is denied. An approved call can be used once, within a short window, and only by the run that
asked. The files live in the state folder next to the CLI, which is how a person answers.

The approver names are whatever the operator types (``--as``, or the login name). Phase 0 has no
sign-in, so quorum protects against a slip, not against someone who is willing to lie.
"""

import hashlib
import json
import re
import time
import unicodedata
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from honeycomb_gate.events import ulid_like
from honeycomb_gate.locking import FileLock, write_json_atomic


@dataclass
class Approval:
    id: str
    key: str  # sha256 of run id, tool and arguments digest
    run_id: str
    agent_id: str
    tool: str
    rule_id: str
    quorum: int
    args_redacted: Any
    blast_radius: str
    created: float
    expires: float  # a pending request is denied after this
    status: str = "pending"  # pending | approved | denied | expired | used
    approved_until: float = 0.0
    decisions: list[dict[str, Any]] = field(default_factory=list)

    @property
    def approvers(self) -> list[str]:
        return [d["by"] for d in self.decisions if d["verdict"] == "approve"]


_INVISIBLE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u00ad\ufeff\x00-\x1f\x7f]")


def who(name: str) -> str:
    """An approver's name in one canonical shape: no case, spacing or look-alike tricks."""
    return unicodedata.normalize("NFKC", _INVISIBLE.sub("", name)).strip().casefold()


def call_key(run_id: str, tool: str, args_digest: str) -> str:
    return hashlib.sha256(f"{run_id}|{tool}|{args_digest}".encode()).hexdigest()


class ApprovalStore:
    def __init__(self, directory: Path) -> None:
        self.dir = directory
        self._lock = FileLock(directory / ".lock")

    def _path(self, approval_id: str) -> Path:
        return self.dir / f"{approval_id}.json"

    def _load(self, path: Path) -> Approval:
        return Approval(**json.loads(path.read_text("utf-8")))

    def _save(self, a: Approval) -> None:
        write_json_atomic(self._path(a.id), asdict(a), indent=2)

    def get(self, approval_id: str) -> Approval | None:
        # Ids come from the command line: only an id we could have made reaches the filesystem.
        if not approval_id.startswith("apr_") or not approval_id[4:].isalnum():
            return None
        path = self._path(approval_id)
        return self._load(path) if path.exists() else None

    def all(self) -> list[Approval]:
        if not self.dir.exists():
            return []
        found = [self._load(p) for p in self.dir.glob("apr_*.json")]
        return sorted(found, key=lambda a: a.created)

    def request(
        self, *, key: str, run_id: str, agent_id: str, tool: str, rule_id: str, quorum: int,
        args_redacted: Any, blast_radius: str, timeout_s: float, now: float | None = None,
    ) -> tuple[Approval, bool]:  # fmt: skip
        """The open request for this exact call, or a new one. The flag says if it is new."""
        now = time.time() if now is None else now
        with self._lock:
            for a in self.all():
                if a.key == key and a.status in {"pending", "approved"} and a.expires > now:
                    if a.status == "pending" or a.approved_until > now:
                        return a, False
            made = Approval(
                id=f"apr_{ulid_like()}", key=key, run_id=run_id, agent_id=agent_id, tool=tool,
                rule_id=rule_id, quorum=quorum, args_redacted=args_redacted,
                blast_radius=blast_radius, created=now, expires=now + timeout_s,
            )  # fmt: skip
            self._save(made)
            return made, True

    def decide(
        self, approval_id: str, by: str, verdict: str, *, ttl_s: float, now: float | None = None
    ) -> str:
        """Record a person's answer. Returns ok, unknown, unnamed, closed, expired or duplicate."""
        now = time.time() if now is None else now
        by = who(by)
        if not by:
            return "unnamed"
        with self._lock:
            a = self.get(approval_id)
            if a is None:
                return "unknown"
            if a.status != "pending":
                return "closed"
            if a.expires <= now:  # too late; the sweep closes it and says so in the log
                return "expired"
            if any(d["by"] == by for d in a.decisions):
                return "duplicate"  # one person is one voice, whatever they typed twice
            a.decisions.append({"by": by, "verdict": verdict, "at": now})
            if verdict == "deny":
                a.status = "denied"
            elif len(a.approvers) >= a.quorum:
                a.status, a.approved_until = "approved", now + ttl_s
            self._save(a)
            return "ok"

    def consume(self, key: str, now: float | None = None) -> Approval | None:
        """Use up an approved request for this exact call, once."""
        now = time.time() if now is None else now
        with self._lock:
            for a in self.all():
                if a.key == key and a.status == "approved" and a.approved_until > now:
                    a.status = "used"
                    self._save(a)
                    return a
        return None

    def sweep(self, now: float | None = None) -> list[Approval]:
        """Close requests nobody answered in time, and approvals nobody used. Returns the former."""
        now = time.time() if now is None else now
        timed_out: list[Approval] = []
        with self._lock:
            for a in self.all():
                if a.status == "pending" and a.expires <= now:
                    a.status = "expired"
                    self._save(a)
                    timed_out.append(a)
                elif a.status == "approved" and a.approved_until <= now:
                    a.status = "expired"
                    self._save(a)
        return timed_out
