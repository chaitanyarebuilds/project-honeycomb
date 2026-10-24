"""Reading the egress proxy's records into the gate (F8).

The proxy writes one JSON line per request. We treat that file as untrusted data: every line is
checked for shape, nothing in it is executed, and a flood of blocked requests is summarised
instead of filling the log. A line that carries a honeytoken id trips the runs of the agent the
source address belongs to. The proxy can't tell runs apart, so that is every active run of the
agent, and the event says so.
"""

import asyncio
import contextlib
import hashlib
import json
import time
from typing import Any

from honeycomb_gate.locking import read_json, write_json_atomic
from honeycomb_gate.proxy import Gate, Run
from honeycomb_gate.redact import sanitize_name
from honeycomb_gate.tokens import Sighting

MAX_LINE = 8 * 1024  # the proxy writes lines of about 200 bytes
MAX_READ = 1_000_000  # bytes taken from the file in one poll
WINDOW_S = 10.0
EVENTS_PER_WINDOW = 50  # blocked requests logged one by one; more are counted
VERDICTS = {"allowed", "blocked"}


def _valid(entry: Any) -> bool:
    return (
        isinstance(entry, dict)
        and isinstance(entry.get("src_ip"), str)
        and isinstance(entry.get("host"), str)
        and isinstance(entry.get("port"), int)
        and entry.get("verdict") in VERDICTS
        and isinstance(entry.get("reason"), str)
        and isinstance(entry.get("honeytoken_id", ""), str)
    )


def _parse(raw: bytes) -> Any:
    """One line as JSON, or None if it is too long, not JSON, or nested absurdly deep."""
    if len(raw) > MAX_LINE:
        return None
    try:
        return json.loads(raw)
    except (ValueError, RecursionError):
        return None


class EgressWatch:
    def __init__(self, gate: Gate) -> None:
        self.gate = gate
        self.path = gate.config.egress.log
        self.offset_path = gate.config.egress_offset_path
        self._window = 0.0
        self._count = 0
        self._suppressed = 0
        self._next: dict[str, Any] | None = None  # where to resume once this batch is handled

    # -- reading the file ---------------------------------------------------------------------

    def _position(self) -> dict[str, Any]:
        saved = read_json(self.offset_path, {})
        offset = saved.get("offset")
        # A damaged offset file means "start again", never "stop reading".
        return saved if isinstance(offset, int) and offset >= 0 else {}

    def read_new(self) -> list[Any]:
        """Complete new lines since the last poll. A torn last line waits for its newline."""
        assert self.path is not None
        try:
            stat = self.path.stat()
        except FileNotFoundError:
            return []
        saved = self._position()
        offset = int(saved.get("offset", 0))
        with self.path.open("rb") as f:
            first = f.readline(1024)
            head = hashlib.sha256(first).hexdigest() if first.endswith(b"\n") else ""
            # A different inode, a shorter file or a different first line means a new file, even
            # when the system reused the inode number.
            if (
                stat.st_ino != saved.get("inode")
                or stat.st_size < offset
                or (saved.get("head") and head != saved["head"])
            ):
                offset = 0
            f.seek(offset)
            chunk = f.read(MAX_READ)
        end = chunk.rfind(b"\n") + 1
        if end == 0 and len(chunk) == MAX_READ:  # one line longer than we will ever read: skip it
            end = len(chunk)
        body = chunk[:end]
        raws = body.split(b"\n")[:-1] if body.endswith(b"\n") else ([body] if body else [])
        entries = [_parse(raw) for raw in raws]
        self._next = {"offset": offset + end, "inode": stat.st_ino, "head": head}
        return entries

    def commit(self) -> None:
        """Remember how far we have read. Done after the batch is handled, never before."""
        if self._next is not None:
            write_json_atomic(self.offset_path, self._next)
            self._next = None

    # -- turning lines into events ------------------------------------------------------------

    async def process(self, entries: list[Any]) -> None:
        bad = sum(1 for e in entries if not _valid(e))
        if bad:
            self.gate.default.emit("egress.malformed", severity="medium", details={"lines": bad})
        for entry in entries:
            if not (_valid(entry) and entry["verdict"] == "blocked"):
                continue
            try:  # one failing line must not cost the lines after it
                await self._blocked(entry)
            except Exception as exc:
                with contextlib.suppress(Exception):
                    self.gate.default.emit(
                        "gate.error", severity="high",
                        details={"error": type(exc).__name__, "while": "handling an egress line"},
                    )  # fmt: skip

    def _may_log(self) -> bool:
        now = time.monotonic()
        if now - self._window >= WINDOW_S:
            if self._suppressed:
                self.gate.default.emit(
                    "egress.blocked", severity="low", details={"suppressed": self._suppressed}
                )
            self._window, self._count, self._suppressed = now, 0, 0
        self._count += 1
        if self._count > EVENTS_PER_WINDOW:
            self._suppressed += 1
            return False
        return True

    async def _blocked(self, entry: dict[str, Any]) -> None:
        gate = self.gate
        token_id = entry.get("honeytoken_id", "")
        agent = gate.config.egress.sources.get(entry["src_ip"])
        hit = next((t for t in gate.tokens.tokens() if t.id == token_id and not t.revoked), None)
        details = {
            "host": sanitize_name(entry["host"])[:253],
            "port": entry["port"],
            "reason": sanitize_name(entry["reason"])[:40],
            "source": sanitize_name(entry["src_ip"])[:45],
        }
        if hit is None:
            if self._may_log():
                gate.default.emit(
                    "egress.blocked", severity="medium", decision="deny", details=details
                )
            return
        runs: list[Run] = gate.active_runs(agent) or [gate.default]
        scope = "agent-wide" if agent else "all-agents"
        sighting = Sighting(hit.id, hit.kind, hit.placed)
        for run in runs:
            try:  # every run gets its turn, even if one of them fails
                run.emit(
                    "egress.blocked", severity="high", decision="deny",
                    details={**details, "attribution": scope},
                )  # fmt: skip
                await gate._trip_token(
                    run, sighting, "egress", f"egress:{details['host']}", {"upstream": "egress"}, {}
                )
            except Exception as exc:
                with contextlib.suppress(Exception):
                    run.emit(
                        "gate.error", severity="high",
                        details={"error": type(exc).__name__, "while": "pausing after egress"},
                    )  # fmt: skip

    # -- the loop -----------------------------------------------------------------------------

    async def poll(self) -> None:
        await self.process(await asyncio.to_thread(self.read_new))
        self.commit()

    async def run(self) -> None:
        poll = self.gate.config.egress.poll_s
        while True:
            try:
                await self.poll()
            except Exception as exc:  # a bad poll must not stop the next one
                with contextlib.suppress(Exception):
                    self.gate.default.emit(
                        "gate.error", severity="high",
                        details={"error": type(exc).__name__, "while": "reading egress log"},
                    )  # fmt: skip
            await asyncio.sleep(poll)
