"""Incidents: what happened, how sure we are, what the gate did and what a person should do.

Every message answers the five questions in docs/program/DEFENCE-MODEL.md, so someone woken
at 3 AM can act without reading logs first.
"""

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from honeycomb_gate.events import ulid_like
from honeycomb_gate.locking import FileLock, write_json_atomic
from honeycomb_gate.redact import sanitize_name

POSTURE_NOTE = (
    "Enforcement level L1: the gate is checking calls, but nothing stops this agent from "
    "reaching tools or the internet another way. Network enforcement arrives in a later "
    "milestone (see ADR-0004)."
)


@dataclass
class Incident:
    id: str
    severity: str
    kind: str  # decoy.tripped | honeytoken.used
    title: str
    run_id: str
    agent_id: str
    tool: str
    opened_at: str
    what: str
    confidence: str
    actions: list[str]
    next_steps: list[str]
    evidence: list[dict[str, str]] = field(default_factory=list)
    posture: str = POSTURE_NOTE
    state: str = "open"  # open | acknowledged | closed
    acknowledged_by: str | None = None
    notifications: list[dict[str, str]] = field(default_factory=list)
    escalations: int = 0  # how many times it was sent again because nobody acknowledged it
    escalated_at: str | None = None


class IncidentStore:
    def __init__(self, directory: Path) -> None:
        self.dir = directory
        self._lock = FileLock(directory / ".lock")

    def add_notifications(self, incident_id: str, results: list[dict[str, str]]) -> None:
        """Append send results to the stored incident without undoing an acknowledgement."""
        with self._lock:
            current = self.get(incident_id)
            if current is not None:
                current.notifications.extend(results)
                self.save(current)

    def save(self, incident: Incident) -> None:
        write_json_atomic(self.dir / f"{incident.id}.json", asdict(incident), indent=2)

    def get(self, incident_id: str) -> Incident | None:
        path = self.dir / f"{incident_id}.json"
        if not path.exists():
            return None
        return Incident(**json.loads(path.read_text("utf-8")))

    def all(self) -> list[Incident]:
        if not self.dir.exists():
            return []
        return sorted(
            (Incident(**json.loads(p.read_text("utf-8"))) for p in self.dir.glob("*.json")),
            key=lambda i: i.opened_at,
        )

    def due_for_escalation(self, now: datetime, after_s: int, limit: int) -> list[Incident]:
        """Open high or critical incidents that have gone unanswered for ``after_s`` seconds."""
        if after_s <= 0:
            return []
        due = []
        for i in self.all():
            if i.state != "open" or i.severity not in {"high", "critical"}:
                continue
            if i.escalations >= limit:
                continue
            since = datetime.fromisoformat(i.escalated_at or i.opened_at)
            if (now - since).total_seconds() >= after_s:
                due.append(i)
        return due

    def record_escalation(self, incident_id: str, now: datetime, after_s: int, limit: int) -> int:
        """Count one more escalation unless it was acknowledged, is not due or is at its limit.

        The checks are repeated under the lock, so two gates can't both send the same one.
        """
        with self._lock:
            incident = self.get(incident_id)
            if incident is None or incident.state != "open" or incident.escalations >= limit:
                return 0
            since = datetime.fromisoformat(incident.escalated_at or incident.opened_at)
            if (now - since).total_seconds() < after_s:
                return 0
            incident.escalations += 1
            incident.escalated_at = now.isoformat(timespec="seconds")
            self.save(incident)
            return incident.escalations

    def acknowledge(self, incident_id: str, by: str) -> bool:
        with self._lock:
            incident = self.get(incident_id)
            if incident is None:
                return False
            incident.state = "acknowledged"
            incident.acknowledged_by = by
            self.save(incident)
            return True


def _evidence(events: list[dict[str, Any]]) -> list[dict[str, str]]:
    return [
        {
            "time": str(e["ts"]),
            "event": str(e["kind"]),
            "tool": str(e.get("tool") or ""),
            "decision": str(e.get("decision") or ""),
        }
        for e in events
        if e["kind"] not in {"tool.pinned", "tools.listed"}  # routine noise
    ]


def open_decoy_incident(
    *, run_id: str, agent_id: str, tool: str, events: list[dict[str, Any]], config_hint: str
) -> Incident:
    tool = sanitize_name(tool)  # agent-chosen text: never let it shape the message
    agent_id = sanitize_name(agent_id)
    short = tool.split("__", 1)[-1]
    return Incident(
        id="inc_" + ulid_like()[:16],
        severity="critical",
        kind="decoy.tripped",
        title=f"Agent '{agent_id}' called decoy tool '{short}'",
        run_id=run_id,
        agent_id=agent_id,
        tool=tool,
        opened_at=datetime.now(UTC).isoformat(timespec="seconds"),
        what=f"Agent '{agent_id}' tried to use '{tool}'. That tool is a decoy: it does not exist "
        "upstream and no real task needs it.",
        confidence="Very high. Legitimate runs never touch decoys, so this is almost certainly "
        "an agent that was hijacked (for example by instructions hidden in a document) or one "
        "that is out of control.",
        actions=[
            "Blocked the call; it was never forwarded to any real tool.",
            "Paused the run. Every later call is refused until a person resumes it, even if "
            "the gate is restarted.",
            f"Retired run identity {run_id}; it can never be used again. A resume issues a "
            "new one.",
            "Returned made-up data so the agent keeps going in a dead end.",
        ],
        next_steps=[
            f"Review what the run did: honeycomb-gate events query --run {run_id} {config_hint}",
            "Find what steered the agent here: look at the documents, pages and tool output it "
            "read just before this call.",
            "If it was a hijack, rotate any credential the agent could reach. The gate has not "
            "rotated anything.",
            f"Only when you are satisfied, resume with: honeycomb-gate runs resume {run_id} "
            f"{config_hint}",
        ],
        evidence=_evidence(events),
    )


def open_token_incident(
    *,
    run_id: str,
    agent_id: str,
    tool: str,
    token_id: str,
    kind: str,
    placed: list[str],
    where: str,
    events: list[dict[str, Any]],
    config_hint: str,
) -> Incident:
    tool = sanitize_name(tool)
    agent_id = sanitize_name(agent_id)
    where_text = "in the arguments of a tool call" if where == "arguments" else "in a tool's result"
    planted = ", ".join(placed) if placed else "unknown"
    return Incident(
        id="inc_" + ulid_like()[:16],
        severity="critical",
        kind="honeytoken.used",
        title=f"Agent '{agent_id}' touched planted {kind} credential {token_id}",
        run_id=run_id,
        agent_id=agent_id,
        tool=tool,
        opened_at=datetime.now(UTC).isoformat(timespec="seconds"),
        what=f"A fake {kind} credential (id {token_id}, planted at: {planted}) appeared "
        f"{where_text} for '{tool}'.",
        confidence="Very high. The credential is fake and only exists where we planted it, so "
        "something went looking for it and picked it up.",
        actions=[
            "Blocked the call, or withheld the result, so the credential did not move on.",
            "Paused the run until a person resumes it, even if the gate is restarted.",
            f"Retired run identity {run_id}; it can never be used again. A resume issues a "
            "new one.",
        ],
        next_steps=[
            f"Review what the run did: honeycomb-gate events query --run {run_id} {config_hint}",
            f"Check how the agent found {planted}: what task was it on, and what steered it?",
            "Look in your network and proxy logs for any use of the fake credential elsewhere.",
            f"Resume only when satisfied: honeycomb-gate runs resume {run_id} {config_hint}",
        ],
        evidence=_evidence(events),
    )


def render_text(i: Incident) -> str:
    lines = [
        f"INCIDENT {i.id}  [{i.severity.upper()}]",
        i.title,
        "",
        "1. WHAT HAPPENED",
        f"   {i.what}",
        "",
        "2. HOW SURE ARE WE",
        f"   {i.confidence}",
        "",
        "3. WHAT THE GATE ALREADY DID",
        *[f"   - {a}" for a in i.actions],
        "",
        "4. WHAT YOU SHOULD DO NOW",
        *[f"   {n}. {s}" for n, s in enumerate(i.next_steps, start=1)],
        "",
        "5. HOW PROTECTED ARE WE",
        f"   {i.posture}",
        "",
        f"Run: {i.run_id}   Agent: {i.agent_id}   Opened (UTC): {i.opened_at}",
        "",
        "RECENT ACTIVITY IN THIS RUN",
        *[f"   {e['time']}  {e['event']:<24} {e['tool']}" for e in i.evidence[-12:]],
        "",
        "Acknowledge: honeycomb-gate incidents ack " + i.id,
    ]
    return "\n".join(lines)
