"""The governor: approvals, caps and escalation (F10, F4, F11), the parts of M4 that say "not yet".

It sits beside the gate and uses its run, its log and its notifier. Anything that goes wrong in
here ends in a refusal: a call that needs a person's yes never goes through because of an error.
"""

import asyncio
import json
import time
from collections import deque
from collections.abc import Callable
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import mcp.types as types

from honeycomb_gate.approvals import Approval, ApprovalStore, call_key
from honeycomb_gate.policy import Decision

if TYPE_CHECKING:
    from honeycomb_gate.proxy import Gate, Run

POLL_S = 0.25
SWEEP_S = 2.0
MAX_PENDING = 50  # open requests per agent; past that the call is refused outright
Deny = Callable[..., types.CallToolResult]


def _rows_in(value: Any) -> int:
    """The largest list anywhere in ``value``, or a map of records, counted by its entries."""
    best, stack = 0, [value]
    while stack:
        item = stack.pop()
        if isinstance(item, list):
            best = max(best, len(item))
            stack.extend(item)
        elif isinstance(item, dict):
            values = list(item.values())
            if values and all(isinstance(v, dict | list) for v in values):
                best = max(best, len(values))  # a mapping of records
            stack.extend(values)
    return best


def count_rows(result: types.CallToolResult) -> int:
    """Rows in an answer: items of the biggest JSON list in it, else the lines of text.

    Looks at text, embedded resources and structured content, at any depth.
    """
    rows = _rows_in(result.structured_content)
    for item in result.content:
        resource = getattr(item, "resource", None)
        text = getattr(item, "text", None) or getattr(resource, "text", None)
        if not isinstance(text, str):
            continue
        try:
            rows = max(rows, _rows_in(json.loads(text)))
        except (ValueError, RecursionError):
            rows = max(rows, sum(1 for line in text.splitlines() if line.strip()))
    return rows


class Governor:
    def __init__(self, gate: "Gate") -> None:
        self.gate = gate
        self.store = ApprovalStore(gate.config.approvals_dir)
        self._calls: dict[tuple[str, str], deque[float]] = {}

    # -- caps -----------------------------------------------------------------------------------

    def within_rate(self, run: "Run", decision: Decision, *, record: bool = True) -> bool:
        """Is there room under the rule's per-minute cap? With ``record``, this call uses a slot."""
        limit = decision.caps.get("per_minute")
        if limit is None:
            return True
        now = time.monotonic()
        window = self._calls.setdefault((run.agent_id, decision.rule_id), deque())
        while window and now - window[0] > 60:
            window.popleft()
        if len(window) >= limit:
            return False
        if record:
            window.append(now)
        return True

    @staticmethod
    def over_result_cap(result: types.CallToolResult, decision: Decision) -> str | None:
        caps = decision.caps
        if "max_result_bytes" in caps:
            payload = result.model_dump(by_alias=True, exclude_none=True)
            if len(json.dumps(payload, default=str)) > caps["max_result_bytes"]:
                return "cap_max_result_bytes"
        if "max_rows" in caps and count_rows(result) > caps["max_rows"]:
            return "cap_max_rows"
        return None

    # -- approvals --------------------------------------------------------------------------------

    async def approval(
        self, run: "Run", decision: Decision, tool: str, base: dict[str, Any], deny: Deny
    ) -> types.CallToolResult | None:
        """None if the call may go ahead; otherwise the answer to give the agent."""
        try:
            return await self._approval(run, decision, tool, base, deny)
        except Exception as exc:  # fail closed: an error never counts as a yes
            run.emit("gate.error", severity="high", details={"error": type(exc).__name__}, **base)
            return deny("approval_error", decision.rule_id, "high")

    async def _approval(
        self, run: "Run", decision: Decision, tool: str, base: dict[str, Any], deny: Deny
    ) -> types.CallToolResult | None:
        cfg = self.gate.config.defaults
        store = self.store
        key = call_key(run.id, tool, base["args_digest"])

        def approved(a: Approval) -> None:
            run.emit(
                "call.approved",
                decision="approve",
                rule_id=decision.rule_id,
                details={"approval_id": a.id, "approvers": a.approvers},
                **base,
            )

        used = await asyncio.to_thread(store.consume, key)
        if used is not None:
            approved(used)
            return None
        open_now = [a for a in await asyncio.to_thread(store.all) if a.status == "pending"]
        if sum(1 for a in open_now if a.agent_id == run.agent_id) >= MAX_PENDING:
            return deny("too_many_approvals_pending", decision.rule_id, "high")
        radius = (
            f"{'high-impact' if self.gate.policy.is_high_impact(tool) else 'ordinary'} tool, "
            f"needs {decision.quorum} approver(s), caps: {decision.caps or 'none'}"
        )
        request, new = await asyncio.to_thread(
            lambda: store.request(
                key=key,
                run_id=run.id,
                agent_id=run.agent_id,
                tool=tool,
                rule_id=decision.rule_id,
                quorum=decision.quorum,
                args_redacted=base["args_redacted"],
                blast_radius=radius,
                timeout_s=cfg.approval_timeout_s,
            )
        )
        if new:
            run.emit(
                "call.approval_requested",
                severity="medium",
                decision="pending",
                rule_id=decision.rule_id,
                details={
                    "approval_id": request.id,
                    "quorum": request.quorum,
                    "expires_in_s": cfg.approval_timeout_s,
                    "blast_radius": radius,
                },
                **base,
            )
            self.gate._spawn(self._tell_a_person(request))
        deadline = time.monotonic() + cfg.approval_wait_s
        while True:
            current = await asyncio.to_thread(store.get, request.id)
            if current is None:
                return deny("approval_lost", decision.rule_id, "high")
            if current.status == "approved":
                used = await asyncio.to_thread(store.consume, key)
                if used is not None:
                    approved(used)
                    return None
            elif current.status == "denied":
                run.emit(
                    "call.approval_denied",
                    severity="medium",
                    decision="deny",
                    rule_id=decision.rule_id,
                    details={
                        "approval_id": current.id,
                        "by": [d["by"] for d in current.decisions if d["verdict"] == "deny"],
                    },
                    **base,
                )
                return deny("approval_denied", decision.rule_id, "medium")
            elif current.status in {"expired", "used"} or current.expires <= time.time():
                return deny("approval_timeout", decision.rule_id, "medium")  # the sweep logs it
            if run.paused:
                return deny("run_paused", "run-control", "medium")
            if time.monotonic() >= deadline:
                deny("approval_pending", decision.rule_id, "low")
                message = (
                    f"This call needs a person's approval (request {request.id}, code "
                    "approval_pending). Ask the user to approve it, then make the same call again."
                )
                return types.CallToolResult(
                    is_error=True, content=[types.TextContent(type="text", text=message)]
                )
            await asyncio.sleep(POLL_S)

    async def _tell_a_person(self, a: Approval) -> None:
        cfg = self.gate.config.defaults
        text = (
            f"Agent {a.agent_id} wants to call {a.tool}.\n"
            f"Rule: {a.rule_id}. {a.blast_radius}.\n"
            f"Arguments (secrets hidden): {json.dumps(a.args_redacted, default=str)[:600]}\n\n"
            f"Approve:  honeycomb-gate approvals approve {a.id}\n"
            f"Refuse:   honeycomb-gate approvals deny {a.id}\n"
            f"No answer within {cfg.approval_timeout_s} s counts as a refusal."
        )
        subject = f"{self.gate.config.notify.subject_prefix} approval needed: {a.tool}"
        for r in await self.gate.notifier.deliver(
            subject, text, {"approval": a.__dict__, "text": text}
        ):
            if not r.ok:
                self.gate.default.emit(
                    "notify.failed",
                    severity="medium",
                    details={"approval_id": a.id, "channel": r.channel, "error": r.error},
                )

    async def sweep(self) -> None:
        """Say so in the log when a request ran out of time without an answer."""
        for a in await asyncio.to_thread(self.store.sweep):
            self.gate.log.emit(
                "call.approval_timeout",
                severity="medium",
                decision="deny",
                rule_id=a.rule_id,
                run_id=a.run_id,
                agent_id=a.agent_id,
                tool=a.tool,
                details={"approval_id": a.id, "approvers_so_far": a.approvers},
            )

    # -- escalation -------------------------------------------------------------------------------

    async def escalate(self, now: datetime | None = None) -> int:
        """Send incidents nobody has acknowledged again. Returns how many were sent."""
        gate, cfg = self.gate, self.gate.config.notify
        now = now or datetime.now(UTC)
        due = await asyncio.to_thread(
            gate.incidents.due_for_escalation, now, cfg.escalate_after_s, cfg.escalate_max
        )
        for incident in due:
            n = await asyncio.to_thread(
                gate.incidents.record_escalation,
                incident.id,
                now,
                cfg.escalate_after_s,
                cfg.escalate_max,
            )
            if not n:  # acknowledged a moment ago
                continue
            gate.default.emit(
                "incident.escalated",
                severity="high",
                details={"incident_id": incident.id, "escalation": n},
            )
            for r in await gate.notifier.send(incident, escalation=n):
                if not r.ok:
                    gate.default.emit(
                        "notify.failed",
                        severity="medium",
                        details={
                            "incident_id": incident.id,
                            "channel": r.channel,
                            "error": r.error,
                        },
                    )
        return len(due)

    async def loop(self) -> None:
        """Background: close out old requests and escalate, until cancelled."""
        after = self.gate.config.notify.escalate_after_s
        escalate_every = max(1.0, min(30.0, after / 4)) if after else 0.0
        last = 0.0
        while True:
            try:
                await self.sweep()
                if escalate_every and time.monotonic() - last >= escalate_every:
                    last = time.monotonic()
                    await self.escalate()
            except Exception as exc:
                self.gate.default.emit(
                    "gate.error",
                    severity="high",
                    details={"error": type(exc).__name__, "while": "governor"},
                )
            await asyncio.sleep(SWEEP_S)
