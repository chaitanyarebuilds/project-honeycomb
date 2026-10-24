"""Approvals, caps, escalation and baselines inside the gate, with a fake upstream."""

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import mcp.types as types

from honeycomb_gate.incidents import Incident
from honeycomb_gate.proxy import Gate
from test_gate_robustness import FakeClient, events, make_gate, tool

APPROVE = {"id": "approve-rotate", "match": {"tool": "sample__t"}, "action": "approve"}
FAST = {"approval_wait_s": 0.4, "approval_timeout_s": 3, "approval_ttl_s": 60}


class TextClient(FakeClient):
    """A fake upstream whose answer we choose."""

    def __init__(self, text: str = "ok") -> None:
        super().__init__({None: types.ListToolsResult(tools=[tool(), tool("u")])})
        self.text = text

    async def call_tool(self, name: str, arguments: dict[str, Any] | None) -> types.CallToolResult:
        self.calls.append(name)
        return types.CallToolResult(content=[types.TextContent(type="text", text=self.text)])


async def call(gate: Gate, name: str = "sample__t", **args: Any) -> types.CallToolResult:
    params = types.CallToolRequestParams(name=name, arguments=args)
    return await gate.call_tool(SimpleNamespace(), params)  # type: ignore[arg-type]


def say(result: types.CallToolResult) -> str:
    return str(result.content[0].text)  # type: ignore[union-attr]


def kinds(gate: Gate) -> list[str]:
    return [e["kind"] for e in events(gate)]


def pending(gate: Gate) -> Any:
    return next(a for a in gate.governor.store.all() if a.status == "pending")


def answer(gate: Gate, who: str, verdict: str = "approve") -> str:
    return gate.governor.store.decide(pending(gate).id, who, verdict, ttl_s=60)


def make(
    tmp_path: Path, client: FakeClient | None = None, **config: Any
) -> tuple[Gate, FakeClient]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    client = client or TextClient()
    defaults = {**FAST, **config.pop("defaults", {})}
    return make_gate(tmp_path, client, defaults=defaults, **config), client


# -- approvals ---------------------------------------------------------------------------------


async def test_a_call_that_needs_approval_is_held_then_goes_through_once(tmp_path: Path) -> None:
    gate, client = make(tmp_path, rules=[APPROVE])
    first = await call(gate, x=1)
    assert first.is_error and "approval_pending" in say(first) and client.calls == []
    assert kinds(gate).count("call.approval_requested") == 1
    assert answer(gate, "asha") == "ok"
    done = await call(gate, x=1)
    assert not done.is_error and client.calls == ["t"]
    k = kinds(gate)
    assert k.index("call.approved") < k.index("call.allowed") < k.index("call.completed")
    again = await call(gate, x=1)  # the approval is used up
    assert again.is_error and client.calls == ["t"]


async def test_an_answer_that_arrives_during_the_wait_lets_the_first_call_through(
    tmp_path: Path,
) -> None:
    gate, client = make(tmp_path, rules=[APPROVE], defaults={"approval_wait_s": 3})
    task = asyncio.create_task(call(gate, x=1))
    for _ in range(40):  # wait for the request to appear
        await asyncio.sleep(0.05)
        if gate.governor.store.all():
            break
    answer(gate, "asha")
    result = await asyncio.wait_for(task, 5)
    assert not result.is_error and client.calls == ["t"]


async def test_quorum_needs_two_different_people(tmp_path: Path) -> None:
    rule = {**APPROVE, "quorum": 2}
    gate, client = make(tmp_path, rules=[rule])
    await call(gate, x=1)
    answer(gate, "asha")
    assert (await call(gate, x=1)).is_error and client.calls == []  # one yes is not enough
    assert answer(gate, "asha") == "duplicate"
    answer(gate, "ravi")
    assert not (await call(gate, x=1)).is_error and client.calls == ["t"]


async def test_a_no_ends_it_and_is_logged_with_who_said_it(tmp_path: Path) -> None:
    gate, client = make(tmp_path, rules=[APPROVE], defaults={"approval_wait_s": 3})
    task = asyncio.create_task(call(gate, x=1))
    for _ in range(40):
        await asyncio.sleep(0.05)
        if gate.governor.store.all():
            break
    answer(gate, "asha", "deny")
    result = await asyncio.wait_for(task, 5)
    assert result.is_error and client.calls == []
    denied = next(e for e in events(gate) if e["kind"] == "call.approval_denied")
    assert denied["details"]["by"] == ["asha"]


async def test_no_answer_in_time_is_a_denial_and_a_late_yes_is_refused(tmp_path: Path) -> None:
    gate, client = make(tmp_path, rules=[APPROVE], defaults={"approval_timeout_s": 1})
    await call(gate, x=1)
    await asyncio.sleep(1.2)
    await gate.governor.sweep()
    assert kinds(gate).count("call.approval_timeout") == 1
    await gate.governor.sweep()
    assert kinds(gate).count("call.approval_timeout") == 1  # said once
    assert gate.governor.store.all()[0].status == "expired"
    retry = await call(gate, x=1)  # asks again, from scratch
    assert retry.is_error and client.calls == [] and len(gate.governor.store.all()) == 2


async def test_an_approval_is_for_those_exact_arguments_and_that_run(tmp_path: Path) -> None:
    gate, client = make(tmp_path, rules=[APPROVE])
    await call(gate, amount=1)
    answer(gate, "asha")
    assert (await call(gate, amount=5000)).is_error  # a different call
    assert client.calls == []
    gate.default.id = "run_somebody_else"  # the same call from another run
    assert (await call(gate, amount=1)).is_error and client.calls == []


async def test_a_paused_run_stops_waiting(tmp_path: Path) -> None:
    gate, client = make(tmp_path, rules=[APPROVE], defaults={"approval_wait_s": 5})
    task = asyncio.create_task(call(gate, x=1))
    await asyncio.sleep(0.5)
    gate.default.paused = True
    result = await asyncio.wait_for(task, 3)
    assert result.is_error and client.calls == []


async def test_an_error_in_the_approval_path_never_counts_as_a_yes(tmp_path: Path) -> None:
    gate, client = make(tmp_path, rules=[APPROVE])

    def boom(*a: Any, **k: Any) -> Any:
        raise OSError("disk full")

    gate.governor.store.request = boom  # type: ignore[method-assign]
    result = await call(gate, x=1)
    assert result.is_error and client.calls == [] and "gate.error" in kinds(gate)


async def test_a_flood_of_requests_is_refused_past_the_limit(tmp_path: Path) -> None:
    from honeycomb_gate.governor import MAX_PENDING

    gate, client = make(tmp_path, rules=[APPROVE], defaults={"approval_wait_s": 0})
    for i in range(MAX_PENDING + 3):
        await call(gate, n=i)
    assert len(gate.governor.store.all()) == MAX_PENDING
    assert "too_many_approvals_pending" in json.dumps(events(gate))


# -- caps --------------------------------------------------------------------------------------


async def test_a_per_minute_cap_stops_the_next_call_but_not_other_tools(tmp_path: Path) -> None:
    rule = {"id": "cap", "match": {"tool": "sample__t"}, "action": "allow",
            "caps": {"per_minute": 2}}  # fmt: skip
    gate, client = make(tmp_path, rules=[rule])
    assert not (await call(gate)).is_error and not (await call(gate)).is_error
    assert (await call(gate)).is_error and client.calls == ["t", "t"]
    assert not (await call(gate, "sample__u")).is_error  # a look-alike tool has no cap
    assert any(e["details"].get("reason") == "rate_limit" for e in events(gate) if "details" in e)


async def test_a_big_answer_is_withheld_and_a_small_one_passes(tmp_path: Path) -> None:
    rule = {"id": "cap", "match": {"tool": "sample__t"}, "action": "allow",
            "caps": {"max_rows": 100}}  # fmt: skip
    big = "\n".join(["id,name"] + [f"{i},x" for i in range(300)])
    gate, client = make(tmp_path, TextClient(big), rules=[rule])
    result = await call(gate)
    assert result.is_error and client.calls == ["t"]  # it ran, but the data did not come back
    assert "big" not in say(result) and "cap_max_rows" in json.dumps(events(gate))
    gate2, _ = make(tmp_path / "b", TextClient("\n".join(["id,name"] + ["1,x"] * 20)), rules=[rule])
    assert not (await call(gate2)).is_error


async def test_rows_are_counted_in_json_lists_and_objects_too(tmp_path: Path) -> None:
    rule = {"id": "cap", "match": {"tool": "sample__t"}, "action": "allow",
            "caps": {"max_rows": 5}}  # fmt: skip
    cases = [
        (json.dumps(list(range(9))), True),
        (json.dumps({"rows": list(range(9))}), True),
        (json.dumps(list(range(3))), False),
    ]
    for n, (body, blocked) in enumerate(cases):
        gate, _ = make(tmp_path / str(n), TextClient(body), rules=[rule])
        assert (await call(gate)).is_error is blocked


async def test_a_byte_cap_withholds_a_large_answer(tmp_path: Path) -> None:
    rule = {"id": "cap", "match": {"tool": "sample__t"}, "action": "allow",
            "caps": {"max_result_bytes": 1000}}  # fmt: skip
    gate, _ = make(tmp_path, TextClient("x" * 5000), rules=[rule])
    assert (await call(gate)).is_error
    gate2, _ = make(tmp_path / "b", TextClient("x" * 100), rules=[rule])
    assert not (await call(gate2)).is_error


# -- escalation --------------------------------------------------------------------------------


def stale_incident(gate: Gate, severity: str = "critical", minutes: int = 20) -> Incident:
    opened = (datetime.now(UTC) - timedelta(minutes=minutes)).isoformat(timespec="seconds")
    incident = Incident(
        id="inc_test", severity=severity, kind="decoy.tripped", title="a decoy was called",
        run_id="run_x", agent_id="bot", tool="crm__x", opened_at=opened, what="w",
        confidence="c", actions=[], next_steps=[],
    )  # fmt: skip
    gate.incidents.save(incident)
    return incident


async def test_an_unanswered_incident_is_sent_again_up_to_the_limit(tmp_path: Path) -> None:
    gate, _ = make(tmp_path, notify={"escalate_after_s": 600, "escalate_max": 2})
    stale_incident(gate)
    now = datetime.now(UTC)
    assert await gate.governor.escalate(now) == 1
    assert await gate.governor.escalate(now) == 0  # just done: not due again yet
    later = now + timedelta(minutes=11)
    assert await gate.governor.escalate(later) == 1
    assert await gate.governor.escalate(later + timedelta(minutes=11)) == 0  # the limit
    assert kinds(gate).count("incident.escalated") == 2


async def test_acknowledged_and_minor_incidents_are_left_alone(tmp_path: Path) -> None:
    gate, _ = make(tmp_path, notify={"escalate_after_s": 600})
    stale_incident(gate)
    gate.incidents.acknowledge("inc_test", "asha")
    assert await gate.governor.escalate() == 0
    stale_incident(gate, severity="medium")
    assert await gate.governor.escalate() == 0


# -- baselines in the gate ---------------------------------------------------------------------


async def test_a_new_tool_after_the_learning_period_raises_a_deviation_event(
    tmp_path: Path,
) -> None:
    gate, client = make(tmp_path, baseline={"min_runs": 3})
    for r in range(3):
        gate.baselines.observe(f"run_old{r}", gate.default.agent_id, "sample", "sample__t", 10, 10)
    await call(gate, "sample__t")
    assert "baseline.deviation" not in kinds(gate)  # a tool it knows
    await call(gate, "sample__u")
    dev = [e for e in events(gate) if e["kind"] == "baseline.deviation"]
    assert (
        len(dev) == 1 and dev[0]["details"]["kind"] == "new_tool" and dev[0]["severity"] == "medium"
    )


# -- fixes from review ------------------------------------------------------------------------


def _text(t: str) -> list[Any]:
    return [types.TextContent(type="text", text=t)]


def test_rows_are_counted_at_any_depth_in_structured_content_and_resources() -> None:
    from honeycomb_gate.governor import count_rows

    nested = json.dumps({"data": {"rows": list(range(1000))}})
    records = json.dumps({str(i): {"n": i} for i in range(1000)})
    assert count_rows(types.CallToolResult(content=_text(nested))) == 1000
    assert count_rows(types.CallToolResult(content=_text(records))) == 1000
    structured = types.CallToolResult(
        content=_text("ok"), structured_content={"rows": list(range(1000))}
    )
    assert count_rows(structured) == 1000
    embedded = types.EmbeddedResource(
        type="resource",
        resource=types.TextResourceContents(uri="file:///x", text="\n".join(["row"] * 1000)),
    )
    assert count_rows(types.CallToolResult(content=[embedded])) == 1000
    one_record = json.dumps({"name": "a", "email": "b"})
    assert count_rows(types.CallToolResult(content=_text(one_record))) <= 2


async def test_a_capped_call_that_ran_says_so_instead_of_claiming_it_was_blocked(
    tmp_path: Path,
) -> None:
    rule = {"id": "cap", "match": {"tool": "sample__t"}, "action": "allow", "caps": {"max_rows": 3}}
    gate, client = make(tmp_path, TextClient("\n".join(["row"] * 50)), rules=[rule])
    result = await call(gate)
    assert result.is_error and "ran" in say(result) and "Do not repeat" in say(result)
    done = next(e for e in events(gate) if e["kind"] == "call.completed")
    assert done["details"]["withheld"] == "cap_max_rows"
    assert "call.denied" not in kinds(gate)


async def test_a_rate_limited_call_does_not_use_up_its_approval(tmp_path: Path) -> None:
    rule = {**APPROVE, "caps": {"per_minute": 1}}
    gate, client = make(tmp_path, rules=[rule])
    await call(gate, n=1)  # two requests are open while the minute is still free
    await call(gate, n=2)
    answer(gate, "asha")
    answer(gate, "asha")
    assert not (await call(gate, n=1)).is_error  # uses the one slot
    assert (await call(gate, n=2)).is_error  # approved, but the minute is used up
    assert [a.status for a in gate.governor.store.all()].count("approved") == 1  # still usable
    assert client.calls == ["t"]
    third = await call(gate, n=3)  # nobody is asked while the cap is used up
    assert third.is_error and len(gate.governor.store.all()) == 2


async def test_a_tool_that_changes_while_a_call_waits_is_not_run_under_the_old_approval(
    tmp_path: Path,
) -> None:
    gate, client = make(tmp_path, rules=[APPROVE])
    await call(gate, x=1)  # pins the definition and asks
    answer(gate, "asha")
    changed = types.Tool(
        name="t", description="now with hidden orders", input_schema={"type": "object"}
    )
    client.pages = {None: types.ListToolsResult(tools=[changed])}
    result = await call(gate, x=1)
    assert result.is_error and client.calls == []
    assert "tool.definition_changed" in kinds(gate)


async def test_a_baseline_failure_never_changes_what_happens_to_a_call(tmp_path: Path) -> None:
    gate, client = make(tmp_path)

    def boom(*a: Any, **k: Any) -> Any:
        raise KeyError("tools")

    gate.baselines.observe = boom  # type: ignore[method-assign]
    result = await call(gate)
    assert not result.is_error and client.calls == ["t"]
    errors = [e for e in events(gate) if e["kind"] == "gate.error"]
    assert any(e["details"].get("while") == "baseline" for e in errors)


async def test_two_gates_do_not_wipe_each_others_baselines(tmp_path: Path) -> None:
    from honeycomb_gate.baseline import BaselineConfig, Baselines

    path = tmp_path / "b.json"
    one, two = Baselines(path, BaselineConfig()), Baselines(path, BaselineConfig())
    one.observe("r1", "agent-a", "crm", "crm__x", 1, 1)
    two.observe("r2", "agent-b", "crm", "crm__y", 1, 1)
    one.flush()
    two.flush()
    assert set(Baselines.load(path)) == {"agent-a", "agent-b"}


def test_escalating_twice_at_once_sends_once(tmp_path: Path) -> None:
    gate, _ = make(tmp_path, notify={"escalate_after_s": 600})
    stale_incident(gate)
    now = datetime.now(UTC)
    assert gate.incidents.record_escalation("inc_test", now, 600, 3) == 1
    assert gate.incidents.record_escalation("inc_test", now, 600, 3) == 0  # the second gate is late


def test_rows_are_added_up_across_content_items_and_binary_items_count() -> None:
    from honeycomb_gate.governor import count_rows

    many = types.CallToolResult(content=[*_text("row"), *(_text("row") * 999)])
    assert count_rows(many) == 1000
    lists = types.CallToolResult(content=[*(_text(json.dumps([1, 2, 3])) * 100)])
    assert count_rows(lists) == 300
    images = types.CallToolResult(
        content=[types.ImageContent(type="image", data="AA==", mime_type="image/png")] * 100
    )
    assert count_rows(images) == 100
