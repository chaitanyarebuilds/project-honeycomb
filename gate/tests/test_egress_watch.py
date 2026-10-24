"""The gate reads the proxy's records as untrusted data and trips the right runs."""

import json
from pathlib import Path
from typing import Any

import mcp.types as types

from honeycomb_gate.egress_watch import EVENTS_PER_WINDOW, MAX_LINE, MAX_READ, EgressWatch
from honeycomb_gate.proxy import Gate, Run
from test_gate_robustness import FakeClient, events, make_gate

SRC = "172.30.0.10"


def gate_with_log(tmp_path: Path, agent: str = "default", **extra: Any) -> tuple[Gate, Path]:
    log = tmp_path / "egress.jsonl"
    client = FakeClient({None: types.ListToolsResult(tools=[])})
    gate = make_gate(
        tmp_path, client, egress={"log": str(log), "sources": {SRC: agent}}, agent_id=agent, **extra
    )
    return gate, log


def line(host: str = "sink", verdict: str = "blocked", src: str = SRC, **extra: Any) -> str:
    entry = {"ts": 1.0, "src_ip": src, "method": "POST", "host": host, "port": 8080,
             "verdict": verdict, "reason": "host_not_allowed", **extra}  # fmt: skip
    return json.dumps(entry) + "\n"


async def feed(gate: Gate, log: Path, *lines: str, watch: EgressWatch | None = None) -> EgressWatch:
    with log.open("a") as f:
        f.writelines(lines)
    watch = watch or EgressWatch(gate)
    await watch.poll()
    return watch


def kinds(gate: Gate) -> list[str]:
    return [e["kind"] for e in events(gate)]


async def test_a_blocked_request_is_logged_and_nothing_is_paused(tmp_path: Path) -> None:
    gate, log = gate_with_log(tmp_path)
    await feed(gate, log, line(), line(verdict="allowed", host="partner-api"))
    blocked = [e for e in events(gate) if e["kind"] == "egress.blocked"]
    assert len(blocked) == 1 and blocked[0]["details"]["host"] == "sink"
    assert not gate.default.paused and "honeytoken.used" not in kinds(gate)


async def test_a_honeytoken_pauses_every_active_run_of_that_agent_only(tmp_path: Path) -> None:
    gate, log = gate_with_log(tmp_path, agent="support-bot")
    token = gate.tokens.create("api-key")
    mine = Run("run_mine", "support-bot", gate.log)
    other = Run("run_other", "billing-bot", gate.log)
    gate.http_runs.update({"run_mine": mine, "run_other": other})
    await feed(gate, log, line(honeytoken_id=token.id, reason="honeytoken"))
    assert gate.default.paused and mine.paused and not other.paused
    trips = [e for e in events(gate) if e["kind"] == "honeytoken.used"]
    assert {e["run_id"] for e in trips} == {gate.default.id, "run_mine"}
    assert all(e["details"]["where"] == "egress" for e in trips)
    egress = [e for e in events(gate) if e["kind"] == "egress.blocked"]
    assert {e["details"]["attribution"] for e in egress} == {"agent-wide"}
    assert token.value not in gate.log.path.read_text()


async def test_a_source_nobody_owns_pauses_every_run(tmp_path: Path) -> None:
    gate, log = gate_with_log(tmp_path, agent="support-bot")
    token = gate.tokens.create("api-key")
    other = Run("run_other", "billing-bot", gate.log)
    gate.http_runs["run_other"] = other
    await feed(gate, log, line(src="172.30.0.99", honeytoken_id=token.id, reason="honeytoken"))
    assert gate.default.paused and other.paused
    assert {
        e["details"].get("attribution") for e in events(gate) if e["kind"] == "egress.blocked"
    } == {"all-agents"}


async def test_a_token_id_we_do_not_hold_is_only_a_blocked_request(tmp_path: Path) -> None:
    gate, log = gate_with_log(tmp_path)
    revoked = gate.tokens.create("api-key")
    gate.tokens.revoke(revoked.id)
    await feed(gate, log, line(honeytoken_id="zzzzzzzzzzzz"), line(honeytoken_id=revoked.id))
    assert not gate.default.paused and "honeytoken.used" not in kinds(gate)
    assert kinds(gate).count("egress.blocked") == 2


async def test_a_half_written_line_waits_and_nothing_is_read_twice(tmp_path: Path) -> None:
    gate, log = gate_with_log(tmp_path)
    whole = line()
    log.write_text(whole[:20])
    watch = EgressWatch(gate)
    assert watch.read_new() == []  # torn: no newline yet
    watch.commit()
    log.write_text(whole + line(host="second"))
    assert [e["host"] for e in watch.read_new()] == ["sink", "second"]
    watch.commit()
    assert watch.read_new() == []
    assert EgressWatch(gate).read_new() == []  # a restarted gate picks up where it stopped


async def test_a_truncated_or_replaced_file_is_read_from_the_start(tmp_path: Path) -> None:
    gate, log = gate_with_log(tmp_path)
    log.write_text(line(host="a") + line(host="b"))
    watch = EgressWatch(gate)
    assert len(watch.read_new()) == 2
    watch.commit()
    log.unlink()
    log.write_text(line(host="c"))
    assert [e["host"] for e in watch.read_new()] == ["c"]


async def test_garbage_lines_are_counted_and_do_not_crash_the_gate(tmp_path: Path) -> None:
    gate, log = gate_with_log(tmp_path)
    junk = ["not json\n", "[1, 2]\n", '{"verdict": "blocked"}\n', "x" * (MAX_LINE + 5) + "\n",
            line(verdict="maybe"), line(port="eighty")]  # fmt: skip
    await feed(gate, log, *junk, line(host="fine"))
    malformed = [e for e in events(gate) if e["kind"] == "egress.malformed"]
    assert malformed[0]["details"]["lines"] == len(junk)
    assert [e["details"]["host"] for e in events(gate) if e["kind"] == "egress.blocked"] == ["fine"]


async def test_a_flood_of_blocked_requests_becomes_a_summary(tmp_path: Path) -> None:
    gate, log = gate_with_log(tmp_path)
    watch = await feed(gate, log, *[line(host=f"h{i}") for i in range(EVENTS_PER_WINDOW + 30)])
    assert kinds(gate).count("egress.blocked") == EVENTS_PER_WINDOW
    watch._window -= 100  # the next window opens
    await feed(gate, log, line(host="later"), watch=watch)
    summary = [e for e in events(gate) if e["details"].get("suppressed")]
    assert summary and summary[0]["details"]["suppressed"] == 30


async def test_hostile_text_in_a_line_cannot_reach_the_terminal_or_the_log_raw(
    tmp_path: Path,
) -> None:
    gate, log = gate_with_log(tmp_path)
    await feed(gate, log, line(host="evil\x1b[31m\nrun_FAKE"))
    blocked = next(e for e in events(gate) if e["kind"] == "egress.blocked")
    assert "\x1b" not in blocked["details"]["host"] and "\n" not in blocked["details"]["host"]


async def test_a_nested_or_oversized_line_cannot_blind_the_watcher(tmp_path: Path) -> None:
    gate, log = gate_with_log(tmp_path)
    token = gate.tokens.create("api-key")
    nested = (
        "[" * 6000 + "]" * 6000 + "\n"
    )  # under the length cap, deep enough to overflow a parser
    huge = "x" * (MAX_READ + 10)  # longer than one read, and no newline yet
    watch = await feed(gate, log, nested, huge)
    await feed(gate, log, "\n", line(honeytoken_id=token.id, reason="honeytoken"), watch=watch)
    await watch.poll()  # skipping the huge line took one whole poll; the token line is next
    assert gate.default.paused and "honeytoken.used" in kinds(gate)


async def test_a_line_that_fails_to_process_does_not_cost_the_lines_after_it(
    tmp_path: Path,
) -> None:
    gate, log = gate_with_log(tmp_path)
    token = gate.tokens.create("api-key")
    real = gate._trip_token
    calls = {"n": 0}

    async def flaky(*args: Any, **kwargs: Any) -> Any:
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("disk full")
        return await real(*args, **kwargs)

    gate._trip_token = flaky  # type: ignore[method-assign]
    mine = Run("run_mine", "default", gate.log)
    gate.http_runs["run_mine"] = mine
    await feed(gate, log, line(honeytoken_id=token.id, reason="honeytoken"))
    assert "gate.error" in kinds(gate) and calls["n"] >= 2  # the second run was still handled


async def test_a_reused_inode_with_a_new_first_line_is_read_from_the_start(
    tmp_path: Path,
) -> None:
    gate, log = gate_with_log(tmp_path)
    log.write_text(line(host="a") + line(host="b"))
    watch = EgressWatch(gate)
    watch.read_new()
    watch.commit()
    log.write_text(line(host="zzzz-a-different-first-line") + line(host="c") + line(host="d"))
    assert [e["host"] for e in watch.read_new()][0] == "zzzz-a-different-first-line"


async def test_a_damaged_offset_file_means_start_again_not_stop(tmp_path: Path) -> None:
    gate, log = gate_with_log(tmp_path)
    gate.config.state_dir.mkdir(parents=True, exist_ok=True)
    gate.config.egress_offset_path.write_text('{"offset": "abc"}')
    await feed(gate, log, line(host="fine"))
    assert [e["details"]["host"] for e in events(gate) if e["kind"] == "egress.blocked"] == ["fine"]
