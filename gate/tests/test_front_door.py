"""The HTTP front door end to end: a real gate process, real tokens, several runs at once."""

import json
import signal
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml
from lab.scenarios.s1_poisoned_doc import write_config as write_lab_config
from mcp import Client, MCPError
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client
from typer.testing import CliRunner

from honeycomb_gate.cli import app

AGENTS = {
    "support-bot": {"scopes": ["*"]},
    "docs-reader": {"scopes": ["docs__*"]},
}


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def make_config(tmp_path: Path, port: int, **extra: Any) -> Path:
    path = write_lab_config(tmp_path, email=False)
    cfg = yaml.safe_load(path.read_text())
    cfg.update({"agents": AGENTS, "http": {"port": port}, **extra})
    path.write_text(yaml.safe_dump(cfg))
    return path


def cli(*args: str) -> tuple[int, str, str]:
    result = CliRunner().invoke(app, list(args))
    return result.exit_code, result.stdout.strip(), result.stderr


def token_for(cfg: Path, agent: str) -> str:
    code, out, err = cli("identity", "issue", "--config", str(cfg), "--agent", agent)
    assert code == 0, err
    return out


@contextmanager
def running(cfg: Path, port: int) -> Iterator[None]:
    proc = subprocess.Popen(
        [sys.executable, "-m", "honeycomb_gate.cli", "serve", "--config", str(cfg)],
        stderr=subprocess.PIPE,
    )
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                if proc.poll() is not None:
                    raise RuntimeError(proc.stderr.read().decode() if proc.stderr else "") from None
                time.sleep(0.2)
        else:
            raise RuntimeError("the gate never started listening")
        yield
    finally:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
        if proc.stderr:
            proc.stderr.close()


def agent(port: int, token: str) -> Client:
    http = create_mcp_http_client(headers={"Authorization": f"Bearer {token}"})
    return Client(streamable_http_client(f"http://127.0.0.1:{port}/mcp", http_client=http))


def events(tmp_path: Path) -> list[dict[str, Any]]:
    lines = (tmp_path / "state" / "events.jsonl").read_text().splitlines()
    return [json.loads(line) for line in lines]


def status(port: int, token: str | None, **headers: str) -> int:
    h = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
    if token is not None:
        h["Authorization"] = f"Bearer {token}"
    body = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
    r = httpx.post(f"http://127.0.0.1:{port}/mcp", json=body, headers={**h, **headers})
    return r.status_code


async def test_a_run_with_a_token_gets_its_tools_and_is_logged_under_its_own_id(
    tmp_path: Path,
) -> None:
    port = free_port()
    cfg = make_config(tmp_path, port)
    token = token_for(cfg, "support-bot")
    with running(cfg, port):
        async with agent(port, token) as a:
            names = {t.name for t in (await a.list_tools()).tools}
            assert {"crm__search_customers", "docs__read_document"} <= names
            out = await a.call_tool("docs__read_document", {"name": "notes.txt"})
            assert "Stand-up" in str(out.content[0].text)  # type: ignore[union-attr]
    started = [e for e in events(tmp_path) if e.get("details", {}).get("front_door") == "http"]
    assert len(started) == 1 and started[0]["agent_id"] == "support-bot"
    run_id = started[0]["run_id"]
    calls = [e for e in events(tmp_path) if e["kind"] == "call.allowed"]
    assert calls and {e["run_id"] for e in calls} == {run_id}
    code, out, _ = cli("agents", "list", "--config", str(cfg))
    assert "support-bot  registered  runs 1" in out and "docs-reader  registered  runs 0" in out


async def test_requests_without_a_good_token_never_reach_the_gate(tmp_path: Path) -> None:
    port = free_port()
    cfg = make_config(tmp_path, port)
    good = token_for(cfg, "support-bot")
    head, body, sig = good.split(".")
    tampered = f"{head}.{body}.{'A' if sig[0] != 'A' else 'B'}{sig[1:]}"
    with running(cfg, port):
        assert status(port, good) == 200
        assert status(port, None) == 401
        assert status(port, "hc1.nonsense.token") == 401
        assert status(port, tampered) == 401
        assert status(port, good, Authorization="Basic abc") == 401
    rejected = [e for e in events(tmp_path) if e["kind"] == "identity.rejected"]
    assert len(rejected) == 1  # the rest fell inside one logging window
    assert good not in (tmp_path / "state" / "events.jsonl").read_text()


async def test_an_expired_token_stops_working(tmp_path: Path) -> None:
    port = free_port()
    cfg = make_config(tmp_path, port)
    with running(cfg, port):  # issue after start-up: a 2 second token must not run out first
        code, token, _ = cli("identity", "issue", "--config", str(cfg), "--agent", "support-bot",
                             "--ttl", "2")  # fmt: skip
        assert code == 0 and status(port, token) == 200
        time.sleep(2.5)
        assert status(port, token) == 401


async def test_an_operator_can_revoke_a_run_and_renew_a_live_one(tmp_path: Path) -> None:
    port = free_port()
    cfg = make_config(tmp_path, port)
    code, _, err = cli("identity", "issue", "--config", str(cfg), "--agent", "support-bot")
    run_id = err.split()[1]
    token = token_for(cfg, "support-bot")
    with running(cfg, port):
        assert status(port, token) == 200
        code, renewed, _ = cli("identity", "renew", run_id, "--config", str(cfg))
        assert code == 0 and status(port, renewed) == 200
        assert cli("identity", "revoke", run_id, "--config", str(cfg))[0] == 0
        assert status(port, renewed) == 401
        assert cli("identity", "renew", run_id, "--config", str(cfg))[0] == 1


async def test_a_decoy_trip_revokes_only_that_runs_token_and_resume_issues_a_new_one(
    tmp_path: Path,
) -> None:
    port = free_port()
    cfg = make_config(tmp_path, port)
    hijacked, bystander = token_for(cfg, "support-bot"), token_for(cfg, "support-bot")
    with running(cfg, port):
        async with agent(port, hijacked) as a, agent(port, bystander) as b:
            decoy = next(t.name for t in (await a.list_tools()).tools if "export_all" in t.name)
            await a.call_tool(decoy, {})
            await b.list_tools()
            assert status(port, hijacked) == 401  # revoked
            assert status(port, bystander) == 200  # untouched
            ok = await b.call_tool("crm__search_customers", {"query": "an"})
            assert not ok.is_error
        trip = next(e for e in events(tmp_path) if e["kind"] == "decoy.tripped")
        code, out, _ = cli("runs", "list", "--config", str(cfg))
        assert trip["run_id"] in out
        code, fresh, err = cli("runs", "resume", trip["run_id"], "--config", str(cfg))
        assert code == 0 and "Resumed as run_" in err
        assert status(port, fresh) == 200 and status(port, hijacked) == 401
        async with agent(port, fresh) as c:
            await c.list_tools()
    log = events(tmp_path)
    resumed = [e for e in log if e["kind"] == "session.resumed"]
    assert resumed and resumed[0]["details"]["previous_run_id"] == trip["run_id"]
    assert resumed[0]["run_id"] != trip["run_id"]


async def test_scopes_limit_what_a_run_can_see_and_call(tmp_path: Path) -> None:
    port = free_port()
    cfg = make_config(tmp_path, port)
    token = token_for(cfg, "docs-reader")
    with running(cfg, port):
        async with agent(port, token) as a:
            names = {t.name for t in (await a.list_tools()).tools}
            assert "docs__read_document" in names and "crm__search_customers" not in names
            assert any("export_all" in n for n in names)  # a decoy must look the same to everyone
            out = await a.call_tool("crm__search_customers", {"query": "an"})
            assert out.is_error
            assert (await a.call_tool("docs__list_documents", {})).is_error is False
            assert len((await a.list_resources()).resources) == 1
    denied = [e for e in events(tmp_path) if e["kind"] == "call.denied"]
    assert denied[0]["details"]["reason"] == "out_of_scope"
    assert not [e for e in events(tmp_path) if e["kind"] == "call.allowed"
                and e["tool"] == "crm__search_customers"]  # fmt: skip


async def test_scopes_cover_resources_and_prompts_too(tmp_path: Path) -> None:
    port = free_port()
    cfg = make_config(tmp_path, port, agents={"crm-only": {"scopes": ["crm__*"]}})
    token = token_for(cfg, "crm-only")
    with running(cfg, port):
        async with agent(port, token) as a:
            assert (await a.list_resources()).resources == []
            assert (await a.list_prompts()).prompts == []
            with pytest.raises(MCPError):
                await a.get_prompt("docs__summarise", {"name": "x"})


async def test_strict_mode_turns_away_agents_that_are_not_registered(tmp_path: Path) -> None:
    port = free_port()
    cfg = make_config(tmp_path, port)
    stranger = token_for(cfg, "intruder")  # learning mode lets the operator mint it...
    data = yaml.safe_load(cfg.read_text())
    cfg.write_text(yaml.safe_dump({**data, "mode": "strict"}))
    code, _, err = cli("identity", "issue", "--config", str(cfg), "--agent", "intruder")
    assert code == 1 and "not registered" in err
    with running(cfg, port):  # ...but a strict gate will not accept it
        assert status(port, stranger) == 401
        assert status(port, token_for(cfg, "support-bot")) == 200


async def test_an_unknown_agent_is_accepted_but_logged_in_learning_mode(tmp_path: Path) -> None:
    port = free_port()
    cfg = make_config(tmp_path, port)
    token = token_for(cfg, "new-hire-bot")
    with running(cfg, port):
        async with agent(port, token) as a:
            await a.list_tools()
    unknown = [e for e in events(tmp_path) if e["kind"] == "agent.unknown"]
    assert unknown and unknown[0]["agent_id"] == "new-hire-bot"
    assert "UNREGISTERED" in cli("agents", "list", "--config", str(cfg))[1]


async def test_a_wrong_host_header_is_refused_even_with_a_good_token(tmp_path: Path) -> None:
    port = free_port()
    cfg = make_config(tmp_path, port)
    token = token_for(cfg, "support-bot")
    with running(cfg, port):
        assert status(port, token, Host="evil.example") in (400, 403, 421)
        assert status(port, token, Host=f"127.0.0.1:{port}") == 200


async def test_narrowing_an_agents_scopes_reaches_renewed_and_resumed_tokens(
    tmp_path: Path,
) -> None:
    port = free_port()
    cfg = make_config(tmp_path, port)
    code, _, err = cli("identity", "issue", "--config", str(cfg), "--agent", "support-bot")
    run_id = err.split()[1]
    data = yaml.safe_load(cfg.read_text())
    data["agents"]["support-bot"]["scopes"] = ["docs__*"]
    cfg.write_text(yaml.safe_dump(data))
    _, renewed, _ = cli("identity", "renew", run_id, "--config", str(cfg))
    with running(cfg, port):
        async with agent(port, renewed) as a:
            assert (await a.call_tool("crm__search_customers", {"query": "an"})).is_error
            assert not (await a.call_tool("docs__list_documents", {})).is_error


async def test_starting_a_stdio_gate_leaves_a_token_runs_pause_alone(tmp_path: Path) -> None:
    from helpers import gate_params

    port = free_port()
    cfg = make_config(tmp_path, port)
    hijacked = token_for(cfg, "support-bot")
    with running(cfg, port):
        async with agent(port, hijacked) as a:
            decoy = next(t.name for t in (await a.list_tools()).tools if "export_all" in t.name)
            await a.call_tool(decoy, {})
    trip = next(e for e in events(tmp_path) if e["kind"] == "decoy.tripped")
    async with Client(gate_params(cfg)) as stdio_agent:  # a stdio start in the same state folder
        await stdio_agent.list_tools()
    code, _, err = cli("runs", "resume", trip["run_id"], "--config", str(cfg))
    assert code == 0 and "Resumed as run_" in err
