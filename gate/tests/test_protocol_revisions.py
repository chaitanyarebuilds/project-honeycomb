"""The gate must behave the same whichever protocol revision the client speaks.

The newer revision (2026-07-28) has no protocol sessions; the older ones start with an
`initialize` handshake. Real clients are on both sides of that line, so the same checks run with
the client forced onto the older handshake (`legacy`) and left to pick the newer one (`auto`), over
stdio and over HTTP with a run token. If run identity or scopes ever depended on a session, this is
where it would show.
"""

import time
from pathlib import Path
from typing import Any

import pytest
from lab.scenarios.s1_poisoned_doc import gate_client_params, write_config
from mcp import Client, MCPError

from helpers import cli, read_log
from test_front_door import agent, free_port, make_config, running, token_for

MODES = ["legacy", "auto"]
REVISION = {"legacy": "2025-11-25", "auto": "2026-07-28"}  # what each mode negotiates


async def basic_flow(client: Client) -> str:
    """What every client does: list, call, read a resource, fetch a prompt, then hit the decoy."""
    names = {t.name for t in (await client.list_tools()).tools}
    assert {"crm__search_customers", "docs__read_document"} <= names
    found = await client.call_tool("crm__search_customers", {"query": "an"})
    assert not found.is_error
    resources = (await client.list_resources()).resources
    assert len(resources) == 1
    assert (await client.read_resource(str(resources[0].uri))).contents
    prompt = await client.get_prompt("docs__summarise", {"name": "notes.txt"})
    assert prompt.messages
    decoy = next(n for n in names if "export_all" in n)
    await client.call_tool(decoy, {})  # trips: the run is paused from here on
    return client.protocol_version


@pytest.mark.parametrize("mode", MODES)
async def test_the_gate_behaves_the_same_over_stdio_in_both_revisions(
    tmp_path: Path, mode: Any
) -> None:
    cfg = write_config(tmp_path, email=False)
    async with Client(gate_client_params(cfg), mode=mode) as client:
        version = await basic_flow(client)
        refused = await client.call_tool("crm__search_customers", {"query": "an"})
        assert refused.is_error  # the pause held, whatever the handshake
    assert version == REVISION[mode]
    kinds = [e["kind"] for e in read_log(tmp_path)]
    assert kinds.count("decoy.tripped") == 1 and "session.paused" in kinds
    assert not [e for e in read_log(tmp_path) if e["kind"] == "gate.error"]


@pytest.mark.parametrize("mode", MODES)
async def test_the_gate_behaves_the_same_over_http_in_both_revisions(
    tmp_path: Path, mode: Any
) -> None:
    port = free_port()
    cfg = make_config(tmp_path, port)
    token = token_for(cfg, "support-bot")
    with running(cfg, port):
        async with agent(port, token, mode) as client:
            assert await basic_flow(client) == REVISION[mode]
        # The identity rode on the token, not on a protocol session: the tripped token is dead.
        with pytest.raises((MCPError, Exception)):
            async with agent(port, token, mode) as again:
                await again.list_tools()
        fresh = token_for(cfg, "support-bot")  # a new run is unaffected by the first one's trip
        async with agent(port, fresh, mode) as other:
            assert not (await other.call_tool("crm__search_customers", {"query": "an"})).is_error
    runs = {e["run_id"] for e in read_log(tmp_path) if e["kind"] == "decoy.tripped"}
    assert len(runs) == 1


@pytest.mark.parametrize("mode", MODES)
async def test_scopes_and_the_missing_token_hold_in_both_revisions(
    tmp_path: Path, mode: Any
) -> None:
    port = free_port()
    cfg = make_config(tmp_path, port)
    token = token_for(cfg, "docs-reader")
    with running(cfg, port):
        async with agent(port, token, mode) as client:
            names = {t.name for t in (await client.list_tools()).tools}
            assert "docs__read_document" in names and "crm__search_customers" not in names
            assert (await client.call_tool("crm__search_customers", {"query": "an"})).is_error
        started = time.monotonic()
        with pytest.raises(Exception):  # noqa: B017  (no token: whatever the client raises)
            async with Client(f"http://127.0.0.1:{port}/mcp", mode=mode) as nobody:
                await nobody.list_tools()
        assert time.monotonic() - started < 20
    assert cli("agents", "list", "--config", str(cfg))[0] == 0
