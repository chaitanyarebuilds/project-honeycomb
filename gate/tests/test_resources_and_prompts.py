"""Resources and prompts go through the gate: namespaced, logged, scanned, paused with the run."""

from pathlib import Path
from urllib.parse import quote

import pytest
from lab.scenarios.s1_poisoned_doc import gate_client_params, write_config
from mcp import Client, MCPError

from helpers import read_log
from honeycomb_gate.tokens import TokenRegistry
from test_honeytokens_in_gate import plant

NOTES = "hc://docs/" + quote("docs://notes", safe="")


def kinds(tmp_path: Path) -> list[str]:
    return [e["kind"] for e in read_log(tmp_path)]


async def test_a_benign_resource_and_prompt_come_through_namespaced(tmp_path: Path) -> None:
    cfg = write_config(tmp_path, email=False)
    async with Client(gate_client_params(cfg)) as agent:
        listed = await agent.list_resources()
        assert [str(r.uri) for r in listed.resources] == [NOTES]
        read = await agent.read_resource(NOTES)
        assert "Stand-up moved" in read.contents[0].text  # type: ignore[union-attr]
        assert str(read.contents[0].uri) == NOTES
        prompts = await agent.list_prompts()
        assert [p.name for p in prompts.prompts] == ["docs__summarise"]
        got = await agent.get_prompt("docs__summarise", {"name": "notes.txt"})
        assert "notes.txt" in got.messages[0].content.text  # type: ignore[union-attr]
        assert "tools.listed" not in kinds(tmp_path)
    k = kinds(tmp_path)
    assert {"resource.listed", "resource.read", "prompt.listed", "prompt.fetched"} <= set(k)
    assert not {"honeytoken.used", "session.paused", "gate.error"} & set(k)


async def test_a_resource_that_holds_a_planted_credential_is_withheld_and_trips(
    tmp_path: Path,
) -> None:
    cfg = write_config(tmp_path, email=False)
    docs = tmp_path / "docs"
    docs.mkdir(exist_ok=True)
    token_id = plant(cfg, docs)
    value = TokenRegistry(tmp_path / "state" / "tokens.json").tokens()[0].value
    uri = "hc://docs/" + quote("docs://file/.env.old", safe="")
    async with Client(gate_client_params(cfg)) as agent:
        with pytest.raises(MCPError):
            await agent.read_resource(uri)
        with pytest.raises(MCPError):  # the run is paused now
            await agent.read_resource(NOTES)
        assert (await agent.list_resources()).resources == []
        assert (await agent.list_prompts()).prompts == []
    trip = next(e for e in read_log(tmp_path) if e["kind"] == "honeytoken.used")
    assert trip["details"] == {"honeytoken_id": token_id, "kind": "api-key", "where": "result"}
    assert value not in (tmp_path / "state" / "events.jsonl").read_text()


async def test_a_planted_credential_in_a_prompt_argument_trips_before_forwarding(
    tmp_path: Path,
) -> None:
    cfg = write_config(tmp_path, email=False)
    docs = tmp_path / "docs"
    docs.mkdir(exist_ok=True)
    plant(cfg, docs)
    value = TokenRegistry(tmp_path / "state" / "tokens.json").tokens()[0].value
    async with Client(gate_client_params(cfg)) as agent:
        with pytest.raises(MCPError):
            await agent.get_prompt("docs__summarise", {"name": value})
    k = kinds(tmp_path)
    assert "honeytoken.used" in k and "prompt.fetched" not in k
    assert value not in (tmp_path / "state" / "events.jsonl").read_text()


async def test_unknown_resources_and_prompts_are_refused_plainly(tmp_path: Path) -> None:
    cfg = write_config(tmp_path, email=False)
    async with Client(gate_client_params(cfg)) as agent:
        for uri in ("file:///etc/passwd", "hc://nope/x", "hc://docs"):
            with pytest.raises(MCPError):
                await agent.read_resource(uri)
        with pytest.raises(MCPError):
            await agent.get_prompt("summarise", {"name": "x"})
    assert "session.paused" not in kinds(tmp_path)
