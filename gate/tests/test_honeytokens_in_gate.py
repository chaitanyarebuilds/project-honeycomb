"""Honeytokens end to end: planted in a workspace, read or used by an agent, caught by the gate."""

from pathlib import Path

from lab.scenarios.s1_poisoned_doc import gate_client_params, write_config
from mcp import Client
from typer.testing import CliRunner

from helpers import read_log
from honeycomb_gate.cli import app
from honeycomb_gate.tokens import TokenRegistry


def plant(cfg: Path, workspace: Path, kind: str = "api-key") -> str:
    result = CliRunner().invoke(
        app, ["tokens", "create", "--config", str(cfg), "--kind", kind, "--place", str(workspace)]
    )
    assert result.exit_code == 0, result.output
    return result.output.split("honeytoken ")[1].split()[0]


async def test_reading_a_planted_credential_withholds_it_and_pauses_the_run(tmp_path: Path) -> None:
    cfg = write_config(tmp_path, email=False)
    docs = tmp_path / "docs"
    docs.mkdir(exist_ok=True)
    token_id = plant(cfg, docs)
    value = TokenRegistry(tmp_path / "state" / "tokens.json").tokens()[0].value
    async with Client(gate_client_params(tmp_path, cfg)) as agent:
        listing = await agent.call_tool("docs__list_documents", {})
        assert ".env.old" in str(listing.content[0].text)  # type: ignore[union-attr]
        result = await agent.call_tool("docs__read_document", {"name": ".env.old"})
        assert result.is_error and value not in str(result.content)  # withheld
        assert (await agent.call_tool("crm__search_customers", {"query": "an"})).is_error
    events = read_log(tmp_path)
    trip = next(e for e in events if e["kind"] == "honeytoken.used")
    assert trip["details"] == {"honeytoken_id": token_id, "kind": "api-key", "where": "result"}
    assert trip["severity"] == "critical" and "session.paused" in [e["kind"] for e in events]
    assert value not in (tmp_path / "state" / "events.jsonl").read_text()  # never logged


async def test_using_a_planted_credential_in_a_call_is_caught_before_it_goes_anywhere(
    tmp_path: Path,
) -> None:
    cfg = write_config(tmp_path, email=False)
    docs = tmp_path / "docs"
    docs.mkdir(exist_ok=True)
    token_id = plant(cfg, docs, "db-url")
    value = TokenRegistry(tmp_path / "state" / "tokens.json").tokens()[0].value
    async with Client(gate_client_params(tmp_path, cfg)) as agent:
        out = await agent.call_tool(
            "crm__send_email", {"to": "x@example.test", "subject": "hi", "body": f"use {value}"}
        )
        assert out.is_error
    events = read_log(tmp_path)
    trip = next(e for e in events if e["kind"] == "honeytoken.used")
    assert trip["details"]["where"] == "arguments" and trip["details"]["honeytoken_id"] == token_id
    assert not [e for e in events if e["kind"] == "call.allowed" and e["tool"] == "crm__send_email"]
    assert value not in (tmp_path / "state" / "events.jsonl").read_text()
    incident = next((tmp_path / "state" / "incidents").glob("inc_*.json")).read_text()
    assert token_id in incident and value not in incident


async def test_look_alike_strings_and_revoked_tokens_pass(tmp_path: Path) -> None:
    cfg = write_config(tmp_path, email=False)
    docs = tmp_path / "docs"
    docs.mkdir(exist_ok=True)
    token_id = plant(cfg, docs)
    async with Client(gate_client_params(tmp_path, cfg)) as agent:
        ok = await agent.call_tool(
            "crm__send_email",
            {"to": "x@example.test", "subject": "key", "body": "sk_live_" + "Z" * 36},
        )
        assert not ok.is_error  # same shape, not a registered token
        revoked = CliRunner().invoke(app, ["tokens", "revoke", token_id, "--config", str(cfg)])
        assert revoked.exit_code == 0
        again = await agent.call_tool("docs__read_document", {"name": ".env.old"})
        assert not again.is_error  # no longer watched
    assert "honeytoken.used" not in [e["kind"] for e in read_log(tmp_path)]


def test_planting_inside_a_git_repository_fails_from_the_cli(tmp_path: Path) -> None:
    cfg = write_config(tmp_path, email=False)
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    result = CliRunner().invoke(
        app, ["tokens", "create", "--config", str(cfg), "--kind", "api-key", "--place", str(repo)]
    )
    assert result.exit_code == 1 and "never be committed" in result.output
    assert not list(repo.glob(".env.old"))
    assert all(t.revoked for t in TokenRegistry(tmp_path / "state" / "tokens.json").tokens())
