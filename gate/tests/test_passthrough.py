from pathlib import Path

from mcp import Client

from helpers import gate_params, read_log, write_config


def _text(result: object) -> str:
    return result.content[0].text  # type: ignore[attr-defined, no-any-return]


async def test_tools_are_namespaced_and_calls_pass_through(tmp_path: Path) -> None:
    async with Client(gate_params(write_config(tmp_path))) as client:
        names = {t.name for t in (await client.list_tools()).tools}
        assert names == {"sample__add", "sample__echo", "sample__poison"}
        result = await client.call_tool("sample__add", {"a": 2, "b": 3})
        assert not result.is_error
        assert "5" in _text(result)
    events = read_log(tmp_path)
    kinds = [e["kind"] for e in events]
    assert kinds[0] == "session.started"
    assert {"tools.listed", "call.allowed", "tool.pinned"} <= set(kinds)
    assert len({e["run_id"] for e in events}) == 1  # ADR-0002: one run id per connection


async def test_unknown_tool_is_denied_and_logged(tmp_path: Path) -> None:
    async with Client(gate_params(write_config(tmp_path))) as client:
        result = await client.call_tool("nope__thing", {})
        assert result.is_error
        assert "blocked" in _text(result)
    denied = [e for e in read_log(tmp_path) if e["kind"] == "call.denied"]
    assert denied and denied[0]["details"]["reason"] == "unknown_tool"


async def test_secrets_in_arguments_are_redacted_in_the_log(tmp_path: Path) -> None:
    async with Client(gate_params(write_config(tmp_path))) as client:
        await client.call_tool(
            "sample__echo", {"text": "key sk-test-0123456789abcdefghij", "api_key": "hunter2"}
        )
    raw = (tmp_path / "state" / "events.jsonl").read_text()
    assert "hunter2" not in raw
    assert "sk-test-0123456789abcdefghij" not in raw
    call = [e for e in read_log(tmp_path) if e["kind"] == "call.allowed"][0]
    assert call["args_digest"].startswith("sha256:")  # digest of the full payload is kept
