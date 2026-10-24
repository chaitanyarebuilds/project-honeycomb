"""Scenario S0: fifty ordinary sessions must raise no high or critical alert.

The sessions are scripted and vary (names searched, customer ids, how often documents are read),
but they use the tools a real support agent would use. After them, one hijacked run is the only
thing that should stand out.
"""

import json
import random
from pathlib import Path

from mcp import Client

from helpers import cli, read_log
from test_front_door import agent, free_port, make_config, running, token_for

SESSIONS = 50
NAMES = [
    "ana",
    "ben",
    "chitra",
    "dev",
    "esha",
    "farid",
    "gita",
    "hari",
    "isha",
    "jon",
    "rao",
    "shah",
]


async def benign_session(client: Client, rng: random.Random) -> None:
    await client.list_tools()
    for _ in range(rng.randint(2, 4)):
        await client.call_tool("crm__search_customers", {"query": rng.choice(NAMES)})
        await client.call_tool("crm__get_customer", {"customer_id": rng.randint(1, 200)})
    await client.call_tool("docs__list_documents", {})
    await client.call_tool("docs__read_document", {"name": "notes.txt"})


async def test_s0_fifty_benign_sessions_raise_no_alert(tmp_path: Path) -> None:
    port = free_port()
    cfg = make_config(tmp_path, port)
    rng = random.Random(2026)
    with running(cfg, port):
        for _ in range(SESSIONS):
            async with agent(port, token_for(cfg, "support-bot")) as client:
                await benign_session(client, rng)
        events = read_log(tmp_path)
        loud = [e for e in events if e["severity"] in {"high", "critical"}]
        assert loud == [], [e["kind"] for e in loud]
        unwanted = {"baseline.deviation", "decoy.tripped", "honeytoken.used", "gate.error"}
        noisy = [e["kind"] for e in events if e["kind"] in unwanted]
        assert noisy == [], "benign sessions must not even raise a baseline deviation"
        assert len({e["run_id"] for e in events if e["kind"] == "identity.issued"}) >= SESSIONS

        # The same gate still catches the one run that goes for the decoy.
        async with agent(port, token_for(cfg, "support-bot")) as bad:
            decoy = next(t.name for t in (await bad.list_tools()).tools if "export_all" in t.name)
            await bad.call_tool(decoy, {})
    critical = [e for e in read_log(tmp_path) if e["severity"] == "critical"]
    assert {e["kind"] for e in critical} == {"decoy.tripped", "incident.opened"}  # one trip
    out = cli("baseline", "show", "--config", str(cfg))[1]
    assert f"{SESSIONS} run(s)" in out and "crm__search_customers" in out
    profile = json.loads((tmp_path / "state" / "baselines.json").read_text())["agents"][
        "support-bot"
    ]
    assert profile["runs"] >= SESSIONS
