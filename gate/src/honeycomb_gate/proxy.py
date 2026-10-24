"""Transparent pass-through MCP proxy (M0): one agent-facing server, N stdio upstreams.

Tools are namespaced ``<upstream>__<tool>``. Nothing is blocked yet: this milestone only
proves the plumbing and records events. Upstream tool annotations are untrusted hints.
"""

import time
from contextlib import AsyncExitStack
from typing import Any

import mcp.types as types
from mcp import Client
from mcp.client.stdio import StdioServerParameters
from mcp.server import Server, ServerRequestContext
from mcp.server.stdio import stdio_server

from honeycomb_gate import __version__
from honeycomb_gate.config import GateConfig
from honeycomb_gate.events import EventLog, digest

SEP = "__"


class Gate:
    def __init__(self, config: GateConfig, log: EventLog) -> None:
        self.config = config
        self.log = log
        self.clients: dict[str, Client] = {}

    async def list_tools(
        self, ctx: ServerRequestContext[Any], params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        tools: list[types.Tool] = []
        for name, client in self.clients.items():
            cursor: str | None = None
            while True:
                page = await client.list_tools(cursor=cursor)
                tools += [t.model_copy(update={"name": f"{name}{SEP}{t.name}"}) for t in page.tools]
                cursor = page.next_cursor
                if not cursor:
                    break
        self.log.emit("tools.listed", tool_count=len(tools))
        return types.ListToolsResult(tools=tools)

    async def call_tool(
        self, ctx: ServerRequestContext[Any], params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        started = time.monotonic()
        upstream, _, tool = params.name.partition(SEP)
        base: dict[str, Any] = {
            "upstream": upstream,
            "tool": params.name,
            "args_digest": digest(params.arguments),
        }
        client = self.clients.get(upstream)
        if client is None or not tool:
            self.log.emit(
                "call.denied", severity="low", decision="deny", reason="unknown_tool", **base
            )
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=f"Unknown tool: {params.name}")],
                is_error=True,
            )
        try:
            result = await client.call_tool(tool, params.arguments)
        except Exception as exc:
            self.log.emit(
                "gate.error", severity="medium", details={"error": type(exc).__name__}, **base
            )
            raise
        self.log.emit(
            "call.allowed",
            decision="allow",
            latency_ms=int((time.monotonic() - started) * 1000),
            **base,
        )
        return result


async def serve(config: GateConfig) -> None:
    log = EventLog(config.event_log)
    gate = Gate(config, log)
    server: Server[Any] = Server(
        "honeycomb-gate",
        version=__version__,
        on_list_tools=gate.list_tools,
        on_call_tool=gate.call_tool,
    )
    async with AsyncExitStack() as stack:
        for name, up in config.upstreams.items():
            params = StdioServerParameters(command=up.command[0], args=up.command[1:])
            gate.clients[name] = await stack.enter_async_context(Client(params))
        log.emit("session.started", upstreams=list(config.upstreams))
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())
        log.emit("session.ended")
