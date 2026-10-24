"""honeycomb-gate data plane (M1): pass-through MCP proxy with pinning, policy and logging.

One agent-facing server, N stdio upstreams. Tools are namespaced ``<upstream>__<tool>``.
Every list and call goes through: definition pinning (quarantine on change), the policy
engine, and the hash-chained event log. Upstream tool annotations are untrusted hints.
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
from honeycomb_gate.policy import PolicyEngine
from honeycomb_gate.registry import APPROVED, PinResult, PinStore, definition_of, scan_definition

SEP = "__"
MAX_PAGES = 100


def _blocked(message: str) -> types.CallToolResult:
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=message)], is_error=True
    )


class Gate:
    def __init__(self, config: GateConfig, log: EventLog) -> None:
        self.config = config
        self.log = log
        self.pins = PinStore(config.pins_path)
        self.policy = PolicyEngine(config)
        self.strict = config.mode == "strict"
        self.clients: dict[str, Client] = {}
        self._defs: dict[str, tuple[float, dict[str, types.Tool]]] = {}
        self._flagged: set[tuple[str, str, str]] = set()

    # -- upstream definitions -------------------------------------------------------------

    async def _fetch(self, upstream: str, *, max_age: float) -> dict[str, types.Tool]:
        cached = self._defs.get(upstream)
        if cached is not None and time.monotonic() - cached[0] <= max_age:
            return cached[1]
        tools: dict[str, types.Tool] = {}
        cursor: str | None = None
        seen: set[str] = set()
        for _ in range(MAX_PAGES):
            page = await self.clients[upstream].list_tools(cursor=cursor)
            tools.update({t.name: t for t in page.tools})
            cursor = page.next_cursor
            if not cursor:
                break
            if cursor in seen:  # a hostile upstream repeating a cursor must not hang the gate
                raise RuntimeError(f"upstream {upstream!r} repeated a pagination cursor")
            seen.add(cursor)
        else:
            raise RuntimeError(f"upstream {upstream!r} returned more than {MAX_PAGES} pages")
        self._defs[upstream] = (time.monotonic(), tools)
        return tools

    def _check_pin(self, upstream: str, tool: types.Tool) -> PinResult:
        """Pin the definition, record any resulting events, and flag odd descriptions."""
        definition = definition_of(tool)
        result = self.pins.check(upstream, tool.name, definition, strict=self.strict)
        h = result.current_hash
        name = f"{upstream}{SEP}{tool.name}"
        for kind, details in result.earlier:
            self.log.emit(kind, upstream=upstream, tool=name, decision="approve", details=details)
        if result.event == "tool.definition_changed":
            self.log.emit(
                "tool.definition_changed",
                severity="high",
                upstream=upstream,
                tool=name,
                decision="quarantine",
                details={"previous_hash": result.previous_hash, "current_hash": h},
            )
        elif result.event == "tool.unapproved":
            self.log.emit(
                "tool.unapproved",
                severity="low",
                upstream=upstream,
                tool=name,
                details={"current_hash": h},
            )
        elif result.event == "tool.approved":
            self.log.emit(
                "tool.approved",
                upstream=upstream,
                tool=name,
                decision="approve",
                details={**result.details, "hash": h},
            )
        elif result.event == "tool.pinned":
            self.log.emit("tool.pinned", upstream=upstream, tool=name, details={"hash": h})
        key = (upstream, tool.name, h)
        if key not in self._flagged:
            finding = scan_definition(definition)
            if finding.suspicious:
                self._flagged.add(key)
                self.log.emit(
                    "tool.suspicious_description",
                    severity="medium",
                    upstream=upstream,
                    tool=name,
                    details={"reasons": finding.reasons, "score": finding.score, "hash": h},
                )
        return result

    # -- MCP handlers ---------------------------------------------------------------------

    async def list_tools(
        self, ctx: ServerRequestContext[Any], params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        visible: list[types.Tool] = []
        hidden = 0
        for upstream in self.clients:
            for tool in (await self._fetch(upstream, max_age=0)).values():
                pin = self._check_pin(upstream, tool)
                name = f"{upstream}{SEP}{tool.name}"
                decision = self.policy.evaluate(upstream, name, None)
                if pin.status != APPROVED or (decision.action == "deny" and decision.hide):
                    hidden += 1
                    continue
                # Metadata and icons are not pinned, so they are not forwarded.
                visible.append(tool.model_copy(update={"name": name, "meta": None, "icons": None}))
        self.log.emit("tools.listed", details={"visible": len(visible), "hidden": hidden})
        return types.ListToolsResult(tools=visible)

    async def call_tool(
        self, ctx: ServerRequestContext[Any], params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        started = time.monotonic()
        upstream, _, tool_name = params.name.partition(SEP)
        base: dict[str, Any] = {
            "upstream": upstream,
            "tool": params.name,
            "args_digest": digest(params.arguments),
            "args_redacted": params.arguments or {},
        }

        def deny(reason: str, rule_id: str = "gate", severity: str = "low") -> types.CallToolResult:
            self.log.emit(
                "call.denied",
                severity=severity,
                decision="deny",
                rule_id=rule_id,
                details={"reason": reason},
                **base,
            )
            return _blocked("This tool call was blocked by honeycomb-gate.")

        if upstream not in self.clients or not tool_name:
            return deny("unknown_tool")
        try:
            tools = await self._fetch(upstream, max_age=self.config.recheck_ttl_s)
            live = tools.get(tool_name)
            if live is None:
                return deny("unknown_tool")
            pin = self._check_pin(upstream, live)
            if pin.status != APPROVED:
                return deny(pin.status, "pinning", "medium")
            decision = self.policy.evaluate(upstream, params.name, params.arguments or {})
            if decision.action == "deny":
                return deny(decision.reason, decision.rule_id)
            # Record the decision before the action: if the log cannot be written, the call
            # does not happen (fail closed on evidence).
            self.log.emit("call.allowed", decision="allow", rule_id=decision.rule_id, **base)
            result = await self.clients[upstream].call_tool(tool_name, params.arguments)
        except Exception as exc:
            self.log.emit(
                "gate.error", severity="high", details={"error": type(exc).__name__}, **base
            )
            if self.strict or self.policy.is_high_impact(params.name):
                return _blocked("This tool call was blocked by honeycomb-gate (internal error).")
            raise
        self.log.emit(
            "call.completed",
            upstream=upstream,
            tool=params.name,
            latency_ms=int((time.monotonic() - started) * 1000),
            details={"is_error": bool(result.is_error)},
        )
        return result


async def serve(config: GateConfig) -> None:
    log = EventLog(config.event_log_path, agent_id=config.agent_id, alert_sink=config.alert_sink)
    gate = Gate(config, log)
    server: Server[Any] = Server(
        "honeycomb-gate",
        version=__version__,
        on_list_tools=gate.list_tools,
        on_call_tool=gate.call_tool,
    )
    try:
        async with AsyncExitStack() as stack:
            for name, up in config.upstreams.items():
                params = StdioServerParameters(command=up.command[0], args=up.command[1:])
                gate.clients[name] = await stack.enter_async_context(Client(params))
            log.emit("session.started", details={"upstreams": list(config.upstreams)})
            async with stdio_server() as (read, write):
                await server.run(read, write, server.create_initialization_options())
            log.emit("session.ended")
    finally:
        log.close()
