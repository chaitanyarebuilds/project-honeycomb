"""honeycomb-gate data plane (M1): pass-through MCP proxy with pinning, policy and logging.

One agent-facing server, N stdio upstreams. Tools are namespaced ``<upstream>__<tool>``.
Every list and call goes through: definition pinning (quarantine on change), the policy
engine, and the hash-chained event log. Upstream tool annotations are untrusted hints.
"""

import asyncio
import hashlib
import json
import time
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Any

import mcp.types as types
from mcp import Client
from mcp.client.stdio import StdioServerParameters
from mcp.server import Server, ServerRequestContext
from mcp.server.stdio import stdio_server

from honeycomb_gate import __version__
from honeycomb_gate.config import GateConfig
from honeycomb_gate.decoys import DecoyBook, tarpit_delay, tarpit_text
from honeycomb_gate.events import EventLog, digest, new_run_id, query_events
from honeycomb_gate.incidents import (
    Incident,
    IncidentStore,
    open_decoy_incident,
    open_token_incident,
)
from honeycomb_gate.notify import Notifier
from honeycomb_gate.policy import PolicyEngine
from honeycomb_gate.registry import APPROVED, PinResult, PinStore, definition_of, scan_definition
from honeycomb_gate.runs import RunControl
from honeycomb_gate.tokens import Sighting, TokenRegistry

SEP = "__"
MAX_PAGES = 100
MAX_ARGS_CHARS = 4_000_000  # larger calls are refused, so no scan can be padded past a cap


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
        self.tokens = TokenRegistry(config.tokens_path)
        self.runs = RunControl(config.runs_path)
        self.incidents = IncidentStore(config.incidents_dir)
        self.notifier = Notifier(config.notify)
        self.decoys: DecoyBook | None = None  # built once the upstreams are known
        self.paused = False
        self.config_path: Path | None = None
        self._background: set[asyncio.Task[None]] = set()

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

    # -- run control, decoys and tokens ----------------------------------------------------

    def setup_decoys(self) -> None:
        self.decoys = DecoyBook(
            self.config.decoys, list(self.config.upstreams), self.config.decoys_path
        )

    def _check_resume(self) -> None:
        """If an operator asked to resume the paused run, retire its identity and mint a new one."""
        if not self.paused:
            return
        old = self.log.run_id
        if not self.runs.resume_requested(old):  # cheap read first: no lock on every call
            return
        new = new_run_id()
        entry = self.runs.take_resume(old, new)
        if entry is None:
            return
        self.paused = False
        self.log.run_id = new
        self.log.emit(
            "identity.issued",
            severity="medium",
            decision="resume",
            details={"previous_run_id": old, "approved_by": entry.get("resume_requested_by")},
        )
        self.log.emit("session.resumed", severity="medium", details={"previous_run_id": old})

    def inherit_pause(self) -> None:
        """A gate that restarts while a run is paused starts paused: restarting is not a resume."""
        previous = self.runs.inherit(self.log.run_id)
        if previous:
            self.paused = True
            self.log.emit(
                "session.paused",
                severity="high",
                decision="pause",
                details={"reason": "inherited_pause", "previous_run_ids": previous},
            )

    def _config_hint(self) -> str:
        return f"--config {self.config_path}" if getattr(self, "config_path", None) else ""

    def _run_events(self) -> list[dict[str, Any]]:
        db = self.log.path.with_suffix(".sqlite3")
        if not db.exists():
            return []
        return query_events(db, run_id=self.log.run_id, limit=15)

    def _tarpit_credential(self, tool: str, args: dict[str, Any] | None) -> str:
        """A stable fake credential for credential-like decoys, itself a registered honeytoken."""
        key = (
            "tarpit:"
            + hashlib.sha256(
                f"{tool}|{json.dumps(args or {}, sort_keys=True)}".encode()
            ).hexdigest()[:16]
        )
        for t in self.tokens.tokens():
            if key in t.placed and not t.revoked:
                return t.value
        return self.tokens.create("api-key", placed=[key]).value

    async def _trip(
        self,
        *,
        event_kind: str,
        rule_id: str,
        tool: str,
        base: dict[str, Any],
        details: dict[str, Any],
        args: dict[str, Any],
        incident_for: Any,
    ) -> types.CallToolResult:
        """Record a trip, pause the run, revoke its identity, open an incident, then answer."""
        run_id = self.log.run_id
        self.log.emit(
            event_kind,
            severity="critical",
            decision="trip",
            rule_id=rule_id,
            details={**details, **({"already_paused": True} if self.paused else {})},
            **base,
        )
        if self.paused:  # a second trip while paused is evidence, not a second incident
            return _blocked("This tool call was blocked by honeycomb-gate.")
        self.paused = True
        self.runs.pause(run_id, event_kind, tool)
        self.log.emit(
            "session.paused", severity="high", decision="pause", details={"reason": event_kind}
        )
        self.log.emit("identity.revoked", severity="high", decision="revoke")
        try:  # the run is already contained; a failure here must not undo or hide that
            incident = incident_for(self._run_events())
            self.incidents.save(incident)
            self.log.emit(
                "incident.opened",
                severity="critical",
                details={"incident_id": incident.id, "title": incident.title},
            )
            self._spawn(self._notify(incident))
        except Exception as exc:
            self.log.emit("gate.error", severity="high", details={"error": type(exc).__name__})
        return await self._trip_response(tool, args)

    async def _trip_response(self, tool: str, args: dict[str, Any] | None) -> types.CallToolResult:
        on_trip = self.config.decoys.on_trip
        if self.decoys is None or on_trip.response == "error" or not self.decoys.is_decoy(tool):
            return _blocked("This tool call was blocked by honeycomb-gate.")
        # The slow drip: plausible, never real. It only delays this one call, not the gate.
        await asyncio.sleep(tarpit_delay(self.decoys, tool, args, on_trip.tarpit_delay_s))
        name = tool.split("__", 1)[-1]
        if name in ("get_admin_api_key", "read_secrets_vault"):
            text = json.dumps({"credential": self._tarpit_credential(tool, args)})
        else:
            text = tarpit_text(self.decoys, tool, args)
        return types.CallToolResult(content=[types.TextContent(type="text", text=text)])

    def _spawn(self, coro: Any) -> None:
        task: asyncio.Task[None] = asyncio.get_running_loop().create_task(coro)
        self._background.add(task)
        task.add_done_callback(self._background.discard)

    async def _notify(self, incident: Incident) -> None:
        try:
            key = f"{incident.kind}|{incident.tool}|{incident.run_id}"
            if self.notifier.is_duplicate(key, time.monotonic()):
                self.log.emit("incident.deduplicated", details={"incident_id": incident.id})
                return
            sent: list[dict[str, str]] = []
            for result in await self.notifier.send(incident):
                sent.append(
                    {"channel": result.channel, "ok": str(result.ok), "error": result.error}
                )
                self.log.emit(
                    "incident.notified" if result.ok else "notify.failed",
                    severity="info" if result.ok else "medium",
                    details={
                        "incident_id": incident.id,
                        "channel": result.channel,
                        **({"error": result.error} if result.error else {}),
                    },
                )
            self.incidents.add_notifications(incident.id, sent)
        except Exception as exc:  # a lost notification must at least leave a trace
            try:
                self.log.emit(
                    "notify.failed",
                    severity="high",
                    details={"incident_id": incident.id, "error": type(exc).__name__},
                )
            except Exception:  # noqa: S110 - nothing more can be done if the log itself is gone
                pass

    async def drain(self, timeout: float = 15.0) -> None:
        """Let pending notifications finish before the process exits."""
        if self._background:
            await asyncio.wait(self._background, timeout=timeout)

    def _token_trip_incident(self, sighting: Sighting, tool: str, where: str) -> Any:
        def build(events: list[dict[str, Any]]) -> Incident:
            return open_token_incident(
                run_id=self.log.run_id,
                agent_id=self.config.agent_id,
                tool=tool,
                token_id=sighting.token_id,
                kind=sighting.kind,
                placed=sighting.placed,
                where=where,
                events=events,
                config_hint=self._config_hint(),
            )

        return build

    # -- MCP handlers ---------------------------------------------------------------------

    async def list_tools(
        self, ctx: ServerRequestContext[Any], params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        self._check_resume()
        if self.paused:
            self.log.emit("tools.listed", details={"visible": 0, "hidden": 0, "paused": True})
            return types.ListToolsResult(tools=[])
        visible: list[types.Tool] = []
        real_names: set[str] = set()
        hidden = 0
        for upstream in self.clients:
            for tool in (await self._fetch(upstream, max_age=0)).values():
                name = f"{upstream}{SEP}{tool.name}"
                real_names.add(name)
                pin = self._check_pin(upstream, tool)
                decision = self.policy.evaluate(upstream, name, None)
                if pin.status != APPROVED or (decision.action == "deny" and decision.hide):
                    hidden += 1
                    continue
                # Metadata and icons are not pinned, so they are not forwarded.
                visible.append(tool.model_copy(update={"name": name, "meta": None, "icons": None}))
        decoy_count = 0
        if self.decoys is not None and self.decoys.names:
            decoy_tools, skipped = self.decoys.tools(real_names)
            for name in skipped:
                self.log.emit(
                    "decoy.collision", severity="medium", tool=name,
                    details={"note": "a real tool has this name, so the decoy was left out"},
                )  # fmt: skip
            visible.extend(decoy_tools)
            decoy_count = len(decoy_tools)
        self.log.emit(
            "tools.listed",
            details={
                "visible": len(visible) - decoy_count,
                "hidden": hidden,
                "decoys": decoy_count,
            },
        )
        return types.ListToolsResult(tools=visible)

    async def call_tool(
        self, ctx: ServerRequestContext[Any], params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        started = time.monotonic()
        self._check_resume()
        args = params.arguments or {}
        upstream, _, tool_name = params.name.partition(SEP)
        safe_name = self.tokens.mask(params.name)  # a token could be smuggled in the tool name
        base: dict[str, Any] = {
            "upstream": self.tokens.mask(upstream),
            "tool": safe_name,
            "args_digest": digest(params.arguments),
            "args_redacted": self.tokens.mask(args),  # honeytoken values never reach the log
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

        if self.paused:
            return deny("run_paused", "run-control", "medium")
        if len(params.name) + len(json.dumps(args, default=str)) > MAX_ARGS_CHARS:
            return deny("payload_too_large", "gate", "medium")

        # 1. Decoys: no legitimate run ever calls one. The call is never forwarded.
        if self.decoys is not None and self.decoys.is_decoy(params.name):
            return await self._trip(
                event_kind="decoy.tripped",
                rule_id="decoy-default",
                tool=safe_name,
                base=base,
                details={"decoy": tool_name},
                args=args,
                incident_for=lambda events: open_decoy_incident(
                    run_id=self.log.run_id,
                    agent_id=self.config.agent_id,
                    tool=params.name,
                    events=events,
                    config_hint=self._config_hint(),
                ),
            )

        # 2. Honeytokens in the arguments: the agent is trying to use or pass on a planted secret.
        seen = self.tokens.find({"tool": params.name, "arguments": args})
        if seen:
            return await self._trip(
                event_kind="honeytoken.used",
                rule_id="honeytoken-default",
                tool=safe_name,
                base=base,
                details={
                    "honeytoken_id": seen[0].token_id,
                    "kind": seen[0].kind,
                    "where": "arguments",
                },
                args=args,
                incident_for=self._token_trip_incident(seen[0], safe_name, "arguments"),
            )

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
            decision = self.policy.evaluate(upstream, params.name, args)
            if decision.action == "deny":
                return deny(decision.reason, decision.rule_id)
            if self.paused:  # another call tripped while this one was waiting: do not forward
                return deny("run_paused", "run-control", "medium")
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

        # 3. Honeytokens in the result: something handed the agent a planted secret. Withhold it.
        found = self.tokens.find(result.model_dump(by_alias=True, exclude_none=True))
        if found:
            return await self._trip(
                event_kind="honeytoken.used",
                rule_id="honeytoken-default",
                tool=params.name,
                base=base,
                details={
                    "honeytoken_id": found[0].token_id,
                    "kind": found[0].kind,
                    "where": "result",
                },
                args=args,
                incident_for=self._token_trip_incident(found[0], params.name, "result"),
            )
        self.log.emit(
            "call.completed",
            upstream=upstream,
            tool=params.name,
            latency_ms=int((time.monotonic() - started) * 1000),
            details={"is_error": bool(result.is_error)},
        )
        return result


async def serve(config: GateConfig, config_path: Path | None = None) -> None:
    log = EventLog(config.event_log_path, agent_id=config.agent_id, alert_sink=config.alert_sink)
    gate = Gate(config, log)
    gate.config_path = config_path
    server: Server[Any] = Server(
        "honeycomb-gate",
        version=__version__,
        on_list_tools=gate.list_tools,
        on_call_tool=gate.call_tool,
    )
    try:
        async with AsyncExitStack() as stack:
            for name, up in config.upstreams.items():
                params = StdioServerParameters(
                    command=up.command[0], args=up.command[1:], env=up.env or None
                )
                gate.clients[name] = await stack.enter_async_context(Client(params))
            gate.setup_decoys()
            log.emit("session.started", details={"upstreams": list(config.upstreams)})
            gate.inherit_pause()
            try:
                async with stdio_server() as (read, write):
                    await server.run(read, write, server.create_initialization_options())
            finally:
                await gate.drain()  # let incident emails finish before the process exits
            log.emit("session.ended")
    finally:
        log.close()
