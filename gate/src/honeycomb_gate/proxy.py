"""honeycomb-gate data plane (M1): pass-through MCP proxy with pinning, policy and logging.

One agent-facing server, N stdio upstreams. Tools are namespaced ``<upstream>__<tool>``.
Every list and call goes through: definition pinning (quarantine on change), the policy
engine, and the hash-chained event log. Upstream tool annotations are untrusted hints.
"""

import asyncio
import contextlib
import fnmatch
import hashlib
import json
import time
from collections import deque
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, NoReturn
from urllib.parse import quote, unquote, urlsplit

import mcp.types as types
from mcp import Client, MCPError
from mcp.client.stdio import StdioServerParameters
from mcp.server import Server, ServerRequestContext
from mcp.server.stdio import stdio_server
from pydantic import BaseModel

from honeycomb_gate import __version__
from honeycomb_gate.baseline import Baselines
from honeycomb_gate.config import GateConfig
from honeycomb_gate.decoys import DecoyBook, tarpit_delay, tarpit_text
from honeycomb_gate.events import (
    EventLog,
    LogCorruptError,
    digest,
    log_has_event,
    new_run_id,
    query_events,
    unresumed_pauses,
    verify_chain,
)
from honeycomb_gate.governor import Governor
from honeycomb_gate.identity import Claims, Identities, Inventory, KeyRing
from honeycomb_gate.incidents import (
    Incident,
    IncidentStore,
    open_decoy_incident,
    open_memory_incident,
    open_token_incident,
)
from honeycomb_gate.locking import FileLock, LockedError, StateCorruptError
from honeycomb_gate.memory import Memory, Rule
from honeycomb_gate.notify import Notifier
from honeycomb_gate.policy import PolicyEngine
from honeycomb_gate.redact import sanitize_name
from honeycomb_gate.registry import APPROVED, PinResult, PinStore, definition_of, scan_definition
from honeycomb_gate.runs import RunControl
from honeycomb_gate.tokens import Sighting, TokenRegistry
from honeycomb_gate.walk import exceeds_depth, strings_of

SEP = "__"
MAX_PAGES = 100
MAX_ARGS_CHARS = 4_000_000  # larger calls are refused, so no scan can be padded past a cap
MAX_RESULT_CHARS = 8_000_000  # the same for what comes back
MAX_DEPTH = 100  # nesting deeper than any real tool call
RESOURCE_SCHEME = "hc"  # resources come out as hc://<upstream>/<escaped original uri>


def _blocked(message: str) -> types.CallToolResult:
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=message)], is_error=True
    )


def _gate_uri(upstream: str, uri: str) -> str:
    return f"{RESOURCE_SCHEME}://{upstream}/{quote(str(uri), safe='')}"


def _split_gate_uri(uri: str) -> tuple[str, str]:
    try:
        parts = urlsplit(uri)
    except ValueError:
        return "", ""
    if parts.scheme != RESOURCE_SCHEME:
        return "", ""
    return parts.netloc, unquote(parts.path[1:])


@dataclass
class Run:
    """One agent connection: its id, who it is, and whether it is paused."""

    id: str
    agent_id: str
    log: EventLog
    paused: bool = False
    scopes: tuple[str, ...] = ("*",)  # tool globs this run may use; decoys are always visible
    # The last few results this run read, kept so that a trip can learn from them (S5).
    recent: deque[tuple[str, str]] = field(default_factory=lambda: deque(maxlen=5))

    def allows(self, name: str) -> bool:
        return any(fnmatch.fnmatchcase(name.lower(), p.lower()) for p in self.scopes)

    def emit(self, kind: str, **fields: Any) -> dict[str, Any]:
        return self.log.emit(kind, run_id=self.id, agent_id=self.agent_id, **fields)


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
        self.default = Run(log.run_id, config.agent_id, log)  # the stdio connection
        self.identities = Identities(config.identities_path, KeyRing(config.keys_path))
        self.governor = Governor(self)
        self.baselines = Baselines(config.baselines_path, config.baseline)
        self.memory = Memory(config.memory_path, config.memory)
        self.inventory = Inventory(config.inventory_path)
        self.http_runs: dict[str, Run] = {}
        self.require_claims = False  # set when serving over HTTP: no token, no run
        self.config_path: Path | None = None
        self._background: set[asyncio.Task[None]] = set()

    # -- upstream definitions -------------------------------------------------------------

    async def _collect(
        self, upstream: str, fetch: Callable[..., Awaitable[Any]], field: str
    ) -> list[Any]:
        """Walk every page of an upstream list call, with a timeout and loop guards."""
        items: list[Any] = []
        cursor: str | None = None
        seen: set[str] = set()
        for _ in range(MAX_PAGES):
            page = await asyncio.wait_for(fetch(cursor=cursor), self.config.call_timeout_s)
            items.extend(getattr(page, field))
            cursor = page.next_cursor
            if not cursor:
                return items
            if cursor in seen:  # a hostile upstream repeating a cursor must not hang the gate
                raise RuntimeError(f"upstream {upstream!r} repeated a pagination cursor")
            seen.add(cursor)
        raise RuntimeError(f"upstream {upstream!r} returned more than {MAX_PAGES} pages")

    async def _fetch(self, upstream: str, *, max_age: float) -> dict[str, types.Tool]:
        cached = self._defs.get(upstream)
        if cached is not None and time.monotonic() - cached[0] <= max_age:
            return cached[1]
        client = self.clients[upstream]
        tools = {t.name: t for t in await self._collect(upstream, client.list_tools, "tools")}
        self._defs[upstream] = (time.monotonic(), tools)
        return tools

    def _check_pin(self, run: Run, upstream: str, tool: types.Tool) -> PinResult:
        """Pin the definition, record any resulting events, and flag odd descriptions."""
        definition = definition_of(tool)
        result = self.pins.check(upstream, tool.name, definition, strict=self.strict)
        h = result.current_hash
        name = f"{upstream}{SEP}{tool.name}"
        for kind, details in result.earlier:
            run.emit(kind, upstream=upstream, tool=name, decision="approve", details=details)
        extra: dict[str, dict[str, Any]] = {
            "tool.definition_changed": {
                "severity": "high",
                "decision": "quarantine",
                "details": {"previous_hash": result.previous_hash, "current_hash": h},
            },
            "tool.unapproved": {"severity": "low", "details": {"current_hash": h}},
            "tool.approved": {"decision": "approve", "details": {**result.details, "hash": h}},
            "tool.pinned": {"details": {"hash": h}},
        }
        if result.event in extra:
            run.emit(result.event, upstream=upstream, tool=name, **extra[result.event])
        key = (upstream, tool.name, h)
        if key not in self._flagged:
            finding = scan_definition(definition)
            if finding.suspicious:
                self._flagged.add(key)
                run.emit(
                    "tool.suspicious_description",
                    severity="medium",
                    upstream=upstream,
                    tool=name,
                    details={"reasons": finding.reasons, "score": finding.score, "hash": h},
                )
        return result

    # -- run control, decoys and tokens ----------------------------------------------------

    def _resolve(self, ctx: ServerRequestContext[Any]) -> Run:
        """Which run is asking. Over stdio there is one connection, so one run."""
        request = getattr(ctx, "request", None)
        claims: Claims | None = request.scope.get("honeycomb_claims") if request else None
        if claims is None:
            if self.require_claims:  # the front door should have stopped this already
                raise MCPError(types.INVALID_REQUEST, "A run token is required.")
            return self.default
        run = self.http_runs.get(claims.run_id)
        if run is None:
            run = Run(claims.run_id, claims.agent_id, self.log, scopes=claims.scopes)
            self.http_runs[claims.run_id] = run
            self._announce(run, claims)  # if this fails, the next request tries again
        return run

    def active_runs(self, agent_id: str | None) -> list[Run]:
        """Runs that are not paused, for one agent or (with None) for all of them."""
        runs = [self.default, *self.http_runs.values()]
        return [r for r in runs if not r.paused and agent_id in (None, r.agent_id)]

    def _announce(self, run: Run, claims: Claims) -> None:
        """First request of a run that came in with a token: note the agent, log the run."""
        first = self.inventory.note_run(run.agent_id)
        entry = self.identities.get(run.id) or {}
        before = entry.get("resumed_from")
        run.emit("session.started", details={"front_door": "http", "scopes": list(run.scopes)})
        run.emit("identity.issued", details={"expires": claims.expires, "previous_run_id": before})
        if run.agent_id not in self.config.agents:
            run.emit(
                "agent.unknown",
                severity="medium",
                details={"first_sighting": first, "mode": self.config.mode},
            )
        if before:
            run.emit("session.resumed", severity="medium", details={"previous_run_id": before})

    def setup_decoys(self) -> None:
        self.decoys = DecoyBook(
            self.config.decoys, list(self.config.upstreams), self.config.decoys_path
        )

    def _check_resume(self, run: Run) -> None:
        """If an operator asked to resume the paused run, retire its identity and mint a new one."""
        if not run.paused or run is not self.default:  # token runs get a new token instead
            return
        old = run.id
        if not self.runs.resume_requested(old):  # cheap read first: no lock on every call
            return
        new = new_run_id()
        entry = self.runs.take_resume(old, new)
        if entry is None:
            return
        run.paused = False
        run.id = new
        run.emit(
            "identity.issued",
            severity="medium",
            decision="resume",
            details={"previous_run_id": old, "approved_by": entry.get("resume_requested_by")},
        )
        run.emit("session.resumed", severity="medium", details={"previous_run_id": old})

    def inherit_pause(self, run: Run) -> None:
        """A gate that restarts while a run is paused starts paused: restarting is not a resume."""
        token_runs = set(self.identities.all())  # these stay revoked; an operator resumes them
        lost = [r for r in unresumed_pauses(self.log.path) if r != run.id and r not in token_runs]
        previous = self.runs.inherit(run.id, lost, skip=token_runs)
        if previous:
            run.paused = True
            run.emit(
                "session.paused",
                severity="high",
                decision="pause",
                details={"reason": "inherited_pause", "previous_run_ids": previous},
            )

    def _config_hint(self) -> str:
        return f"--config {self.config_path}" if self.config_path else ""

    def _run_events(self, run: Run) -> list[dict[str, Any]]:
        db = self.log.path.with_suffix(".sqlite3")
        if not db.exists():
            return []
        return query_events(db, run_id=run.id, limit=15)

    def _tarpit_credential(self, tool: str, args: dict[str, Any] | None) -> str:
        """A stable fake credential for credential-like decoys, itself a registered honeytoken."""
        key = (
            "tarpit:"
            + hashlib.sha256(
                f"{tool}|{json.dumps(args or {}, sort_keys=True, default=str)}".encode()
            ).hexdigest()[:16]
        )
        for t in self.tokens.tokens():
            if key in t.placed and not t.revoked:
                return t.value
        return self.tokens.create("api-key", placed=[key]).value

    async def _trip(
        self,
        run: Run,
        *,
        event_kind: str,
        rule_id: str,
        tool: str,
        base: dict[str, Any],
        details: dict[str, Any],
        args: dict[str, Any],
        incident_for: Any,
    ) -> types.CallToolResult:
        """Record a trip, pause the run, revoke its identity, open an incident, then answer.

        Each step stands on its own: if the disk is full and one write fails, the others still
        happen, and the run stays paused.
        """
        first = not run.paused
        run.paused = True  # in memory first: nothing below can undo it
        if first:
            self._best_effort(run, self.runs.pause, run.id, event_kind, tool)
        self._best_effort(
            run,
            run.emit,
            event_kind,
            severity="critical",
            decision="trip",
            rule_id=rule_id,
            details={**details, **({} if first else {"already_paused": True})},
            **base,
        )
        if not first:  # a second trip while paused is evidence, not a second incident
            return _blocked("This tool call was blocked by honeycomb-gate.")
        self._best_effort(
            run,
            run.emit,
            "session.paused",
            severity="high",
            decision="pause",
            details={"reason": event_kind},
        )
        self._best_effort(run, self.identities.revoke, run.id, event_kind)
        self._best_effort(run, run.emit, "identity.revoked", severity="high", decision="revoke")
        if event_kind != "memory.rule_matched":  # a repeat teaches nothing new
            self._best_effort(run, self._learn, run, event_kind)
        incident = self._best_effort(run, lambda: self._open_incident(run, incident_for))
        if incident is not None:
            self._spawn(self._notify(run, incident))
        return await self._trip_response(tool, args)

    def _best_effort(self, run: Run, fn: Any, *args: Any, **kwargs: Any) -> Any:
        """Run a step that must not stop the others; if it fails, try to leave a trace."""
        try:
            return fn(*args, **kwargs)
        except Exception as exc:
            with contextlib.suppress(Exception):
                run.emit("gate.error", severity="high", details={"error": type(exc).__name__})
            return None

    def _open_incident(self, run: Run, incident_for: Any) -> Incident:
        incident: Incident = incident_for(self._run_events(run))
        self.incidents.save(incident)
        self._best_effort(
            run,
            run.emit,
            "incident.opened",
            severity="critical",
            details={"incident_id": incident.id, "title": incident.title},
        )
        return incident

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

    async def _notify(self, run: Run, incident: Incident) -> None:
        try:
            key = f"{incident.kind}|{incident.tool}|{incident.run_id}"
            if self.notifier.is_duplicate(key, time.monotonic()):
                run.emit("incident.deduplicated", details={"incident_id": incident.id})
                return
            sent: list[dict[str, str]] = []
            for result in await self.notifier.send(incident):
                sent.append(
                    {"channel": result.channel, "ok": str(result.ok), "error": result.error}
                )
                run.emit(
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
            with contextlib.suppress(Exception):  # if the log itself is gone, nothing more to do
                run.emit(
                    "notify.failed",
                    severity="high",
                    details={"incident_id": incident.id, "error": type(exc).__name__},
                )

    def _inspect_result(self, result: BaseModel) -> tuple[bool, list[Sighting], Rule | None]:
        """Size check, honeytoken scan and learned-rule check of a result (in a worker thread)."""
        payload = result.model_dump(by_alias=True, exclude_none=True)
        if len(json.dumps(payload, default=str)) > MAX_RESULT_CHARS:
            return True, [], None
        found = self.tokens.find(payload)
        rule = None if found else self.memory.match(strings_of(payload, keys=False))
        return False, found, rule

    def _remember(self, run: Run, label: str, payload: Any) -> None:
        """Keep what this run just read, in case it turns out to be how an attack got in."""
        text = "\n".join(strings_of(payload, keys=False))[:50_000]
        if text:
            run.recent.append((sanitize_name(label), text))

    def _learn(self, run: Run, reason: str) -> None:
        for rule in self.memory.learn(run.id, list(run.recent), reason):
            run.emit(
                "memory.rule_learned", severity="medium",
                details={"rule_id": rule.id, "kind": rule.kind, "reason": reason},
            )  # fmt: skip

    async def _trip_memory(
        self, run: Run, rule: Rule, label: str, base: dict[str, Any]
    ) -> types.CallToolResult:
        """A result matched something learned from an earlier incident."""
        self.memory.hit(rule.id)
        details = {"rule_id": rule.id, "kind": rule.kind}
        if self.config.memory.on_match == "withhold":
            run.emit("memory.rule_matched", severity="high", decision="withhold",
                     rule_id=rule.id, details=details, **base)  # fmt: skip
            return _blocked("This result was withheld by honeycomb-gate.")
        return await self._trip(
            run,
            event_kind="memory.rule_matched",
            rule_id=rule.id,
            tool=label,
            base=base,
            details=details,
            args={},
            incident_for=lambda events: open_memory_incident(
                run_id=run.id, agent_id=run.agent_id, tool=label, rule_id=rule.id,
                kind=rule.kind, paused=True, events=events, config_hint=self._config_hint(),
            ),
        )  # fmt: skip

    async def drain(self, timeout: float = 15.0) -> None:
        """Let pending notifications finish before the process exits."""
        if self._background:
            await asyncio.wait(self._background, timeout=timeout)

    async def _trip_token(
        self,
        run: Run,
        hit: Sighting,
        where: str,
        tool: str,
        base: dict[str, Any],
        args: dict[str, Any],
    ) -> types.CallToolResult:
        return await self._trip(
            run,
            event_kind="honeytoken.used",
            rule_id="honeytoken-default",
            tool=tool,
            base=base,
            details={"honeytoken_id": hit.token_id, "kind": hit.kind, "where": where},
            args=args,
            incident_for=lambda events: open_token_incident(
                run_id=run.id,
                agent_id=run.agent_id,
                tool=tool,
                token_id=hit.token_id,
                kind=hit.kind,
                placed=hit.placed,
                where=where,
                events=events,
                config_hint=self._config_hint(),
            ),
        )

    # -- MCP handlers ---------------------------------------------------------------------

    async def list_tools(
        self, ctx: ServerRequestContext[Any], params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        run = self._resolve(ctx)
        self._check_resume(run)
        if run.paused:
            run.emit("tools.listed", details={"visible": 0, "hidden": 0, "paused": True})
            return types.ListToolsResult(tools=[])
        visible: list[types.Tool] = []
        real_names: set[str] = set()
        hidden = 0
        for upstream in self.clients:
            try:
                tools = list((await self._fetch(upstream, max_age=0)).values())
                for tool in tools:
                    name = f"{upstream}{SEP}{tool.name}"
                    real_names.add(name)
                    pin = self._check_pin(run, upstream, tool)
                    decision = self.policy.evaluate(upstream, name, None)
                    if (
                        pin.status != APPROVED
                        or not run.allows(name)
                        or (decision.action == "deny" and decision.hide)
                    ):
                        hidden += 1
                        continue
                    # Metadata and icons are not pinned, so they are not forwarded.
                    visible.append(
                        tool.model_copy(update={"name": name, "meta": None, "icons": None})
                    )
            except Exception as exc:  # fail closed for this upstream only, and say so
                run.emit(
                    "gate.error",
                    severity="high",
                    upstream=upstream,
                    details={"error": type(exc).__name__, "while": "listing tools"},
                )
        decoy_count = 0
        if self.decoys is not None and self.decoys.names:
            decoy_tools, skipped = self.decoys.tools(real_names)
            for name in skipped:
                run.emit(
                    "decoy.collision", severity="medium", tool=name,
                    details={"note": "a real tool has this name, so the decoy was left out"},
                )  # fmt: skip
            visible.extend(decoy_tools)
            decoy_count = len(decoy_tools)
        run.emit(
            "tools.listed",
            details={
                "visible": len(visible) - decoy_count,
                "hidden": hidden,
                "decoys": decoy_count,
            },
        )
        return types.ListToolsResult(tools=visible)

    # -- resources and prompts: passed through, logged and scanned, never trusted -------------

    def _offers(self, upstream: str, what: str) -> bool:
        caps = getattr(self.clients[upstream], "server_capabilities", None)
        return caps is not None and getattr(caps, what, None) is not None

    def _refuse(self, run: Run, rule_id: str, label: str, reason: str, message: str) -> NoReturn:
        run.emit(
            "call.denied", severity="medium", decision="deny", rule_id=rule_id,
            tool=label, details={"reason": reason},
        )  # fmt: skip
        raise MCPError(types.INVALID_REQUEST, f"Blocked by honeycomb-gate: {message}.")

    def _refuse_if_paused(self, run: Run, what: str) -> None:
        self._check_resume(run)
        if run.paused:
            self._refuse(run, "run-control", what, "run_paused", "the run is paused")

    def _require_scope(self, run: Run, scope_name: str, label: str) -> None:
        if not run.allows(scope_name):
            self._refuse(run, "scopes", label, "out_of_scope", "out of scope")

    async def _vet(
        self, run: Run, label: str, payload: Any, where: str, base: dict[str, Any]
    ) -> None:
        """Scan something an agent sent or an upstream returned. A planted secret trips the run."""
        too_big = len(json.dumps(payload, default=str)) > MAX_RESULT_CHARS
        found = [] if too_big else await asyncio.to_thread(self.tokens.find, payload)
        rule = None
        if where == "result" and not too_big and not found:
            texts = strings_of(payload, keys=False)
            rule = await asyncio.to_thread(self.memory.match, texts)
        if rule is not None:
            await self._trip_memory(run, rule, label, base)
            raise MCPError(types.INVALID_REQUEST, "Blocked by honeycomb-gate.")
        if too_big:
            run.emit("call.denied", severity="medium", decision="deny", rule_id="gate",
                          details={"reason": "payload_too_large"}, **base)  # fmt: skip
        elif found:
            await self._trip_token(run, found[0], where, label, base, {})
        if too_big or found:
            raise MCPError(types.INVALID_REQUEST, "Blocked by honeycomb-gate.")

    async def _upstream_lists(
        self, run: Run, what: str, field: str, call: str, rename: Callable[[str, Any], Any]
    ) -> list[Any]:
        out: list[Any] = []
        for upstream in self.clients:
            if not self._offers(upstream, what):
                continue
            fetch = getattr(self.clients[upstream], call)
            try:
                items = await self._collect(upstream, fetch, field)
            except Exception as exc:
                run.emit(
                    "gate.error",
                    severity="high",
                    upstream=upstream,
                    details={"error": type(exc).__name__, "while": f"listing {what}"},
                )
                continue
            out.extend(rename(upstream, item) for item in items)
        return out

    async def _passthrough[R: BaseModel](
        self,
        run: Run,
        label: str,
        request: Any,
        base: dict[str, Any],
        kind: str,
        call: Callable[[], Awaitable[R]],
        failure: str,
    ) -> R:
        """Vet the request, log it, make the upstream call, then vet what came back."""
        await self._vet(run, label, request, "arguments", base)
        run.emit(kind, decision="allow", **base)
        try:
            result = await asyncio.wait_for(call(), self.config.call_timeout_s)
        except Exception as exc:
            run.emit("gate.error", severity="high", details={"error": type(exc).__name__}, **base)
            raise MCPError(types.INTERNAL_ERROR, f"The upstream could not {failure}.") from exc
        payload = result.model_dump(by_alias=True, exclude_none=True)
        await self._vet(run, label, payload, "result", base)
        self._remember(run, label, payload)
        return result

    async def list_resources(
        self, ctx: ServerRequestContext[Any], params: types.PaginatedRequestParams | None
    ) -> types.ListResourcesResult:
        run = self._resolve(ctx)
        self._check_resume(run)
        resources: list[types.Resource] = []
        if not run.paused:
            resources = await self._upstream_lists(
                run,
                "resources", "resources", "list_resources",
                lambda up, r: r.model_copy(
                    update={"uri": _gate_uri(up, r.uri), "meta": None, "icons": None}
                ),
            )  # fmt: skip
        resources = [
            r for r in resources if run.allows(f"{_split_gate_uri(r.uri)[0]}{SEP}resources/read")
        ]
        run.emit("resource.listed", details={"count": len(resources), "paused": run.paused})
        return types.ListResourcesResult(resources=resources)

    async def read_resource(
        self, ctx: ServerRequestContext[Any], params: types.ReadResourceRequestParams
    ) -> types.ReadResourceResult:
        run = self._resolve(ctx)
        self._refuse_if_paused(run, "resources/read")
        upstream, original = _split_gate_uri(params.uri)
        if upstream not in self.clients:
            raise MCPError(types.INVALID_PARAMS, "Unknown resource.")
        self._require_scope(run, f"{upstream}{SEP}resources/read", "resources/read")
        shown = {"uri": self.tokens.mask(params.uri)}
        base: dict[str, Any] = {
            "upstream": upstream,
            "tool": "resources/read",
            "args_redacted": shown,
        }
        result = await self._passthrough(
            run, "resources/read", params.uri, base, "resource.read",
            lambda: self.clients[upstream].read_resource(original), "read that resource",
        )  # fmt: skip
        for item in result.contents:
            item.uri = _gate_uri(upstream, item.uri)
            item.meta = None
        return result

    async def list_prompts(
        self, ctx: ServerRequestContext[Any], params: types.PaginatedRequestParams | None
    ) -> types.ListPromptsResult:
        run = self._resolve(ctx)
        self._check_resume(run)
        prompts: list[types.Prompt] = []
        if not run.paused:
            prompts = await self._upstream_lists(
                run,
                "prompts", "prompts", "list_prompts",
                lambda up, p: p.model_copy(
                    update={"name": f"{up}{SEP}{p.name}", "meta": None, "icons": None}
                ),
            )  # fmt: skip
        prompts = [p for p in prompts if run.allows(p.name)]
        run.emit("prompt.listed", details={"count": len(prompts), "paused": run.paused})
        return types.ListPromptsResult(prompts=prompts)

    async def get_prompt(
        self, ctx: ServerRequestContext[Any], params: types.GetPromptRequestParams
    ) -> types.GetPromptResult:
        run = self._resolve(ctx)
        self._refuse_if_paused(run, "prompts/get")
        upstream, _, name = params.name.partition(SEP)
        if upstream not in self.clients or not name:
            raise MCPError(types.INVALID_PARAMS, "Unknown prompt.")
        self._require_scope(run, params.name, "prompts/get")
        args = params.arguments or {}
        shown = self.tokens.mask({"name": params.name, "arguments": args})
        base = {"upstream": upstream, "tool": "prompts/get", "args_redacted": shown}
        result = await self._passthrough(
            run, "prompts/get", {"name": params.name, "arguments": args}, base, "prompt.fetched",
            lambda: self.clients[upstream].get_prompt(name, args), "return that prompt",
        )  # fmt: skip
        result.meta = None
        return result

    async def call_tool(
        self, ctx: ServerRequestContext[Any], params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        run = self._resolve(ctx)
        started = time.monotonic()
        self._check_resume(run)
        args = params.arguments or {}
        upstream, _, tool_name = params.name.partition(SEP)
        safe_name = self.tokens.mask(params.name)  # a token could be smuggled in the tool name
        base: dict[str, Any] = {"upstream": self.tokens.mask(upstream), "tool": safe_name}

        def deny(reason: str, rule_id: str = "gate", severity: str = "low") -> types.CallToolResult:
            run.emit(
                "call.denied",
                severity=severity,
                decision="deny",
                rule_id=rule_id,
                details={"reason": reason},
                **base,
            )
            return _blocked("This tool call was blocked by honeycomb-gate.")

        if exceeds_depth(args, MAX_DEPTH):  # nothing real nests this deep; scanners would choke
            return deny("too_deeply_nested", "gate", "medium")
        try:
            size = len(params.name) + len(json.dumps(args, default=str))
        except (TypeError, ValueError, RecursionError):
            return deny("unreadable_arguments", "gate", "medium")
        base["args_digest"] = digest(params.arguments)
        base["args_redacted"] = self.tokens.mask(args)  # honeytoken values never reach the log
        if run.paused:
            return deny("run_paused", "run-control", "medium")
        if size > MAX_ARGS_CHARS:
            return deny("payload_too_large", "gate", "medium")

        # 1. Decoys: no legitimate run ever calls one. The call is never forwarded.
        if self.decoys is not None and self.decoys.is_decoy(params.name):
            return await self._trip(
                run,
                event_kind="decoy.tripped",
                rule_id="decoy-default",
                tool=safe_name,
                base=base,
                details={"decoy": tool_name},
                args=args,
                incident_for=lambda events: open_decoy_incident(
                    run_id=run.id,
                    agent_id=run.agent_id,
                    tool=params.name,
                    events=events,
                    config_hint=self._config_hint(),
                ),
            )

        # 2. Honeytokens in the arguments: the agent is trying to use or pass on a planted secret.
        seen = await asyncio.to_thread(self.tokens.find, {"tool": params.name, "arguments": args})
        if seen:
            return await self._trip_token(run, seen[0], "arguments", safe_name, base, args)

        if not run.allows(params.name):
            return deny("out_of_scope", "scopes", "medium")
        if upstream not in self.clients or not tool_name:
            return deny("unknown_tool")
        try:
            tools = await self._fetch(upstream, max_age=self.config.recheck_ttl_s)
            live = tools.get(tool_name)
            if live is None:
                return deny("unknown_tool")
            pin = self._check_pin(run, upstream, live)
            if pin.status != APPROVED:
                return deny(pin.status, "pinning", "medium")
            decision = self.policy.evaluate(upstream, params.name, args)
            if decision.action == "deny":
                return deny(decision.reason, decision.rule_id)
            if not self.governor.within_rate(run, decision, record=False):
                return deny("rate_limit", decision.rule_id, "medium")  # before using an approval
            if decision.action == "approve":  # a person has to say yes first
                answer = await self.governor.approval(run, decision, params.name, base, deny)
                if answer is not None:
                    return answer
                # The wait can be long: look at the tool again before acting on the answer.
                tools = await self._fetch(upstream, max_age=self.config.recheck_ttl_s)
                again = tools.get(tool_name)
                if again is None or self._check_pin(run, upstream, again).status != APPROVED:
                    return deny("changed_while_waiting", "pinning", "medium")
            if not self.governor.within_rate(run, decision):
                return deny("rate_limit", decision.rule_id, "medium")
            if run.paused:  # another call tripped while this one was waiting: do not forward
                return deny("run_paused", "run-control", "medium")
            # Record the decision before the action: if the log cannot be written, the call
            # does not happen (fail closed on evidence).
            run.emit("call.allowed", decision="allow", rule_id=decision.rule_id, **base)
            result = await asyncio.wait_for(
                self.clients[upstream].call_tool(tool_name, params.arguments),
                self.config.call_timeout_s,
            )
        except Exception as exc:
            run.emit("gate.error", severity="high", details={"error": type(exc).__name__}, **base)
            if self.strict or self.policy.is_high_impact(params.name):
                return _blocked("This tool call was blocked by honeycomb-gate (internal error).")
            raise

        # 3. Honeytokens in the result: something handed the agent a planted secret. Withhold it.
        too_big, found, rule = await asyncio.to_thread(self._inspect_result, result)
        if too_big:  # refused unseen, so the agent never receives it; also keeps the scan quick
            return deny("result_too_large", "gate", "medium")
        if found:
            return await self._trip_token(run, found[0], "result", params.name, base, args)
        if rule is not None:
            return await self._trip_memory(run, rule, params.name, base)
        if run.paused:  # the run tripped while this call was in flight: its result is withheld
            return deny("run_paused", "run-control", "medium")
        over = self.governor.over_result_cap(result, decision)
        run.emit(
            "call.completed",
            upstream=upstream,
            tool=params.name,
            latency_ms=int((time.monotonic() - started) * 1000),
            details={"is_error": bool(result.is_error), **({"withheld": over} if over else {})},
        )
        if over:  # it ran, so say so: the agent must not repeat a call that already happened
            return _blocked(
                "This tool ran, but honeycomb-gate withheld its answer because it was larger "
                f"than the rule allows ({over}). Do not repeat the call."
            )
        self._remember(run, params.name, result.model_dump(by_alias=True, exclude_none=True))
        try:  # a baseline problem is logged, and never changes what happens to the call
            answer_size = sum(len(getattr(c, "text", "") or "") for c in result.content)
            for found_dev in self.baselines.observe(
                run.id, run.agent_id, upstream, params.name, size, answer_size
            ):
                run.emit(
                    "baseline.deviation", severity="medium", upstream=upstream,
                    tool=params.name, details=found_dev,
                )  # fmt: skip
        except Exception as exc:
            run.emit(
                "gate.error", severity="medium",
                details={"error": type(exc).__name__, "while": "baseline"},
            )  # fmt: skip
        return result


def check_state(config: GateConfig) -> None:
    """Refuse to start on evidence of tampering or lost state, instead of quietly starting fresh."""
    log = config.event_log_path
    lock = FileLock(log.with_name(log.name + ".lock"))
    try:  # another gate writing right now would make a half-written line look like damage
        lock.acquire(blocking=False)
    except LockedError as exc:
        raise LogCorruptError(f"another gate is already writing {log}") from exc
    lock.release()
    report = verify_chain(log, config.alert_sink)
    if not report.ok:
        raise StateCorruptError(
            f"The event log failed its integrity check ({report.reason}; line "
            f"{report.first_break}). Keep the log and the second sink as evidence, move both "
            "aside and start a new chain. If you only just turned the second sink on, create an "
            "empty file at its path first."
        )
    # Read every state file now, so a damaged one is reported here, by name, not on a first call.
    PinStore(config.pins_path).entries()
    Baselines.load(config.baselines_path)
    Memory(config.memory_path, config.memory)
    RunControl(config.runs_path).paused()
    TokenRegistry(config.tokens_path).tokens()
    DecoyBook(config.decoys, list(config.upstreams), config.decoys_path)
    if log_has_event(log, "tool.pinned") and not config.pins_path.exists():
        raise StateCorruptError(
            f"{config.pins_path} is missing, but the log shows tools were pinned. Starting "
            "without it would trust a quarantined tool again. Restore the file from a backup, "
            "or move the event log aside to start fresh."
        )


def build_server(gate: Gate) -> Server[Any]:
    return Server(
        "honeycomb-gate",
        version=__version__,
        on_list_tools=gate.list_tools,
        on_call_tool=gate.call_tool,
        on_list_resources=gate.list_resources,
        on_read_resource=gate.read_resource,
        on_list_prompts=gate.list_prompts,
        on_get_prompt=gate.get_prompt,
    )


@contextlib.asynccontextmanager
async def open_gate(
    config: GateConfig, config_path: Path | None, *, front_door: str
) -> AsyncIterator[Gate]:
    """Check the state, start the upstreams and the log, and close it all down afterwards."""
    check_state(config)
    log = EventLog(config.event_log_path, agent_id=config.agent_id, alert_sink=config.alert_sink)
    gate = Gate(config, log)
    gate.config_path = config_path
    try:
        async with AsyncExitStack() as stack:
            for name, up in config.upstreams.items():
                params = StdioServerParameters(
                    command=up.command[0], args=up.command[1:], env=up.env or None
                )
                gate.clients[name] = await stack.enter_async_context(Client(params))
            gate.setup_decoys()
            gate.default.emit(
                "session.started", details={"upstreams": list(config.upstreams), "via": front_door}
            )
            gate.default.emit("identity.issued", details={"how": "minted by the gate at start-up"})
            governor = asyncio.create_task(gate.governor.loop())
            watcher = None
            if config.egress.log is not None:
                from honeycomb_gate.egress_watch import EgressWatch  # imports this module

                watcher = asyncio.create_task(EgressWatch(gate).run())
            try:
                yield gate
            finally:
                for task in (governor, watcher):
                    if task is not None:
                        task.cancel()
                        await asyncio.gather(task, return_exceptions=True)
                gate.baselines.flush()
            await gate.drain()  # let incident emails finish before the process exits
            gate.default.emit("session.ended")
    finally:
        log.close()


async def serve(config: GateConfig, config_path: Path | None = None) -> None:
    """Serve one agent over stdio: the process that starts the gate is the agent's run."""
    async with open_gate(config, config_path, front_door="stdio") as gate:
        gate.inherit_pause(gate.default)
        server = build_server(gate)
        try:
            async with stdio_server() as (read, write):
                await server.run(read, write, server.create_initialization_options())
        finally:
            await gate.drain()
