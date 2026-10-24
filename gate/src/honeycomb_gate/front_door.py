"""The HTTP front door (F1, F7): Streamable HTTP in, a run token checked on every request.

Nothing reaches the MCP handlers without a valid token, and the token's claims travel with the
request, so one gate process can serve many runs at once. A tripped run has its identity
revoked, which closes this door for that run until an operator issues it a new token.
"""

import contextlib
import json
import sys
import time
from pathlib import Path

import uvicorn
from mcp.server.transport_security import TransportSecuritySettings
from starlette.responses import Response
from starlette.types import ASGIApp, Receive, Scope, Send

from honeycomb_gate.config import GateConfig
from honeycomb_gate.identity import Claims, Identities, TokenError
from honeycomb_gate.locking import StateCorruptError
from honeycomb_gate.proxy import Gate, build_server, open_gate

LOG_EVERY_S = 10.0  # a client hammering the door gets one log line per window, not a flood


class BearerGuard:
    """Pure ASGI middleware, so streaming responses pass through untouched."""

    def __init__(self, app: ASGIApp, gate: Gate) -> None:
        self.app = app
        self.gate = gate
        self._last_logged = -LOG_EVERY_S
        self._suppressed = 0

    def _authenticate(self, scope: Scope) -> Claims:
        header = dict(scope["headers"]).get(b"authorization", b"").decode("latin-1")
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise TokenError("no bearer token")
        ids: Identities = self.gate.identities
        claims = ids.verify(token.strip())
        if self.gate.config.mode == "strict" and claims.agent_id not in self.gate.config.agents:
            raise TokenError("agent is not registered")
        return claims

    def _rejected(self, reason: str) -> None:
        now = time.monotonic()
        if now - self._last_logged < LOG_EVERY_S:
            self._suppressed += 1
            return
        self.gate.default.emit(
            "identity.rejected",
            severity="medium",
            decision="deny",
            details={"reason": reason, "suppressed_since_last": self._suppressed},
        )
        self._last_logged, self._suppressed = now, 0

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        try:
            scope["honeycomb_claims"] = self._authenticate(scope)
        except (TokenError, StateCorruptError, ValueError) as exc:
            # A full disk must not turn a refusal into an opening.
            with contextlib.suppress(Exception):
                self._rejected(str(exc))
            refusal = Response(
                json.dumps({"error": "unauthorized"}),
                status_code=401,
                headers={"www-authenticate": "Bearer"},
                media_type="application/json",
            )
            await refusal(scope, receive, send)
        else:
            await self.app(scope, receive, send)


def build_app(gate: Gate) -> ASGIApp:
    cfg = gate.config.http
    security = None
    if cfg.allowed_hosts:
        loopback = [f"{h}:*" for h in ("127.0.0.1", "localhost", "[::1]")]
        security = TransportSecuritySettings(allowed_hosts=[*loopback, *cfg.allowed_hosts])
    app = build_server(gate).streamable_http_app(
        stateless_http=True,
        host=cfg.host,
        max_request_body_size=cfg.max_body_bytes,
        transport_security=security,
    )
    return BearerGuard(app, gate)


async def serve_http(config: GateConfig, config_path: Path | None = None) -> None:
    """Serve many runs over HTTP until the process is stopped."""
    async with open_gate(config, config_path, front_door="http") as gate:
        gate.require_claims = True
        cfg = config.http
        if cfg.host not in ("127.0.0.1", "localhost", "::1"):
            print(
                f"honeycomb-gate listens on {cfg.host} without TLS. Put it on a private network "
                "or behind a reverse proxy that terminates TLS.",
                file=sys.stderr,
            )
        server = uvicorn.Server(
            uvicorn.Config(build_app(gate), host=cfg.host, port=cfg.port, log_level="warning")
        )
        await server.serve()
