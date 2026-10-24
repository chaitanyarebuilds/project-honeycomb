"""honeycomb-egress: a small allowlisting HTTP proxy for the agent's only way out (F8).

It is plain standard library and holds no signing key. For every request it writes one JSON
line (who asked, where to, allowed or blocked, and the id of a honeytoken if one was in the
request). The gate reads that file as untrusted data and decides what to do.

What it can see depends on the request. For plain HTTP it reads the URL, the headers and the
first megabyte of the body and scans them for honeytokens. For HTTPS (CONNECT) it sees only the
host and port, because we do not break TLS, so a token sent over HTTPS to an allowed host goes
through unseen. An allowed name is trusted to resolve where its owner says.
"""

import argparse
import asyncio
import contextlib
import json
import re
import time
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

from honeycomb_gate.redact import sanitize_name
from honeycomb_gate.tokens import TokenRegistry
from honeycomb_gate.walk import strings_of

HEAD_LIMIT = 64 * 1024
MAX_BODY = 1_000_000
TIMEOUT_S = 15.0
IDLE_S = 120.0
MAX_CONNECTIONS = 200
SLOT_WAIT_S = 2.0
MAX_PER_SOURCE = 64  # open connections from one address, so one agent can't use every slot
_BAD_HEAD = re.compile(r"(?<!\r)\n|\r(?!\n)|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
HOP_BY_HOP = {"connection", "proxy-connection", "keep-alive", "te", "trailer", "upgrade"}


def _plain_number(text: str) -> bool:
    return text.isascii() and text.isdigit()  # isdigit alone accepts digits like "²"


def _body_views(body: bytes) -> list[str]:
    """The body read three ways, so an odd text encoding or JSON escapes don't hide a token."""
    views = [body.decode("latin-1"), body.decode("utf-8", "replace")]
    try:
        views.extend(strings_of(json.loads(body)))  # \\uXXXX escapes become real characters
    except (ValueError, RecursionError):
        pass
    return views


def parse_hostport(text: str, default_port: int | None = None) -> tuple[str, int] | None:
    """``host:port`` (or a bare host with a default port), or None if it isn't one."""
    host, sep, port = text.strip().rpartition(":")
    if not sep or not host:
        host, port = text.strip(), str(default_port or "")
    host = host.strip("[]").lower()
    if not host or not _plain_number(port) or not 0 < int(port) < 65536:
        return None
    return host, int(port)


class EgressProxy:
    def __init__(
        self, allow: set[tuple[str, int]], log: Path, tokens: TokenRegistry | None = None
    ) -> None:
        self.allow = allow
        self.log = log
        self.tokens = tokens
        self._slots = asyncio.Semaphore(MAX_CONNECTIONS)
        self._open: Counter[str] = Counter()

    # -- records ------------------------------------------------------------------------------

    def _record(self, src: str, method: str, host: str, port: int, verdict: str, reason: str,
                token_id: str = "") -> None:  # fmt: skip
        entry = {
            "ts": time.time(),
            "src_ip": src,
            "method": method[:16],
            "host": sanitize_name(host)[:253],
            "port": port,
            "verdict": verdict,
            "reason": reason,
        }
        if token_id:
            entry["honeytoken_id"] = token_id
        self.log.parent.mkdir(parents=True, exist_ok=True)
        with self.log.open("ab") as f:  # one write per line, append only
            f.write(json.dumps(entry).encode() + b"\n")

    def _scan(self, *parts: str) -> str:
        """The id of a honeytoken found in any of the texts, or an empty string."""
        if self.tokens is None:
            return ""
        found = self.tokens.find({"parts": list(parts)})
        return found[0].token_id if found else ""

    # -- the server ---------------------------------------------------------------------------

    async def serve(self, host: str, port: int) -> None:
        server = await asyncio.start_server(self.handle, host, port, limit=HEAD_LIMIT)
        async with server:
            await server.serve_forever()

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername") or ("?", 0)
        src = str(peer[0])
        if self._open[src] >= MAX_PER_SOURCE:
            writer.close()  # not logged: a flood of refusals must not flood the log
            return
        self._open[src] += 1
        try:
            await asyncio.wait_for(self._slots.acquire(), SLOT_WAIT_S)
        except TimeoutError:  # busy: say so quickly instead of queueing behind idle tunnels
            self._open[src] -= 1
            with contextlib.suppress(Exception):
                await self._reply(writer, 503, "busy")
                writer.close()
            return
        try:
            try:
                await self._handle(reader, writer, src)
            except Exception:  # fail closed: whatever went wrong, nothing is forwarded after it
                with contextlib.suppress(Exception):
                    await self._reply(writer, 502, "honeycomb-egress could not handle that")
            finally:
                self._open[src] -= 1
                with contextlib.suppress(Exception):
                    writer.close()
                    await writer.wait_closed()
        finally:
            self._slots.release()

    @staticmethod
    async def _reply(writer: asyncio.StreamWriter, code: int, text: str) -> None:
        body = text.encode()
        writer.write(
            f"HTTP/1.1 {code} {text.split(':')[0][:30]}\r\nContent-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n".encode()
            + body
        )
        await writer.drain()

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, src: str
    ) -> None:
        try:
            raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), TIMEOUT_S)
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, TimeoutError):
            self._record(src, "?", "?", 0, "blocked", "bad_request")
            await self._reply(writer, 400, "bad request")
            return
        head = raw.decode("latin-1")
        if _BAD_HEAD.search(head):  # a bare line feed or a control character can smuggle a header
            self._record(src, "?", "?", 0, "blocked", "bad_request")
            await self._reply(writer, 400, "bad request")
            return
        first, *rest = head.split("\r\n")
        words = first.split(" ")
        headers = {}
        for line in rest:
            if not line:
                continue
            name, sep, value = line.partition(":")
            if not sep or not name.strip():
                self._record(src, "?", "?", 0, "blocked", "bad_request")
                await self._reply(writer, 400, "bad request")
                return
            headers[name.strip().lower()] = value.strip()
        if len(words) != 3:
            self._record(src, "?", "?", 0, "blocked", "bad_request")
            await self._reply(writer, 400, "bad request")
        elif words[0].upper() == "CONNECT":
            await self._connect(reader, writer, src, words[1], head)
        else:
            await self._forward(reader, writer, src, words[0], words[1], head, headers)

    async def _deny(
        self, writer: asyncio.StreamWriter, src: str, method: str, host: str, port: int,
        reason: str, token_id: str = "",
    ) -> None:  # fmt: skip
        self._record(src, method, host, port, "blocked", reason, token_id)
        await self._reply(writer, 403, "blocked by honeycomb-egress")

    async def _connect(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, src: str,
        target: str, head: str,
    ) -> None:  # fmt: skip
        parsed = parse_hostport(target, 443)
        if parsed is None:
            await self._deny(writer, src, "CONNECT", "?", 0, "bad_target")
            return
        host, port = parsed
        token_id = self._scan(host, target)
        if token_id:
            await self._deny(writer, src, "CONNECT", host, port, "honeytoken", token_id)
        elif (host, port) not in self.allow:
            await self._deny(writer, src, "CONNECT", host, port, "host_not_allowed")
        else:
            try:
                up_r, up_w = await asyncio.wait_for(asyncio.open_connection(host, port), TIMEOUT_S)
            except (OSError, TimeoutError):
                self._record(src, "CONNECT", host, port, "blocked", "upstream_unreachable")
                await self._reply(writer, 502, "upstream unreachable")
                return
            self._record(src, "CONNECT", host, port, "allowed", "allowlist")
            writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
            await writer.drain()
            await asyncio.gather(_pipe(reader, up_w), _pipe(up_r, writer))

    async def _forward(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, src: str,
        method: str, target: str, head: str, headers: dict[str, str],
    ) -> None:  # fmt: skip
        parts = urlsplit(target)
        parsed = parse_hostport(parts.netloc.rpartition("@")[2], 80)
        if parts.scheme != "http" or parsed is None:
            await self._deny(writer, src, method, "?", 0, "not_a_proxy_request")
            return
        host, port = parsed
        if "transfer-encoding" in headers:
            await self._deny(writer, src, method, host, port, "chunked_unsupported")
            return
        length = headers.get("content-length", "0")
        if not _plain_number(length) or int(length) > MAX_BODY:
            await self._deny(writer, src, method, host, port, "body_too_large")
            return
        try:
            body = await asyncio.wait_for(reader.readexactly(int(length)), TIMEOUT_S)
        except (asyncio.IncompleteReadError, TimeoutError):
            await self._deny(writer, src, method, host, port, "bad_request")
            return
        token_id = self._scan(head, *_body_views(body))
        if token_id:
            await self._deny(writer, src, method, host, port, "honeytoken", token_id)
            return
        if (host, port) not in self.allow:
            await self._deny(writer, src, method, host, port, "host_not_allowed")
            return
        try:
            up_r, up_w = await asyncio.wait_for(asyncio.open_connection(host, port), TIMEOUT_S)
        except (OSError, TimeoutError):
            self._record(src, method, host, port, "blocked", "upstream_unreachable")
            await self._reply(writer, 502, "upstream unreachable")
            return
        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        kept = "".join(
            f"{k}: {v}\r\n" for k, v in headers.items()
            if k not in HOP_BY_HOP and not k.startswith("proxy-") and k != "host"
        )  # fmt: skip
        up_w.write(
            f"{method} {path} HTTP/1.1\r\nHost: {parts.netloc.rpartition('@')[2]}\r\n"
            f"{kept}Connection: close\r\n\r\n".encode("latin-1", "replace")
            + body
        )
        await up_w.drain()
        self._record(src, method, host, port, "allowed", "allowlist")
        await _pipe(up_r, writer)
        up_w.close()


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while data := await asyncio.wait_for(reader.read(65536), IDLE_S):
            writer.write(data)
            await writer.drain()
    except (OSError, TimeoutError, asyncio.IncompleteReadError):
        pass
    finally:
        with contextlib.suppress(Exception):
            writer.close()


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="honeycomb-egress", description=__doc__.split("\n\n")[0])
    ap.add_argument("--listen", default="127.0.0.1:3128", help="host:port to listen on")
    ap.add_argument(
        "--allow", action="append", default=[], metavar="HOST:PORT",
        help="a destination the agent may reach; everything else is blocked",
    )  # fmt: skip
    ap.add_argument("--log", type=Path, required=True, help="JSON lines file for the gate to read")
    ap.add_argument("--tokens", type=Path, help="the gate's tokens.json, to spot honeytokens")
    args = ap.parse_args(argv)
    listen = parse_hostport(args.listen)
    allow = {p for a in args.allow if (p := parse_hostport(a)) is not None}
    if listen is None or len(allow) != len(args.allow):
        ap.error("--listen and --allow must look like host:port")
    tokens = TokenRegistry(args.tokens, read_only=True) if args.tokens else None
    asyncio.run(EgressProxy(allow, args.log, tokens).serve(*listen))


if __name__ == "__main__":
    main()
