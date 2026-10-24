"""The egress proxy: allowed traffic passes, everything else is blocked, tokens are spotted."""

import asyncio
import base64
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from honeycomb_gate.egress import EgressProxy, parse_hostport
from honeycomb_gate.tokens import Token, TokenRegistry


@dataclass
class Origin:
    port: int
    seen: list[bytes] = field(default_factory=list)


@asynccontextmanager
async def origin() -> AsyncIterator[Origin]:
    """A tiny HTTP server that remembers what it was sent, and an echo for tunnels."""
    state = Origin(0)

    async def handle(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        data = await r.read(65536)
        state.seen.append(data)
        if data.startswith((b"GET", b"POST", b"PUT")):
            w.write(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
        else:
            w.write(data)  # an echo, for the CONNECT tunnel
        await w.drain()
        w.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    state.port = server.sockets[0].getsockname()[1]
    async with server:
        yield state


@asynccontextmanager
async def proxy(tmp_path: Path, allow_port: int | None) -> AsyncIterator[tuple[int, Token, Path]]:
    tokens = TokenRegistry(tmp_path / "tokens.json")
    token = tokens.create("api-key")
    log = tmp_path / "egress.jsonl"
    allow = {("127.0.0.1", allow_port)} if allow_port else set()
    p = EgressProxy(allow, log, tokens)
    server = await asyncio.start_server(p.handle, "127.0.0.1", 0, limit=64 * 1024)
    async with server:
        yield server.sockets[0].getsockname()[1], token, log


def lines(log: Path) -> list[dict[str, object]]:
    return [json.loads(x) for x in log.read_text().splitlines()]


async def get(proxy_port: int, url: str, **kw: object) -> httpx.Response:
    async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{proxy_port}") as c:
        return await c.request(str(kw.pop("method", "GET")), url, **kw)  # type: ignore[arg-type]


async def raw(proxy_port: int, request: bytes) -> bytes:
    r, w = await asyncio.open_connection("127.0.0.1", proxy_port)
    w.write(request)
    await w.drain()
    data = await asyncio.wait_for(r.read(65536), 5)
    w.close()
    return data


async def test_an_allowed_request_goes_through_and_a_lookalike_is_not_a_token(
    tmp_path: Path,
) -> None:
    async with origin() as up:
        async with proxy(tmp_path, up.port) as (pp, token, log):
            ok = await get(pp, f"http://127.0.0.1:{up.port}/health?id=abc123def456")
            assert ok.status_code == 200 and ok.text == "hello"
            lookalike = "sk_live_" + "a1b2c3d4e5f6" * 3  # looks like a key, is not ours
            assert (
                await get(pp, f"http://127.0.0.1:{up.port}/", params={"k": lookalike})
            ).status_code == 200
            assert [e["verdict"] for e in lines(log)] == ["allowed", "allowed"]
            assert not [e for e in lines(log) if "honeytoken_id" in e]


async def test_a_host_that_is_not_on_the_list_is_blocked_and_never_contacted(
    tmp_path: Path,
) -> None:
    async with origin() as elsewhere, origin() as allowed:
        async with proxy(tmp_path, allowed.port) as (pp, _, log):
            r = await get(
                pp, f"http://127.0.0.1:{elsewhere.port}/collect", method="POST", content=b"x"
            )
            assert r.status_code == 403 and elsewhere.seen == []
            assert lines(log)[-1]["reason"] == "host_not_allowed"
            assert lines(log)[-1]["port"] == elsewhere.port


async def test_a_honeytoken_is_caught_in_the_url_body_and_headers_even_for_allowed_hosts(
    tmp_path: Path,
) -> None:
    async with origin() as up:
        async with proxy(tmp_path, up.port) as (pp, token, log):
            base = f"http://127.0.0.1:{up.port}/"
            wrapped = base64.b64encode(f"export KEY={token.value}".encode()).decode()
            tries = [
                get(pp, base + f"?k={token.value}"),
                get(pp, base, method="POST", content=token.value.encode()),
                get(pp, base, method="POST", content=wrapped.encode()),
                get(pp, base, headers={"X-Note": token.value}),
            ]
            for t in tries:
                assert (await t).status_code == 403
            assert up.seen == []  # nothing reached the destination
            hits = lines(log)
            assert len(hits) == 4 and {e["honeytoken_id"] for e in hits} == {token.id}
            assert {e["reason"] for e in hits} == {"honeytoken"}
            assert token.value not in log.read_text()


async def test_connect_is_checked_by_host_and_port_only(tmp_path: Path) -> None:
    async with origin() as up, origin() as other:
        async with proxy(tmp_path, up.port) as (pp, token, log):
            ok = await raw(pp, f"CONNECT 127.0.0.1:{up.port} HTTP/1.1\r\n\r\n".encode())
            assert ok.startswith(b"HTTP/1.1 200")
            no = await raw(pp, f"CONNECT 127.0.0.1:{other.port} HTTP/1.1\r\n\r\n".encode())
            assert no.startswith(b"HTTP/1.1 403")
            hidden = await raw(pp, f"CONNECT {token.id}.example.test:443 HTTP/1.1\r\n\r\n".encode())
            assert hidden.startswith(b"HTTP/1.1 403")
            assert [e["reason"] for e in lines(log)] == [
                "allowlist",
                "host_not_allowed",
                "honeytoken",
            ]


async def test_odd_requests_are_refused_not_forwarded(tmp_path: Path) -> None:
    async with origin() as up:
        async with proxy(tmp_path, up.port) as (pp, _, log):
            url = f"http://127.0.0.1:{up.port}/"
            chunked = f"POST {url} HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n".encode()
            assert (await raw(pp, chunked)).startswith(b"HTTP/1.1 403")
            big = f"POST {url} HTTP/1.1\r\nContent-Length: 99999999\r\n\r\n".encode()
            assert (await raw(pp, big)).startswith(b"HTTP/1.1 403")
            assert (await raw(pp, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")).startswith(b"HTTP/1.1 403")
            assert (await raw(pp, b"nonsense\r\n\r\n")).startswith(b"HTTP/1.1 400")
            assert up.seen == []
            assert [e["reason"] for e in lines(log)] == [
                "chunked_unsupported", "body_too_large", "not_a_proxy_request", "bad_request",
            ]  # fmt: skip


def test_host_and_port_parsing() -> None:
    assert parse_hostport("Example.test:8080") == ("example.test", 8080)
    assert parse_hostport("example.test", 80) == ("example.test", 80)
    assert parse_hostport("[::1]:443") == ("::1", 443)
    for bad in ("", "host:0", "host:99999", "host:abc", ":80"):
        assert parse_hostport(bad) is None


async def test_a_bare_line_feed_cannot_smuggle_a_header_to_an_allowed_host(tmp_path: Path) -> None:
    async with origin() as up:
        async with proxy(tmp_path, up.port) as (pp, _, log):
            url = f"http://127.0.0.1:{up.port}/"
            sneaky = f"GET {url} HTTP/1.1\r\nX-A: 1\nTransfer-Encoding: chunked\r\n\r\n".encode()
            assert (await raw(pp, sneaky)).startswith(b"HTTP/1.1 400")
            nocolon = f"GET {url} HTTP/1.1\r\nnot a header\r\n\r\n".encode()
            assert (await raw(pp, nocolon)).startswith(b"HTTP/1.1 400")
            control = f"GET {url} HTTP/1.1\r\nX-A: a\x00b\r\n\r\n".encode()
            assert (await raw(pp, control)).startswith(b"HTTP/1.1 400")
            assert up.seen == [] and {e["reason"] for e in lines(log)} == {"bad_request"}
            ok = await get(pp, url)  # a normal request still passes
            assert ok.status_code == 200


async def test_odd_encodings_of_the_body_do_not_hide_a_token(tmp_path: Path) -> None:
    async with origin() as up:
        async with proxy(tmp_path, up.port) as (pp, token, log):
            url = f"http://127.0.0.1:{up.port}/"
            spaced = "​".join(token.value).encode("utf-8")
            escaped = json.dumps({"k": token.value}, ensure_ascii=True)
            escaped = escaped.replace(
                token.value[:2], "".join(f"\\u{ord(c):04x}" for c in token.value[:2])
            )
            for body in (spaced, escaped.encode()):
                assert (await get(pp, url, method="POST", content=body)).status_code == 403
            assert up.seen == []


async def test_unusual_digits_in_a_port_or_length_are_a_logged_refusal(tmp_path: Path) -> None:
    async with origin() as up:
        async with proxy(tmp_path, up.port) as (pp, _, log):
            await raw(pp, b"CONNECT 127.0.0.1:\xb2 HTTP/1.1\r\n\r\n")
            bad = f"POST http://127.0.0.1:{up.port}/ HTTP/1.1\r\nContent-Length: \xb2\r\n\r\n"
            await raw(pp, bad.encode("latin-1"))
            assert [e["verdict"] for e in lines(log)] == ["blocked", "blocked"]
