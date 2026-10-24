# ADR-0002: Gate-minted run identity

Status: Accepted by the owner on 24 October 2026. Date: 2026-10-24. Changes F7 and the event schema.

## Context

MCP revision 2026-07-28 removes protocol-level sessions and the `Mcp-Session-Id` header. List endpoints no longer vary per connection, and servers that need state use explicit handles (official repo, `docs/specification/2026-07-28/changelog.mdx`, SEP-2567). The Python SDK 2.x serves both the old handshake era and the new per-request era.

## Decision

The gate mints its own `run_id` and a short-lived signed run token (HMAC or Ed25519, 15 minutes or less, renewable under policy). Nothing depends on an MCP session value.

- stdio: one connection is one run.
- Streamable HTTP: the agent presents the run token on every request, and the gate checks signature, expiry and revocation on every call.
- Events always carry `run_id`. `session_id` is optional and only set when the transport provides one.
- The "session manager" component is renamed "run manager".
- Pausing and revoking act on the `run_id`.

## Consequences

Event schema v1 is unreleased, so we change it now and note it in the spec: `run_id` becomes required and `session_id` optional.

We need a small key-management story (a key per deployment, and rotation). That goes on the M3 backlog. We also run a contract test against each new MCP revision.
