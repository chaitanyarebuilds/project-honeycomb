# M3 plan: run identity, egress and the Docker lab

Status: M3a built, M3b next (25 October 2026). Updated after the [direction check](DIRECTION-CHECK.md).

## What M3 has to deliver

From the spec: signed run identity with revocation (F7), a default-deny egress proxy whose logs feed the event log (F8), and scenario S3 passing in the lab. Two things from the decision records ride along: the agent inventory with run lifetime limits (ADR-0006, F13) and the `posture` report (ADR-0004).

After M2 the gate pauses and "revokes" a run, but revoking only means we stop answering one run id. There is no token anyone can check, and nothing stops an agent from simply walking around the gate. M3 fixes both.

## Split it in two

M3 is the biggest milestone so far, so we'd do it in two halves and commit each one when it's done.

**M3a: identity.** In this order: resources and prompts through the gate (with logging and the honeytoken scan), per-run state, a front door the agent can present a token to, signed run tokens, a simple agent inventory and the posture report.

**M3b: egress.** The egress proxy, the Docker lab on an internal network, and scenario S3 with S1 re-run inside the containers.

## M3a in detail

### Resources and prompts first

Today the gate only answers tool calls, so a client can't use MCP resources or prompts through it. That's safe but it breaks servers that depend on them, and it's an F1 item we promised. We pass them through, log them, and run the honeytoken scan on what comes back. It's a small change and it closes a gap before we open a network port.

### Streamable HTTP in front of the gate

A stdio connection has nowhere to show a token: there are no headers, and the gate just trusts whoever started it. Streamable HTTP does, and it fits the new MCP spec (no sessions, every request stands alone). So M3a adds `honeycomb-gate serve`, which listens on HTTP and checks a bearer token on every request. The MCP SDK we already depend on can serve this, so no new dependency.

It listens on 127.0.0.1 by default. The gate doesn't do TLS itself: in the lab it sits on a private network, and in a real deployment it goes behind a reverse proxy. We'll say so in the deployment notes. This is the first network listener the gate has, so it gets its own threat-model rows.

### The part that needs real surgery: many runs in one process

Today the gate assumes one run per process. `Gate` keeps a single `paused` flag and the log holds a single `run_id`. That's fine for stdio, where one connection is one run. With HTTP, many runs share one gate process, so the run id has to travel with each request, and pause and revoke state has to be kept per run. This is the riskiest change in the milestone, and it touches `proxy.py`, `events.py` and `runs.py`. We'll do it first and keep the stdio tests passing the whole way through.

### Run tokens

- HMAC-SHA256 from the standard library, so no new dependency. The token carries the run id, agent id, scopes, issued-at, expiry and a key id.
- Lifetime is 15 minutes or less and renewable, as the spec says. The gate checks signature, expiry, revocation and the agent's registration on every call.
- The signing key lives outside the repo: an environment variable or a 0600 file in the state directory. A key id lets us rotate: the previous key stays valid only for as long as a token can live.
- The operator hands out tokens with `honeycomb-gate identity issue --agent support-bot`, and can `renew`, `revoke` and `list` them.
- A symmetric key means only the gate can verify tokens. If upstream servers should check them too, we need asymmetric signatures, which means the `cryptography` package. We don't think Phase 0 needs that, so we'd leave it for later and write it down as an ADR when it comes up.

### Agent inventory and scopes

The policy gets an `agents:` section: each agent id with its allowed tool patterns (its scopes) and a maximum run lifetime. A call outside the token's scopes is denied as `out_of_scope`. An agent that isn't registered is denied in strict mode and logged as `agent.unknown` in learning mode. The gate keeps a list of every agent it has seen, with first and last seen, which `honeycomb-gate agents list` prints. Token expiry already stops an identity living forever. Hard maximum run lifetimes and the audit of MCP client configs move to M4.

### Posture report

`honeycomb-gate posture` says which of the four levels (L0 to L3) the deployment is really at, and what it would take to reach the next. It has to be honest about what it can't see: from inside the gate we can read the config, but only the lab test can prove the agent has no other route out. So the report separates "declared" from "verified".

## M3b in detail

### The egress proxy

A small program of our own, written with the standard library: an HTTP proxy that handles plain requests and CONNECT, denies everything that isn't on an allowlist (host and port), and logs every request as one JSON line.

It can only read what it can see. For plain HTTP that's the URL, headers and the start of the body, and the proxy scans those for honeytokens. For HTTPS it sees the host and port and nothing else, because we won't break TLS. So a token sent over HTTPS to a host on the allowlist gets through unseen. We'll write that limit into the threat model instead of hiding it. A token placed in a hostname is visible, which covers the simple DNS-style leak.

### Getting the proxy's records into the gate

The proxy writes its log to a volume shared with the gate. The gate tails that file and turns each line into an `egress.blocked` event in its own hash-chained log. If a line shows a honeytoken, the gate trips just as it does for a decoy. One catch: the proxy can't tell which run sent the request. In the lab there's one agent, so we pause every active run of that agent, and we'll say clearly that this is a blunt choice.

### The Docker lab

Five containers and two networks:

- `labnet` is `internal: true`, so it has no route out. The agent, the gate and the egress proxy are on it.
- `outside` has a route to the world. Only the egress proxy and a `sink` container (a stand-in for an attacker's server) are on it.
- The agent can reach the gate and the proxy and nothing else. The sink can only be reached through the proxy, and the proxy is told to block it.

The gate container runs the lab's CRM and document servers as stdio subprocesses. That keeps M3 smaller: the gate speaking HTTP to its upstreams is a separate piece of work we're not doing yet.

### Scenarios

**S3.** The scripted agent finds a planted honeytoken in its own workspace and tries to send it to the sink, first by connecting directly, then through the proxy. We expect the direct attempt to fail, the proxy to log `egress.blocked`, the gate to log `honeytoken.used` and pause the run, and the sink to have received nothing.

**S1 again, in the containers.** Same scenario as M2, but over HTTP with a real run token, so we know the whole path works.

We can run the lab in the build sandbox: the Docker CLI is there, the daemon starts when we run `dockerd` by hand, images pull, and a network marked internal really has no route out (we checked on 25 October). We'll also run the same lab in GitHub Actions, and on your machine with Docker Desktop. The proxy, the token code and the log ingestion have ordinary in-process tests too.

## Tests we'd write

- Tokens: tampered, expired, replayed after revoke, signed with an old key, wrong agent, scope too wide, and a benign token that must pass.
- Inventory: unknown agent in both modes, and the list of agents the gate has seen.
- Resources and prompts: a poisoned resource is logged, a honeytoken in one trips the run, a normal one passes.
- Proxy: allowed host, blocked host, CONNECT, a token in a URL and in a body, a big body, a look-alike string that isn't a token.
- Ingestion: a log line becomes the right event, a torn line doesn't crash the gate, a token hit pauses the run.
- Posture: the right level for four example setups.
- Lab: S1 and S3 in Docker.

## How we'll know it's done (gate G3)

1. S3 passes in the Docker lab, and the sink received nothing.
2. Every token test above passes.
3. An unregistered agent is denied in strict mode.
4. `posture` gives the right answer in all four example setups.
5. The threat model has rows for the HTTP listener, tokens and the egress proxy, with the HTTPS limit written down.
6. The same stdio tests from M0 to M2 still pass.

## What we're leaving out

- HTTP between the gate and its upstream servers.
- Asymmetric signatures, approvals, rate limits, run lifetime limits and the MCP config audit (M4).

## Risks

- The many-runs refactor could break behaviour M1 and M2 already tested. We keep every old test and add new ones before touching the code.
- An HTTP listener is new attack surface: bind to localhost by default, require a token on every request, and cap request sizes.
- Docker behaves a little differently on Windows. We use only `docker compose`, no bash scripts, and test on Docker Desktop with WSL 2 before calling it done.

## Decisions from the owner (25 October 2026)

All four questions were answered "go", with these conditions:

1. The gate may listen on a network port. It binds to localhost by default, and every request needs a run token.
2. The egress proxy is a new program in the repo (`honeycomb-egress`), written with the standard library.
3. HMAC tokens now, asymmetric later. The signing key must never be reachable by the agent.
4. When the proxy sees a honeytoken and can't tell which run sent it, we first try to identify the run (the agent authenticates to the proxy with its run token). If that isn't possible we pause every active run of that agent.

## Decision on attribution (25 October 2026)

Two agents argued opposite sides for one round: the proxy must verify the run token, or the proxy stays keyless and identifies the caller by source address only. We took the keyless design. The proxy handles hostile bytes and shouldn't sit next to the signing key, the log is untrusted either way, and many HTTP clients can't send proxy credentials. The cost is that a hit pauses every active run of the agent, which the events and the incident say plainly. A token claim sent to the proxy can't narrow that, because the proxy can't check it and a forged claim could point the pause at the wrong run.

## Where M3a stands

M3b is built too: `honeycomb-egress`, the log ingestion in the gate, the Docker lab and S3 (15 of 15 lab checks pass, in the sandbox and in CI). The rest of this section is what M3a delivered.

Built and tested: resources and prompts through the gate, per-run state, the HTTP front door (`honeycomb-gate serve`), signed run tokens with revocation and key rotation, scopes, the agent inventory, and `honeycomb-gate posture`. M3b is described above.

Two small design calls we made on the way, both easy to change:

- A token run that trips has its identity revoked for good. `runs resume` issues a new token for the same agent instead of reviving the old one, which keeps the rule that a tripped identity stays dead.
- For scopes, reading a resource counts as the tool name `<upstream>__resources/read`, and a prompt is scoped by its `upstream__name`.
