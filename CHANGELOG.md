# Changelog

## 0.1.0, October 2026

The first public build of the Phase 0 gate. It sits between an AI agent and its tools (MCP) and
watches what passes through. It is an early prototype, tested in a lab with a scripted attacker.

What is in it:

- An MCP gateway that serves an agent over stdio or HTTP and reaches several upstream servers, with
  a hash-chained event log and a second log sink that an agent cannot edit.
- Tool pinning: a tool whose definition changes after it was trusted is quarantined until a person
  approves the exact new hash.
- A policy engine with allow, deny and approve rules, per-agent scopes, and caps on calls per
  minute and on how much one answer may hold.
- Decoy tools and a tarpit, and honeytokens planted in an agent's workspace. Touching either pauses
  the run, revokes its identity and opens an incident, which goes out by email or webhook.
- Signed run tokens that expire within 15 minutes, an inventory of the agents the gate has seen,
  and a posture report that says which enforcement level is really in place.
- `honeycomb-egress`, a small proxy that is the agent's only way out in the lab, and a Docker lab on a
  network with no other route.
- Human approvals with quorum, behaviour baselines per agent, escalation of incidents nobody
  answers, and memory of past attacks that stops the same text the second time.
- `uv run lab-run`, which plays six scenarios and writes the results. See
  [docs/LAB-RESULTS.md](docs/LAB-RESULTS.md).

What is not in it, and what we know does not work yet, is written down in
[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md). The main points: HTTPS to an allowed host is not
inspected, a reworded attack gets past learned rules the first time, approver names are typed by the
operator, and the agent's own memory is not audited. Please try to break it.
