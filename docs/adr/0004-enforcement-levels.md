# ADR-0004: Enforcement levels and an honest posture report

Status: Accepted by the owner on 24 October 2026. Date: 2026-10-24.

## Context

The spec says the gate is advisory unless the agent can only reach tools and the internet through it. Operators won't read that, so the product has to say it.

## Decision

We define four levels. `honeycomb-gate posture` and every incident state which one is active.

| Level | Name | What is true |
| --- | --- | --- |
| L0 | Observe | Gate logs and flags. Agent may bypass it. |
| L1 | Gate | Policy enforced on calls through the gate. Bypass is still possible. |
| L2 | Gate + egress | Agent has no route except the gate and an allowlisting proxy, so exfiltration and bypass are blocked at the network. |
| L3 | Full | L2 plus per-run identity enforced by upstream servers, and human approvals wired to a real channel. |

The posture report also lists what is missing to reach the next level.

## Consequences

Marketing and docs may claim protection only for the level that is actually enforced.

The lab runs at L2 (internal Docker network). Deployment docs describe how to reach L2 on Docker and, with weaker guarantees, on a host firewall.
