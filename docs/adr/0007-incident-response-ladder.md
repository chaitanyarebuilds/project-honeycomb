# ADR-0007: Incident object, response ladder, notification and escalation

Status: Accepted (owner approval, 24 October 2026). Date: 2026-10-24. Replaces F11 "Alerts" with a fuller design. The owner approved steps 3 and 4 as automatic on a decoy or honeytoken trip, and everything beyond step 4 needing a human. Further automatic holding actions are an open question (see Consequences).

## Decision

**Incident object:** id, severity, state (open, acknowledged, contained, closed), run and agent, event ids as evidence, actions the gate already took, recommended next steps, notification log, enforcement level at the time, and a `regulatory_clock_start` field for later CERT-In and DPDP workflows.

**Response ladder:**

| Step | Action | Who may trigger |
| --- | --- | --- |
| 0 | Log | automatic |
| 1 | Alert | automatic |
| 2 | Slow (rate limit, tarpit) | automatic |
| 3 | Pause the run (human resumes) | automatic on decoy or honeytoken trip |
| 4 | Revoke run identity, quarantine tool or upstream | automatic on decoy or honeytoken trip |
| 5 | Isolate the agent (egress deny-all) | policy-configured; off by default outside the lab |
| 6 | Rotate credentials the agent could reach | human approval only (quorum for critical) |

**Notification:** critical incidents go to the primary channel at once. If not acknowledged within N minutes (default 10), escalate to the secondary channel. Every message says what the gate already did and what the person should do next. Phase 0 channels: webhook and CLI. Email, Slack and Telegram come later (D3).

## Why

Decoy and honeytoken trips are high-fidelity and reversible (a run can be resumed), so steps 3 and 4 are safe to automate. Isolation and credential rotation can hurt the business, so they are never silent (see "autoimmunity" in [ARCHITECTURE.md](../ARCHITECTURE.md)).

## Consequences

- Needs an acknowledgement path (`honeycomb-gate incidents ack`).
- Steps 3 and 4 are automatic on a trip (approved).
- Open question for the owner: while a human is on their way, may the gate also take other reversible holding actions (for example step 5, isolating the agent) and leave irreversible ones (step 6, credential rotation) for the human? Until answered, only steps 3 and 4 are automatic.
