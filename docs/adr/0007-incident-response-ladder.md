# ADR-0007: Incident object, response ladder, notification and escalation

Status: Accepted by the owner on 24 October 2026. Date: 2026-10-24. Replaces F11 "Alerts" with a fuller design. The owner approved steps 3 and 4 as automatic on a decoy or honeytoken trip, and everything beyond step 4 as needing a human. Whether the gate may take further automatic holding actions is still open (see Consequences).

## Decision

An incident records its id, severity, state (open, acknowledged, contained, closed), run and agent, event ids as evidence, the actions the gate already took, recommended next steps, a notification log and the enforcement level at the time. When the CERT-In and DPDP workflows exist, we'll add a field that marks when the reporting clock started.

The response ladder:

| Step | Action | Who may trigger |
| --- | --- | --- |
| 0 | Log | automatic |
| 1 | Alert | automatic |
| 2 | Slow (rate limit, tarpit) | automatic |
| 3 | Pause the run (human resumes) | automatic on decoy or honeytoken trip |
| 4 | Revoke run identity, quarantine tool or upstream | automatic on decoy or honeytoken trip |
| 5 | Isolate the agent (egress deny-all) | policy-configured; off by default outside the lab |
| 6 | Rotate credentials the agent could reach | human approval only (quorum for critical) |

Critical incidents go to the primary channel at once. If nobody acknowledges within N minutes (default 10), they escalate to the secondary channel. Every message says what the gate already did and what the person should do next. Phase 0 channels are email, a webhook and the CLI (D3 settled on email first). Slack and Telegram come later.

## Why

Decoy and honeytoken trips are high-fidelity and reversible, since a run can be resumed, so steps 3 and 4 are safe to automate. Isolation and credential rotation can hurt the business, so they are never silent (see "autoimmunity" in [ARCHITECTURE.md](../ARCHITECTURE.md)).

## Consequences

We need an acknowledgement path (`honeycomb-gate incidents ack`).

Steps 3 and 4 are automatic on a trip, as approved. Until signed run tokens exist (M3), "revoke identity" means the run id is retired and the gate refuses it, including after a restart.

One question for the owner is still open. While a human is on their way, may the gate also take other reversible holding actions, such as step 5 (isolating the agent), and leave irreversible ones, such as step 6 (credential rotation), for the human? Until that's answered, only steps 3 and 4 are automatic.
