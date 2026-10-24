# M2 plan: decoys, honeytokens and the first incident

Status: built (24 October 2026). We're keeping the plan as it was written, for reference. The G2 check at the end is still to be done with the owner.

## Goal

The demo in one sentence, from [PHASE0-SPEC.md](../PHASE0-SPEC.md): a poisoned document tells an agent to export customer data; the agent reaches for a decoy tool; within two seconds the run is paused, its identity is revoked, and a human gets an email.

## What we build

| Item | Backlog | What it does | Test (malicious and benign look-alike) |
| --- | --- | --- | --- |
| Decoy tools | E3-1 | Fake tools with believable names drawn per deployment from a vocabulary, added to `tools/list`, never forwarded, excluded from baselines, never colliding with real tool names | A call trips; a real tool with a similar name does not |
| Decoy trip | E3-2 | On a call: log `decoy.tripped` (critical), pause the run, mark the identity revoked, open an incident, return a tarpit or an error | Trip to pause under 2 s measured; the call never reaches the upstream |
| Run pause and revoke (basic) | E3-2 | A paused or revoked run gets a refusal on every later call and listing, until a human resumes it with `honeycomb-gate runs resume` | After a trip, even a harmless tool call is refused; resume restores it |
| Tarpit | E3-3 | Template-based synthetic responses with a configurable delay; the same question gets the same answer within a run | Repeated query returns identical rows; no real data is ever used |
| Honeytokens | E3-4, E3-5 | Clean-room fake credentials with an embedded id (api key, database URL, webhook URL, password), generated at deploy time and never committed; the gate scans call arguments and tool results for them | A planted token in an argument trips; look-alike strings do not |
| Incident and notifier | E3-6 | An incident record with the five-question message from [DEFENCE-MODEL.md](DEFENCE-MODEL.md); email through SMTP and a generic webhook, with deduplication | Fake SMTP server in tests receives one message per incident; a repeated trip does not send ten |
| Scenario S1 | E3-7 | A scripted attacker follows a poisoned document to a decoy | Decoy trips, run paused, no real export, incident email sent |

M2 deliberately uses the simple version of run identity: a gate-minted run id that can be paused and revoked. Signed run tokens and key management arrive in M3 ([ADR-0002](../adr/0002-gate-minted-run-identity.md)).

## Automatic actions in M2

As approved in [ADR-0007](../adr/0007-incident-response-ladder.md): on a decoy or honeytoken trip the gate pauses the run and revokes its identity by itself, and does nothing else. Isolation (step 5) and credential rotation (step 6) need a human.

One question for you: while a person is on the way, should the gate also take other reversible holding actions? The ADR says only steps 3 and 4 until you decide. I'd keep it that way in M2 and revisit at G2, when we have real trip data.

## Email setup (no secrets in git)

- Settings come from `.env` (see `.env.example`): host, port, user, password, from and to.
- The build sandbox can't reach mail servers, so tests use a local fake SMTP server. The first real send is a one-line command you run on your own machine (`honeycomb-gate notify test`), and I'll tell you exactly what output to expect.
- Please rotate the two mail passwords you pasted in chat before using them, and tell me which one belongs to the sending account when you're ready.

## Exit criteria for G2

1. S1 passes in CI with the scripted attacker.
2. Measured trip-to-pause time under 2 seconds on the lab machine, reported in the results file.
3. Zero decoy trips in the benign scripted sessions (the start of scenario S0).
4. One real email received at the owner's address from a deliberately triggered trip.
5. Threat model updated; community review findings from G1 addressed.

## Risks specific to M2

- Decoys that look fake. Mitigation: templates first, per-deployment vocabulary, same-question-same-answer state, no model in the response path ([ADR-0003](../adr/0003-data-plane-control-plane-split.md)).
- A real tool named like a decoy. Mitigation: a collision check at start-up that refuses to run.
- Token strings that look like real keys and trip secret scanners. Mitigation: they're generated at deploy time, stored only under the state directory and never in git, with a recognisable embedded id so scanners can be told to ignore them.
- An attacker triggering a pause on purpose. A decoy trip is reversible and only affects that run, which is why it's safe to automate. Abuse tests come in M4.
