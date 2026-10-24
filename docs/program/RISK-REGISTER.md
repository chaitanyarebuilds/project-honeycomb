# Risk register

Status: living document, started 24 October 2026. We score each risk as likelihood × impact (1 to 3 each) and review the list every Friday.

| ID | Risk | L | I | Score | Mitigation | Owner |
| --- | --- | --- | --- | --- | --- | --- |
| R1 | The gate is bypassed because the agent has a network route around it | 3 | 3 | 9 | Enforcement levels and an honest posture report ([ADR-0004](../adr/0004-enforcement-levels.md)); lab at L2; deployment docs that say this plainly | Security lead |
| R2 | False positives erode trust or break the business ("autoimmunity") | 2 | 3 | 6 | Benign look-alike test for every detector; S0 gate; limit automatic steps to reversible ones | Detection engineer |
| R3 | An attacker triggers our response on purpose to cause damage | 2 | 3 | 6 | Ladder limits, governors, quorum, rate limits on response ([ADR-0007](../adr/0007-incident-response-ladder.md)); abuse tests in M4 | Security lead |
| R4 | Prompt injection against any model-based part of our system | 2 | 3 | 6 | No model in the enforcement path ([ADR-0003](../adr/0003-data-plane-control-plane-split.md)); sandboxed analysis | Security lead |
| R5 | MCP specification or SDK changes break us again | 3 | 2 | 6 | Pin versions; contract tests per revision; threat watch | Platform engineer |
| R6 | A larger gateway ships our differentiators | 2 | 3 | 6 | Plugin seam ([ADR-0001](../adr/0001-own-core-with-plugin-seam.md)); fortnightly competitor watch; lean on the lab, governors and small-organisation fit | Product owner |
| R7 | Decoys are recognisable (latency, inconsistency, shared fingerprints) | 2 | 2 | 4 | Templates first; per-deployment vocabulary; per-run state; fingerprint tests | Detection engineer |
| R8 | Real personal data leaks into decoys or fixtures | 1 | 3 | 3 | Synthetic-only rule; generated data; secret and PII scan in CI | Security lead |
| R9 | The log or alert channel is tampered with or flooded | 2 | 2 | 4 | Hash chain and second sink ([ADR-0005](../adr/0005-tamper-evident-log.md)); deduplication | Platform engineer |
| R10 | Licence contamination from copied code | 1 | 3 | 3 | Clean-room rule ([ADR-0008](../adr/0008-licence-hygiene.md)); licence check in CI | Security lead |
| R11 | Legal exposure from active countermeasures | 1 | 3 | 3 | Derail only by default; counter-injection off; test only on systems we own; revisit with legal advice before any pilot with real data | Product owner |
| R12 | Team of two (owner and CTO) plus coding agents is thin for the plan | 3 | 2 | 6 | Confirm team size before G0; cut M4 baselines first, keep decoys, tokens, identity and egress | Product owner |
| R13 | Claims in public docs and videos outrun the evidence | 2 | 2 | 4 | Cite sources; keep hedges; label concept and proposed design; review public claims | Product owner |
| R14 | Secrets or tokens committed to the repository (including mail credentials shared in chat) | 1 | 3 | 3 | Rotate any credential pasted into a chat or document; `.gitignore`, secret scanning in CI, honeytokens generated at deploy time | Platform engineer |
| R15 | A build agent or contributor tool is itself hijacked through untrusted input | 2 | 2 | 4 | Working agreements in [TEAM-AND-AGENTS.md](TEAM-AND-AGENTS.md); dogfooding behind the gate; human merges | Security lead |
