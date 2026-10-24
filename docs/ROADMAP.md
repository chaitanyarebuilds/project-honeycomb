# Roadmap

Timings are indicative, and phases overlap.

| Phase | Indicative timing | Scope | Move on when |
| --- | --- | --- | --- |
| 0 | 0 to 6 months | Immune system for AI agents: deception-led, governors from day one | The lab passes all four goals below |
| 1 | 4 to 9 months | Web shield for government and MSME PHP sites: virtual patches in hours, as a managed service | First pilot sites run for 90 days without a governor bypass |
| 2 | 9 to 15 months | Signalling mesh and sentinels | Neighbouring cells raise guard faster than an attacker moves |
| 3 | 15 to 24 months | Specialists and red-team vaccination | Rehearsed attacks fail faster the second time |
| 4 | 24 months and later | Herd immunity across organisations | Sanitised sharing passes a privacy review |

The "move on when" column is a proposal for discussion.

## Phase 0 lab: the first proof (first results in, scripted attacker only)

A scripted AI attack agent goes after a target protected by the Phase 0 module. We want to show four things:

- [x] Decoy skills catch the hijack (S1)
- [x] The tarpit wastes the attacker's time (about a second in the lab, by design)
- [x] Governors block a deliberately triggered self-attack (S4)
- [x] The second attempt fails faster, because the hive remembers (S5)

These pass in the Docker lab with a scripted attacker. [docs/LAB-RESULTS.md](LAB-RESULTS.md) has the numbers and says what they do not show: a real agent driven by a model, and attackers who reword, are still to be tested.

Measures to agree: time to detection, attacker time wasted, false positives, and time to block on the second attempt.
