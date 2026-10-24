# Hard problems

Seven problems that could sink Project Honeycomb, with our current answers. Each answer is a proposal. Tell us where it breaks, or open an issue for problem 8.

## 1. Floods

**Problem:** a large DDoS fills the internet link before any agent inside can act, and a botnet does not care about fake data.
**Current answer:** do not pretend. Volume is stopped upstream by scrubbing networks and internet providers. Inside, agents handle application-layer floods and coordinate the response.
**Open:** which upstream partners are affordable for small Indian organisations?

## 2. The attack nobody has seen

**Problem:** specialist agents are trained on known patterns, and attacks do not arrive labelled.
**Current answer:** two tiers. Sentinels and decoys catch by behaviour and interaction, with no signature needed. A forensic router then classifies what was caught and wakes the right specialists, who multiply as needed.
**Open:** what happens when the router cannot classify at all?

## 3. Believable decoys

**Problem:** research on AI-powered honeypots finds the biggest giveaways are slow replies and answers that do not add up.
**Current answer:** answer common queries instantly from templates, use small local models only for the long tail, and remember every session so the same question always gets the same answer.
**Open:** which small models and serving setups give consistent sub-second replies?

## 4. Fingerprints

**Problem:** in one study, a classifier identified which AI model sat behind a honeypot from a single reply 71 percent of the time, against 9 percent by chance.
**Current answer:** every customer gets different models, prompts and timing. Every decoy record is synthetic by design, so a fake can never carry a real person's data, which matters under India's DPDP Act.
**Open:** how do we measure fingerprint resistance before deployment?

## 5. Attacking the defenders

**Problem:** defender agents read logs, filenames and traffic, and attackers can hide instructions in any of them.
**Current answer:** every piece of text is untrusted; defender agents get least privilege; their outbound traffic is blocked by default; anyone trying to turn our own responses against us runs into the governors.
**Open:** what red-team suite should every release pass?

## 6. The law

**Problem:** in tests, the academic project Mantis used prompt injections hidden in decoys to derail AI attackers more than 95 percent of the time. Where is the legal line?
**Current answer:** wasting an attacker's time inside your own decoy is defence. Running code on the attacker's machine is hacking back, which is legally risky in India and most countries. The default is: derail, do not strike back. This is not legal advice.
**Open:** where exactly does a counter-injection that changes an attacker's own agent stop being defence?

## 7. Who answers the alarm?

**Problem:** a district office or a 50-person company usually has no security team.
**Current answer:** deliver Honeycomb as a managed service: autonomous agents plus a human operations centre. Reporting is built in, from CERT-In's six-hour incident rule to the breach reports the DPDP Rules require (phasing in by May 2027).
**Open:** what would a fair monthly price be, and how do we staff the operations centre?
