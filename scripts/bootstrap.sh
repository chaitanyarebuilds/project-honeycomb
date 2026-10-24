#!/usr/bin/env bash
# Creates Project Honeycomb's labels and starter issues.
# Needs the GitHub CLI (https://cli.github.com), logged in with: gh auth login
# Usage: scripts/bootstrap.sh OWNER/project-honeycomb
set -euo pipefail
REPO="${1:?Usage: scripts/bootstrap.sh OWNER/project-honeycomb}"

label() { gh label create "$1" --repo "$REPO" --color "$2" --description "$3" --force; }
label "critique"         "F2B233" "Where the design breaks"
label "prior-art"        "2EC4B6" "Existing products, projects or papers"
label "idea"             "A371F7" "Suggested additions or changes"
label "research"         "0E8A16" "Reading, surveys and evaluation design"
label "design"           "1D76DB" "Architecture and specifications"
label "phase-0"          "D93F0B" "Immune system for AI agents"
label "contributor"      "C5DEF5" "Contributor introductions"
label "good first issue" "7057FF" "Good for newcomers"
label "help wanted"      "008672" "Extra attention is needed"

issue() { gh issue create --repo "$REPO" --title "$1" --label "$2" --body "$3"; }
issue "Related-work page: compare the closest products" "prior-art,research,good first issue" \
  "Compare Darktrace, Acalvio ShadowPlex, SentinelOne Singularity Hologram, Thinkst Canary, Noma, Zenity and HiddenLayer with the design in docs/ARCHITECTURE.md. For each: what overlaps, what is missing. Update docs/RELATED-WORK.md."
issue "Threat model for the signalling bus" "design,help wanted" \
  "How could an attacker abuse the bus (forged alarms, replay, flooding, a hijacked cell)? Propose mitigations. See the Signalling bus section of docs/ARCHITECTURE.md."
issue "Prototype: tool-call firewall for one agent framework" "phase-0,help wanted" \
  "Build a minimal proxy that checks every tool call against a policy and treats tool descriptions as untrusted input. Pick one framework and explain the choice."
issue "Design five decoy skills and the telemetry each one raises" "phase-0,design,good first issue" \
  "Fake tools or credentials that only a hijacked agent would touch. For each: what it looks like, what touching it logs, and how to keep it believable."
issue "Phase 0 lab spec: the attack agent and the four success measures" "phase-0,research" \
  "Specify the scripted attack agent, the target, and how we measure the four goals in docs/ROADMAP.md. Defensive lab only, on infrastructure we own."
issue "Draft workflow for CERT-In's six-hour incident report" "research,help wanted" \
  "Map what a managed Honeycomb service would need to collect and send to meet CERT-In's six-hour reporting rule, and where DPDP breach reporting differs."
echo "Done: labels and starter issues created in $REPO"
