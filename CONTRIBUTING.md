# Contributing to Project Honeycomb

Thank you for being here. The project is at the concept stage, so the most valuable contributions right now are critique, prior art, research, and early prototypes of the Phase 0 module.

## Ways to help

- **Critique:** open an issue with the Critique form. Blunt is fine; specific is better.
- **Prior art:** tell us what already exists, through a Prior art issue or in Discussions.
- **Research:** help design the Phase 0 lab, the evaluation measures, or the related-work survey.
- **Prototypes:** pick an issue labelled `phase-0` or `good first issue`.
- **Docs and design:** diagrams, explanations and translations.

New here? Introduce yourself in Discussions under **Want to contribute** and say what you would like to work on. You can also fill in the [collaborator form](COLLABORATOR_FORM_URL).

## Before you start

For anything bigger than a typo, open an issue or a discussion first, so nobody duplicates work.

## Making a change

1. Fork the repository and create a branch.
2. Make your change. Link a source for every new claim or number.
3. Sign off every commit: `git commit -s`. This adds a `Signed-off-by` line confirming you have the right to submit the work under the project's licenses, as described by the [Developer Certificate of Origin](https://developercert.org/).
4. Open a pull request and fill in the template.

## Development rules and setup

Code contributors should read [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for the engineering rules, commands and conventions.

## Scope and safety

Honeycomb is a defensive project. Contributions must respect these rules:

- Test only on systems you own or have written permission to test.
- No tooling designed to attack systems you do not own, and no "hack back" features.
- No working exploits for unpatched vulnerabilities in third-party software.
- Decoys and test data must be synthetic. Never commit real personal data, credentials or customer data.
- Report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md).

Pull requests outside this scope will be closed.

## Governance

Chaitanya Pandita is the initial maintainer. Design decisions are discussed in the open in Discussions, and more maintainers will be added as contributors earn trust through their work.

## Recognition

Every contributor is credited in the README and in the end card of future videos.

## Code of conduct

Everyone taking part is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
