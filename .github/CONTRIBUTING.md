# Contributing to MULEGUARD

Thank you for considering a contribution. MULEGUARD is an academic and demonstration prototype for synthetic-data financial-fraud investigation workflows. It is not a production banking system.

## Before opening a pull request

1. Read the project [README](../README.md), [architecture](../docs/architecture.md), [security policy](../SECURITY.md), and [testing guide](../docs/testing.md).
2. Search existing issues and pull requests to avoid duplicate work.
3. For substantial changes, open an issue first. This is especially important for API contracts, schemas/migrations, scoring logic, rules, graph semantics, authorization, model behaviour, or dependencies.
4. Keep changes focused and explain the problem they solve.

## Local setup

The project documents development commands in the root Makefile. A typical setup is:

```bash
make install
make env
```

Review the generated `.env`, replace every `CHANGE_ME` placeholder with local development values, then follow the root README and `make help` for the appropriate database, migration, seed, and run steps. Do not publish the local `.env` file or share demo credentials.

## Tests and quality

Run the checks relevant to your change. The repository's common entry points include:

```bash
make test
make lint
make typecheck
make verify
```

Some targets require PostgreSQL, Docker, or installed backend/frontend dependencies. If a check cannot run locally, say why in the pull request. Never claim that a test passed unless it actually ran successfully.

## Project principles

Contributions should preserve the project's core constraints:

- **Synthetic-first:** use deterministic synthetic data; never commit real customer or financial data.
- **Evidence-backed:** alerts, indicators, and relationships should refer to available evidence.
- **Explainable and human-reviewed:** scores are investigative priorities, not proof of wrongdoing or calibrated probabilities unless validated as such.
- **Auditable:** preserve audit records for material actions.
- **Temporally correct:** avoid data leakage from information that would not have been known at assessment time.
- **Secure by default:** validate inputs, enforce authorization server-side, bound expensive queries, and protect secrets.
- **Honest functionality:** do not add fabricated metrics, fake UI actions, or unsupported production/compliance claims.

Do not add live banking/payment integrations, real customer data, automated account blocking/freezing, or other high-impact actions without prior maintainer discussion and explicit approval.

## Pull request checklist

- Describe the problem and solution.
- Link the related issue where applicable.
- Add or update tests for changed behaviour.
- Update documentation, schemas, and samples when needed.
- Include clear limitations and migration notes for breaking changes.
- Keep the diff focused and make the changes reviewable.
- Ensure no credentials, generated databases, logs, or sensitive data are included.

## Review process

Maintainers may request changes, ask for tests or documentation, or decline contributions that weaken security, reproducibility, explainability, privacy, or the project's intended scope. Be respectful in reviews and follow the [Code of Conduct](../CODE_OF_CONDUCT.md).

## Security reports

Do not report vulnerabilities in public issues. Follow [SECURITY.md](../SECURITY.md) and use GitHub private vulnerability reporting when available.
