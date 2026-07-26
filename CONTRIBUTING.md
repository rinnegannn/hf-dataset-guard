# Contributing to hf-dataset-guard

Thank you for helping improve `hf-dataset-guard`. The project is a static
security scanner for Hugging Face dataset repositories: it must remain safe,
predictable, and easy to review.

## Local setup

Use Python 3.10 or later. From the repository root, create an isolated
environment and install the project with its development dependencies:

```bash
python -m venv .venv
# Activate the environment for your shell, then:
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

Run the full test suite with:

```bash
python -m pytest
```

To try the command-line interface against the included fixtures:

```bash
hf-dataset-guard scan tests/fixtures/clean_dataset
hf-dataset-guard scan tests/fixtures/malicious_dataset
```

## Making changes

Keep changes focused and include tests for behaviour changes. Tests live in
`tests/`; fixture repositories live in `tests/fixtures/`. Do not add real
credentials, private repository content, or executable payloads to fixtures.

For a new detection rule:

1. Give it a stable, descriptive rule ID.
2. Add a concise explanation and actionable remediation guidance.
3. Ensure the scanner only reads files; it must never import, execute, or
   otherwise activate code from a scanned repository.
4. Add positive, negative, and malformed-input coverage where relevant.
5. Avoid exposing a detected secret in a finding, report, or test output.

Small, explainable rules are preferred over opaque heuristics. Document known
false positives or limitations in the pull request when they cannot be
eliminated safely.

## Pull requests

Before opening a pull request, run the test suite and update documentation for
user-facing changes. Describe the security impact, relevant rule IDs, and any
behavioural trade-offs. Keep commits and pull requests narrowly scoped so they
can be reviewed and reverted easily.

Please do not use pull requests to disclose a suspected security vulnerability.
Follow the private reporting process in [SECURITY.md](SECURITY.md) instead.
