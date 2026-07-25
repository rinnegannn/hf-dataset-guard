# Project TODO

This list tracks the work needed to move `hf-dataset-guard` from a useful
v0.1 prototype to a dependable, professional open-source security tool.

## Priority 0 - trustworthy scan boundaries

- [ ] Enforce a remote per-file download-size limit *before* downloading;
  current limits only prevent scanning large files after they are downloaded.
- [ ] Report every skipped, failed, or omitted remote file, including when
  `--max-files` truncates the repository listing.
- [ ] Make incomplete scans explicit in text and JSON output, and provide a
  distinct CI exit code or an opt-in `--fail-on-incomplete` flag.
- [ ] Validate CLI numeric options (`--max-files`, `--max-file-size`) as
  positive values and produce actionable errors.
- [ ] Handle filesystem, network, and report-output errors consistently so
  expected operational failures return exit code 2 rather than a traceback.

## Priority 1 - detection quality and safety

- [ ] Add AST import/alias resolution (for example, `import subprocess as sp`
  and `from subprocess import run`) and detect relevant indirect calls.
- [ ] Improve template-injection analysis so findings are tied to config or
  untrusted input flow rather than every template use.
- [ ] Add context-aware dependency parsing for requirements files, including
  hashes, version pins, direct URLs, and editable installs.
- [ ] Add entropy-based secret detection with allowlists and false-positive
  controls.
- [ ] Add rule allowlists/suppressions through `.hfguard.yml`, keyed by rule
  ID and file path, with an audit trail in reports.
- [ ] Add SARIF output for GitHub code scanning.
- [ ] Support commit-to-commit risk comparison and baseline reports.
- [ ] Document rule coverage, expected false positives, and known detection
  limitations.

## Priority 2 - tests and quality gates

- [x] Add regression coverage for implemented rules, including positive,
  negative, malformed-source, and secret-redaction cases.
- [x] Test CLI argument parsing, exit thresholds, output files, JSON output,
  remote cleanup, and operational errors.
- [x] Mock Hugging Face API interactions for listing, download forwarding,
  truncation, and per-file download failures.
- [ ] Extend these tests alongside pending alias detection, real pagination,
  private/gated repository handling, and pre-download size-limit features.
- [ ] Add regression fixtures for each previously fixed bug.
- [ ] Add coverage reporting and set a meaningful minimum coverage threshold.
- [ ] Add linting, formatting, type checking, and security/dependency checks
  to CI (for example Ruff, mypy, and pip-audit).
- [ ] Run the test suite across supported Python versions in GitHub Actions.

## Professional repository polish

- [ ] Add a CI workflow that runs tests, linting, type checks, package build,
  and dependency/security checks on pull requests.
- [ ] Add a release workflow that builds distributions, validates them, and
  publishes tagged releases to PyPI.
- [ ] Add `CONTRIBUTING.md` with local setup, test commands, rule-design
  guidance, and pull-request expectations.
- [ ] Add `CODE_OF_CONDUCT.md`, `SECURITY.md` (private vulnerability reporting
  process), and issue/PR templates.
- [ ] Add a `CHANGELOG.md` and follow semantic versioning.
- [ ] Declare supported Python versions and classifiers in `pyproject.toml`.
- [ ] Add optional development dependencies and a single documented command
  for running all local checks.
- [ ] Pin or constrain development tooling and document the dependency update
  policy.
- [ ] Add package metadata: project URLs, keywords, author/maintainer,
  license classifier, and a repository link.
- [ ] Add a concise README badge set (CI, PyPI, Python versions, license),
  installation verification, configuration reference, and JSON/SARIF examples.
- [ ] Publish a threat model and privacy statement explaining what is fetched,
  retained, logged, and never executed.
- [ ] Add a tested installation smoke test from the built wheel in CI.
- [ ] Create a `docs/` site or focused documentation pages for rules,
  configuration, CI integration, and release notes.

## Release readiness

- [ ] Resolve all Priority 0 items before presenting scan results as complete.
- [ ] Perform a false-positive/false-negative review against a representative
  corpus of public dataset repositories.
- [ ] Obtain an independent security review of the scanner and its supply
  chain before a 1.0 release.
- [ ] Define support, disclosure, and deprecation policies for releases.
