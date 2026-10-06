# Changelog

All notable changes are documented here. This project follows Semantic
Versioning; until 1.0, minor releases may include incompatible changes.

## [Unreleased]

### Added

- `hf-dataset-guard --version` for installation checks without a scan or network request.

### Fixed

- Declare the test suite's direct HTTPX dependency so clean development installs can collect tests.

## [0.1.0] - 2026-08-09

### Added

- Static scanning for remote and local Hugging Face dataset repositories.
- AST-based code-execution and unsafe-deserialization detection, secret and dependency checks,
  executable/artifact checks, entropy secret detection, and template-flow analysis.
- JSON and SARIF reports, reproducible scan metadata, baselines, and `.hfguard.yml` suppressions.
- Explicit incomplete-scan reporting, safe scan-root handling, and CI exit controls.
- Python 3.10–3.13 CI with tests, coverage, linting, type checking, dependency audit, package
  build, and wheel smoke testing.
- Security policy, contribution guide, architecture/rules/configuration/CI documentation, and
  release workflow.
