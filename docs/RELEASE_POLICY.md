# Release, support, and deprecation policy

Releases follow Semantic Versioning. The latest minor release is supported
with security fixes; pre-1.0 releases may make breaking changes in minor
versions. Security reports are acknowledged within seven calendar days and
handled through the private process in `SECURITY.md`.

Deprecations are announced in release notes and retained for at least one
minor release before removal, except where retaining a feature would create a
security risk. Users should pin a release version and record a scan report's
provenance when auditability matters.

Development tools use bounded version ranges in `pyproject.toml`. Dependency
updates are reviewed through pull requests, with the test suite, type checks,
linting, package build, and dependency audit required before release.
