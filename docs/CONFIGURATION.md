# Configuration reference

`hf-dataset-guard` uses command-line options. Every report also records the
requested revision, resolved remote commit (when available), tool version,
and rule-set version so it can be reproduced later.

| Option | Purpose |
| --- | --- |
| `--revision REVISION` | Remote dataset revision, defaulting to `main`. Prefer an immutable commit where possible. |
| `--format {text,json,sarif}` | Select terminal, JSON, or SARIF output. |
| `--output PATH` | Write the report to a file. |
| `--fail-on LEVEL` | Exit with code 1 at `low`, `medium`, `high`, or `critical`. |
| `--fail-on-incomplete` | Exit with code 3 if any file was omitted from the scan. |
| `--max-files N` | Bound remote files downloaded for a scan. Must be positive. |
| `--max-file-size BYTES` | Skip files larger than the limit. Must be positive. |
| `--token TOKEN` | Supply an HF token for private or gated datasets. Prefer `HF_TOKEN` in CI. |
| `--config PATH` | Load rule suppressions from a YAML file; defaults to `.hfguard.yml` in the scanned target. |
| `--baseline REPORT.json` | Identify findings that are new relative to a previous JSON report. |

Reports always include `scan_complete` and `incomplete_reasons`. A scan is
incomplete when a local or remote file is omitted (for example by a size/file
limit, symlink protection, an unsupported data format, or a download failure).
Use `--fail-on-incomplete` in CI when a partial result must fail the build.

## Suppressions

Use narrowly scoped, reviewable suppressions. Suppressed findings remain in
the JSON report's `suppressed_findings` audit trail.

```yaml
suppressions:
  - rule_id: CODE004
    path: examples/legacy_loader.py
```

## Baselines

Pass a previous JSON report to compare finding identity (`rule_id`, path, and
line). The JSON `new_findings` field contains only findings absent from the
baseline. A baseline does not hide findings or change risk scoring.
