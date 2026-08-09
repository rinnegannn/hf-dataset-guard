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

Reports always include `scan_complete` and `incomplete_reasons`. A scan is
incomplete when a local or remote file is omitted (for example by a size/file
limit, symlink protection, an unsupported data format, or a download failure).
Use `--fail-on-incomplete` in CI when a partial result must fail the build.
