# Configuration reference

`hf-dataset-guard` currently uses command-line options; `.hfguard.yml`
suppression support is planned but is not implemented.

| Option | Purpose |
| --- | --- |
| `--revision REVISION` | Remote dataset revision, defaulting to `main`. Prefer an immutable commit where possible. |
| `--format {text,json}` | Select terminal or JSON output. |
| `--output PATH` | Write the report to a file. |
| `--fail-on LEVEL` | Exit with code 1 at `low`, `medium`, `high`, or `critical`. |
| `--max-files N` | Bound remote files downloaded for a scan. Must be positive. |
| `--max-file-size BYTES` | Skip files larger than the limit. Must be positive. |
| `--token TOKEN` | Supply an HF token for private or gated datasets. Prefer `HF_TOKEN` in CI. |

Remote scans may be incomplete when limits apply or downloads fail. Treat
results as scoped to inspected content until incomplete-scan reporting lands.
