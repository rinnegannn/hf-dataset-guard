# CI integration

Use the included [example workflow](../.github/workflows/example-scan.yml) to
scan a dataset dependency on demand. Store any required Hugging Face token as a
repository secret and pass it through `HF_TOKEN`; never place tokens in a
workflow file or command line.

For an application pipeline, make risk actionable with a threshold:

```bash
hf-dataset-guard scan org/dataset --revision COMMIT_SHA --fail-on high --fail-on-incomplete
```

Use JSON output for artifacts or downstream tooling:

```bash
hf-dataset-guard scan org/dataset --format json --output report.json
```

The report includes `scan_complete` and `incomplete_reasons`. With
`--fail-on-incomplete`, a partial scan returns exit code 3 even if no finding
reaches the configured risk threshold.

The project’s own pull-request CI workflow is tracked separately in
`docs/TODO.md`.
