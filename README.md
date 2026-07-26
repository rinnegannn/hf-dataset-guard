# hf-dataset-guard

Static security scanner for Hugging Face dataset repos.

```
hf-dataset-guard scan username/dataset-name
```

## Why this exists

In July 2026, Hugging Face disclosed that a malicious dataset abused two
code-execution paths in its dataset-processing pipeline: a remote-code
dataset loader, and a template-injection flaw in a dataset config, to run
code on an internal processing worker. `hf-dataset-guard` scans for exactly
these classes of issue (plus a few other common ones) *before* you load a
dataset, using pure static analysis. It never imports, executes, or unpickles
anything from the repo it's scanning.

This tool reports indicators, not proof of malicious intent. Review findings
before making trust decisions, and don't treat a clean report as a guarantee
of safety. It's static heuristic analysis, not a sandboxed execution trace.

## What it checks for

| Rule ID | Category | Examples |
|---|---|---|
| CODE001 | Shell/process execution | `subprocess.run`, `os.system`, `os.popen` |
| CODE002 | Unsafe deserialization | `pickle.load`, `torch.load` (without `weights_only=True`), unsafe `yaml.load` |
| CODE003 | Template injection | Jinja2 `Template(...).render()` on config-derived data |
| CODE004 | Dynamic execution | `eval`, `exec`, `compile`, `__import__` |
| NET001 | Unpinned remote download | `requests.get`, `urlretrieve`, shell `curl`/`wget` in loader code |
| SECRET01-06 | Exposed credentials | AWS keys, GitHub/HF/Slack tokens, private key blocks (redacted in output) |
| FILE001 | Pickle-like artifacts | `.pkl`, `.pt`, `.pth`, `.ckpt`, `.bin` (vs. safer `.safetensors`) |
| FILE002 | Unexpected executables | ELF/PE/Mach-O magic bytes, or `.sh`/`.exe`/`.so` regardless of extension |
| DEP001-02 | Unsafe dependencies | Unpinned `git+` requirements, runtime `pip install` calls |

## Usage

```bash
pip install hf-dataset-guard

# Scan a remote dataset repo
hf-dataset-guard scan username/dataset

# Scan a local checkout instead
hf-dataset-guard scan ./my-dataset

# JSON output
hf-dataset-guard scan username/dataset --format json --output report.json

# CI: fail the build if risk reaches "high" or above
hf-dataset-guard scan username/dataset --fail-on high

# Pin a revision
hf-dataset-guard scan username/dataset --revision 4f36a90

# Limit remote inspection
hf-dataset-guard scan username/dataset --max-files 200 --max-file-size 500000
```

For private or gated repositories, set the `HF_TOKEN` environment variable,
log in via `huggingface-cli login`, or pass `--token` explicitly.

Remote scan reports include every file that was skipped, failed to download,
or omitted because of `--max-files`. JSON reports expose these entries in the
`file_issues` array with the file path, status, and reason.

Example output:

```
Risk: CRITICAL (100/100)
Dataset: demo/malicious-example

[~]  FILE001  cache.pkl: File uses a pickle-based serialization format (.pkl)...
[!!] SECRET04 loader.py: Possible Hugging Face access token found in file contents.
     evidence: hf_a...redacted...6789
[!]  CODE003  loader.py:20: Dataset config/loader renders a template with data...
[!!] CODE001  loader.py:16: Call to subprocess.run() can lead to arbitrary code execution.
[!!] FILE002  run_me: File has no executable extension but matches ELF executable magic bytes.

Note: static analysis only. No file from this repo was executed or imported.
```

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | Scan completed and threshold was not reached |
| `1` | A finding reached the configured `--fail-on` threshold |
| `2` | Target could not be scanned (bad repo id, network error, etc.) |

## GitHub Action

See [`.github/workflows/example-scan.yml`](.github/workflows/example-scan.yml)
for a drop-in workflow that scans a dataset dependency before it's used in CI.

## How it works

1. `fetch.py` downloads a dataset repo's files locally via the official
   `huggingface_hub` client (no custom HTTP/auth handling; it already
   supports revisions, gated repos, and retries correctly).
2. `scanner.py` walks the local copy, skipping large binary data shards
   (parquet/arrow/etc., since those aren't where loader-script logic lives).
3. `rules.py` runs a mix of regex and light AST checks against each file.
   AST is used specifically for call-detection so `subprocess.run(...)` is
   recognized reliably rather than pattern-matched, and each finding carries
   a stable rule ID rather than just free-text.
4. `scorer.py` combines findings into a 0-100 score with diminishing
   weight for repeated findings in the same category, so one noisy file
   doesn't automatically max out the score.

## Roadmap

- SARIF output for GitHub code scanning
- Rule allowlists via a `.hfguard.yml` file, keyed by rule ID
- Entropy-based secret detection (catches secrets that don't match a known pattern)
- Commit-to-commit risk comparison

## Contributing

Small, explainable rules are preferred over opaque scoring. A new rule should
include a stable rule ID, a concise explanation, a remediation note, and a
test fixture demonstrating both the positive case and a plausible false positive.

## Development

```bash
pip install -e ".[dev]"
python -m pytest
```

## License

MIT
