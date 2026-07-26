# Architecture

`hf-dataset-guard` is a static scanner for local directories and Hugging Face
dataset repositories. Its design centres on a strict safety boundary: scanned
content is inspected as data and is never imported or executed.

## System flow

```text
CLI (cli.py)
  |-- local directory --------------------> scanner.py
  |-- Hugging Face repository -> fetch.py -> temporary local files -> scanner.py
                                                               |
                                                               v
                                                           rules.py
                                                               |
                                                               v
                                                          scorer.py
                                                               |
                                                               v
                                                          report.py
```

## Components

| Component | Responsibility |
| --- | --- |
| `cli.py` | Parses the `scan` command, selects a local or remote target, applies failure thresholds, and selects text or JSON output. |
| `fetch.py` | Lists remote repository files and downloads a bounded subset into a temporary directory using `huggingface_hub`. Failed individual downloads are skipped so one unavailable file does not end the scan. |
| `scanner.py` | Walks a local directory, excludes known large data payloads, applies the configured per-file size limit, and dispatches readable files to the rule engine. |
| `rules.py` | Defines the `Finding` model and detection rules. It uses file metadata, text matching, and lightweight Python AST inspection; parsing failures are treated as findings or safely contained rather than crashing the scan. |
| `scorer.py` | Converts findings into an aggregate score and risk level. |
| `report.py` | Renders a result as terminal text or JSON without changing scan results. |

## Data and trust boundaries

Remote datasets are untrusted. The fetch layer receives repository identifiers,
revisions, and optional authentication tokens, then downloads files into a
temporary workspace. The scanner and rules layer read those files but must not
execute them. Downloaded files are not retained after a remote scan finishes.

The current limits reduce scan scope: `--max-files` bounds the remote file list
and `--max-file-size` bounds local scanning. A pre-download remote size check
and explicit incomplete-scan reporting remain planned work; see `TODO.md`.

Findings pass one way from rules to scoring and reporting. Secrets detected in
content are redacted before they are included in findings, so reports are safe
to share with the usual care for security results.

## Extending the design

New rules should be independent functions in `rules.py` and return stable
`Finding` values. Register them through `scan_file`, then add focused unit tests
and fixture coverage. Keep network access in `fetch.py`, directory traversal in
`scanner.py`, and presentation logic in `report.py`; this separation keeps rule
tests fast and prevents untrusted content from crossing unnecessary boundaries.

Future planned extensions include rule suppressions through `.hfguard.yml`,
SARIF reporting, stronger import/alias analysis, and complete-scan status
reporting.
