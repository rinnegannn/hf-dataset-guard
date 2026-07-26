# Threat model and privacy

## Trust boundary

Dataset repositories are untrusted. The scanner lists and downloads remote
files through `huggingface_hub`, then reads local bytes and text for static
analysis. It does not import, execute, unpickle, or otherwise activate scanned
content.

## Data handling

For remote scans, files are placed in a temporary directory and removed after
the scan. The tool sends no scan report to a third party. Reports written by a
user may contain repository paths and redacted secret evidence, so handle them
as security-sensitive artifacts.

Authentication tokens are passed only to the Hugging Face client. Avoid
supplying tokens on shared command lines; use `HF_TOKEN` or a cached login.

## Limits

Static analysis can miss obfuscated or unsupported patterns and can produce
false positives. Remote listing and download limits can make a scan incomplete.
Review findings before trust decisions and pin the target revision when a
reproducible result matters.
