"""
Directory scanner. Deliberately decoupled from the network layer: this
module only ever reads local files it's given. fetch.py is responsible
for getting a dataset repo onto disk first. That split makes the rule
engine unit-testable without hitting the Hugging Face API at all.
"""

from __future__ import annotations

from pathlib import Path
from typing import List

from .rules import Finding, scan_file

# Skip large data payloads that aren't useful to scan as text and would
# just slow things down (real datasets can have huge parquet/arrow shards).
SKIP_EXTENSIONS = {".parquet", ".arrow", ".csv", ".jsonl", ".zip", ".tar", ".gz", ".npy", ".npz"}
DEFAULT_MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # don't slurp huge files into memory


def scan_directory(
    root: Path,
    max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES,
    incomplete_reasons: list[str] | None = None,
) -> List[Finding]:
    """Scan a directory and optionally record omissions that limit coverage.

    ``incomplete_reasons`` is an output parameter so callers that only need
    findings retain the original, simple API.  Each recorded reason means the
    scan did not inspect every file in the requested target.
    """
    root = root.resolve()
    findings: List[Finding] = []

    def record_incomplete(reason: str) -> None:
        if incomplete_reasons is not None:
            incomplete_reasons.append(reason)

    for path in sorted(root.rglob("*")):
        rel_path = str(path.relative_to(root))

        # Never follow links supplied by a scanned directory. A local target
        # may contain a link to any readable location on the host, so even a
        # harmless-looking file link is outside this scanner's trust boundary.
        if path.is_symlink():
            record_incomplete(f"Skipped symlink: {rel_path}")
            findings.append(Finding(
                severity="info",
                category="scan_boundary",
                rule_id="SCAN001",
                message="Skipped symlink to keep the scan inside the requested directory.",
                file=rel_path,
            ))
            continue

        try:
            resolved_path = path.resolve(strict=True)
            resolved_path.relative_to(root)
        except ValueError:
            record_incomplete(f"Skipped path outside scan root: {rel_path}")
            findings.append(Finding(
                severity="info",
                category="scan_boundary",
                rule_id="SCAN001",
                message="Skipped path that resolves outside the requested directory.",
                file=rel_path,
            ))
            continue
        except OSError as error:
            record_incomplete(f"Could not resolve path {rel_path}: {error}")
            continue

        if not resolved_path.is_file():
            continue

        if resolved_path.suffix.lower() in SKIP_EXTENSIONS:
            record_incomplete(f"Skipped unsupported data file: {rel_path}")
            continue
        try:
            if resolved_path.stat().st_size > max_file_size_bytes:
                record_incomplete(
                    f"Skipped file exceeding --max-file-size ({max_file_size_bytes} bytes): {rel_path}"
                )
                continue
        except OSError as error:
            record_incomplete(f"Could not read metadata for {rel_path}: {error}")
            continue

        findings.extend(scan_file(rel_path, resolved_path))
    return findings
