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


def scan_directory(root: Path, max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES) -> List[Finding]:
    root = root.resolve()
    findings: List[Finding] = []
    for path in sorted(root.rglob("*")):
        rel_path = str(path.relative_to(root))

        # Never follow links supplied by a scanned directory. A local target
        # may contain a link to any readable location on the host, so even a
        # harmless-looking file link is outside this scanner's trust boundary.
        if path.is_symlink():
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
            findings.append(Finding(
                severity="info",
                category="scan_boundary",
                rule_id="SCAN001",
                message="Skipped path that resolves outside the requested directory.",
                file=rel_path,
            ))
            continue
        except OSError:
            continue

        if not resolved_path.is_file():
            continue

        if resolved_path.suffix.lower() in SKIP_EXTENSIONS:
            continue
        try:
            if resolved_path.stat().st_size > max_file_size_bytes:
                continue
        except OSError:
            continue

        findings.extend(scan_file(rel_path, resolved_path))
    return findings
