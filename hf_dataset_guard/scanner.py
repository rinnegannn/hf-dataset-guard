"""
Directory scanner. Deliberately decoupled from the network layer: this
module only ever reads local files it's given. fetch.py is responsible
for getting a dataset repo onto disk first. That split makes the rule
engine unit-testable without hitting the Hugging Face API at all.
"""

from __future__ import annotations

from pathlib import Path
from typing import List

from .limits import DEFAULT_MAX_FILE_SIZE_BYTES
from .rules import Finding, scan_file

# Skip large data payloads that aren't useful to scan as text and would
# just slow things down (real datasets can have huge parquet/arrow shards).
SKIP_EXTENSIONS = {".parquet", ".arrow", ".csv", ".jsonl", ".zip", ".tar", ".gz", ".npy", ".npz"}


def scan_directory(root: Path, max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES) -> List[Finding]:
    findings: List[Finding] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel_path = str(path.relative_to(root))

        if path.suffix.lower() in SKIP_EXTENSIONS:
            continue
        try:
            if path.stat().st_size > max_file_size_bytes and path.suffix.lower() not in (".py",):
                continue
        except OSError:
            continue

        findings.extend(scan_file(rel_path, path))
    return findings
