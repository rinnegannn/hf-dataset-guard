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
from .status import FileIssue

# Skip large data payloads that aren't useful to scan as text and would
# just slow things down (real datasets can have huge parquet/arrow shards).
SKIP_EXTENSIONS = {".parquet", ".arrow", ".csv", ".jsonl", ".zip", ".tar", ".gz", ".npy", ".npz"}
DEFAULT_MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # don't slurp huge files into memory


def scan_directory(
    root: Path,
    max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES,
    file_issues: list[FileIssue] | None = None,
) -> List[Finding]:
    findings: List[Finding] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel_path = str(path.relative_to(root))

        if path.suffix.lower() in SKIP_EXTENSIONS:
            if file_issues is not None:
                file_issues.append(
                    FileIssue(
                        rel_path,
                        "skipped",
                        f"{path.suffix.lower()} files are excluded from scanning",
                    )
                )
            continue
        try:
            if path.stat().st_size > max_file_size_bytes and path.suffix.lower() not in (".py",):
                if file_issues is not None:
                    file_issues.append(
                        FileIssue(
                            rel_path,
                            "skipped",
                            f"file exceeds --max-file-size ({max_file_size_bytes} bytes)",
                        )
                    )
                continue
        except OSError:
            if file_issues is not None:
                file_issues.append(
                    FileIssue(rel_path, "failed", "could not read file metadata")
                )
            continue

        findings.extend(scan_file(rel_path, path, file_issues=file_issues))
    return findings
