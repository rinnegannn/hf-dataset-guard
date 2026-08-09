"""Run reproducible hf-dataset-guard scans for a labelled evaluation corpus.

The manifest is a JSON list of {"repo_id", "label", "revision"} objects.
Labels are preserved in the summary but are intentionally not inferred by the
scanner; a human reviewer supplies ground truth.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate a labelled HF dataset corpus")
    parser.add_argument("manifest", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args(argv)

    entries = json.loads(args.manifest.read_text())
    if not isinstance(entries, list):
        parser.error("manifest must be a JSON list")
    args.output.mkdir(parents=True, exist_ok=True)
    summary = []
    for entry in entries:
        repo_id = entry["repo_id"]
        revision = entry.get("revision", "main")
        report_path = args.output / f"{repo_id.replace('/', '__')}.json"
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "hf_dataset_guard.cli",
                "scan",
                repo_id,
                "--revision",
                revision,
                "--format",
                "json",
                "--output",
                str(report_path),
            ],
            check=False,
        )
        report = json.loads(report_path.read_text()) if report_path.exists() else {}
        summary.append(
            {
                "repo_id": repo_id,
                "label": entry.get("label"),
                "exit_code": completed.returncode,
                "risk_level": report.get("risk_level"),
                "scan_complete": report.get("scan_complete"),
                "finding_count": len(report.get("findings", [])),
            }
        )
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
