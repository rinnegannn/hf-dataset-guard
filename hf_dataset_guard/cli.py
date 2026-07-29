from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

from .fetch import DEFAULT_MAX_FILES_TO_FETCH, download_dataset_repo
from .scanner import DEFAULT_MAX_FILE_SIZE_BYTES, scan_directory
from .scorer import build_result
from .report import render_terminal, render_json

# Exit codes:
#   0 - scan completed, threshold (if any) not reached
#   1 - a finding reached the configured --fail-on threshold
#   2 - target could not be scanned (bad repo id, network error, etc.)
#   3 - scan was incomplete and --fail-on-incomplete was requested
FAIL_ON_THRESHOLDS = {"low": 1, "medium": 15, "high": 40, "critical": 70}


def _add_scan_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("target", help="Dataset repo (username/dataset) or a local directory path")
    parser.add_argument("--revision", default="main", help="Git revision/branch for remote repos (default: main)")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format (default: text)")
    parser.add_argument("--output", "-o", help="Write report to this file instead of stdout")
    parser.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "critical", "none"],
        default="none",
        help="Exit 1 if risk reaches this level or higher (for CI use).",
    )
    parser.add_argument(
        "--fail-on-incomplete",
        action="store_true",
        help="Exit 3 when any file was omitted from the scan (for CI use).",
    )
    parser.add_argument(
        "--max-files", type=int, default=DEFAULT_MAX_FILES_TO_FETCH,
        help=f"Max number of files to download and scan from a remote repo (default: {DEFAULT_MAX_FILES_TO_FETCH})",
    )
    parser.add_argument(
        "--max-file-size", type=int, default=DEFAULT_MAX_FILE_SIZE_BYTES,
        help=f"Skip local files and avoid downloading remote files above this size in bytes (default: {DEFAULT_MAX_FILE_SIZE_BYTES})",
    )
    parser.add_argument(
        "--token", default=None,
        help="HF access token for private/gated datasets. Omit to use HF_TOKEN env var or cached login.",
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="hf-dataset-guard",
        description="Static security scanner for Hugging Face dataset repos.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan_parser = subparsers.add_parser("scan", help="Scan a remote dataset repo or local directory")
    _add_scan_args(scan_parser)

    args = parser.parse_args(argv)

    if args.max_files <= 0:
        parser.error("--max-files must be a positive integer (> 0)")
    if args.max_file_size <= 0:
        parser.error("--max-file-size must be a positive integer (> 0)")

    is_local = Path(args.target).is_dir()
    local_dir = None
    incomplete_reasons: list[str] = []
    try:
        if is_local:
            local_dir = Path(args.target)
            findings = scan_directory(
                local_dir,
                max_file_size_bytes=args.max_file_size,
                incomplete_reasons=incomplete_reasons,
            )
        else:
            local_dir = download_dataset_repo(
                args.target,
                revision=args.revision,
                max_files=args.max_files,
                max_file_size_bytes=args.max_file_size,
                token=args.token,
                incomplete_reasons=incomplete_reasons,
            )
            findings = scan_directory(
                local_dir,
                max_file_size_bytes=args.max_file_size,
                incomplete_reasons=incomplete_reasons,
            )
        result = build_result(args.target, findings, incomplete_reasons)
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2
    finally:
        # Only clean up directories we created ourselves (remote downloads),
        # never the user's own local checkout.
        if local_dir is not None and not is_local:
            shutil.rmtree(local_dir, ignore_errors=True)

    output_text = render_json(result) if args.format == "json" else render_terminal(result)

    if args.output:
        Path(args.output).write_text(output_text)
    else:
        print(output_text)

    if args.fail_on_incomplete and not result.scan_complete:
        return 3
    if args.fail_on != "none" and result.score >= FAIL_ON_THRESHOLDS[args.fail_on]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
