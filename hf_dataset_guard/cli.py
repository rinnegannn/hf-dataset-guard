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
        "--max-files", type=int, default=DEFAULT_MAX_FILES_TO_FETCH,
        help=f"Max number of files to download and scan from a remote repo (default: {DEFAULT_MAX_FILES_TO_FETCH})",
    )
    parser.add_argument(
        "--max-file-size", type=int, default=DEFAULT_MAX_FILE_SIZE_BYTES,
        help=f"Skip scanning any single file above this size in bytes (default: {DEFAULT_MAX_FILE_SIZE_BYTES})",
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

    is_local = Path(args.target).is_dir()
    local_dir = None
    try:
        if is_local:
            local_dir = Path(args.target)
            findings = scan_directory(local_dir, max_file_size_bytes=args.max_file_size)
        else:
            local_dir = download_dataset_repo(
                args.target,
                revision=args.revision,
                max_files=args.max_files,
                token=args.token,
            )
            findings = scan_directory(local_dir, max_file_size_bytes=args.max_file_size)
        result = build_result(args.target, findings)

        output_text = render_json(result) if args.format == "json" else render_terminal(result)

        if args.output:
            try:
                Path(args.output).write_text(output_text, encoding="utf-8")
            except OSError as error:
                raise RuntimeError(
                    f"Could not write report to '{args.output}': {error}"
                ) from error
        else:
            print(output_text)
    except (OSError, RuntimeError, UnicodeError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2
    finally:
        # Only clean up directories we created ourselves (remote downloads),
        # never the user's own local checkout.
        if local_dir is not None and not is_local:
            shutil.rmtree(local_dir, ignore_errors=True)

    if args.fail_on != "none" and result.score >= FAIL_ON_THRESHOLDS[args.fail_on]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
