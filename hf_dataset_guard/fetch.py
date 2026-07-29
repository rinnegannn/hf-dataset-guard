"""
Network layer. Uses huggingface_hub (the official client) instead of
hand-rolled HTTP calls -- it already handles auth, pagination, revisions,
and retries correctly, and it's the same client most HF users have
installed already.

This module never executes anything from the dataset. It only lists
and downloads files to a local directory for rules.py to read as text/bytes.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from huggingface_hub import HfApi, hf_hub_download
from huggingface_hub.utils import HfHubHTTPError

from .scanner import DEFAULT_MAX_FILE_SIZE_BYTES

# Cap total download size for a scan. Full dataset payloads (parquet
# shards etc.) aren't needed to find loader-script / config vulnerabilities,
# and scanner.py skips known-large data extensions anyway -- this is a
# second guard in case of a repo with many small-but-numerous files.
# Overridable via --max-files on the CLI.
DEFAULT_MAX_FILES_TO_FETCH = 500


def list_dataset_files(repo_id: str, revision: str = "main", token: str | None = None) -> list[str]:
    api = HfApi(token=token)
    try:
        return api.list_repo_files(repo_id=repo_id, repo_type="dataset", revision=revision)
    except HfHubHTTPError as e:
        raise RuntimeError(f"Could not list files for dataset '{repo_id}': {e}") from e


def list_dataset_file_metadata(repo_id: str, revision: str = "main", token: str | None = None) -> list[object]:
    """Return recursive repository-tree entries, including each file's size."""
    api = HfApi(token=token)
    try:
        return list(api.list_repo_tree(
            repo_id=repo_id,
            repo_type="dataset",
            revision=revision,
            recursive=True,
        ))
    except HfHubHTTPError as e:
        raise RuntimeError(f"Could not list files for dataset '{repo_id}': {e}") from e


def download_dataset_repo(
    repo_id: str,
    revision: str = "main",
    max_files: int = DEFAULT_MAX_FILES_TO_FETCH,
    token: str | None = None,
    max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES,
    incomplete_reasons: list[str] | None = None,
) -> Path:
    """Download every file in a dataset repo into a fresh temp directory
    and return its path. Caller is responsible for cleanup.

    token: an explicit HF token, or None to let huggingface_hub fall back
    to the HF_TOKEN environment variable / cached `huggingface-cli login`
    credentials automatically -- needed for private or gated datasets.
    """
    def record_incomplete(reason: str) -> None:
        if incomplete_reasons is not None:
            incomplete_reasons.append(reason)

    files: list[str] = []
    for entry in list_dataset_file_metadata(repo_id, revision=revision, token=token):
        path = getattr(entry, "path", None)
        if not isinstance(path, str):
            continue
        size = getattr(entry, "size", None)
        if not isinstance(size, int) or size < 0:
            record_incomplete(f"Skipped remote file with unknown size: {path}")
            continue
        if size > max_file_size_bytes:
            record_incomplete(
                f"Skipped remote file exceeding --max-file-size ({max_file_size_bytes} bytes): {path}"
            )
            continue
        files.append(path)
    if len(files) > max_files:
        record_incomplete(
            f"Skipped {len(files) - max_files} remote file(s) due to --max-files={max_files}"
        )
        files = files[:max_files]

    dest_root = Path(tempfile.mkdtemp(prefix="hf-dataset-guard-"))

    for filename in files:
        try:
            hf_hub_download(
                repo_id=repo_id,
                filename=filename,
                repo_type="dataset",
                revision=revision,
                local_dir=str(dest_root),
                token=token,
            )
        except HfHubHTTPError:
            # A single missing/gated file shouldn't abort the whole scan.
            record_incomplete(f"Could not download remote file: {filename}")
            continue
    return dest_root
