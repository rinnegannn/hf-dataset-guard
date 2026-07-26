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
from dataclasses import dataclass
from pathlib import Path

from huggingface_hub import HfApi, RepoFile, hf_hub_download
from huggingface_hub.utils import HfHubHTTPError

from .limits import DEFAULT_MAX_FILE_SIZE_BYTES, DEFAULT_MAX_FILES_TO_FETCH

# Cap the number of remote files considered for a scan. Full dataset payloads
# (parquet shards etc.) aren't needed to find loader-script/config
# vulnerabilities, and scanner.py skips known-large data extensions anyway.
# Overridable via --max-files on the CLI.


@dataclass(frozen=True)
class DatasetFile:
    path: str
    size: int


def list_dataset_files(
    repo_id: str, revision: str = "main", token: str | None = None
) -> list[DatasetFile]:
    """List all files and their remote sizes without downloading contents."""
    api = HfApi(token=token)
    try:
        entries = api.list_repo_tree(
            repo_id=repo_id,
            repo_type="dataset",
            revision=revision,
            recursive=True,
        )
        return [
            DatasetFile(path=entry.path, size=entry.size)
            for entry in entries
            if isinstance(entry, RepoFile)
        ]
    except HfHubHTTPError as e:
        raise RuntimeError(f"Could not list files for dataset '{repo_id}': {e}") from e


def download_dataset_repo(
    repo_id: str,
    revision: str = "main",
    max_files: int = DEFAULT_MAX_FILES_TO_FETCH,
    max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES,
    token: str | None = None,
) -> Path:
    """Download eligible files in a dataset repo into a fresh temp directory.

    Remote size metadata is checked before each download, so files larger than
    ``max_file_size_bytes`` are never requested. Caller is responsible for
    cleanup.

    token: an explicit HF token, or None to let huggingface_hub fall back
    to the HF_TOKEN environment variable / cached `huggingface-cli login`
    credentials automatically -- needed for private or gated datasets.
    """
    files = list_dataset_files(repo_id, revision=revision, token=token)
    if len(files) > max_files:
        files = files[:max_files]

    dest_root = Path(tempfile.mkdtemp(prefix="hf-dataset-guard-"))

    for file in files:
        if file.size > max_file_size_bytes:
            continue
        try:
            hf_hub_download(
                repo_id=repo_id,
                filename=file.path,
                repo_type="dataset",
                revision=revision,
                local_dir=str(dest_root),
                token=token,
            )
        except HfHubHTTPError:
            # A single missing/gated file shouldn't abort the whole scan.
            continue
    return dest_root
