from pathlib import Path

import httpx
import pytest
from huggingface_hub.utils import HfHubHTTPError

from hf_dataset_guard import fetch


def test_list_dataset_files_uses_dataset_arguments(monkeypatch):
    calls = {}

    class FakeRepoFile:
        def __init__(self, path, size):
            self.path = path
            self.size = size

    class FakeRepoFolder:
        pass

    class FakeApi:
        def __init__(self, token):
            calls["token"] = token

        def list_repo_tree(self, **kwargs):
            calls["kwargs"] = kwargs
            return [
                FakeRepoFile("README.md", 10),
                FakeRepoFolder(),
                FakeRepoFile("data/loader.py", 20),
            ]

    monkeypatch.setattr(fetch, "HfApi", FakeApi)
    monkeypatch.setattr(fetch, "RepoFile", FakeRepoFile)

    assert fetch.list_dataset_files("owner/dataset", revision="v1", token="secret") == [
        fetch.DatasetFile("README.md", 10),
        fetch.DatasetFile("data/loader.py", 20),
    ]
    assert calls == {
        "token": "secret",
        "kwargs": {
            "repo_id": "owner/dataset",
            "repo_type": "dataset",
            "revision": "v1",
            "recursive": True,
        },
    }


def test_list_dataset_files_wraps_hub_errors(monkeypatch):
    response = httpx.Response(404, request=httpx.Request("GET", "https://example.test"))

    class FakeApi:
        def __init__(self, token):
            pass

        def list_repo_tree(self, **kwargs):
            raise HfHubHTTPError("missing", response=response)

    monkeypatch.setattr(fetch, "HfApi", FakeApi)

    with pytest.raises(RuntimeError, match="Could not list files"):
        fetch.list_dataset_files("owner/missing")


def test_download_truncates_file_list_and_continues_after_file_error(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        fetch,
        "list_dataset_files",
        lambda *args, **kwargs: [
            fetch.DatasetFile("one.py", 1),
            fetch.DatasetFile("two.py", 2),
            fetch.DatasetFile("three.py", 3),
        ],
    )
    monkeypatch.setattr(fetch.tempfile, "mkdtemp", lambda prefix: str(tmp_path / "download"))
    calls = []
    response = httpx.Response(404, request=httpx.Request("GET", "https://example.test"))

    def fake_download(**kwargs):
        calls.append(kwargs)
        if kwargs["filename"] == "two.py":
            raise HfHubHTTPError("missing", response=response)

    monkeypatch.setattr(fetch, "hf_hub_download", fake_download)

    assert fetch.download_dataset_repo("owner/dataset", revision="v1", max_files=2, token="secret") == tmp_path / "download"
    assert [call["filename"] for call in calls] == ["one.py", "two.py"]
    assert all(call["repo_id"] == "owner/dataset" for call in calls)
    assert all(call["repo_type"] == "dataset" for call in calls)
    assert all(call["revision"] == "v1" for call in calls)
    assert all(call["token"] == "secret" for call in calls)


def test_download_skips_oversized_files_before_requesting_them(
    tmp_path: Path, monkeypatch
):
    monkeypatch.setattr(
        fetch,
        "list_dataset_files",
        lambda *args, **kwargs: [
            fetch.DatasetFile("at-limit.py", 10),
            fetch.DatasetFile("too-large.py", 11),
        ],
    )
    monkeypatch.setattr(
        fetch.tempfile, "mkdtemp", lambda prefix: str(tmp_path / "download")
    )
    calls = []
    monkeypatch.setattr(
        fetch, "hf_hub_download", lambda **kwargs: calls.append(kwargs)
    )

    fetch.download_dataset_repo("owner/dataset", max_file_size_bytes=10)

    assert [call["filename"] for call in calls] == ["at-limit.py"]
