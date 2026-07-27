from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from huggingface_hub.utils import HfHubHTTPError

from hf_dataset_guard import fetch


def test_list_dataset_files_uses_dataset_arguments(monkeypatch):
    calls = {}

    class FakeApi:
        def __init__(self, token):
            calls["token"] = token

        def list_repo_files(self, **kwargs):
            calls["kwargs"] = kwargs
            return ["README.md", "loader.py"]

    monkeypatch.setattr(fetch, "HfApi", FakeApi)

    assert fetch.list_dataset_files("owner/dataset", revision="v1", token="secret") == [
        "README.md", "loader.py"
    ]
    assert calls == {
        "token": "secret",
        "kwargs": {
            "repo_id": "owner/dataset", "repo_type": "dataset", "revision": "v1"
        },
    }


def test_list_dataset_files_wraps_hub_errors(monkeypatch):
    response = httpx.Response(404, request=httpx.Request("GET", "https://example.test"))

    class FakeApi:
        def __init__(self, token):
            pass

        def list_repo_files(self, **kwargs):
            raise HfHubHTTPError("missing", response=response)

    monkeypatch.setattr(fetch, "HfApi", FakeApi)

    with pytest.raises(RuntimeError, match="Could not list files"):
        fetch.list_dataset_files("owner/missing")


def test_list_dataset_file_metadata_uses_recursive_dataset_tree(monkeypatch):
    calls = {}

    class FakeApi:
        def __init__(self, token):
            calls["token"] = token

        def list_repo_tree(self, **kwargs):
            calls["kwargs"] = kwargs
            return [SimpleNamespace(path="loader.py", size=12)]

    monkeypatch.setattr(fetch, "HfApi", FakeApi)

    assert fetch.list_dataset_file_metadata("owner/dataset", revision="v1", token="secret") == [
        SimpleNamespace(path="loader.py", size=12)
    ]
    assert calls == {
        "token": "secret",
        "kwargs": {
            "repo_id": "owner/dataset", "repo_type": "dataset", "revision": "v1", "recursive": True
        },
    }


def test_download_skips_oversized_files_before_download_and_truncates(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        fetch,
        "list_dataset_file_metadata",
        lambda *args, **kwargs: [
            SimpleNamespace(path="one.py", size=10),
            SimpleNamespace(path="too-large.py", size=11),
            SimpleNamespace(path="two.py", size=10),
            SimpleNamespace(path="unknown-size.py", size=None),
            SimpleNamespace(path="three.py", size=10),
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

    assert fetch.download_dataset_repo(
        "owner/dataset", revision="v1", max_files=2, max_file_size_bytes=10, token="secret"
    ) == tmp_path / "download"
    assert [call["filename"] for call in calls] == ["one.py", "two.py"]
    assert all(call["repo_id"] == "owner/dataset" for call in calls)
    assert all(call["repo_type"] == "dataset" for call in calls)
    assert all(call["revision"] == "v1" for call in calls)
    assert all(call["token"] == "secret" for call in calls)
