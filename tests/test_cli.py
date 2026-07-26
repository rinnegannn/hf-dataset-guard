import json
from pathlib import Path

import pytest

from hf_dataset_guard import cli
from hf_dataset_guard.rules import Finding


def test_local_scan_writes_json_report(tmp_path: Path, capsys):
    dataset = tmp_path / "dataset"
    dataset.mkdir()
    (dataset / "loader.py").write_text("eval('1 + 1')")
    output = tmp_path / "report.json"

    assert cli.main(["scan", str(dataset), "--format", "json", "--output", str(output)]) == 0
    assert capsys.readouterr().out == ""
    report = json.loads(output.read_text())
    assert report["risk_level"] == "HIGH"
    assert report["findings"][0]["rule_id"] == "CODE004"


def test_fail_threshold_returns_one_for_local_scan(tmp_path: Path):
    dataset = tmp_path / "dataset"
    dataset.mkdir()
    (dataset / "loader.py").write_text("eval('1 + 1')")

    assert cli.main(["scan", str(dataset), "--fail-on", "high"]) == 1


def test_remote_scan_forwards_options_and_removes_download(tmp_path: Path, monkeypatch):
    downloaded = tmp_path / "downloaded"
    downloaded.mkdir()
    calls = {}

    def fake_download(repo_id, revision, max_files, token):
        calls.update(repo_id=repo_id, revision=revision, max_files=max_files, token=token)
        return downloaded

    monkeypatch.setattr(cli, "download_dataset_repo", fake_download)
    monkeypatch.setattr(
        cli,
        "scan_directory",
        lambda root, max_file_size_bytes: [
            Finding("low", "test", "TEST001", "Test finding", "loader.py")
        ],
    )

    assert cli.main([
        "scan", "owner/dataset", "--revision", "abc123", "--max-files", "12",
        "--max-file-size", "34", "--token", "token-value",
    ]) == 0
    assert calls == {
        "repo_id": "owner/dataset", "revision": "abc123", "max_files": 12,
        "token": "token-value",
    }
    assert not downloaded.exists()


def test_scan_error_returns_exit_code_two(tmp_path: Path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "download_dataset_repo", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("not found")))

    assert cli.main(["scan", "owner/missing"]) == 2
    assert "Error: not found" in capsys.readouterr().err


def test_local_filesystem_error_returns_exit_code_two(
    tmp_path: Path, monkeypatch, capsys
):
    dataset = tmp_path / "dataset"
    dataset.mkdir()
    monkeypatch.setattr(
        cli,
        "scan_directory",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            OSError("permission denied")
        ),
    )

    assert cli.main(["scan", str(dataset)]) == 2
    assert "Error: permission denied" in capsys.readouterr().err


def test_report_write_error_returns_exit_code_two(tmp_path: Path, capsys):
    dataset = tmp_path / "dataset"
    dataset.mkdir()
    output = tmp_path / "missing" / "report.json"

    assert cli.main(["scan", str(dataset), "--output", str(output)]) == 2
    stderr = capsys.readouterr().err
    assert f"Error: Could not write report to '{output}'" in stderr
    assert "Traceback" not in stderr


def test_remote_download_is_cleaned_up_after_report_error(
    tmp_path: Path, monkeypatch
):
    downloaded = tmp_path / "downloaded"
    downloaded.mkdir()
    monkeypatch.setattr(
        cli, "download_dataset_repo", lambda *args, **kwargs: downloaded
    )
    output = tmp_path / "missing" / "report.txt"

    assert cli.main(["scan", "owner/dataset", "--output", str(output)]) == 2
    assert not downloaded.exists()


def test_invalid_command_line_exits_with_usage_error():
    with pytest.raises(SystemExit) as error:
        cli.main([])
    assert error.value.code == 2
