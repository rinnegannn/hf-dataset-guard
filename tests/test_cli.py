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

    def fake_download(repo_id, revision, max_files, max_file_size_bytes, token, incomplete_reasons):
        calls.update(repo_id=repo_id, revision=revision, max_files=max_files, max_file_size_bytes=max_file_size_bytes, token=token)
        return downloaded

    monkeypatch.setattr(cli, "download_dataset_repo", fake_download)
    monkeypatch.setattr(
        cli,
        "scan_directory",
        lambda root, max_file_size_bytes, incomplete_reasons: [
            Finding("low", "test", "TEST001", "Test finding", "loader.py")
        ],
    )

    assert cli.main([
        "scan", "owner/dataset", "--revision", "abc123", "--max-files", "12",
        "--max-file-size", "34", "--token", "token-value",
    ]) == 0
    assert calls == {
        "repo_id": "owner/dataset", "revision": "abc123", "max_files": 12, "max_file_size_bytes": 34,
        "token": "token-value",
    }
    assert not downloaded.exists()


def test_fail_on_incomplete_returns_three_and_writes_json_report(tmp_path: Path, capsys):
    dataset = tmp_path / "dataset"
    dataset.mkdir()
    (dataset / "too-large.py").write_text("eval('must not be scanned')")
    output = tmp_path / "report.json"

    assert cli.main([
        "scan", str(dataset), "--max-file-size", "1", "--fail-on-incomplete",
        "--format", "json", "--output", str(output),
    ]) == 3
    assert capsys.readouterr().out == ""
    report = json.loads(output.read_text())
    assert report["scan_complete"] is False
    assert any("too-large.py" in reason for reason in report["incomplete_reasons"])


def test_complete_scan_is_explicit_in_terminal_output(tmp_path: Path, capsys):
    dataset = tmp_path / "dataset"
    dataset.mkdir()
    (dataset / "loader.py").write_text("x = 1")

    assert cli.main(["scan", str(dataset)]) == 0
    assert "Scan status: COMPLETE" in capsys.readouterr().out


def test_scan_error_returns_exit_code_two(tmp_path: Path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "download_dataset_repo", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("not found")))

    assert cli.main(["scan", "owner/missing"]) == 2
    assert "Error: not found" in capsys.readouterr().err


def test_invalid_command_line_exits_with_usage_error():
    with pytest.raises(SystemExit) as error:
        cli.main([])
    assert error.value.code == 2


@pytest.mark.parametrize("invalid_val", ["0", "-1", "-50"])
def test_invalid_max_files_exits_with_error(invalid_val: str, capsys):
    with pytest.raises(SystemExit) as error:
        cli.main(["scan", "some/repo", "--max-files", invalid_val])
    assert error.value.code == 2
    assert "--max-files must be a positive integer" in capsys.readouterr().err


@pytest.mark.parametrize("invalid_val", ["0", "-1", "-100"])
def test_invalid_max_file_size_exits_with_error(invalid_val: str, capsys):
    with pytest.raises(SystemExit) as error:
        cli.main(["scan", "some/repo", "--max-file-size", invalid_val])
    assert error.value.code == 2
    assert "--max-file-size must be a positive integer" in capsys.readouterr().err
