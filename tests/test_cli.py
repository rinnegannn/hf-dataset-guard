import json
from pathlib import Path

import pytest

from hf_dataset_guard import cli
from hf_dataset_guard.rules import Finding


def test_version_exits_without_scanning(monkeypatch, capsys):
    def unexpected_scan(*args, **kwargs):
        pytest.fail("Version checks must not scan or contact Hugging Face")

    monkeypatch.setattr(cli, "resolve_dataset_commit", unexpected_scan)
    monkeypatch.setattr(cli, "scan_directory", unexpected_scan)
    with pytest.raises(SystemExit) as error:
        cli.main(["--version"])

    assert error.value.code == 0
    assert capsys.readouterr().out == f"hf-dataset-guard {cli.__version__}\n"


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
        calls.update(
            repo_id=repo_id,
            revision=revision,
            max_files=max_files,
            max_file_size_bytes=max_file_size_bytes,
            token=token,
        )
        return downloaded

    monkeypatch.setattr(cli, "download_dataset_repo", fake_download)
    monkeypatch.setattr(cli, "resolve_dataset_commit", lambda *args, **kwargs: "deadbeef")
    monkeypatch.setattr(
        cli,
        "scan_directory",
        lambda root, max_file_size_bytes, incomplete_reasons: [
            Finding("low", "test", "TEST001", "Test finding", "loader.py")
        ],
    )

    assert (
        cli.main(
            [
                "scan",
                "owner/dataset",
                "--revision",
                "abc123",
                "--max-files",
                "12",
                "--max-file-size",
                "34",
                "--token",
                "token-value",
            ]
        )
        == 0
    )
    assert calls == {
        "repo_id": "owner/dataset",
        "revision": "abc123",
        "max_files": 12,
        "max_file_size_bytes": 34,
        "token": "token-value",
    }
    assert not downloaded.exists()


def test_output_error_returns_exit_code_two(tmp_path: Path, monkeypatch, capsys):
    dataset = tmp_path / "dataset"
    dataset.mkdir()
    monkeypatch.setattr(
        Path, "write_text", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("disk full"))
    )

    assert cli.main(["scan", str(dataset), "--output", str(tmp_path / "report.json")]) == 2
    assert "could not write report" in capsys.readouterr().err


def test_json_report_contains_reproducibility_provenance(tmp_path: Path, capsys):
    dataset = tmp_path / "dataset"
    dataset.mkdir()

    assert cli.main(["scan", str(dataset), "--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["provenance"]["tool_version"]
    assert report["provenance"]["rule_set_version"] == "1"


def test_sarif_output_contains_findings(tmp_path: Path, capsys):
    dataset = tmp_path / "dataset"
    dataset.mkdir()
    (dataset / "loader.py").write_text("eval('1 + 1')")

    assert cli.main(["scan", str(dataset), "--format", "sarif"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["version"] == "2.1.0"
    assert report["runs"][0]["results"][0]["ruleId"] == "CODE004"


def test_config_suppression_is_audited_in_json(tmp_path: Path, capsys):
    dataset = tmp_path / "dataset"
    dataset.mkdir()
    (dataset / "loader.py").write_text("eval('1 + 1')")
    (dataset / ".hfguard.yml").write_text(
        "suppressions:\n  - rule_id: CODE004\n    path: loader.py\n"
    )

    assert cli.main(["scan", str(dataset), "--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["findings"] == []
    assert report["suppressed_findings"][0]["rule_id"] == "CODE004"


def test_baseline_identifies_only_new_findings(tmp_path: Path, capsys):
    dataset = tmp_path / "dataset"
    dataset.mkdir()
    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps({"findings": [{"rule_id": "CODE004", "file": "loader.py", "line": 1}]})
    )
    (dataset / "loader.py").write_text("eval('1 + 1')\nexec('2 + 2')")

    assert cli.main(["scan", str(dataset), "--format", "json", "--baseline", str(baseline)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert len(report["new_findings"]) == 1
    assert report["new_findings"][0]["line"] == 2


def test_fail_on_incomplete_returns_three_and_writes_json_report(tmp_path: Path, capsys):
    dataset = tmp_path / "dataset"
    dataset.mkdir()
    (dataset / "too-large.py").write_text("eval('must not be scanned')")
    output = tmp_path / "report.json"

    assert (
        cli.main(
            [
                "scan",
                str(dataset),
                "--max-file-size",
                "1",
                "--fail-on-incomplete",
                "--format",
                "json",
                "--output",
                str(output),
            ]
        )
        == 3
    )
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
    monkeypatch.setattr(cli, "resolve_dataset_commit", lambda *args, **kwargs: "deadbeef")
    monkeypatch.setattr(
        cli,
        "download_dataset_repo",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("not found")),
    )

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
