import json
from pathlib import Path
from types import SimpleNamespace

from tools import evaluate_corpus


def test_revisions_get_distinct_reports_and_summary_provenance(tmp_path: Path, monkeypatch):
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            [
                {"repo_id": "owner/dataset", "revision": "first", "label": "benign"},
                {"repo_id": "owner/dataset", "revision": "second", "label": "malicious"},
            ]
        )
    )
    output = tmp_path / "reports"
    paths = []

    def fake_run(command, check):
        revision = command[command.index("--revision") + 1]
        report_path = Path(command[command.index("--output") + 1])
        paths.append(report_path)
        report_path.write_text(
            json.dumps({"risk_level": revision, "scan_complete": True, "findings": []})
        )
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(evaluate_corpus.subprocess, "run", fake_run)
    assert evaluate_corpus.main([str(manifest), str(output)]) == 0
    assert len(set(paths)) == 2
    assert [json.loads(path.read_text())["risk_level"] for path in paths] == ["first", "second"]
    summary = json.loads((output / "summary.json").read_text())
    assert [row["revision"] for row in summary] == ["first", "second"]
    assert [row["report_file"] for row in summary] == [path.name for path in paths]


def test_failed_rerun_does_not_reuse_prior_report_and_continues(tmp_path: Path, monkeypatch):
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps([{"repo_id": "owner/first"}, {"repo_id": "owner/second"}]))
    output = tmp_path / "reports"
    fail_first = False

    def fake_run(command, check):
        repo_id = command[command.index("scan") + 1]
        report_path = Path(command[command.index("--output") + 1])
        if fail_first and repo_id == "owner/first":
            assert not report_path.exists()
            return SimpleNamespace(returncode=2)
        report_path.write_text(
            json.dumps({"risk_level": "LOW", "scan_complete": True, "findings": []})
        )
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(evaluate_corpus.subprocess, "run", fake_run)
    assert evaluate_corpus.main([str(manifest), str(output)]) == 0
    fail_first = True
    assert evaluate_corpus.main([str(manifest), str(output)]) == 1
    summary = json.loads((output / "summary.json").read_text())
    assert summary[0]["exit_code"] == 2
    assert summary[0]["risk_level"] is None
    assert summary[0]["scan_complete"] is None
    assert summary[0]["finding_count"] == 0
    assert summary[1]["exit_code"] == 0
    assert summary[1]["risk_level"] == "LOW"
