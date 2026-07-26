import json

from hf_dataset_guard.report import render_json, render_terminal
from hf_dataset_guard.scorer import build_result
from hf_dataset_guard.status import FileIssue


def test_reports_include_remote_file_issues():
    result = build_result(
        "owner/dataset",
        [],
        file_issues=[
            FileIssue("large.csv", "skipped", ".csv files are excluded"),
            FileIssue("missing.py", "failed", "download failed"),
            FileIssue("extra.py", "omitted", "--max-files limit reached"),
        ],
    )

    terminal = render_terminal(result)
    assert "Remote file coverage: 1 skipped, 1 failed, 1 omitted" in terminal
    assert "[FAILED] missing.py: download failed" in terminal

    payload = json.loads(render_json(result))
    assert payload["file_issues"] == [
        {
            "file": "large.csv",
            "status": "skipped",
            "reason": ".csv files are excluded",
        },
        {
            "file": "missing.py",
            "status": "failed",
            "reason": "download failed",
        },
        {
            "file": "extra.py",
            "status": "omitted",
            "reason": "--max-files limit reached",
        },
    ]
