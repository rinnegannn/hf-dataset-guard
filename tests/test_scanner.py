import sys
from pathlib import Path
import json

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hf_dataset_guard.report import render_json, render_terminal
from hf_dataset_guard.scanner import scan_directory
from hf_dataset_guard.scorer import build_result

FIXTURES = Path(__file__).parent / "fixtures"


def test_clean_dataset_has_no_high_severity_findings():
    findings = scan_directory(FIXTURES / "clean_dataset")
    result = build_result("test/clean", findings)
    assert result.risk_level in ("CLEAN", "LOW")


def test_malicious_dataset_flags_dangerous_calls():
    findings = scan_directory(FIXTURES / "malicious_dataset")
    categories = {f.category for f in findings}
    assert "dangerous_call" in categories
    assert "exposed_secret" in categories
    assert "template_injection" in categories
    assert "pickle_like_artifact" in categories
    assert "unexpected_executable" in categories
    assert "unsafe_dependency" in categories


def test_malicious_dataset_scores_high_risk():
    findings = scan_directory(FIXTURES / "malicious_dataset")
    result = build_result("test/malicious", findings)
    assert result.risk_level in ("HIGH", "CRITICAL")


def test_secret_is_redacted_in_output():
    findings = scan_directory(FIXTURES / "malicious_dataset")
    secret_findings = [f for f in findings if f.category == "exposed_secret"]
    assert secret_findings
    assert "...redacted..." in secret_findings[0].evidence


def test_local_scan_skips_and_reports_symlinked_files(tmp_path: Path):
    dataset = tmp_path / "dataset"
    dataset.mkdir()
    outside_file = tmp_path / "outside.py"
    outside_file.write_text("eval('sensitive host file')")
    linked_file = dataset / "linked.py"

    try:
        linked_file.symlink_to(outside_file)
    except OSError as error:
        pytest.skip(f"Symlinks are unavailable in this test environment: {error}")

    findings = scan_directory(dataset)

    assert not any(f.rule_id == "CODE004" for f in findings)
    skipped = [f for f in findings if f.rule_id == "SCAN001"]
    assert len(skipped) == 1
    assert skipped[0].severity == "info"
    assert skipped[0].file == "linked.py"


def test_skipped_link_is_not_scanned_and_is_in_reports(tmp_path: Path, monkeypatch):
    dataset = tmp_path / "dataset"
    dataset.mkdir()
    linked_file = dataset / "linked.py"
    linked_file.write_text("eval('must not be scanned')")
    path_type = type(linked_file)
    original_is_symlink = path_type.is_symlink

    monkeypatch.setattr(
        path_type,
        "is_symlink",
        lambda path: path == linked_file or original_is_symlink(path),
    )

    findings = scan_directory(dataset)
    result = build_result("test/symlink", findings)

    assert not any(f.rule_id == "CODE004" for f in findings)
    assert "SCAN001" in render_terminal(result)
    assert json.loads(render_json(result))["findings"][0]["rule_id"] == "SCAN001"


def test_large_python_files_respect_max_file_size(tmp_path: Path):
    dataset = tmp_path / "dataset"
    dataset.mkdir()
    (dataset / "large_loader.py").write_text("eval('must not be scanned')")

    findings = scan_directory(dataset, max_file_size_bytes=1)

    assert not any(f.rule_id == "CODE004" for f in findings)


def test_omitted_local_files_make_scan_incomplete_in_reports(tmp_path: Path):
    dataset = tmp_path / "dataset"
    dataset.mkdir()
    (dataset / "large.py").write_text("eval('must not be scanned')")
    incomplete_reasons = []

    findings = scan_directory(dataset, max_file_size_bytes=1, incomplete_reasons=incomplete_reasons)
    result = build_result("test/large", findings, incomplete_reasons)

    assert result.scan_complete is False
    assert "Scan status: INCOMPLETE" in render_terminal(result)
    payload = json.loads(render_json(result))
    assert payload["scan_complete"] is False
    assert any("large.py" in reason for reason in payload["incomplete_reasons"])


if __name__ == "__main__":
    # Minimal runner so this works even without pytest installed.
    import traceback

    tests = [obj for name, obj in list(globals().items()) if name.startswith("test_")]
    failures = 0
    for t in tests:
        try:
            t()
            print(f"PASS {t.__name__}")
        except Exception:
            failures += 1
            print(f"FAIL {t.__name__}")
            traceback.print_exc()
    sys.exit(1 if failures else 0)
