from pathlib import Path

import pytest

from hf_dataset_guard.rules import (
    check_dangerous_calls_ast,
    check_pickle_like_files,
    check_remote_download,
    check_secrets,
    check_template_injection,
    check_unexpected_executable,
    check_unsafe_dependency_install,
    scan_file,
)


def test_pickle_and_safe_tensor_extensions():
    assert [finding.rule_id for finding in check_pickle_like_files("model.PKL")] == ["FILE001"]
    assert check_pickle_like_files("model.safetensors") == []


@pytest.mark.parametrize(
    ("path", "head", "severity"),
    [
        ("run.sh", b"#!/bin/sh", "high"),
        ("payload", b"\x7fELF\x02", "critical"),
        ("payload", b"MZ\x90\x00", "critical"),
    ],
)
def test_executable_detection(path, head, severity):
    findings = check_unexpected_executable(path, head)
    assert len(findings) == 1
    assert findings[0].rule_id == "FILE002"
    assert findings[0].severity == severity


@pytest.mark.parametrize(
    ("secret", "rule_id"),
    [
        ("AKIA1234567890ABCDEF", "SECRET01"),
        ("ghp_" + "a" * 36, "SECRET02"),
        ("sk-" + "a" * 20, "SECRET03"),
        ("hf_" + "a" * 30, "SECRET04"),
        ("-----BEGIN PRIVATE KEY-----", "SECRET05"),
        ("xoxb-1234567890", "SECRET06"),
    ],
)
def test_secret_detection_is_redacted(secret, rule_id):
    findings = check_secrets("config.txt", f"token={secret}")
    matching = [finding for finding in findings if finding.rule_id == rule_id]
    assert len(matching) == 1
    assert secret not in matching[0].evidence
    assert "...redacted..." in matching[0].evidence


def test_non_secret_text_has_no_findings():
    assert check_secrets("README.md", "This dataset contains public images.") == []


@pytest.mark.parametrize(
    "source",
    [
        "Template(config).render()",
        "Environment().from_string(config)",
        "jinja2.Template(config)",
        "{{ value | safe }}",
    ],
)
def test_template_patterns_are_detected(source):
    findings = check_template_injection("loader.py", source)
    assert findings and all(finding.rule_id == "CODE003" for finding in findings)


@pytest.mark.parametrize(
    "source",
    [
        "requests.get(url)",
        "urllib.request.urlopen(url)",
        "urlretrieve(url, path)",
        "os.system('curl https://example.test/file')",
    ],
)
def test_remote_download_patterns_are_detected(source):
    findings = check_remote_download("loader.py", source)
    assert len(findings) == 1
    assert findings[0].rule_id == "NET001"


def test_dependency_rules_distinguish_pinned_and_runtime_install():
    findings = check_unsafe_dependency_install(
        "requirements.txt", "git+https://example.test/org/project.git\n"
    )
    assert [finding.rule_id for finding in findings] == ["DEP001"]
    assert check_unsafe_dependency_install(
        "requirements.txt", "git+https://example.test/org/project.git@v1.2.3\n"
    ) == []
    findings = check_unsafe_dependency_install("loader.py", "subprocess.run('pip install thing')")
    assert [finding.rule_id for finding in findings] == ["DEP002"]


def test_dangerous_calls_and_safe_load_options():
    source = """
import os, pickle, subprocess, torch, yaml
subprocess.run(['echo', 'hello'])
os.system('echo hello')
pickle.loads(data)
eval(code)
torch.load('weights.pt', weights_only=True)
yaml.load(text, Loader=yaml.SafeLoader)
"""
    findings = check_dangerous_calls_ast("loader.py", source)
    assert {(finding.rule_id, finding.line) for finding in findings} == {
        ("CODE001", 3),
        ("CODE001", 4),
        ("CODE002", 5),
        ("CODE004", 6),
    }


def test_malformed_python_does_not_break_scanning():
    assert check_dangerous_calls_ast("broken.py", "def broken(:\n") == []


def test_scan_file_only_parses_known_text_extensions(tmp_path: Path):
    binary_path = tmp_path / "payload.dat"
    binary_path.write_text("hf_" + "a" * 30)
    assert scan_file("payload.dat", binary_path) == []


def test_scan_file_records_read_failures(tmp_path: Path):
    file_issues = []

    assert scan_file("missing.txt", tmp_path / "missing.txt", file_issues) == []
    assert [(issue.file, issue.status) for issue in file_issues] == [
        ("missing.txt", "failed")
    ]
