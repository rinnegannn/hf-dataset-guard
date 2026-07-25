import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

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
    assert "…redacted…" in secret_findings[0].evidence


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
