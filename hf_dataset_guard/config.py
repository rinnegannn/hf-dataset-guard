"""Configuration and baseline helpers for audit-friendly scan customization."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from .rules import Finding


def load_suppressions(config_path: Path | None) -> list[dict[str, str]]:
    if config_path is None or not config_path.exists():
        return []
    try:
        payload = yaml.safe_load(config_path.read_text()) or {}
    except (OSError, yaml.YAMLError) as error:
        raise RuntimeError(f"Could not read configuration {config_path}: {error}") from error
    entries = payload.get("suppressions", []) if isinstance(payload, dict) else []
    if not isinstance(entries, list):
        raise TypeError("Configuration field 'suppressions' must be a list")
    suppressions: list[dict[str, str]] = []
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("rule_id"), str):
            raise TypeError("Each suppression must include a string rule_id")
        path = entry.get("path", "*")
        if not isinstance(path, str):
            raise TypeError("Suppression path must be a string")
        suppressions.append({"rule_id": entry["rule_id"], "path": path})
    return suppressions


def apply_suppressions(
    findings: list[Finding], suppressions: list[dict[str, str]]
) -> tuple[list[Finding], list[Finding]]:
    kept, suppressed = [], []
    for finding in findings:
        if any(
            finding.rule_id == item["rule_id"] and Path(finding.file).match(item["path"])
            for item in suppressions
        ):
            suppressed.append(finding)
        else:
            kept.append(finding)
    return kept, suppressed


def new_findings_from_baseline(findings: list[Finding], baseline_path: Path) -> list[Finding]:
    try:
        payload = json.loads(baseline_path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"Could not read baseline {baseline_path}: {error}") from error
    previous = payload.get("findings")
    if not isinstance(previous, list):
        raise TypeError("Baseline must be an hf-dataset-guard JSON report")
    identities = {
        (item.get("rule_id"), item.get("file"), item.get("line"))
        for item in previous
        if isinstance(item, dict)
    }
    return [f for f in findings if (f.rule_id, f.file, f.line) not in identities]
