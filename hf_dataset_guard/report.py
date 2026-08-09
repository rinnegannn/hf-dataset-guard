from __future__ import annotations

import json

from .scorer import ScanResult

RESET = "\033[0m"
COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH": "\033[91m",
    "MEDIUM": "\033[93m",
    "LOW": "\033[93m",
    "CLEAN": "\033[92m",
}
SEVERITY_MARK = {
    "critical": "[!!]",
    "high": "[!]",
    "medium": "[~]",
    "low": "[.]",
    "info": "[i]",
}


def render_terminal(result: ScanResult) -> str:
    color = COLORS.get(result.risk_level, "")
    lines = []
    lines.append(f"{color}Risk: {result.risk_level} ({result.score}/100){RESET}")
    lines.append(f"Dataset: {result.repo_id}")
    provenance = result.provenance or {}
    lines.append(
        f"Resolved commit: {provenance.get('resolved_commit') or 'local target / unavailable'}"
    )
    lines.append(f"Tool version: {provenance.get('tool_version') or 'unknown'}")
    lines.append(f"Rule-set version: {provenance.get('rule_set_version') or 'unknown'}")
    if result.scan_complete:
        lines.append("Scan status: COMPLETE")
    else:
        lines.append("Scan status: INCOMPLETE")
        lines.append("Warning: not every file in the target was inspected.")
        for reason in result.incomplete_reasons or []:
            lines.append(f"  - {reason}")
    lines.append("")

    if not result.findings:
        lines.append("[+] No issues detected by current rule set.")
        return "\n".join(lines)

    # Group by file for readability.
    by_file: dict[str, list] = {}
    for f in result.findings:
        by_file.setdefault(f.file, []).append(f)

    for file, findings in by_file.items():
        for f in findings:
            mark = SEVERITY_MARK.get(f.severity, "[?]")
            loc = f"{file}:{f.line}" if f.line else file
            lines.append(f"{mark} {f.rule_id:<8} {loc}: {f.message}")
            if f.evidence:
                lines.append(f"      evidence: {f.evidence}")

    lines.append("")
    lines.append("Note: static analysis only. No file from this repo was executed or imported.")
    return "\n".join(lines)


def render_json(result: ScanResult) -> str:
    payload = {
        "repo_id": result.repo_id,
        "score": result.score,
        "risk_level": result.risk_level,
        "scan_complete": result.scan_complete,
        "incomplete_reasons": result.incomplete_reasons or [],
        "provenance": result.provenance or {},
        "findings": [f.to_dict() for f in result.findings],
    }
    return json.dumps(payload, indent=2)


def render_sarif(result: ScanResult) -> str:
    """Render findings in SARIF 2.1.0 for GitHub code scanning and CI tools."""
    rules: dict[str, dict[str, object]] = {}
    sarif_results: list[dict[str, object]] = []
    for finding in result.findings:
        rules.setdefault(
            finding.rule_id,
            {
                "id": finding.rule_id,
                "shortDescription": {"text": finding.category.replace("_", " ")},
                "help": {"text": finding.message},
            },
        )
        location: dict[str, object] = {
            "physicalLocation": {"artifactLocation": {"uri": finding.file}}
        }
        if finding.line:
            physical_location = location["physicalLocation"]
            assert isinstance(physical_location, dict)
            physical_location["region"] = {"startLine": finding.line}
        sarif_results.append(
            {
                "ruleId": finding.rule_id,
                "level": {
                    "critical": "error",
                    "high": "error",
                    "medium": "warning",
                    "low": "note",
                    "info": "note",
                }[finding.severity],
                "message": {"text": finding.message},
                "locations": [location],
            }
        )
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "hf-dataset-guard", "rules": list(rules.values())}},
                "results": sarif_results,
                "properties": {
                    "scan_complete": result.scan_complete,
                    "provenance": result.provenance or {},
                },
            }
        ],
    }
    return json.dumps(payload, indent=2)
