"""
Detection rules for hf-dataset-guard.

Each rule inspects either file metadata (name/extension/bytes) or Python
source text and yields Finding objects. Rules are intentionally static
(regex + light AST) so the tool has no execution risk of its own: it
never imports or runs the code it is scanning.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List

# --------------------------------------------------------------------------
# Finding model
# --------------------------------------------------------------------------

@dataclass
class Finding:
    severity: str        # "critical" | "high" | "medium" | "low" | "info"
    category: str        # short machine-friendly tag, e.g. "remote_code_exec"
    rule_id: str          # stable ID, e.g. "CODE001" -- safe to reference in .hfguard.yml allowlists
    message: str          # human-readable description
    file: str             # relative path within the dataset repo
    line: int | None = None
    evidence: str | None = None  # short snippet, no full-file reproduction

    def to_dict(self):
        return {
            "severity": self.severity,
            "category": self.category,
            "rule_id": self.rule_id,
            "message": self.message,
            "file": self.file,
            "line": self.line,
            "evidence": self.evidence,
        }


# Weight per severity, used by the scorer.
SEVERITY_WEIGHT = {
    "critical": 40,
    "high": 25,
    "medium": 12,
    "low": 5,
    "info": 0,
}

# --------------------------------------------------------------------------
# Static extension / filename checks
# --------------------------------------------------------------------------

PICKLE_LIKE_EXTENSIONS = {".pkl", ".pickle", ".pt", ".pth", ".ckpt", ".bin", ".joblib"}
SAFE_TENSOR_EXTENSIONS = {".safetensors"}
EXECUTABLE_EXTENSIONS = {".sh", ".exe", ".bat", ".ps1", ".so", ".dll"}

MAGIC_BYTES = {
    b"\x7fELF": "ELF executable",
    b"MZ": "Windows PE executable",
    b"\xca\xfe\xba\xbe": "Mach-O / Java class (fat binary)",
    b"\xfe\xed\xfa": "Mach-O executable",
}

SECRET_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key", "SECRET01"),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"), "GitHub personal access token", "SECRET02"),
    (re.compile(r"gho_[A-Za-z0-9]{36}"), "GitHub OAuth token", "SECRET02"),
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "API secret key (OpenAI-style)", "SECRET03"),
    (re.compile(r"hf_[A-Za-z0-9]{30,}"), "Hugging Face access token", "SECRET04"),
    (re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"), "Embedded private key", "SECRET05"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "Slack token", "SECRET06"),
]

DANGEROUS_CALL_NAMES = {
    "system": "os.system",
    "popen": "os.popen",
    "eval": "eval",
    "exec": "exec",
    "compile": "compile",
    "load": "pickle.load / torch.load / yaml.load",
    "loads": "pickle.loads / marshal.loads",
}

DANGEROUS_MODULE_CALLS = {
    ("subprocess", "run"),
    ("subprocess", "call"),
    ("subprocess", "Popen"),
    ("subprocess", "check_output"),
    ("os", "system"),
    ("os", "popen"),
    ("pickle", "load"),
    ("pickle", "loads"),
    ("marshal", "loads"),
    ("torch", "load"),  # only unsafe when weights_only is not explicitly True
    ("yaml", "load"),   # unsafe unless Loader=yaml.SafeLoader
}

TEMPLATE_INJECTION_PATTERNS = [
    re.compile(r"Template\s*\(.*\)\.render\("),
    re.compile(r"Environment\s*\(.*\)\.from_string\("),
    re.compile(r"jinja2\.Template"),
    re.compile(r"\{\{.*\|.*safe.*\}\}"),  # unsafe Jinja "| safe" filter on user input
]

REMOTE_DOWNLOAD_PATTERNS = [
    re.compile(r"urllib\.request\.urlopen\("),
    re.compile(r"requests\.get\("),
    re.compile(r"urlretrieve\("),
    re.compile(r"os\.system\([\"']\s*(curl|wget)"),
]

UNPINNED_GIT_DEP = re.compile(r"git\+(https?|git)://[^@\s]+(?!@)")


# --------------------------------------------------------------------------
# File-level checks (no source parsing required)
# --------------------------------------------------------------------------

def check_pickle_like_files(rel_path: str) -> List[Finding]:
    ext = Path(rel_path).suffix.lower()
    if ext in PICKLE_LIKE_EXTENSIONS:
        return [Finding(
            severity="medium",
            category="pickle_like_artifact",
            rule_id="FILE001",
            message=(
                f"File uses a pickle-based serialization format ({ext}). "
                "These can execute arbitrary code on load. Prefer .safetensors."
            ),
            file=rel_path,
        )]
    return []


def check_unexpected_executable(rel_path: str, head_bytes: bytes) -> List[Finding]:
    findings = []
    ext = Path(rel_path).suffix.lower()
    if ext in EXECUTABLE_EXTENSIONS:
        findings.append(Finding(
            severity="high",
            category="unexpected_executable",
            rule_id="FILE002",
            message=f"Executable/script file present in dataset repo ({ext}).",
            file=rel_path,
        ))
        return findings
    for magic, label in MAGIC_BYTES.items():
        if head_bytes.startswith(magic):
            findings.append(Finding(
                severity="critical",
                category="unexpected_executable",
                rule_id="FILE002",
                message=f"File has no executable extension but matches {label} magic bytes.",
                file=rel_path,
            ))
    return findings


def check_secrets(rel_path: str, text: str) -> List[Finding]:
    findings = []
    for pattern, label, rule_id in SECRET_PATTERNS:
        m = pattern.search(text)
        if m:
            findings.append(Finding(
                severity="critical",
                category="exposed_secret",
                rule_id=rule_id,
                message=f"Possible {label} found in file contents.",
                file=rel_path,
                evidence=_redact(m.group(0)),
            ))
    return findings


def _redact(secret: str) -> str:
    if len(secret) <= 8:
        return "*" * len(secret)
    return secret[:4] + "…redacted…" + secret[-4:]


# --------------------------------------------------------------------------
# Source-level checks (Python loader scripts, config files)
# --------------------------------------------------------------------------

def check_template_injection(rel_path: str, text: str) -> List[Finding]:
    findings = []
    for pattern in TEMPLATE_INJECTION_PATTERNS:
        m = pattern.search(text)
        if m:
            line = text[: m.start()].count("\n") + 1
            findings.append(Finding(
                severity="high",
                category="template_injection",
                rule_id="CODE003",
                message="Dataset config/loader renders a template with data that may be attacker-controlled.",
                file=rel_path,
                line=line,
            ))
    return findings


def check_remote_download(rel_path: str, text: str) -> List[Finding]:
    findings = []
    for pattern in REMOTE_DOWNLOAD_PATTERNS:
        m = pattern.search(text)
        if m:
            line = text[: m.start()].count("\n") + 1
            findings.append(Finding(
                severity="medium",
                category="unpinned_remote_download",
                rule_id="NET001",
                message="Loader downloads content from a remote URL at runtime; verify it is pinned/hash-checked.",
                file=rel_path,
                line=line,
            ))
    return findings


def check_unsafe_dependency_install(rel_path: str, text: str) -> List[Finding]:
    findings = []
    if UNPINNED_GIT_DEP.search(text):
        findings.append(Finding(
            severity="medium",
            category="unsafe_dependency",
            rule_id="DEP001",
            message="Unpinned git dependency (no @commit/tag) can silently change code after review.",
            file=rel_path,
        ))
    if re.search(r"pip\s+install", text) and rel_path.endswith((".py",)):
        findings.append(Finding(
            severity="low",
            category="unsafe_dependency",
            rule_id="DEP002",
            message="Loader script invokes pip install at runtime.",
            file=rel_path,
        ))
    return findings


def check_dangerous_calls_ast(rel_path: str, text: str) -> List[Finding]:
    """AST-based check for dangerous calls in Python source.

    Falls back silently if the file doesn't parse (e.g. Python 2, or not
    actually Python despite the .py extension) -- we don't want a parse
    error to crash the whole scan.
    """
    findings: List[Finding] = []
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return findings

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        module_attr = _resolve_call(func)
        if module_attr is None:
            continue
        module, attr = module_attr

        if (module, attr) in DANGEROUS_MODULE_CALLS:
            severity = "critical" if module in ("subprocess", "os") else "high"

            # torch.load / yaml.load are only dangerous without safe options
            if module == "torch" and attr == "load" and _has_kwarg(node, "weights_only", True):
                continue
            if module == "yaml" and attr == "load" and _has_safe_loader(node):
                continue

            rule_id = "CODE001" if module in ("subprocess", "os") else "CODE002"
            findings.append(Finding(
                severity=severity,
                category="dangerous_call",
                rule_id=rule_id,
                message=f"Call to {module}.{attr}() can lead to arbitrary code execution.",
                file=rel_path,
                line=getattr(node, "lineno", None),
            ))
        elif isinstance(func, ast.Name) and func.id in ("eval", "exec", "compile", "__import__"):
            findings.append(Finding(
                severity="critical",
                category="dangerous_call",
                rule_id="CODE004",
                message=f"Call to builtin {func.id}() can execute arbitrary code.",
                file=rel_path,
                line=getattr(node, "lineno", None),
            ))
    return findings


def _resolve_call(func_node) -> tuple[str, str] | None:
    """Return (module, attr) for calls like subprocess.run(...) or os.system(...)."""
    if isinstance(func_node, ast.Attribute) and isinstance(func_node.value, ast.Name):
        return (func_node.value.id, func_node.attr)
    return None


def _has_kwarg(call_node: ast.Call, name: str, expected) -> bool:
    for kw in call_node.keywords:
        if kw.arg == name and isinstance(kw.value, ast.Constant):
            return kw.value.value == expected
    return False


def _has_safe_loader(call_node: ast.Call) -> bool:
    for kw in call_node.keywords:
        if kw.arg == "Loader" and isinstance(kw.value, ast.Attribute):
            return "Safe" in kw.value.attr
    return False


# --------------------------------------------------------------------------
# Entry point used by the scanner: run every applicable rule on one file
# --------------------------------------------------------------------------

TEXT_SCANNABLE_EXTENSIONS = {".py", ".json", ".yaml", ".yml", ".txt", ".cfg", ".ini", ".md"}


def scan_file(rel_path: str, absolute_path: Path) -> List[Finding]:
    findings: List[Finding] = []
    findings.extend(check_pickle_like_files(rel_path))

    try:
        with open(absolute_path, "rb") as fh:
            head = fh.read(16)
    except OSError:
        return findings
    findings.extend(check_unexpected_executable(rel_path, head))

    ext = Path(rel_path).suffix.lower()
    if ext in TEXT_SCANNABLE_EXTENSIONS:
        try:
            text = absolute_path.read_text(errors="ignore")
        except OSError:
            return findings

        findings.extend(check_secrets(rel_path, text))
        findings.extend(check_template_injection(rel_path, text))
        findings.extend(check_remote_download(rel_path, text))
        findings.extend(check_unsafe_dependency_install(rel_path, text))
        if ext == ".py":
            findings.extend(check_dangerous_calls_ast(rel_path, text))

    return findings
