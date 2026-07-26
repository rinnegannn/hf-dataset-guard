# Rules reference

The scanner performs static inspection only. A finding is an indicator for
review, not proof of malicious intent; a clean result is not a safety
guarantee.

| Rule | Coverage | Key limitations |
| --- | --- | --- |
| `CODE001` | Direct `subprocess` and `os` execution calls | Import aliases are not resolved yet. |
| `CODE002` | Unsafe pickle, Torch, marshal, and YAML load calls | Dynamic dispatch and non-Python loaders are not analysed. |
| `CODE003` | Common Jinja template rendering patterns | It is pattern-based and may over-report safe template use. |
| `CODE004` | Direct dynamic-execution builtins | Indirect aliases are not resolved yet. |
| `NET001` | Common runtime download calls | Custom clients and obfuscated code may be missed. |
| `SECRET01-06` | Known token and private-key formats | Entropy detection and allowlists are planned. |
| `FILE001-002` | Pickle-like files and executable signatures | File extension and magic-byte checks are not malware analysis. |
| `DEP001-002` | Unpinned Git dependencies and runtime installs | Requirements parsing is intentionally limited. |
| `SCAN001` | Skipped symlinks and paths outside the scan root | It is informational and does not affect risk score. |

Detected secret evidence is redacted. See `docs/TODO.md` for planned rule
coverage improvements and known limitations being addressed.
