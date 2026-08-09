# Rules reference

The scanner performs static inspection only. A finding is an indicator for
review, not proof of malicious intent; a clean result is not a safety
guarantee.

| Rule | Coverage | Key limitations |
| --- | --- | --- |
| `CODE001` | `subprocess` and `os` execution calls, including direct import aliases | Dynamic dispatch and assignments are not resolved. |
| `CODE002` | Unsafe pickle, Torch, marshal, and YAML load calls | Dynamic dispatch and non-Python loaders are not analysed. |
| `CODE003` | Jinja template construction/rendering tied to config or untrusted input | Flow analysis is intra-file and intentionally conservative. |
| `CODE004` | Direct dynamic-execution builtins | Indirect aliases and dynamic dispatch are not resolved. |
| `NET001` | Common runtime download calls | Custom clients and obfuscated code may be missed. |
| `SECRET01-07` | Known token/private-key formats plus sensitive-variable high-entropy values | Entropy detection is scoped to reduce false positives; `hfguard: allow-secret` is an explicit inline exception. |
| `FILE001-002` | Pickle-like files and executable signatures | File extension and magic-byte checks are not malware analysis. |
| `DEP001-002` | Unpinned Git/direct-URL dependencies and runtime installs | Complex requirements indirection and lockfiles are not evaluated. |
| `SCAN001` | Skipped symlinks and paths outside the scan root | It is informational and does not affect risk score. |

Detected secret evidence is redacted. See `docs/TODO.md` for planned rule
coverage improvements and known limitations being addressed.
