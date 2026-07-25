import json
from pathlib import Path


def load_examples(data_dir: str):
    """Load JSON lines from a local data directory. No network, no exec."""
    examples = []
    for path in sorted(Path(data_dir).glob("*.jsonl")):
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    examples.append(json.loads(line))
    return examples
