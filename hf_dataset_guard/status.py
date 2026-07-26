from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Literal


@dataclass(frozen=True)
class FileIssue:
    """A remote file that was not fully scanned."""

    file: str
    status: Literal["skipped", "failed", "omitted"]
    reason: str

    def to_dict(self) -> dict:
        return asdict(self)
