"""Stable evidence contract. Observations describe a source, not ground truth."""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Evidence:
    source: str
    status: str
    target: str
    endpoint: str
    collected_at: str = field(default_factory=now)
    observations: dict[str, Any] = field(default_factory=dict)
    message: str = ""
    verification: str = (
        "Analyst verification required; source records may be stale or incomplete."
    )

    def to_dict(self):
        return asdict(self)
