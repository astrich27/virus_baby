"""Общие типы результатов и событий для модулей VirusWall."""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class Finding:
    source: str
    name: str
    risk: str
    description: str
    rule: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    path: str
    name: str
    sha256: str | None
    status: str
    scanned_at: str
    elapsed_seconds: float
    threat_name: str | None = None
    classification: str | None = None
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SecurityEvent:
    event_type: str
    source: str
    target: str
    threat_name: str
    severity: str
    action: str = "none"
    outcome: str = "pending"
    timestamp: str = field(default_factory=now_utc)
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
