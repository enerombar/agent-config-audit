from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            valid = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"unknown severity {value!r} (valid: {valid})") from exc


@dataclass
class Finding:
    rule: str
    severity: Severity
    file: str
    location: str  # e.g. "mcpServers.filesystem.args[2]"
    message: str
    remediation: str = ""

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity.name.lower(),
            "file": self.file,
            "location": self.location,
            "message": self.message,
            "remediation": self.remediation,
        }


@dataclass
class ServerConfig:
    """One MCP server entry, normalised across client config formats."""

    name: str
    file: str
    path: str  # JSON path to the entry, e.g. "mcpServers.github"
    command: str | None = None
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    url: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    auto_approve: list[str] = field(default_factory=list)
    disabled: bool = False
