"""Load MCP server definitions and agent permission settings from config files.

Supported shapes (all JSON):

* ``{"mcpServers": {...}}`` – Claude Desktop, Claude Code ``.mcp.json``, Cursor,
  Windsurf and most other MCP clients.
* ``{"servers": {...}}`` – VS Code ``.vscode/mcp.json``.
* ``{"mcp": {"servers": {...}}}`` – VS Code ``settings.json``.
* ``{"permissions": {"allow": [...]}}`` – Claude Code ``settings.json``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .model import ServerConfig

KNOWN_FILENAMES = {
    "claude_desktop_config.json",
    ".mcp.json",
    "mcp.json",
    "settings.json",
    "settings.local.json",
    "mcp_config.json",
}

AUTO_APPROVE_KEYS = ("autoApprove", "alwaysAllow", "auto_approve", "trust")


class ConfigError(Exception):
    pass


@dataclass
class LoadedConfig:
    file: str
    servers: list[ServerConfig] = field(default_factory=list)
    allow_rules: list[str] = field(default_factory=list)
    default_mode: str | None = None


def _str_list(value) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value]
    return []


def _str_dict(value) -> dict[str, str]:
    if isinstance(value, dict):
        return {str(k): "" if v is None else str(v) for k, v in value.items()}
    return {}


def _parse_servers(block: dict, file: str, prefix: str) -> list[ServerConfig]:
    servers = []
    for name, entry in block.items():
        if not isinstance(entry, dict):
            continue
        auto = []
        for key in AUTO_APPROVE_KEYS:
            val = entry.get(key)
            if val is True:
                auto = ["*"]
            elif isinstance(val, list):
                auto.extend(str(v) for v in val)
        servers.append(
            ServerConfig(
                name=str(name),
                file=file,
                path=f"{prefix}.{name}",
                command=str(entry["command"]) if entry.get("command") else None,
                args=_str_list(entry.get("args")),
                env=_str_dict(entry.get("env")),
                url=str(entry.get("url") or entry.get("serverUrl") or "") or None,
                headers=_str_dict(entry.get("headers")),
                auto_approve=auto,
                disabled=bool(entry.get("disabled", False)),
            )
        )
    return servers


def load_file(path: Path) -> LoadedConfig:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{path}: invalid JSON ({exc.msg}, line {exc.lineno})") from exc
    except OSError as exc:
        raise ConfigError(f"{path}: cannot read ({exc.strerror})") from exc

    file = str(path)
    loaded = LoadedConfig(file=file)
    if not isinstance(data, dict):
        return loaded

    if isinstance(data.get("mcpServers"), dict):
        loaded.servers += _parse_servers(data["mcpServers"], file, "mcpServers")
    if isinstance(data.get("servers"), dict):
        loaded.servers += _parse_servers(data["servers"], file, "servers")
    mcp = data.get("mcp")
    if isinstance(mcp, dict) and isinstance(mcp.get("servers"), dict):
        loaded.servers += _parse_servers(mcp["servers"], file, "mcp.servers")

    perms = data.get("permissions")
    if isinstance(perms, dict):
        loaded.allow_rules = _str_list(perms.get("allow"))
        mode = perms.get("defaultMode")
        loaded.default_mode = str(mode) if mode else None

    return loaded


def discover(paths: list[Path]) -> list[Path]:
    """Expand directories into the config files we know how to read."""
    found: list[Path] = []
    for p in paths:
        if p.is_file():
            found.append(p)
        elif p.is_dir():
            for candidate in sorted(p.rglob("*.json")):
                if candidate.name in KNOWN_FILENAMES and "node_modules" not in candidate.parts:
                    found.append(candidate)
    # stable order, no duplicates
    seen, unique = set(), []
    for f in found:
        key = f.resolve()
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique
