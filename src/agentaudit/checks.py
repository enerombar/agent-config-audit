"""Security checks. Each check takes a parsed config and yields Findings."""

from __future__ import annotations

import math
import re
from collections.abc import Iterator
from urllib.parse import urlparse

from .loader import LoadedConfig
from .model import Finding, ServerConfig, Severity

# --- secrets -----------------------------------------------------------------

SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("Anthropic API key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("OpenAI API key", re.compile(r"sk-(?:proj-)?[A-Za-z0-9_\-]{20,}")),
    ("GitHub token", re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}")),
    ("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("Slack token", re.compile(r"xox[abposr]-[A-Za-z0-9\-]{10,}")),
    ("Stripe secret key", re.compile(r"(?:sk|rk)_live_[A-Za-z0-9]{20,}")),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
]

SECRET_NAME_HINT = re.compile(r"(key|token|secret|passw(or)?d|pwd|auth|credential|bearer)", re.I)

# Values that point somewhere else instead of holding the secret.
INDIRECT_VALUE = re.compile(r"^\s*(\$\{[^}]+\}|\$[A-Z_][A-Z0-9_]*|\{\{[^}]+\}\}|<[^>]+>|op://|env:|\$\{input:)", re.I)
PLACEHOLDER = re.compile(r"^(your[-_ ]|xxx|changeme|replace|todo|example|<|\.\.\.)", re.I)


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in counts.values())


def _looks_like_secret(name: str, value: str) -> str | None:
    if not value or INDIRECT_VALUE.match(value) or PLACEHOLDER.match(value):
        return None
    for label, pattern in SECRET_PATTERNS:
        if pattern.search(value):
            return label
    token = value.split()[-1]  # handles "Bearer <token>"
    if SECRET_NAME_HINT.search(name) and len(token) >= 16 and _entropy(token) >= 3.5:
        return "high-entropy value in a secret-named field"
    return None


def check_hardcoded_secrets(cfg: LoadedConfig) -> Iterator[Finding]:
    for s in cfg.servers:
        for bucket, mapping in (("env", s.env), ("headers", s.headers)):
            for key, value in mapping.items():
                kind = _looks_like_secret(key, value)
                if kind:
                    yield Finding(
                        rule="AC001-hardcoded-secret",
                        severity=Severity.HIGH,
                        file=s.file,
                        location=f"{s.path}.{bucket}.{key}",
                        message=f"Server '{s.name}' has a hardcoded credential ({kind}).",
                        remediation="Reference an environment variable (e.g. ${VAR}) or a secret "
                        "manager instead of storing the value in the config file.",
                    )
        for i, arg in enumerate(s.args):
            for label, pattern in SECRET_PATTERNS:
                if pattern.search(arg):
                    yield Finding(
                        rule="AC001-hardcoded-secret",
                        severity=Severity.HIGH,
                        file=s.file,
                        location=f"{s.path}.args[{i}]",
                        message=f"Server '{s.name}' passes a credential ({label}) as a command-line "
                        "argument; it is visible in process listings.",
                        remediation="Pass credentials through env vars, not argv.",
                    )
                    break


# --- supply chain -------------------------------------------------------------

RUNNERS = {"npx", "bunx", "pnpx", "uvx", "pipx"}
PINNED = re.compile(r"(@[\w.\-]+/)?[\w.\-]+@\d[\w.\-+]*$|==\d")


def _package_arg(args: list[str]) -> tuple[int, str] | None:
    skip_next = False
    for i, a in enumerate(args):
        if skip_next:
            skip_next = False
            continue
        if a in ("-p", "--package", "--from", "--with"):
            skip_next = True
            continue
        if a.startswith("-"):
            continue
        return i, a
    return None


def check_unpinned_packages(cfg: LoadedConfig) -> Iterator[Finding]:
    for s in cfg.servers:
        if not s.command:
            continue
        runner = s.command.replace("\\", "/").rsplit("/", 1)[-1].removesuffix(".cmd").removesuffix(".exe")
        if runner not in RUNNERS:
            continue
        pkg = _package_arg(s.args)
        if pkg is None:
            continue
        i, name = pkg
        if name.endswith("@latest") or not PINNED.search(name):
            yield Finding(
                rule="AC002-unpinned-package",
                severity=Severity.MEDIUM,
                file=s.file,
                location=f"{s.path}.args[{i}]",
                message=f"Server '{s.name}' runs '{name}' via {runner} without a pinned version; "
                "every launch can pull new, unreviewed code.",
                remediation=f"Pin an exact version, e.g. '{name.removesuffix('@latest')}@1.2.3'.",
            )
        if runner in ("npx", "pnpx", "bunx") and any(a in ("-y", "--yes") for a in s.args):
            yield Finding(
                rule="AC003-auto-install",
                severity=Severity.LOW,
                file=s.file,
                location=f"{s.path}.args",
                message=f"Server '{s.name}' uses '{runner} -y', installing packages without a prompt.",
                remediation="Install the server as a pinned dependency, or at least pin the version.",
            )


# --- filesystem / execution scope ----------------------------------------------

BROAD_PATHS = {"/", "~", "~/", "$HOME", "${HOME}", "/home", "/Users", "/root", "C:\\", "C:/", "C:\\Users", "%USERPROFILE%"}
SHELLS = {"bash", "sh", "zsh", "fish", "cmd", "powershell", "pwsh"}
DANGEROUS_SERVER_HINT = re.compile(r"(shell|terminal|exec|command|cmd|bash|ssh|desktop-commander)", re.I)


def check_broad_filesystem(cfg: LoadedConfig) -> Iterator[Finding]:
    for s in cfg.servers:
        if "filesystem" not in " ".join([s.name, *s.args]).lower():
            continue
        for i, a in enumerate(s.args):
            if a.rstrip("/\\") in {p.rstrip("/\\") for p in BROAD_PATHS} or a in BROAD_PATHS:
                yield Finding(
                    rule="AC004-broad-filesystem",
                    severity=Severity.HIGH,
                    file=s.file,
                    location=f"{s.path}.args[{i}]",
                    message=f"Filesystem server '{s.name}' is granted '{a}', exposing the whole "
                    "disk or home directory (SSH keys, browser profiles, .env files) to the agent.",
                    remediation="Limit allowed directories to the project folders the agent needs.",
                )


def check_shell_access(cfg: LoadedConfig) -> Iterator[Finding]:
    for s in cfg.servers:
        cmd = (s.command or "").replace("\\", "/").rsplit("/", 1)[-1].lower().removesuffix(".exe")
        runs_shell = cmd in SHELLS and any(a in ("-c", "/c", "-Command") for a in s.args)
        named_shell = bool(DANGEROUS_SERVER_HINT.search(s.name)) or any(
            DANGEROUS_SERVER_HINT.search(a) for a in s.args if not a.startswith("-")
        )
        if not (runs_shell or named_shell):
            continue
        sev = Severity.CRITICAL if s.auto_approve else Severity.MEDIUM
        yield Finding(
            rule="AC005-shell-execution",
            severity=sev,
            file=s.file,
            location=s.path,
            message=f"Server '{s.name}' appears to provide arbitrary command execution"
            + (" and its tools are auto-approved." if s.auto_approve else "."),
            remediation="Keep human confirmation on for execution tools and run them in a "
            "container or sandbox with no access to credentials.",
        )


# --- auto approval -------------------------------------------------------------

DANGEROUS_TOOL = re.compile(
    r"(write|edit|delete|remove|rm|exec|run|shell|command|bash|push|merge|deploy|send|post|"
    r"create|update|drop|sql|query|transfer|pay|fetch|navigate|click)",
    re.I,
)


def check_auto_approve(cfg: LoadedConfig) -> Iterator[Finding]:
    for s in cfg.servers:
        if not s.auto_approve:
            continue
        if "*" in s.auto_approve:
            yield Finding(
                rule="AC006-auto-approve",
                severity=Severity.HIGH,
                file=s.file,
                location=s.path,
                message=f"All tools of server '{s.name}' run without user confirmation.",
                remediation="Auto-approve only read-only tools; keep confirmation for side effects.",
            )
            continue
        risky = [t for t in s.auto_approve if DANGEROUS_TOOL.search(t)]
        if risky:
            yield Finding(
                rule="AC006-auto-approve",
                severity=Severity.HIGH,
                file=s.file,
                location=s.path,
                message=f"Server '{s.name}' auto-approves side-effecting tools: {', '.join(risky)}.",
                remediation="Remove write/execute/send tools from the auto-approve list.",
            )


# --- transport -----------------------------------------------------------------

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


def check_transport(cfg: LoadedConfig) -> Iterator[Finding]:
    for s in cfg.servers:
        if not s.url:
            continue
        u = urlparse(s.url)
        if u.scheme in ("http", "ws") and (u.hostname or "") not in LOCAL_HOSTS:
            yield Finding(
                rule="AC007-insecure-transport",
                severity=Severity.HIGH if s.headers else Severity.MEDIUM,
                file=s.file,
                location=f"{s.path}.url",
                message=f"Remote server '{s.name}' uses unencrypted {u.scheme}://"
                + (" while sending auth headers." if s.headers else "."),
                remediation="Use https:// (or wss://) for any non-local MCP server.",
            )
        if u.username or u.password or re.search(r"(^|&)(api[_-]?key|access[_-]?token|token|key|secret)=", u.query or "", re.I):
            yield Finding(
                rule="AC001-hardcoded-secret",
                severity=Severity.HIGH,
                file=s.file,
                location=f"{s.path}.url",
                message=f"Server '{s.name}' embeds a credential in its URL; it will end up in logs.",
                remediation="Send credentials in a header that references an environment variable.",
            )


# --- containers ----------------------------------------------------------------


def check_docker(cfg: LoadedConfig) -> Iterator[Finding]:
    for s in cfg.servers:
        if (s.command or "").rsplit("/", 1)[-1] not in ("docker", "podman"):
            continue
        a = s.args
        joined = " ".join(a)
        if "--privileged" in a:
            yield Finding("AC008-container-escape", Severity.CRITICAL, s.file, f"{s.path}.args",
                          f"Container for '{s.name}' runs with --privileged.",
                          "Drop --privileged; grant only the specific capabilities needed.")
        if re.search(r"(-v|--volume)[ =](/|/var/run/docker\.sock|~|\$HOME|/home|/Users)(:|\s|$)", joined):
            yield Finding("AC008-container-escape", Severity.HIGH, s.file, f"{s.path}.args",
                          f"Container for '{s.name}' mounts the host root, home or Docker socket.",
                          "Mount only the project directory, read-only where possible.")
        if re.search(r"--(network|net)[ =]host", joined):
            yield Finding("AC009-host-network", Severity.LOW, s.file, f"{s.path}.args",
                          f"Container for '{s.name}' shares the host network namespace.",
                          "Use the default bridge network unless host networking is required.")


# --- agent permission settings (Claude Code style) ------------------------------

BROAD_ALLOW = re.compile(r"^(Bash|Write|Edit|WebFetch|mcp__.*)(\(\s*\*?\s*\)|\(\*\*?\)|)$")
RISKY_BASH = re.compile(r"^Bash\((curl|wget|rm|sudo|ssh|scp|git push|npm publish|docker|chmod|python|node|sh|bash)[ :*]", re.I)


def check_permission_rules(cfg: LoadedConfig) -> Iterator[Finding]:
    if cfg.default_mode == "bypassPermissions":
        yield Finding("AC010-permissions", Severity.HIGH, cfg.file, "permissions.defaultMode",
                      "Agent runs with bypassPermissions: every tool call executes without review.",
                      "Use the default mode, or acceptEdits inside a sandboxed workspace only.")
    for i, rule in enumerate(cfg.allow_rules):
        r = rule.strip()
        if BROAD_ALLOW.match(r):
            sev = Severity.HIGH if r.startswith(("Bash", "mcp__")) else Severity.MEDIUM
            yield Finding("AC010-permissions", sev, cfg.file, f"permissions.allow[{i}]",
                          f"Blanket allow rule '{r}' pre-approves every call to that tool.",
                          "Scope allow rules to specific commands or paths.")
        elif RISKY_BASH.match(r):
            yield Finding("AC010-permissions", Severity.MEDIUM, cfg.file, f"permissions.allow[{i}]",
                          f"Allow rule '{r}' pre-approves a command that can exfiltrate data or "
                          "run arbitrary code.",
                          "Keep confirmation for network, deletion and interpreter commands.")


ALL_CHECKS = [
    check_hardcoded_secrets,
    check_unpinned_packages,
    check_broad_filesystem,
    check_shell_access,
    check_auto_approve,
    check_transport,
    check_docker,
    check_permission_rules,
]


def run_all(cfg: LoadedConfig, include_disabled: bool = False) -> list[Finding]:
    if not include_disabled:
        cfg = LoadedConfig(cfg.file, [s for s in cfg.servers if not s.disabled], cfg.allow_rules, cfg.default_mode)
    findings: list[Finding] = []
    for check in ALL_CHECKS:
        findings.extend(check(cfg))
    findings.sort(key=lambda f: (-f.severity, f.file, f.location))
    return findings


def redact(value: str) -> str:
    """Never print a full secret back to the terminal."""
    return value[:4] + "…" if len(value) > 8 else "…"


__all__ = ["run_all", "ALL_CHECKS", "redact", "ServerConfig"]
