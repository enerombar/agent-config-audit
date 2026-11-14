# agent-config-audit

Static security audit for **MCP server configurations** and **AI agent permission settings**.

AI agents are only as safe as the tools they are wired to. A single line in an MCP config
can hand an agent your whole disk, a shell with no confirmation, or a production token stored
in plain text. Prompt injection turns any of those into an exploit path: a malicious web page
or document the agent reads can steer it into using whatever it was given.

`agent-config-audit` reads the config files your agent clients already use and flags the
settings that widen that attack surface. It is read-only, has no dependencies and never
connects to the servers it inspects.

## What it checks

| Rule | Severity | Finds |
|------|----------|-------|
| `AC001-hardcoded-secret` | high | API keys, tokens, private keys or JWTs written into `env`, `headers`, `args` or URLs instead of referenced from the environment |
| `AC002-unpinned-package` | medium | `npx` / `uvx` / `bunx` servers without an exact version (or `@latest`) – a supply-chain risk on every launch |
| `AC003-auto-install` | low | `npx -y` installing packages without a prompt |
| `AC004-broad-filesystem` | high | filesystem servers granted `/`, `~`, `/Users`, `C:\` … |
| `AC005-shell-execution` | medium → critical | servers that provide arbitrary command execution; critical when their tools are auto-approved |
| `AC006-auto-approve` | high | `autoApprove` / `alwaysAllow` / `trust` on write, execute, send or network tools |
| `AC007-insecure-transport` | medium / high | remote servers over `http://` or `ws://` (high when auth headers are sent) |
| `AC008-container-escape` | high / critical | Docker-based servers with `--privileged`, or mounting `/`, `$HOME` or the Docker socket |
| `AC009-host-network` | low | Docker-based servers on `--network host` |
| `AC010-permissions` | medium / high | Claude Code `bypassPermissions` mode and blanket allow rules such as `Bash` or `Bash(curl:*)` |

Supported formats: Claude Desktop (`claude_desktop_config.json`), Claude Code (`.mcp.json`,
`.claude/settings.json`), Cursor (`.cursor/mcp.json`), Windsurf (`mcp_config.json`),
VS Code (`.vscode/mcp.json`, `settings.json`) and any file using the `mcpServers` shape.

## Usage

```bash
pip install git+https://github.com/enerombar/agent-config-audit
agent-config-audit                       # scan the current directory recursively
agent-config-audit ~/Library/Application\ Support/Claude/claude_desktop_config.json
agent-config-audit . -f json             # machine-readable output
agent-config-audit . -f sarif > out.sarif  # GitHub code scanning
agent-config-audit . --fail-on medium    # CI gate
```

Exit codes: `0` no findings at or above `--fail-on` (default `high`), `1` findings at or above
it, `2` no file could be parsed.

Example output on a deliberately bad config:

```
[CRITICAL] AC005-shell-execution  demo.json :: mcpServers.terminal
    Server 'terminal' appears to provide arbitrary command execution and its tools are auto-approved.
[HIGH] AC004-broad-filesystem  demo.json :: mcpServers.filesystem.args[2]
    Filesystem server 'filesystem' is granted '/', exposing the whole disk or home directory ...
[HIGH] AC007-insecure-transport  demo.json :: mcpServers.remote.url
    Remote server 'remote' uses unencrypted http:// while sending auth headers.
```

### In CI

```yaml
- run: pip install git+https://github.com/enerombar/agent-config-audit
- run: agent-config-audit . -f sarif > agent-audit.sarif || true
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: agent-audit.sarif }
```

## Limitations

- Heuristic: shell detection relies on command names and server names, and secret detection
  on known token formats plus entropy in secret-named fields. Expect some false positives and
  negatives; treat findings as review prompts.
- Static only: it does not inspect what each MCP server's tools actually do at runtime.
- Secret values are never printed; only their location is reported.

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT
