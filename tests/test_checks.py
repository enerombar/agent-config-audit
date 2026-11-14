import json

import pytest

from agentaudit.checks import run_all
from agentaudit.cli import main
from agentaudit.loader import discover, load_file
from agentaudit.model import Severity

# Fake credentials are assembled at runtime so no secret-shaped string is committed.
FAKE_GH = "ghp" + "_" + "A1b2C3d4" * 5
FAKE_OPENAI = "sk" + "-proj-" + "Zz9Yy8Xx7" * 4


def write(tmp_path, data, name=".mcp.json"):
    p = tmp_path / name
    p.write_text(json.dumps(data))
    return p


def rules(findings):
    return [f.rule for f in findings]


def scan(tmp_path, data, **kw):
    return run_all(load_file(write(tmp_path, data)), **kw)


def test_clean_config_has_no_findings(tmp_path):
    cfg = {"mcpServers": {"github": {
        "command": "npx",
        "args": ["@modelcontextprotocol/server-github@2025.4.8"],
        "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "${GITHUB_TOKEN}"},
    }}}
    assert scan(tmp_path, cfg) == []


def test_hardcoded_secret_in_env(tmp_path):
    cfg = {"mcpServers": {"github": {"command": "node", "args": ["server.js"],
                                     "env": {"GITHUB_TOKEN": FAKE_GH}}}}
    f = scan(tmp_path, cfg)
    assert rules(f) == ["AC001-hardcoded-secret"]
    assert f[0].severity == Severity.HIGH
    assert f[0].location == "mcpServers.github.env.GITHUB_TOKEN"


def test_secret_in_header_and_argv(tmp_path):
    cfg = {"mcpServers": {
        "remote": {"url": "https://mcp.example.com", "headers": {"Authorization": "Bearer " + FAKE_OPENAI}},
        "cli": {"command": "python", "args": ["srv.py", "--key", FAKE_OPENAI]},
    }}
    assert rules(scan(tmp_path, cfg)).count("AC001-hardcoded-secret") == 2


@pytest.mark.parametrize("value", ["${API_KEY}", "$API_KEY", "your-api-key-here", "<token>", "op://vault/item"])
def test_secret_references_are_not_flagged(tmp_path, value):
    cfg = {"mcpServers": {"s": {"command": "node", "args": ["x.js"], "env": {"API_KEY": value}}}}
    assert scan(tmp_path, cfg) == []


def test_high_entropy_secret_named_field(tmp_path):
    cfg = {"mcpServers": {"s": {"command": "node", "args": ["x.js"],
                                "env": {"INTERNAL_API_TOKEN": "q8Fz2LpW9xRt4KbN7mVc1HsY"}}}}
    assert rules(scan(tmp_path, cfg)) == ["AC001-hardcoded-secret"]


def test_unpinned_npx_and_auto_install(tmp_path):
    cfg = {"mcpServers": {"fs": {"command": "npx", "args": ["-y", "some-mcp-server"]}}}
    assert set(rules(scan(tmp_path, cfg))) == {"AC002-unpinned-package", "AC003-auto-install"}


def test_latest_tag_counts_as_unpinned(tmp_path):
    cfg = {"mcpServers": {"x": {"command": "npx", "args": ["@scope/pkg@latest"]}}}
    assert rules(scan(tmp_path, cfg)) == ["AC002-unpinned-package"]


def test_uvx_pinned_with_equals(tmp_path):
    cfg = {"mcpServers": {"x": {"command": "uvx", "args": ["mcp-server-fetch==2025.1.0"]}}}
    assert scan(tmp_path, cfg) == []


@pytest.mark.parametrize("path", ["/", "~", "/Users", "C:\\"])
def test_broad_filesystem_access(tmp_path, path):
    cfg = {"mcpServers": {"filesystem": {"command": "npx",
                                         "args": ["@modelcontextprotocol/server-filesystem@1.0.0", path]}}}
    f = scan(tmp_path, cfg)
    assert "AC004-broad-filesystem" in rules(f)


def test_scoped_filesystem_is_fine(tmp_path):
    cfg = {"mcpServers": {"filesystem": {"command": "npx",
                                         "args": ["@modelcontextprotocol/server-filesystem@1.0.0",
                                                  "/Users/me/projects/app"]}}}
    assert scan(tmp_path, cfg) == []


def test_shell_server_with_auto_approve_is_critical(tmp_path):
    cfg = {"mcpServers": {"terminal": {"command": "node", "args": ["term.js"], "autoApprove": ["run_command"]}}}
    f = scan(tmp_path, cfg)
    shell = [x for x in f if x.rule == "AC005-shell-execution"]
    assert shell and shell[0].severity == Severity.CRITICAL
    assert "AC006-auto-approve" in rules(f)


def test_auto_approve_read_only_tools_is_fine(tmp_path):
    cfg = {"mcpServers": {"docs": {"command": "node", "args": ["docs.js"], "alwaysAllow": ["list_pages", "get_page"]}}}
    assert scan(tmp_path, cfg) == []


def test_auto_approve_everything(tmp_path):
    cfg = {"mcpServers": {"docs": {"command": "node", "args": ["docs.js"], "trust": True}}}
    assert rules(scan(tmp_path, cfg)) == ["AC006-auto-approve"]


def test_insecure_remote_transport(tmp_path):
    cfg = {"mcpServers": {
        "remote": {"url": "http://mcp.example.com/sse", "headers": {"X-Client": "a"}},
        "local": {"url": "http://localhost:3000/mcp"},
    }}
    f = scan(tmp_path, cfg)
    assert rules(f) == ["AC007-insecure-transport"]
    assert f[0].severity == Severity.HIGH


def test_credential_in_url_query(tmp_path):
    cfg = {"mcpServers": {"r": {"url": "https://mcp.example.com/sse?api_key=abc123"}}}
    assert rules(scan(tmp_path, cfg)) == ["AC001-hardcoded-secret"]


def test_docker_privileged_and_socket(tmp_path):
    cfg = {"mcpServers": {"d": {"command": "docker", "args": [
        "run", "--privileged", "-v", "/var/run/docker.sock:/var/run/docker.sock", "--network=host", "img:1.0"]}}}
    f = rules(scan(tmp_path, cfg))
    assert f.count("AC008-container-escape") == 2
    assert "AC009-host-network" in f


def test_claude_code_permissions(tmp_path):
    cfg = {"permissions": {"defaultMode": "bypassPermissions",
                           "allow": ["Bash", "Bash(curl:*)", "Bash(npm run test:*)", "Read(./src/**)"]}}
    f = run_all(load_file(write(tmp_path, cfg, "settings.json")))
    locs = [x.location for x in f]
    assert "permissions.defaultMode" in locs
    assert "permissions.allow[0]" in locs
    assert "permissions.allow[1]" in locs
    assert "permissions.allow[2]" not in locs
    assert "permissions.allow[3]" not in locs


def test_vscode_formats(tmp_path):
    a = write(tmp_path, {"servers": {"x": {"command": "npx", "args": ["pkg"]}}}, "mcp.json")
    sub = tmp_path / "sub"
    sub.mkdir()
    b = write(sub, {"mcp": {"servers": {"y": {"command": "npx", "args": ["pkg2"]}}}}, "settings.json")
    assert rules(run_all(load_file(a))) == ["AC002-unpinned-package"]
    assert rules(run_all(load_file(b))) == ["AC002-unpinned-package"]


def test_disabled_servers_skipped_by_default(tmp_path):
    cfg = {"mcpServers": {"x": {"command": "npx", "args": ["pkg"], "disabled": True}}}
    assert scan(tmp_path, cfg) == []
    assert scan(tmp_path, cfg, include_disabled=True) != []


def test_discover_finds_known_files_only(tmp_path):
    write(tmp_path, {"mcpServers": {}})
    write(tmp_path, {"a": 1}, "package.json")
    nm = tmp_path / "node_modules"
    nm.mkdir()
    write(nm, {"mcpServers": {}})
    assert [p.name for p in discover([tmp_path])] == [".mcp.json"]


def test_cli_exit_codes_and_json(tmp_path, capsys):
    write(tmp_path, {"mcpServers": {"x": {"command": "npx", "args": ["pkg"]}}})
    assert main([str(tmp_path), "--fail-on", "high", "--no-color"]) == 0
    capsys.readouterr()
    assert main([str(tmp_path), "--fail-on", "medium", "-f", "json"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data[0]["rule"] == "AC002-unpinned-package"


def test_cli_sarif(tmp_path, capsys):
    write(tmp_path, {"mcpServers": {"x": {"command": "npx", "args": ["pkg"]}}})
    main([str(tmp_path), "-f", "sarif"])
    sarif = json.loads(capsys.readouterr().out)
    assert sarif["runs"][0]["results"][0]["ruleId"] == "AC002-unpinned-package"


def test_invalid_json_is_reported(tmp_path, capsys):
    (tmp_path / ".mcp.json").write_text("{not json")
    assert main([str(tmp_path)]) == 2
    assert "invalid JSON" in capsys.readouterr().err
