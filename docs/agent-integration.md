# AI Agent Integration

kxn integrates with AI agents via the Model Context Protocol (MCP), enabling natural language compliance scanning through your preferred AI assistant.

## Supported Agents

`kxn init` registers the kxn MCP server (`kxn serve --mcp --rules <dir>`) in each agent's own config file. Paths are for Linux; macOS and Windows use the same names under `~/Library/Application Support` and `%APPDATA%` where the agent keeps its config there.

| Agent | `--client` | Config file |
|-------|-----------|-------------|
| Claude Code | `claude-code` | `~/.claude.json` (`$CLAUDE_CONFIG_DIR/.claude.json` when set) |
| Claude Desktop | `claude-desktop` | `~/.config/Claude/claude_desktop_config.json` |
| GitHub Copilot (CLI, and VS Code new setups) | `copilot` | `~/.copilot/mcp-config.json` (`$COPILOT_HOME`) |
| VS Code (profile `mcp.json`) | `vscode` | `~/.config/Code/User/mcp.json` |
| Cursor | `cursor` | `~/.cursor/mcp.json` |
| Gemini CLI | `gemini` | `~/.gemini/settings.json` |
| Codex | `codex` | `~/.codex/config.toml` (`$CODEX_HOME`) |
| Mistral Vibe | `vibe` | `~/.vibe/config.toml` (`$VIBE_HOME`) |
| Factory Droid | `droid` | `~/.factory/mcp.json` |
| Trae | `trae` | `.trae/mcp.json` in the current project (Trae has no user-level file) |
| OpenCode | `opencode` | `~/.config/opencode/opencode.json` (or `.jsonc`) |
| OpenClaw | `openclaw` | `~/.openclaw/openclaw.json` (`$OPENCLAW_CONFIG_PATH`) |
| Pi | `pi` | `~/.pi/agent/mcp.json` (`$PI_CODING_AGENT_DIR`) |
| Oh My Pi | `omp` | `~/.omp/agent/mcp.json` |
| Hermes | `hermes` | `~/.hermes/config.yaml` |
| Windsurf / Devin Desktop | `windsurf` | `~/.config/devin/mcp_config.json`, plus `~/.codeium/windsurf/mcp_config.json` when that folder exists |
| Cline | `cline` | `~/.cline/data/settings/cline_mcp_settings.json` (`$CLINE_DIR`) |
| Roo Code | `roo` | `~/.config/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json` |
| Kilo Code | `kilocode` | `~/.config/kilo/kilo.jsonc` |
| Google Antigravity | `antigravity` | `~/.gemini/config/mcp_config.json` |
| Kimi CLI | `kimi` | `~/.kimi/mcp.json` |

Aliases are accepted: `claude`, `devin`, `roo-code`, `kilo`, `factory`, `oh-my-pi`, `mistral-vibe`, `gemini-cli`, `kimi-cli`, `copilot-cli`, `vs-code`.

## Setup

### Configure every installed agent

```bash
kxn init --mcp-only
```

Without `--client`, `kxn init` configures each agent whose config folder exists and lists the ones it skipped. Other servers and settings in each file are kept, and running it again replaces the kxn entry rather than adding a second one. A JSON file with comments (common for `.jsonc`) is left untouched; kxn prints the entry to paste instead. `--mcp-only` skips installing the binary to `/usr/local/bin/kxn` and points the configs at the binary you are running. `--rules <dir>` (default `./rules`) is resolved to an absolute path before it is written.

### Configure one agent

```bash
kxn init --mcp-only --client cursor
```

`--client` is repeatable and configures the agent even when its folder does not exist yet.

### The kxn skill

`kxn init` also installs the kxn agent skill, [`skills/kxn/SKILL.md`](../skills/kxn/SKILL.md): the URI for each target, reading results as JSON, and showing a dry run before any fix. It goes to `~/.agents/skills/kxn/`, which Copilot, VS Code, Cursor, Gemini CLI, Codex, Vibe, Droid, OpenCode, OpenClaw, Pi, Oh My Pi, Windsurf, Roo Code, Kilo Code and Kimi read, and to the own folder of Claude Code (`~/.claude/skills`), Cline (`~/.cline/skills`), Antigravity (`~/.gemini/config/skills`) and Hermes (`~/.hermes/skills`). A different skill already named `kxn` is left alone. `--no-skill` skips it. Claude Desktop chats take skills through Customize > Skills instead.

Without kxn installed, paste this into the agent:

```text
Install kxn, the open-source compliance scanner, and learn how to use it:
1. Run: curl -fsSL https://raw.githubusercontent.com/kexa-io/kxn/main/install.sh | sh
2. Download https://raw.githubusercontent.com/kexa-io/kxn/main/skills/kxn/SKILL.md
   to ~/.agents/skills/kxn/SKILL.md (Claude Code: ~/.claude/skills/kxn/SKILL.md) and read it.
3. Ask me which target to scan, scan it with kxn and summarise the findings by
   severity. Do not apply any fix without asking me.
```

### Uninstall

```bash
kxn init --uninstall
```

Removes the kxn entry from every agent config above, including the locations older kxn releases wrote to (`~/.claude/settings.json`, `~/.config/claude/claude_desktop_config.json`, `~/.codeium/windsurf/mcp_config.json`), and leaves everything else in those files as it was. It also removes the kxn skill folders it installed and deletes the binary at `--install-path` (default `/usr/local/bin/kxn`) when that file exists.

## MCP Server

kxn exposes an MCP server over stdio transport:

```bash
kxn serve --mcp
```

### MCP Tools (9)

| Tool | Description |
|------|-------------|
| `kxn_list_providers` | List configured providers and their capabilities |
| `kxn_list_resource_types` | Discover resource types for a given provider |
| `kxn_list_rules` | Parse and list all available TOML rules |
| `kxn_list_targets` | List configured scan targets from kxn.toml |
| `kxn_provider_schema` | Get Terraform provider schema (resource types, attributes) |
| `kxn_gather` | Collect resources from a provider (no rule evaluation) |
| `kxn_scan` | Full scan: gather resources + evaluate rules, returns violations |
| `kxn_check_resource` | Evaluate arbitrary JSON against conditions (zero infrastructure) |
| `kxn_remediate` | List or apply remediations for violations |

### Example: MCP config for Claude Desktop (macOS)

```json
{
  "mcpServers": {
    "kxn": {
      "command": "kxn",
      "args": ["serve", "--mcp", "--rules", "/Users/me/Library/Caches/kxn/rules"]
    }
  }
}
```

Use an absolute `--rules` path: the MCP client starts kxn from its own working directory, so a relative path such as `./rules` usually points nowhere. (`kxn rules pull` downloads the community rules to `~/.cache/kxn/rules` on Linux, `~/Library/Caches/kxn/rules` on macOS.)

## Tool Schema Export

kxn can export tool schemas for use with non-MCP agent frameworks:

```bash
# OpenAI function-calling format (default)
kxn tools

# Anthropic tool format
kxn tools -f anthropic

# Human-readable summary
kxn tools -f summary
```

### Exported Tools (5)

| Tool | Description |
|------|-------------|
| `kxn_scan` | Full compliance scan of a target |
| `kxn_gather` | Gather resources from a provider |
| `kxn_check` | Check JSON against conditions |
| `kxn_cve_lookup` | Look up CVEs for a package/version |
| `kxn_remediate` | Remediate compliance violations |

## Agent Workflow Examples

### Scanning via MCP (Claude Desktop / Claude Code)

Once configured, interact naturally:

```
User: "Scan my SSH server for CIS compliance"
Agent: calls kxn_scan(target: "ssh")
Agent: "Found 3 violations: root login enabled, weak MACs, ..."
```

### Remediation flow

```
User: "Fix the SSH violations"
Agent: calls kxn_remediate(target: "ssh")           # Step 1: list violations
Agent: "Found 3 remediable violations: ..."
User: "Fix the root login and weak MACs issues"
Agent: calls kxn_remediate(target: "ssh", rules: ["ssh-cis-5.2.10-no-root-login", ...])
Agent: "Applied 2 remediations successfully"
```

### Zero-infrastructure checks

```
User: "Does this config comply with CIS 5.2.10?"
Agent: calls kxn_check_resource(resource: {...}, conditions: [...])
Agent: "The resource passes/fails because..."
```
