# AI Agent Integration

kxn integrates with AI agents via the Model Context Protocol (MCP) or markdown instructions, enabling natural language compliance scanning through your preferred AI assistant.

## Supported Agents

| Agent | Integration | Config Location |
|-------|-------------|-----------------|
| Claude Desktop | MCP server | `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) / `~/.config/claude/claude_desktop_config.json` (Linux) |
| Claude Code | MCP server | `~/.claude/settings.json` |
| Cursor | MCP server | `~/.cursor/mcp.json` |
| Gemini | MCP server | `~/.gemini/settings.json` |
| Windsurf | MCP server | `~/.codeium/windsurf/mcp_config.json` |
| OpenCode | MCP server | `~/.config/opencode/opencode.json` |
| Codex | MCP (TOML) | `~/.codex/config.toml` |
| Cline | Markdown instructions | `.clinerules` in project root |
| Copilot | Markdown instructions | `.github/copilot-instructions.md` |

## Setup

### Auto-configure a specific agent

```bash
kxn init --client <agent-name>
```

Where `<agent-name>` is one of: `claude-desktop`, `claude-code`, `cursor`, `gemini`, `windsurf`, `opencode`, `codex`, `cline`, `copilot`.

### Auto-configure all detected agents

```bash
kxn init --mcp-only
```

This detects which agents are installed and configures all of them.

### Uninstall

```bash
kxn init --uninstall
```

Removes kxn MCP configuration from all configured agents.

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
      "args": ["serve", "--mcp", "--rules", "./rules"]
    }
  }
}
```

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
