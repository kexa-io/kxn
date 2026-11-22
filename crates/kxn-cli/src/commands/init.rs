use anyhow::{Context, Result};
use clap::Args;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

/// Every agent `kxn init` can register the MCP server with, in display order.
const ALL_CLIENTS: &[&str] = &[
    "claude-code",
    "claude-desktop",
    "copilot",
    "vscode",
    "cursor",
    "gemini",
    "codex",
    "vibe",
    "droid",
    "trae",
    "opencode",
    "openclaw",
    "pi",
    "omp",
    "hermes",
    "windsurf",
    "cline",
    "roo",
    "kilocode",
    "antigravity",
    "kimi",
];

/// Other names people type for the same agents.
const ALIASES: &[(&str, &str)] = &[
    ("claude", "claude-code"),
    ("copilot-cli", "copilot"),
    ("vs-code", "vscode"),
    ("gemini-cli", "gemini"),
    ("mistral-vibe", "vibe"),
    ("factory", "droid"),
    ("oh-my-pi", "omp"),
    ("devin", "windsurf"),
    ("devin-desktop", "windsurf"),
    ("roo-code", "roo"),
    ("roocode", "roo"),
    ("kilo", "kilocode"),
    ("kilo-code", "kilocode"),
    ("kimi-cli", "kimi"),
];

#[derive(Args)]
pub struct InitArgs {
    /// Install kxn binary to this path
    #[arg(long, default_value = "/usr/local/bin/kxn")]
    pub install_path: String,

    /// Skip binary installation (just configure MCP)
    #[arg(long)]
    pub mcp_only: bool,

    /// Rules directory for MCP server
    #[arg(long, default_value = "./rules")]
    pub rules: String,

    /// Configure only these agents (repeatable). Without it, kxn configures every agent
    /// it finds installed. Values: claude-code, claude-desktop, copilot, vscode, cursor,
    /// gemini, codex, vibe, droid, trae, opencode, openclaw, pi, omp, hermes, windsurf,
    /// cline, roo, kilocode, antigravity, kimi
    #[arg(long = "client", value_name = "CLIENT")]
    pub clients: Vec<String>,

    /// Uninstall: remove MCP configs and binary
    #[arg(long)]
    pub uninstall: bool,
}

/// How a config file stores the kxn server entry.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Shape {
    /// `{"mcpServers": {"kxn": {"command", "args"}}}`, plus fixed extra fields.
    McpServers(Extra),
    /// VS Code profile `mcp.json`: `{"servers": {"kxn": {"type": "stdio", ...}}}`.
    VsCodeServers,
    /// OpenCode: `{"mcp": {"kxn": {"type": "local", "command": [..], "enabled": true}}}`.
    /// Kilo Code uses the same layout.
    OpenCode,
    /// OpenClaw: `{"mcp": {"servers": {"kxn": {"command", "args"}}}}`.
    OpenClaw,
    /// Codex: TOML table `[mcp_servers.kxn]`.
    CodexToml,
    /// Mistral Vibe: TOML array of tables `[[mcp_servers]]` with `name = "kxn"`.
    VibeToml,
    /// Hermes: YAML map `mcp_servers: { kxn: {command, args} }`.
    HermesYaml,
}

/// Extra fields some `mcpServers` dialects require or recommend.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Extra {
    None,
    /// `"type": "stdio"` (Claude Code, Cursor).
    Stdio,
    /// `"type": "stdio", "disabled": false` (Factory Droid).
    StdioEnabled,
    /// `"type": "local", "tools": ["*"]` (GitHub Copilot CLI).
    CopilotLocal,
    /// `"disabled": false, "autoApprove": []` (Cline).
    Cline,
}

/// Where and how one agent stores its MCP servers.
struct Target {
    /// Files to write. Most agents have one; Windsurf keeps a legacy path too.
    paths: Vec<PathBuf>,
    shape: Shape,
    /// Present when the agent is installed for this user.
    detect: Vec<PathBuf>,
}

pub async fn run(args: InitArgs) -> Result<()> {
    if args.uninstall {
        return uninstall(&args);
    }

    println!("kxn init: setting up the kxn MCP server\n");

    let binary_path = if args.mcp_only {
        std::env::current_exe().context("Cannot find current binary")?
    } else {
        install_binary(&args.install_path).await?
    };
    let binary_str = binary_path.to_string_lossy().to_string();
    let rules_path = resolve_rules_path(&args.rules)?;
    let home = dirs::home_dir().context("No home directory")?;
    let cwd = std::env::current_dir()?;

    let explicit = !args.clients.is_empty();
    let targets: Vec<&str> = if explicit {
        let mut t = Vec::new();
        for c in &args.clients {
            match canonical_client(c) {
                Some(name) => t.push(name),
                None => println!(
                    "  Unknown client '{}'. Available: {}",
                    c,
                    ALL_CLIENTS.join(", ")
                ),
            }
        }
        t
    } else {
        ALL_CLIENTS.to_vec()
    };

    let mut configured = Vec::new();
    let mut not_found = Vec::new();
    for client in targets {
        let target = target_for(client, &home, &cwd);
        if !explicit && !target.detect.iter().any(|p| p.exists()) {
            not_found.push(client);
            continue;
        }
        match configure(client, &target, &binary_str, &rules_path) {
            Ok(paths) => {
                for p in &paths {
                    println!("  {:<15} {}", client, p.display());
                }
                configured.push(client);
            }
            Err(e) => println!("  {:<15} skipped: {:#}", client, e),
        }
    }

    println!("\nkxn is ready.\n");
    println!("  Binary:  {}", binary_str);
    println!("  Rules:   {}", rules_path);
    if configured.is_empty() {
        println!("  MCP:     no agent configured");
    } else {
        println!("  MCP:     {}", configured.join(", "));
    }
    if !not_found.is_empty() {
        println!("  Not installed, skipped: {}", not_found.join(", "));
        println!("  Force one with:  kxn init --client <name>");
    }
    Ok(())
}

fn canonical_client(name: &str) -> Option<&'static str> {
    let name = name.trim().to_lowercase();
    if let Some(c) = ALL_CLIENTS.iter().find(|c| **c == name) {
        return Some(c);
    }
    ALIASES
        .iter()
        .find(|(alias, _)| *alias == name)
        .map(|(_, c)| *c)
}

/// The VS Code user directory (`Code/User`) for this OS.
fn vscode_user_dir(home: &Path) -> PathBuf {
    config_dir(home).join("Code").join("User")
}

/// `~/.config` on Linux, `~/Library/Application Support` on macOS, `%APPDATA%` on Windows.
fn config_dir(home: &Path) -> PathBuf {
    dirs::config_dir().unwrap_or_else(|| home.join(".config"))
}

fn env_dir(var: &str) -> Option<PathBuf> {
    std::env::var_os(var)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

fn target_for(client: &str, home: &Path, cwd: &Path) -> Target {
    let one = |path: PathBuf, shape: Shape, detect: Vec<PathBuf>| Target {
        paths: vec![path],
        shape,
        detect,
    };
    match client {
        "claude-code" => {
            let dir = env_dir("CLAUDE_CONFIG_DIR").unwrap_or_else(|| home.to_path_buf());
            one(
                dir.join(".claude.json"),
                Shape::McpServers(Extra::Stdio),
                vec![dir.join(".claude.json"), home.join(".claude")],
            )
        }
        "claude-desktop" => {
            let dir = config_dir(home).join("Claude");
            one(
                dir.join("claude_desktop_config.json"),
                Shape::McpServers(Extra::None),
                vec![dir],
            )
        }
        "copilot" => {
            let dir = env_dir("COPILOT_HOME").unwrap_or_else(|| home.join(".copilot"));
            one(
                dir.join("mcp-config.json"),
                Shape::McpServers(Extra::CopilotLocal),
                vec![dir],
            )
        }
        "vscode" => {
            let dir = vscode_user_dir(home);
            one(dir.join("mcp.json"), Shape::VsCodeServers, vec![dir])
        }
        "cursor" => one(
            home.join(".cursor/mcp.json"),
            Shape::McpServers(Extra::Stdio),
            vec![home.join(".cursor")],
        ),
        "gemini" => one(
            home.join(".gemini/settings.json"),
            Shape::McpServers(Extra::None),
            vec![home.join(".gemini/settings.json")],
        ),
        "codex" => {
            let dir = env_dir("CODEX_HOME").unwrap_or_else(|| home.join(".codex"));
            one(dir.join("config.toml"), Shape::CodexToml, vec![dir])
        }
        "vibe" => {
            let dir = env_dir("VIBE_HOME").unwrap_or_else(|| home.join(".vibe"));
            one(dir.join("config.toml"), Shape::VibeToml, vec![dir])
        }
        "droid" => one(
            home.join(".factory/mcp.json"),
            Shape::McpServers(Extra::StdioEnabled),
            vec![home.join(".factory")],
        ),
        // Trae documents only a project-level file; it is detected per project.
        "trae" => one(
            cwd.join(".trae/mcp.json"),
            Shape::McpServers(Extra::None),
            vec![cwd.join(".trae")],
        ),
        "opencode" => {
            let dir = config_dir_xdg(home).join("opencode");
            let jsonc = dir.join("opencode.jsonc");
            let path = if jsonc.exists() {
                jsonc
            } else {
                dir.join("opencode.json")
            };
            one(path, Shape::OpenCode, vec![dir])
        }
        "openclaw" => {
            let path = env_dir("OPENCLAW_CONFIG_PATH")
                .unwrap_or_else(|| home.join(".openclaw/openclaw.json"));
            one(path, Shape::OpenClaw, vec![home.join(".openclaw")])
        }
        "pi" => {
            let dir = env_dir("PI_CODING_AGENT_DIR").unwrap_or_else(|| home.join(".pi/agent"));
            one(
                dir.join("mcp.json"),
                Shape::McpServers(Extra::None),
                vec![dir],
            )
        }
        "omp" => one(
            home.join(".omp/agent/mcp.json"),
            Shape::McpServers(Extra::None),
            vec![home.join(".omp")],
        ),
        "hermes" => one(
            home.join(".hermes/config.yaml"),
            Shape::HermesYaml,
            vec![home.join(".hermes")],
        ),
        "windsurf" => {
            // Windsurf became Devin Desktop; current builds read the Devin file, older
            // Windsurf builds the Codeium one. Write both when the legacy folder exists.
            let devin = if cfg!(windows) {
                config_dir(home).join("devin")
            } else {
                config_dir_xdg(home).join("devin")
            };
            let legacy = home.join(".codeium/windsurf");
            let mut paths = vec![devin.join("mcp_config.json")];
            if legacy.exists() {
                paths.push(legacy.join("mcp_config.json"));
            }
            Target {
                paths,
                shape: Shape::McpServers(Extra::None),
                detect: vec![devin, legacy],
            }
        }
        "cline" => {
            let dir = env_dir("CLINE_DIR").unwrap_or_else(|| home.join(".cline"));
            let path = env_dir("CLINE_MCP_SETTINGS_PATH")
                .unwrap_or_else(|| dir.join("data/settings/cline_mcp_settings.json"));
            one(path, Shape::McpServers(Extra::Cline), vec![dir])
        }
        "roo" => {
            let dir = vscode_user_dir(home).join("globalStorage/rooveterinaryinc.roo-cline");
            one(
                dir.join("settings/mcp_settings.json"),
                Shape::McpServers(Extra::None),
                vec![dir],
            )
        }
        "kilocode" => {
            let dir = config_dir_xdg(home).join("kilo");
            one(dir.join("kilo.jsonc"), Shape::OpenCode, vec![dir])
        }
        "antigravity" => one(
            home.join(".gemini/config/mcp_config.json"),
            Shape::McpServers(Extra::None),
            vec![home.join(".gemini/config"), home.join(".gemini/antigravity")],
        ),
        "kimi" => one(
            home.join(".kimi/mcp.json"),
            Shape::McpServers(Extra::None),
            vec![home.join(".kimi")],
        ),
        other => unreachable!("client {other} has no target"),
    }
}

/// `$XDG_CONFIG_HOME` or `~/.config` on every OS: the layout CLI tools use even on macOS.
fn config_dir_xdg(home: &Path) -> PathBuf {
    env_dir("XDG_CONFIG_HOME").unwrap_or_else(|| home.join(".config"))
}

fn configure(client: &str, target: &Target, binary: &str, rules: &str) -> Result<Vec<PathBuf>> {
    // Older kxn releases wrote Claude Code's entry into settings.json, which Claude Code
    // never reads for MCP servers. Clean it up so only the working entry remains.
    if client == "claude-code" {
        if let Some(home) = dirs::home_dir() {
            let legacy = home.join(".claude/settings.json");
            let _ = edit_file(&legacy, |c| remove_entry(Shape::McpServers(Extra::None), c));
        }
    }
    for path in &target.paths {
        let shape = target.shape;
        let content = read_or_empty(path)?;
        let updated = upsert_entry(shape, &content, binary, rules).map_err(|e| {
            anyhow::anyhow!("{}: {:#}{}", path.display(), e, manual_hint(shape, binary, rules))
        })?;
        write_file(path, &updated)?;
    }
    Ok(target.paths.clone())
}

fn read_or_empty(path: &Path) -> Result<String> {
    if path.exists() {
        std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))
    } else {
        Ok(String::new())
    }
}

fn write_file(path: &Path, content: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, content).with_context(|| format!("cannot write {}", path.display()))
}

/// For a JSON file kxn cannot rewrite safely: the entry to paste by hand.
fn manual_hint(shape: Shape, binary: &str, rules: &str) -> String {
    let parent = json_parent(shape);
    if parent.is_empty() {
        return String::new();
    }
    let entry = serde_json::to_string(&json_entry(shape, binary, rules)).unwrap_or_default();
    format!("\n      add under \"{}\":  \"kxn\": {}", parent.join("\" > \""), entry)
}

/// Apply `f` to an existing file; write it back only when `f` changed something.
fn edit_file(path: &Path, f: impl Fn(&str) -> Result<Option<String>>) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let content = std::fs::read_to_string(path)?;
    match f(&content)? {
        Some(updated) => {
            std::fs::write(path, updated)?;
            Ok(true)
        }
        None => Ok(false),
    }
}

fn server_args(rules: &str) -> Vec<&str> {
    vec!["serve", "--mcp", "--rules", rules]
}

/// The JSON object for the kxn entry in an `mcpServers`-style file.
fn mcp_servers_entry(extra: Extra, binary: &str, rules: &str) -> Value {
    let mut entry = json!({ "command": binary, "args": server_args(rules) });
    let obj = entry.as_object_mut().expect("object");
    match extra {
        Extra::None => {}
        Extra::Stdio => {
            obj.insert("type".into(), json!("stdio"));
        }
        Extra::StdioEnabled => {
            obj.insert("type".into(), json!("stdio"));
            obj.insert("disabled".into(), json!(false));
        }
        Extra::CopilotLocal => {
            obj.insert("type".into(), json!("local"));
            obj.insert("tools".into(), json!(["*"]));
        }
        Extra::Cline => {
            obj.insert("disabled".into(), json!(false));
            obj.insert("autoApprove".into(), json!([]));
        }
    }
    entry
}

/// Parse a JSON config. An empty file is an empty object; anything unreadable is an
/// error, so a file with comments or another syntax is never overwritten.
fn parse_json(content: &str) -> Result<Value> {
    if content.trim().is_empty() {
        return Ok(json!({}));
    }
    let v: Value = serde_json::from_str(content)
        .context("the file is not plain JSON (it has comments or JSON5 syntax), so kxn leaves it untouched")?;
    anyhow::ensure!(v.is_object(), "the file is not a JSON object");
    Ok(v)
}

/// Return the object at `path` inside `root`, creating empty objects on the way.
fn object_at<'a>(root: &'a mut Value, path: &[&str]) -> Result<&'a mut serde_json::Map<String, Value>> {
    let mut cur = root;
    for key in path {
        let obj = cur
            .as_object_mut()
            .with_context(|| format!("'{}' is not an object", key))?;
        cur = obj.entry(key.to_string()).or_insert_with(|| json!({}));
    }
    cur.as_object_mut().context("expected an object")
}

/// Where the kxn entry lives in each JSON shape.
fn json_parent(shape: Shape) -> &'static [&'static str] {
    match shape {
        Shape::McpServers(_) => &["mcpServers"],
        Shape::VsCodeServers => &["servers"],
        Shape::OpenCode => &["mcp"],
        Shape::OpenClaw => &["mcp", "servers"],
        _ => &[],
    }
}

fn json_entry(shape: Shape, binary: &str, rules: &str) -> Value {
    match shape {
        Shape::McpServers(extra) => mcp_servers_entry(extra, binary, rules),
        Shape::VsCodeServers => {
            json!({ "type": "stdio", "command": binary, "args": server_args(rules) })
        }
        Shape::OpenCode => {
            let mut cmd = vec![binary];
            cmd.extend(server_args(rules));
            json!({ "type": "local", "command": cmd, "enabled": true })
        }
        Shape::OpenClaw => json!({ "command": binary, "args": server_args(rules) }),
        _ => Value::Null,
    }
}

/// Add or replace the kxn entry in a config file's content.
fn upsert_entry(shape: Shape, content: &str, binary: &str, rules: &str) -> Result<String> {
    match shape {
        Shape::CodexToml => Ok(upsert_codex(content, binary, rules)),
        Shape::VibeToml => Ok(upsert_vibe(content, binary, rules)),
        Shape::HermesYaml => Ok(upsert_hermes(content, binary, rules)),
        _ => {
            let mut root = parse_json(content)?;
            object_at(&mut root, json_parent(shape))?
                .insert("kxn".into(), json_entry(shape, binary, rules));
            Ok(serde_json::to_string_pretty(&root)? + "\n")
        }
    }
}

/// Remove the kxn entry. `None` when there was nothing to remove.
fn remove_entry(shape: Shape, content: &str) -> Result<Option<String>> {
    match shape {
        Shape::CodexToml => Ok(remove_toml_table(content, "[mcp_servers.kxn]")),
        Shape::VibeToml => Ok(remove_vibe(content)),
        Shape::HermesYaml => Ok(remove_hermes(content)),
        _ => {
            if content.trim().is_empty() {
                return Ok(None);
            }
            let mut root = parse_json(content)?;
            let mut cur = &mut root;
            for key in json_parent(shape) {
                match cur.get_mut(*key) {
                    Some(v) => cur = v,
                    None => return Ok(None),
                }
            }
            let removed = cur
                .as_object_mut()
                .and_then(|o| o.remove("kxn"))
                .is_some();
            if removed {
                Ok(Some(serde_json::to_string_pretty(&root)? + "\n"))
            } else {
                Ok(None)
            }
        }
    }
}

fn toml_str(s: &str) -> String {
    // A JSON string is a valid TOML basic string.
    serde_json::to_string(s).unwrap_or_else(|_| format!("\"{}\"", s))
}

fn toml_args(rules: &str) -> String {
    let parts: Vec<String> = server_args(rules).iter().map(|a| toml_str(a)).collect();
    format!("[{}]", parts.join(", "))
}

/// Remove a TOML table that starts with `header`, up to the next table header.
fn remove_toml_table(content: &str, header: &str) -> Option<String> {
    let lines: Vec<&str> = content.lines().collect();
    let start = lines.iter().position(|l| l.trim() == header)?;
    let end = lines[start + 1..]
        .iter()
        .position(|l| l.trim_start().starts_with('['))
        .map(|i| start + 1 + i)
        .unwrap_or(lines.len());
    let mut out: Vec<&str> = lines[..start].to_vec();
    out.extend_from_slice(&lines[end..]);
    Some(join_lines(&out))
}

fn join_lines(lines: &[&str]) -> String {
    let s = lines.join("\n");
    let s = s.trim_matches('\n');
    if s.is_empty() {
        String::new()
    } else {
        format!("{}\n", s)
    }
}

fn upsert_codex(content: &str, binary: &str, rules: &str) -> String {
    let base = remove_toml_table(content, "[mcp_servers.kxn]").unwrap_or_else(|| content.to_string());
    let block = format!(
        "[mcp_servers.kxn]\ncommand = {}\nargs = {}\n",
        toml_str(binary),
        toml_args(rules)
    );
    append_block(&base, &block)
}

fn append_block(base: &str, block: &str) -> String {
    let base = base.trim_end_matches('\n');
    if base.is_empty() {
        block.to_string()
    } else {
        format!("{}\n\n{}", base, block)
    }
}

/// Remove every `[[mcp_servers]]` table whose name is "kxn".
fn remove_vibe(content: &str) -> Option<String> {
    let lines: Vec<&str> = content.lines().collect();
    let mut out: Vec<&str> = Vec::new();
    let mut removed = false;
    let mut i = 0;
    while i < lines.len() {
        if lines[i].trim() == "[[mcp_servers]]" {
            let end = lines[i + 1..]
                .iter()
                .position(|l| l.trim_start().starts_with('['))
                .map(|j| i + 1 + j)
                .unwrap_or(lines.len());
            let is_kxn = lines[i + 1..end].iter().any(|l| {
                let t = l.replace(' ', "");
                t == "name=\"kxn\"" || t == "name='kxn'"
            });
            if is_kxn {
                removed = true;
            } else {
                out.extend_from_slice(&lines[i..end]);
            }
            i = end;
        } else {
            out.push(lines[i]);
            i += 1;
        }
    }
    removed.then(|| join_lines(&out))
}

fn upsert_vibe(content: &str, binary: &str, rules: &str) -> String {
    let base = remove_vibe(content).unwrap_or_else(|| content.to_string());
    let block = format!(
        "[[mcp_servers]]\nname = \"kxn\"\ntransport = \"stdio\"\ncommand = {}\nargs = {}\n",
        toml_str(binary),
        toml_args(rules)
    );
    append_block(&base, &block)
}

fn yaml_str(s: &str) -> String {
    // A JSON string is a valid double-quoted YAML scalar.
    serde_json::to_string(s).unwrap_or_else(|_| format!("\"{}\"", s))
}

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// Line range of the `kxn:` entry under the top-level `mcp_servers:` key, if any.
fn hermes_kxn_range(lines: &[&str]) -> Option<(usize, usize, usize)> {
    let top = lines.iter().position(|l| l.trim_end() == "mcp_servers:")?;
    let section_end = lines[top + 1..]
        .iter()
        .position(|l| !l.trim().is_empty() && indent_of(l) == 0)
        .map(|i| top + 1 + i)
        .unwrap_or(lines.len());
    let start = (top + 1..section_end).find(|&i| {
        let t = lines[i].trim();
        t == "kxn:" || t.starts_with("kxn: ") || t.starts_with("kxn:#")
    })?;
    let indent = indent_of(lines[start]);
    let end = (start + 1..section_end)
        .find(|&i| !lines[i].trim().is_empty() && indent_of(lines[i]) <= indent)
        .unwrap_or(section_end);
    Some((top, start, end))
}

fn remove_hermes(content: &str) -> Option<String> {
    let lines: Vec<&str> = content.lines().collect();
    let (_, start, end) = hermes_kxn_range(&lines)?;
    let mut out: Vec<&str> = lines[..start].to_vec();
    out.extend_from_slice(&lines[end..]);
    Some(join_lines(&out))
}

fn upsert_hermes(content: &str, binary: &str, rules: &str) -> String {
    let base = remove_hermes(content).unwrap_or_else(|| content.to_string());
    let lines: Vec<&str> = base.lines().collect();
    let args: Vec<String> = server_args(rules).iter().map(|a| yaml_str(a)).collect();
    let entry = |pad: &str| {
        format!(
            "{pad}kxn:\n{pad}  command: {}\n{pad}  args: [{}]",
            yaml_str(binary),
            args.join(", ")
        )
    };
    match lines.iter().position(|l| l.trim_end() == "mcp_servers:") {
        Some(top) => {
            // Match the indentation of the servers already listed.
            let pad_len = lines[top + 1..]
                .iter()
                .find(|l| !l.trim().is_empty())
                .map(|l| indent_of(l))
                .filter(|&n| n > 0)
                .unwrap_or(2);
            let block = entry(&" ".repeat(pad_len));
            let mut out: Vec<String> = lines[..=top].iter().map(|s| s.to_string()).collect();
            out.push(block);
            out.extend(lines[top + 1..].iter().map(|s| s.to_string()));
            let refs: Vec<&str> = out.iter().map(|s| s.as_str()).collect();
            join_lines(&refs)
        }
        None => append_block(&base, &format!("mcp_servers:\n{}\n", entry("  "))),
    }
}

async fn install_binary(install_path: &str) -> Result<PathBuf> {
    let current_exe = std::env::current_exe().context("Cannot find current binary")?;
    let install = PathBuf::from(install_path);

    if current_exe == install {
        println!("  Binary already at {}", install_path);
        return Ok(install);
    }

    let cargo_toml = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.join("Cargo.toml"));

    if let Some(cargo_path) = cargo_toml.filter(|p| p.exists()) {
        let workspace_dir = cargo_path.parent().unwrap();
        println!("  Building release binary...");
        let status = tokio::process::Command::new("cargo")
            .args(["build", "--release"])
            .current_dir(workspace_dir)
            .status()
            .await
            .context("Failed to run cargo build")?;

        if !status.success() {
            anyhow::bail!("cargo build --release failed");
        }

        let release_bin = workspace_dir.join("target/release/kxn");
        if release_bin.exists() {
            println!("  Installing to {}...", install_path);
            let parent = install.parent().context("Invalid install path")?;
            if !parent.exists() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(&release_bin, &install)
                .context(format!("Failed to copy to {} (try with sudo?)", install_path))?;

            tokio::process::Command::new("strip")
                .arg(&install)
                .status()
                .await
                .ok();

            println!(
                "  Binary installed: {} ({})",
                install_path,
                human_size(std::fs::metadata(&install)?.len())
            );
            return Ok(install);
        }
    }

    println!("  Cannot build, using current binary: {}", current_exe.display());
    Ok(current_exe)
}

fn resolve_rules_path(rules: &str) -> Result<String> {
    let path = if rules.starts_with('/') || rules.starts_with('~') {
        PathBuf::from(shellexpand(rules))
    } else {
        std::env::current_dir()?.join(rules)
    };
    let path = path.canonicalize().unwrap_or(path);
    Ok(path.to_string_lossy().to_string())
}

fn shellexpand(s: &str) -> String {
    if let Some(rest) = s.strip_prefix('~') {
        if let Some(home) = dirs::home_dir() {
            return format!("{}{}", home.display(), rest);
        }
    }
    s.to_string()
}

fn uninstall(args: &InitArgs) -> Result<()> {
    println!("kxn uninstall\n");
    let home = dirs::home_dir().context("No home directory")?;
    let cwd = std::env::current_dir()?;

    let mut paths: Vec<(&str, PathBuf, Shape)> = Vec::new();
    for client in ALL_CLIENTS {
        let target = target_for(client, &home, &cwd);
        for p in target.paths {
            paths.push((client, p, target.shape));
        }
    }
    // Locations written by older kxn releases.
    paths.push((
        "claude-code",
        home.join(".claude/settings.json"),
        Shape::McpServers(Extra::None),
    ));
    paths.push((
        "claude-desktop",
        home.join(".config/claude/claude_desktop_config.json"),
        Shape::McpServers(Extra::None),
    ));
    paths.push((
        "windsurf",
        home.join(".codeium/windsurf/mcp_config.json"),
        Shape::McpServers(Extra::None),
    ));

    for (name, path, shape) in &paths {
        match edit_file(path, |c| remove_entry(*shape, c)) {
            Ok(true) => println!("  Removed from {} ({})", name, path.display()),
            Ok(false) => {}
            Err(e) => println!("  {}: {}: {:#}", name, path.display(), e),
        }
    }

    let install = Path::new(&args.install_path);
    if install.exists() {
        std::fs::remove_file(install)?;
        println!("  Removed binary: {}", args.install_path);
    }

    println!("\nkxn uninstalled.");
    Ok(())
}

fn human_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const B: &str = "/usr/local/bin/kxn";
    const R: &str = "/home/u/rules";

    #[test]
    fn every_client_has_a_target() {
        let home = Path::new("/home/u");
        for c in ALL_CLIENTS {
            let t = target_for(c, home, Path::new("/work"));
            assert!(!t.paths.is_empty(), "{c}");
            assert!(!t.detect.is_empty(), "{c}");
        }
    }

    #[test]
    fn aliases_resolve() {
        assert_eq!(canonical_client("Claude"), Some("claude-code"));
        assert_eq!(canonical_client("roo-code"), Some("roo"));
        assert_eq!(canonical_client("devin"), Some("windsurf"));
        assert_eq!(canonical_client("kilo"), Some("kilocode"));
        assert_eq!(canonical_client("nope"), None);
        for (_, target) in ALIASES {
            assert!(ALL_CLIENTS.contains(target));
        }
    }

    #[test]
    fn mcp_servers_keeps_other_servers_and_keys() {
        let before = r#"{"theme":"dark","mcpServers":{"other":{"command":"x"}}}"#;
        let out = upsert_entry(Shape::McpServers(Extra::Stdio), before, B, R).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["theme"], "dark");
        assert_eq!(v["mcpServers"]["other"]["command"], "x");
        assert_eq!(v["mcpServers"]["kxn"]["type"], "stdio");
        assert_eq!(v["mcpServers"]["kxn"]["command"], B);
        assert_eq!(v["mcpServers"]["kxn"]["args"], json!(["serve", "--mcp", "--rules", R]));
        let removed = remove_entry(Shape::McpServers(Extra::None), &out).unwrap().unwrap();
        let v: Value = serde_json::from_str(&removed).unwrap();
        assert!(v["mcpServers"].get("kxn").is_none());
        assert_eq!(v["mcpServers"]["other"]["command"], "x");
    }

    #[test]
    fn extras_per_dialect() {
        let copilot = mcp_servers_entry(Extra::CopilotLocal, B, R);
        assert_eq!(copilot["type"], "local");
        assert_eq!(copilot["tools"], json!(["*"]));
        let droid = mcp_servers_entry(Extra::StdioEnabled, B, R);
        assert_eq!(droid["disabled"], false);
        let cline = mcp_servers_entry(Extra::Cline, B, R);
        assert_eq!(cline["autoApprove"], json!([]));
        assert!(mcp_servers_entry(Extra::None, B, R).get("type").is_none());
    }

    #[test]
    fn unreadable_json_is_never_overwritten() {
        let jsonc = "{\n  // my comment\n  \"mcpServers\": {}\n}";
        assert!(upsert_entry(Shape::McpServers(Extra::None), jsonc, B, R).is_err());
        assert!(upsert_entry(Shape::OpenCode, "[1,2]", B, R).is_err());
        assert!(upsert_entry(Shape::McpServers(Extra::None), "", B, R).is_ok());
    }

    #[test]
    fn vscode_opencode_openclaw_shapes() {
        let v: Value = serde_json::from_str(&upsert_entry(Shape::VsCodeServers, "", B, R).unwrap()).unwrap();
        assert_eq!(v["servers"]["kxn"]["type"], "stdio");
        let v: Value = serde_json::from_str(&upsert_entry(Shape::OpenCode, r#"{"$schema":"s"}"#, B, R).unwrap()).unwrap();
        assert_eq!(v["$schema"], "s");
        assert_eq!(v["mcp"]["kxn"]["command"], json!([B, "serve", "--mcp", "--rules", R]));
        assert_eq!(v["mcp"]["kxn"]["enabled"], true);
        let v: Value = serde_json::from_str(&upsert_entry(Shape::OpenClaw, "", B, R).unwrap()).unwrap();
        assert_eq!(v["mcp"]["servers"]["kxn"]["command"], B);
    }

    #[test]
    fn codex_replaces_its_table_only() {
        let before = "model = \"o3\"\n\n[mcp_servers.kxn]\ncommand = \"old\"\n\n[mcp_servers.other]\ncommand = \"x\"\n";
        let out = upsert_entry(Shape::CodexToml, before, B, R).unwrap();
        let v: toml::Value = toml::from_str(&out).unwrap();
        assert_eq!(v["model"].as_str(), Some("o3"));
        assert_eq!(v["mcp_servers"]["kxn"]["command"].as_str(), Some(B));
        assert_eq!(v["mcp_servers"]["other"]["command"].as_str(), Some("x"));
        assert_eq!(out.matches("[mcp_servers.kxn]").count(), 1);
        let removed = remove_entry(Shape::CodexToml, &out).unwrap().unwrap();
        let v: toml::Value = toml::from_str(&removed).unwrap();
        assert!(v["mcp_servers"].get("kxn").is_none());
    }

    #[test]
    fn vibe_array_of_tables() {
        let before = "active_model = \"devstral\"\n\n[[mcp_servers]]\nname = \"fs\"\ntransport = \"stdio\"\ncommand = \"fs\"\n";
        let once = upsert_entry(Shape::VibeToml, before, B, R).unwrap();
        let twice = upsert_entry(Shape::VibeToml, &once, B, R).unwrap();
        let v: toml::Value = toml::from_str(&twice).unwrap();
        let servers = v["mcp_servers"].as_array().unwrap();
        assert_eq!(servers.len(), 2);
        let kxn = servers.iter().find(|s| s["name"].as_str() == Some("kxn")).unwrap();
        assert_eq!(kxn["transport"].as_str(), Some("stdio"));
        assert_eq!(kxn["args"].as_array().unwrap().len(), 4);
        let removed = remove_entry(Shape::VibeToml, &twice).unwrap().unwrap();
        let v: toml::Value = toml::from_str(&removed).unwrap();
        assert_eq!(v["mcp_servers"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn hermes_yaml_insert_replace_remove() {
        let fresh = upsert_entry(Shape::HermesYaml, "model: hermes-4\n", B, R).unwrap();
        assert!(fresh.contains("model: hermes-4\n\nmcp_servers:\n  kxn:\n    command: \"/usr/local/bin/kxn\"\n"));

        let existing = "mcp_servers:\n    github:\n        command: gh\n    kxn:\n        command: old\n        args: []\nother: 1\n";
        let out = upsert_entry(Shape::HermesYaml, existing, B, R).unwrap();
        assert_eq!(out.matches("kxn:").count(), 1);
        assert!(!out.contains("old"));
        assert!(out.contains("    kxn:\n      command: \"/usr/local/bin/kxn\""));
        assert!(out.contains("    github:\n        command: gh"));
        assert!(out.ends_with("other: 1\n"));

        let removed = remove_entry(Shape::HermesYaml, &out).unwrap().unwrap();
        assert!(!removed.contains("kxn"));
        assert!(removed.contains("github"));
        assert!(remove_entry(Shape::HermesYaml, &removed).unwrap().is_none());
    }

    #[test]
    fn paths_with_quotes_stay_valid() {
        let b = "C:\\Program Files\\kxn \"x\"\\kxn.exe";
        let out = upsert_entry(Shape::CodexToml, "", b, R).unwrap();
        let v: toml::Value = toml::from_str(&out).unwrap();
        assert_eq!(v["mcp_servers"]["kxn"]["command"].as_str(), Some(b));
    }
}
