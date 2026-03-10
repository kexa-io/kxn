use anyhow::{Context, Result};
use clap::Args;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

/// Supported MCP client targets.
const ALL_CLIENTS: &[&str] = &[
    "claude-desktop",
    "claude-code",
    "gemini",
    "cursor",
    "windsurf",
    "opencode",
    "codex",
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

    /// Configure only specific client(s). Repeatable.
    /// Values: claude-desktop, claude-code, gemini, cursor, windsurf, opencode, codex
    #[arg(long = "client", value_name = "CLIENT")]
    pub clients: Vec<String>,

    /// Uninstall: remove MCP configs and binary
    #[arg(long)]
    pub uninstall: bool,
}

pub async fn run(args: InitArgs) -> Result<()> {
    if args.uninstall {
        return uninstall(&args);
    }

    println!("kxn init — setting up Kexa Next Gen\n");

    // Step 1: Build/locate binary
    let binary_path = if args.mcp_only {
        std::env::current_exe().context("Cannot find current binary")?
    } else {
        install_binary(&args.install_path).await?
    };

    let binary_str = binary_path.to_string_lossy().to_string();
    let rules_path = resolve_rules_path(&args.rules)?;

    // Step 2: Determine which clients to configure
    let targets: Vec<&str> = if args.clients.is_empty() {
        ALL_CLIENTS.to_vec()
    } else {
        let mut t = Vec::new();
        for c in &args.clients {
            let name = c.to_lowercase();
            if ALL_CLIENTS.contains(&name.as_str()) {
                t.push(*ALL_CLIENTS.iter().find(|&&s| s == name).unwrap());
            } else {
                println!(
                    "  Unknown client '{}'. Available: {}",
                    c,
                    ALL_CLIENTS.join(", ")
                );
            }
        }
        t
    };

    // Step 3: Configure each client
    let mut configured = Vec::new();
    for client in &targets {
        match configure_client(client, &binary_str, &rules_path) {
            Ok(path) => {
                println!("  {} configured: {}", client, path.display());
                configured.push(*client);
            }
            Err(e) => println!("  {} skipped: {}", client, e),
        }
    }

    // Step 4: Summary
    println!("\nkxn is ready!\n");
    println!("  Binary:  {}", binary_str);
    println!("  Rules:   {}", rules_path);
    if !configured.is_empty() {
        println!(
            "  MCP:     configured for {}",
            configured.join(", ")
        );
    }
    println!(
        "\n  Available clients: {}",
        ALL_CLIENTS.join(", ")
    );
    println!("  Configure one:  kxn init --client gemini");

    Ok(())
}

fn configure_client(
    client: &str,
    binary: &str,
    rules: &str,
) -> Result<PathBuf> {
    let home = dirs::home_dir().context("No home dir")?;
    match client {
        "claude-desktop" => {
            let path = if cfg!(target_os = "macos") {
                home.join("Library/Application Support/Claude/claude_desktop_config.json")
            } else {
                home.join(".config/claude/claude_desktop_config.json")
            };
            upsert_mcp_json(&path, "mcpServers", binary, rules)?;
            Ok(path)
        }
        "claude-code" => {
            let path = home.join(".claude/settings.json");
            upsert_mcp_json(&path, "mcpServers", binary, rules)?;
            Ok(path)
        }
        "gemini" => {
            let path = home.join(".gemini/settings.json");
            upsert_mcp_json(&path, "mcpServers", binary, rules)?;
            Ok(path)
        }
        "cursor" => {
            let path = home.join(".cursor/mcp.json");
            upsert_mcp_json(&path, "mcpServers", binary, rules)?;
            Ok(path)
        }
        "windsurf" => {
            let path = home.join(".codeium/windsurf/mcp_config.json");
            upsert_mcp_json(&path, "mcpServers", binary, rules)?;
            Ok(path)
        }
        "opencode" => {
            let path = home.join(".config/opencode/opencode.json");
            configure_opencode(&path, binary, rules)?;
            Ok(path)
        }
        "codex" => {
            let path = home.join(".codex/config.toml");
            configure_codex(&path, binary, rules)?;
            Ok(path)
        }
        _ => anyhow::bail!("Unknown client: {}", client),
    }
}

/// Standard MCP JSON config (Claude Desktop/Code, Gemini, Cursor, Windsurf).
fn upsert_mcp_json(
    config_path: &Path,
    key: &str,
    binary: &str,
    rules: &str,
) -> Result<()> {
    let mut config: Value = if config_path.exists() {
        let content = std::fs::read_to_string(config_path)
            .context("Failed to read config")?;
        serde_json::from_str(&content).unwrap_or(json!({}))
    } else {
        json!({})
    };

    if config.get(key).is_none() {
        config[key] = json!({});
    }

    config[key]["kxn"] = json!({
        "command": binary,
        "args": ["serve", "--mcp", "--rules", rules],
    });

    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(config_path, serde_json::to_string_pretty(&config)?)?;
    Ok(())
}

/// OpenCode uses "mcp" key with command as array and "type" field.
fn configure_opencode(config_path: &Path, binary: &str, rules: &str) -> Result<()> {
    let mut config: Value = if config_path.exists() {
        let content = std::fs::read_to_string(config_path)
            .context("Failed to read config")?;
        serde_json::from_str(&content).unwrap_or(json!({}))
    } else {
        json!({})
    };

    if config.get("mcp").is_none() {
        config["mcp"] = json!({});
    }

    config["mcp"]["kxn"] = json!({
        "type": "local",
        "command": [binary, "serve", "--mcp", "--rules", rules],
        "enabled": true,
    });

    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(config_path, serde_json::to_string_pretty(&config)?)?;
    Ok(())
}

/// Codex uses TOML with [mcp_servers.kxn].
fn configure_codex(config_path: &Path, binary: &str, rules: &str) -> Result<()> {
    let mut content = if config_path.exists() {
        std::fs::read_to_string(config_path)
            .context("Failed to read config")?
    } else {
        String::new()
    };

    // Remove existing [mcp_servers.kxn] block if present
    if let Some(start) = content.find("[mcp_servers.kxn]") {
        let end = content[start + 1..]
            .find("\n[")
            .map(|i| start + 1 + i)
            .unwrap_or(content.len());
        content.replace_range(start..end, "");
    }

    // Append new block
    let block = format!(
        "\n[mcp_servers.kxn]\ncommand = \"{}\"\nargs = [\"serve\", \"--mcp\", \"--rules\", \"{}\"]\n",
        binary, rules
    );
    content.push_str(&block);

    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(config_path, content.trim_start())?;
    Ok(())
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
    let home = dirs::home_dir().context("No home dir")?;

    let configs: Vec<(&str, PathBuf, &str)> = vec![
        (
            "claude-desktop",
            if cfg!(target_os = "macos") {
                home.join("Library/Application Support/Claude/claude_desktop_config.json")
            } else {
                home.join(".config/claude/claude_desktop_config.json")
            },
            "mcpServers",
        ),
        ("claude-code", home.join(".claude/settings.json"), "mcpServers"),
        ("gemini", home.join(".gemini/settings.json"), "mcpServers"),
        ("cursor", home.join(".cursor/mcp.json"), "mcpServers"),
        (
            "windsurf",
            home.join(".codeium/windsurf/mcp_config.json"),
            "mcpServers",
        ),
        ("opencode", home.join(".config/opencode/opencode.json"), "mcp"),
    ];

    for (name, path, key) in &configs {
        match remove_json_entry(path, key) {
            Ok(true) => println!("  Removed from {}", name),
            Ok(false) => {}
            Err(e) => println!("  {}: {}", name, e),
        }
    }

    // Codex (TOML)
    let codex_path = home.join(".codex/config.toml");
    if codex_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&codex_path) {
            if content.contains("[mcp_servers.kxn]") {
                if let Some(start) = content.find("[mcp_servers.kxn]") {
                    let end = content[start + 1..]
                        .find("\n[")
                        .map(|i| start + 1 + i)
                        .unwrap_or(content.len());
                    let mut new_content = content.clone();
                    new_content.replace_range(start..end, "");
                    let _ = std::fs::write(&codex_path, new_content.trim());
                    println!("  Removed from codex");
                }
            }
        }
    }

    // Remove binary
    let install = Path::new(&args.install_path);
    if install.exists() {
        std::fs::remove_file(install)?;
        println!("  Removed binary: {}", args.install_path);
    }

    println!("\nkxn uninstalled.");
    Ok(())
}

fn remove_json_entry(config_path: &Path, key: &str) -> Result<bool> {
    if !config_path.exists() {
        return Ok(false);
    }
    let content = std::fs::read_to_string(config_path)?;
    let mut config: Value = serde_json::from_str(&content)?;

    if let Some(servers) = config.get_mut(key).and_then(|v| v.as_object_mut()) {
        if servers.remove("kxn").is_some() {
            std::fs::write(config_path, serde_json::to_string_pretty(&config)?)?;
            return Ok(true);
        }
    }
    Ok(false)
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
