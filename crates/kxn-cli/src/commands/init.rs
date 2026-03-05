use anyhow::{Context, Result};
use clap::Args;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

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

    /// Skip Claude Desktop configuration
    #[arg(long)]
    pub no_desktop: bool,

    /// Skip Claude Code configuration
    #[arg(long)]
    pub no_code: bool,

    /// Uninstall: remove MCP configs and binary
    #[arg(long)]
    pub uninstall: bool,
}

pub async fn run(args: InitArgs) -> Result<()> {
    if args.uninstall {
        return uninstall(&args);
    }

    println!("🔧 kxn init — setting up Kexa Next Gen\n");

    // Step 1: Build release binary
    let binary_path = if args.mcp_only {
        // Find current binary
        std::env::current_exe().context("Cannot find current binary")?
    } else {
        install_binary(&args.install_path).await?
    };

    let binary_str = binary_path.to_string_lossy().to_string();
    let rules_path = resolve_rules_path(&args.rules)?;

    // Step 2: Configure Claude Desktop
    if !args.no_desktop {
        match configure_claude_desktop(&binary_str, &rules_path) {
            Ok(path) => println!("✅ Claude Desktop configured: {}", path.display()),
            Err(e) => println!("⚠️  Claude Desktop: {} (skipped)", e),
        }
    }

    // Step 3: Configure Claude Code
    if !args.no_code {
        match configure_claude_code(&binary_str, &rules_path) {
            Ok(path) => println!("✅ Claude Code configured: {}", path.display()),
            Err(e) => println!("⚠️  Claude Code: {} (skipped)", e),
        }
    }

    // Step 4: Summary
    println!("\n🚀 kxn is ready!\n");
    println!("  Binary:  {}", binary_str);
    println!("  Rules:   {}", rules_path);
    println!("  MCP:     kxn serve --mcp --rules {}", rules_path);
    println!("\n  Usage:");
    println!("    kxn gather --provider ssh --resource-type system_stats --config '{{...}}'");
    println!("    kxn scan -c kxn.toml");
    println!("    kxn watch -c kxn.toml");
    println!("\n  In Claude Desktop / Claude Code, kxn tools are now available:");
    println!("    kxn_list_providers, kxn_list_resource_types, kxn_gather,");
    println!("    kxn_scan, kxn_check_resource, kxn_list_rules, kxn_provider_schema");

    Ok(())
}

async fn install_binary(install_path: &str) -> Result<PathBuf> {
    let current_exe = std::env::current_exe().context("Cannot find current binary")?;
    let install = PathBuf::from(install_path);

    // If we're already running from the install path, skip
    if current_exe == install {
        println!("✅ Binary already at {}", install_path);
        return Ok(install);
    }

    // Build release if we're in development
    let cargo_toml = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.join("Cargo.toml"));

    if let Some(cargo_path) = cargo_toml.filter(|p| p.exists()) {
        let workspace_dir = cargo_path.parent().unwrap();
        println!("📦 Building release binary...");
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
            // Copy to install path
            println!("📋 Installing to {}...", install_path);
            let parent = install.parent().context("Invalid install path")?;
            if !parent.exists() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(&release_bin, &install)
                .context(format!("Failed to copy to {} (try with sudo?)", install_path))?;

            // Strip symbols
            tokio::process::Command::new("strip")
                .arg(&install)
                .status()
                .await
                .ok();

            println!("✅ Binary installed: {} ({})",
                install_path,
                human_size(std::fs::metadata(&install)?.len())
            );
            return Ok(install);
        }
    }

    // Fallback: use current binary
    println!("⚠️  Cannot build, using current binary: {}", current_exe.display());
    Ok(current_exe)
}

fn resolve_rules_path(rules: &str) -> Result<String> {
    let path = if rules.starts_with('/') || rules.starts_with('~') {
        PathBuf::from(shellexpand(rules))
    } else {
        std::env::current_dir()?.join(rules)
    };

    // Canonicalize to remove ./ and ../ components
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

fn configure_claude_desktop(binary: &str, rules: &str) -> Result<PathBuf> {
    // macOS: ~/Library/Application Support/Claude/claude_desktop_config.json
    // Linux: ~/.config/claude/claude_desktop_config.json
    let config_path = if cfg!(target_os = "macos") {
        dirs::home_dir()
            .context("No home dir")?
            .join("Library/Application Support/Claude/claude_desktop_config.json")
    } else {
        dirs::home_dir()
            .context("No home dir")?
            .join(".config/claude/claude_desktop_config.json")
    };

    upsert_mcp_config(&config_path, binary, rules)?;
    Ok(config_path)
}

fn configure_claude_code(binary: &str, rules: &str) -> Result<PathBuf> {
    let config_path = dirs::home_dir()
        .context("No home dir")?
        .join(".claude/settings.json");

    upsert_mcp_config(&config_path, binary, rules)?;
    Ok(config_path)
}

fn upsert_mcp_config(config_path: &Path, binary: &str, rules: &str) -> Result<()> {
    // Read existing config or create new
    let mut config: Value = if config_path.exists() {
        let content = std::fs::read_to_string(config_path)
            .context("Failed to read config")?;
        serde_json::from_str(&content).unwrap_or(json!({}))
    } else {
        json!({})
    };

    // Ensure mcpServers exists
    if config.get("mcpServers").is_none() {
        config["mcpServers"] = json!({});
    }

    // Add/update kxn entry
    config["mcpServers"]["kxn"] = json!({
        "command": binary,
        "args": ["serve", "--mcp", "--rules", rules],
    });

    // Write back
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = serde_json::to_string_pretty(&config)?;
    std::fs::write(config_path, content)?;

    Ok(())
}

fn uninstall(args: &InitArgs) -> Result<()> {
    println!("🗑️  kxn uninstall\n");

    // Remove from Claude Desktop
    if !args.no_desktop {
        let path = if cfg!(target_os = "macos") {
            dirs::home_dir().map(|h| h.join("Library/Application Support/Claude/claude_desktop_config.json"))
        } else {
            dirs::home_dir().map(|h| h.join(".config/claude/claude_desktop_config.json"))
        };
        if let Some(p) = path {
            match remove_mcp_entry(&p) {
                Ok(true) => println!("✅ Removed from Claude Desktop"),
                Ok(false) => println!("⚠️  Not found in Claude Desktop"),
                Err(e) => println!("⚠️  Claude Desktop: {}", e),
            }
        }
    }

    // Remove from Claude Code
    if !args.no_code {
        let path = dirs::home_dir().map(|h| h.join(".claude/settings.json"));
        if let Some(p) = path {
            match remove_mcp_entry(&p) {
                Ok(true) => println!("✅ Removed from Claude Code"),
                Ok(false) => println!("⚠️  Not found in Claude Code"),
                Err(e) => println!("⚠️  Claude Code: {}", e),
            }
        }
    }

    // Remove binary
    let install = Path::new(&args.install_path);
    if install.exists() {
        std::fs::remove_file(install)?;
        println!("✅ Removed binary: {}", args.install_path);
    }

    println!("\n✅ kxn uninstalled.");
    Ok(())
}

fn remove_mcp_entry(config_path: &Path) -> Result<bool> {
    if !config_path.exists() {
        return Ok(false);
    }
    let content = std::fs::read_to_string(config_path)?;
    let mut config: Value = serde_json::from_str(&content)?;

    if let Some(servers) = config.get_mut("mcpServers").and_then(|v| v.as_object_mut()) {
        if servers.remove("kxn").is_some() {
            let content = serde_json::to_string_pretty(&config)?;
            std::fs::write(config_path, content)?;
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
