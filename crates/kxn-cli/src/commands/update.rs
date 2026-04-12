use anyhow::{Context, Result};
use clap::Args;
use std::path::PathBuf;

#[derive(Args)]
pub struct UpdateArgs {
    /// Actually apply updates (default: dry-run, show what would happen)
    #[arg(long)]
    pub apply: bool,

    /// Only update rules (skip binary and CVE DB)
    #[arg(long)]
    pub rules_only: bool,

    /// Only update the kxn binary
    #[arg(long)]
    pub binary_only: bool,

    /// Only update the CVE database
    #[arg(long)]
    pub cve_only: bool,

    /// Force binary update even if installed via Homebrew (not recommended)
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug)]
enum InstallMethod {
    Homebrew,
    Cargo,
    #[allow(dead_code)]
    Manual(PathBuf),
    Unknown,
}

fn detect_install_method() -> InstallMethod {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return InstallMethod::Unknown,
    };

    let exe_str = exe.to_string_lossy();

    // Homebrew paths (Apple Silicon + Intel + Linuxbrew)
    if exe_str.contains("/homebrew/") || exe_str.contains("/Homebrew/")
        || exe_str.contains("/Cellar/") || exe_str.contains("/linuxbrew/")
    {
        return InstallMethod::Homebrew;
    }

    // Cargo
    if exe_str.contains("/.cargo/bin/") {
        return InstallMethod::Cargo;
    }

    InstallMethod::Manual(exe)
}

pub async fn run(args: UpdateArgs) -> Result<()> {
    let current_version = env!("CARGO_PKG_VERSION");
    let install = detect_install_method();

    println!("kxn {} installed via {:?}", current_version, install);
    println!();

    let do_binary = !args.rules_only && !args.cve_only;
    let do_rules = !args.binary_only && !args.cve_only;
    let do_cve = !args.binary_only && !args.rules_only;

    // ── 1. Check binary update ──
    if do_binary {
        let latest = fetch_latest_version().await.ok();
        match &latest {
            Some(v) if v != current_version => {
                println!("Binary: {} → {} available", current_version, v);
                if matches!(install, InstallMethod::Homebrew) && !args.force {
                    println!("  Installed via Homebrew — run: brew upgrade kexa-io/tap/kxn");
                } else if args.apply {
                    update_binary(v, &install).await?;
                } else {
                    println!("  Run with --apply to download and install");
                }
            }
            Some(_) => println!("Binary: up to date ({})", current_version),
            None => println!("Binary: could not check latest version"),
        }
        println!();
    }

    // ── 2. Update rules ──
    if do_rules {
        let cache_dir = dirs::cache_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("kxn")
            .join("rules");

        if args.apply {
            println!("Rules: updating from kexa-io/kxn-rules...");
            let pull_args = crate::commands::rules::PullArgs {
                dir: Some(cache_dir),
                repo: "kexa-io/kxn-rules".to_string(),
                branch: "main".to_string(),
                providers: vec![],
                force: true,
            };
            // Dispatch via rules::run to reuse logic
            crate::commands::rules::run(crate::commands::rules::RulesArgs {
                command: crate::commands::rules::RulesCommand::Pull(pull_args),
            }).await?;
        } else {
            println!("Rules: would update {} (use --apply)", cache_dir.display());
        }
        println!();
    }

    // ── 3. Update CVE DB ──
    if do_cve {
        if args.apply {
            println!("CVE database: syncing from NVD + CISA KEV + EPSS...");
            crate::commands::cve_update::run(crate::commands::cve_update::CveUpdateArgs {
                kev_only: false,
                epss_only: false,
                nvd_api_key: None,
                verbose: false,
            }).await?;
        } else {
            println!("CVE database: would sync NVD + CISA KEV + EPSS (use --apply)");
        }
    }

    Ok(())
}

async fn fetch_latest_version() -> Result<String> {
    let client = crate::alerts::shared_client();
    let resp: serde_json::Value = client
        .get("https://api.github.com/repos/kexa-io/kxn/releases/latest")
        .header("User-Agent", "kxn-update")
        .send()
        .await
        .context("Failed to fetch latest release")?
        .json()
        .await
        .context("Failed to parse release info")?;

    let tag = resp["tag_name"]
        .as_str()
        .context("No tag_name in release response")?;

    Ok(tag.trim_start_matches('v').to_string())
}

async fn update_binary(version: &str, install: &InstallMethod) -> Result<()> {
    let exe = std::env::current_exe()?;
    let arch = std::env::consts::ARCH;
    let os = std::env::consts::OS;

    let target = match (os, arch) {
        ("macos", "aarch64") => "aarch64-apple-darwin",
        ("macos", "x86_64") => "x86_64-apple-darwin",
        ("linux", "x86_64") => "x86_64-unknown-linux-gnu",
        ("linux", "aarch64") => "aarch64-unknown-linux-gnu",
        ("windows", "x86_64") => "x86_64-pc-windows-msvc",
        _ => anyhow::bail!("Unsupported platform: {}-{}", os, arch),
    };

    let url = format!(
        "https://github.com/kexa-io/kxn/releases/download/v{}/kxn-{}.tar.gz",
        version, target
    );

    println!("  Downloading {}...", url);

    let client = crate::alerts::shared_client();
    let resp = client
        .get(&url)
        .send()
        .await
        .context("Download failed")?
        .error_for_status()?;

    let bytes = resp.bytes().await.context("Failed to read download")?;

    // Extract tar.gz to temp dir
    let tmp_dir = std::env::temp_dir().join(format!("kxn-update-{}", std::process::id()));
    std::fs::create_dir_all(&tmp_dir)?;

    let tar_path = tmp_dir.join("kxn.tar.gz");
    std::fs::write(&tar_path, &bytes)?;

    let status = std::process::Command::new("tar")
        .args(["-xzf", tar_path.to_str().unwrap()])
        .current_dir(&tmp_dir)
        .status()
        .context("Failed to extract tar.gz")?;

    if !status.success() {
        anyhow::bail!("tar extraction failed");
    }

    let new_binary = tmp_dir.join("kxn");
    if !new_binary.exists() {
        anyhow::bail!("Binary not found in downloaded archive");
    }

    // Replace binary (need to be careful on the current running process)
    println!("  Installing to {}...", exe.display());

    // macOS/Linux: remove then copy (cannot overwrite running binary directly)
    if let Some(parent) = exe.parent() {
        let backup = parent.join("kxn.old");
        std::fs::rename(&exe, &backup).ok();
        match std::fs::copy(&new_binary, &exe) {
            Ok(_) => {
                std::fs::set_permissions(&exe, std::os::unix::fs::PermissionsExt::from_mode(0o755))?;
                std::fs::remove_file(&backup).ok();
                std::fs::remove_dir_all(&tmp_dir).ok();
                println!("  ✓ Binary updated to v{}", version);
                match install {
                    InstallMethod::Cargo => println!("  Note: cargo may still show old version in ~/.cargo/.crates.toml"),
                    _ => {}
                }
            }
            Err(e) => {
                // Restore backup on failure
                std::fs::rename(&backup, &exe).ok();
                anyhow::bail!("Failed to install new binary: {}", e);
            }
        }
    }

    Ok(())
}
