//! `kxn watch install` / `kxn watch uninstall`: sets up `kxn watch` as a
//! systemd service, so the continuous monitoring survives reboots.
//!
//! Installing is explicit and never starts the service on its own unless asked:
//! a freshly written configuration is an example, so the service is only
//! enabled once the operator has edited it.

use anyhow::{bail, Context, Result};
use clap::Args;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

pub const UNIT_NAME: &str = "kxn-watch.service";
const UNIT_PATH: &str = "/etc/systemd/system/kxn-watch.service";
const DEFAULT_CONFIG: &str = "/etc/kxn/kxn.toml";
const DEFAULT_USER: &str = "kxn";
const STATE_DIR: &str = "/var/lib/kxn";
const EXAMPLE_CONFIG: &str = include_str!("../../../../kxn.toml.example");

#[derive(Args, Debug)]
pub struct InstallArgs {
    /// Configuration file the service reads
    #[arg(long, default_value = DEFAULT_CONFIG)]
    pub config: PathBuf,

    /// System user the service runs as (created if missing)
    #[arg(long, default_value = DEFAULT_USER)]
    pub user: String,

    /// Enable and start the service now (refused when the configuration was just created from the example)
    #[arg(long)]
    pub enable: bool,

    /// Show what would be done, without changing anything
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args, Debug)]
pub struct UninstallArgs {
    /// Also remove the configuration directory and the service user
    #[arg(long)]
    pub purge: bool,

    /// Show what would be done, without changing anything
    #[arg(long)]
    pub dry_run: bool,
}

/// Renders the systemd unit. Pure, so it can be tested without root.
pub fn render_unit(binary: &Path, config: &Path, user: &str) -> String {
    format!(
        "[Unit]\n\
         Description=kxn watch (continuous compliance and security monitoring)\n\
         Documentation=https://github.com/kexa-io/kxn\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         User={user}\n\
         Group={user}\n\
         ExecStart={bin} watch --config-file {cfg}\n\
         Environment=HOME={state}\n\
         WorkingDirectory={state}\n\
         StateDirectory=kxn\n\
         Restart=on-failure\n\
         RestartSec=10\n\
         NoNewPrivileges=yes\n\
         ProtectSystem=strict\n\
         ProtectHome=yes\n\
         PrivateTmp=yes\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        user = user,
        bin = binary.display(),
        cfg = config.display(),
        state = STATE_DIR,
    )
}

fn is_root() -> bool {
    Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
        .unwrap_or(false)
}

fn user_exists(user: &str) -> bool {
    Command::new("id")
        .args(["-u", user])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Runs a system command and turns a failure into a readable error.
fn run(program: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(program)
        .args(args)
        .status()
        .with_context(|| format!("failed to run {program}"))?;
    if !status.success() {
        bail!("{program} {} exited with {status}", args.join(" "));
    }
    Ok(())
}

fn ask_yes_no(question: &str) -> bool {
    if !std::io::stdin().is_terminal() {
        return false;
    }
    print!("{question} [y/N] ");
    let _ = std::io::stdout().flush();
    let mut answer = String::new();
    if std::io::stdin().read_line(&mut answer).is_err() {
        return false;
    }
    matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes" | "o" | "oui"
    )
}

/// Writes `contents` atomically: a temporary file in the same directory, then rename.
fn write_atomic(path: &Path, contents: &str, mode: u32) -> Result<()> {
    let dir = path.parent().context("path has no parent directory")?;
    std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, contents).with_context(|| format!("cannot write {}", tmp.display()))?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
    std::fs::rename(&tmp, path).with_context(|| format!("cannot replace {}", path.display()))?;
    Ok(())
}

pub fn install(args: InstallArgs) -> Result<()> {
    let binary = std::env::current_exe().context("cannot locate the kxn binary")?;
    let binary = std::fs::canonicalize(&binary).unwrap_or(binary);
    let unit = render_unit(&binary, &args.config, &args.user);
    let config_exists = args.config.exists();

    if args.dry_run {
        println!("# would write {UNIT_PATH}:\n{unit}");
        println!("# would create user '{}' if missing", args.user);
        if config_exists {
            println!("# keep existing configuration {}", args.config.display());
        } else {
            println!(
                "# would write an example configuration to {}",
                args.config.display()
            );
        }
        println!("# would run: systemctl daemon-reload");
        return Ok(());
    }

    if !is_root() {
        bail!("kxn watch install must run as root (try: sudo kxn watch install)");
    }

    if !user_exists(&args.user) {
        run(
            "useradd",
            &[
                "--system",
                "--no-create-home",
                "--shell",
                "/usr/sbin/nologin",
                &args.user,
            ],
        )?;
        println!("created system user '{}'", args.user);
    }

    let mut created_config = false;
    if config_exists {
        println!("keeping existing configuration {}", args.config.display());
    } else {
        write_atomic(&args.config, EXAMPLE_CONFIG, 0o640)?;
        run(
            "chown",
            &[
                &format!("root:{}", args.user),
                &args.config.to_string_lossy(),
            ],
        )?;
        println!(
            "wrote example configuration {} (edit it before enabling the service)",
            args.config.display()
        );
        created_config = true;
    }

    write_atomic(Path::new(UNIT_PATH), &unit, 0o644)?;
    println!("wrote {UNIT_PATH}");
    run("systemctl", &["daemon-reload"])?;

    let want_enable =
        args.enable || (!created_config && ask_yes_no("Enable and start kxn watch now?"));
    if want_enable && created_config {
        bail!(
            "configuration was just created from the example: edit {} then run: sudo systemctl enable --now {UNIT_NAME}",
            args.config.display()
        );
    }
    if want_enable {
        run("systemctl", &["enable", "--now", UNIT_NAME])?;
        println!("kxn watch is enabled and running (status: systemctl status {UNIT_NAME})");
    } else {
        println!("kxn watch is installed but not enabled. To start it:");
        println!("  sudo systemctl enable --now {UNIT_NAME}");
    }
    Ok(())
}

pub fn uninstall(args: UninstallArgs) -> Result<()> {
    if args.dry_run {
        println!(
            "# would stop and disable {UNIT_NAME}, remove {UNIT_PATH}, run systemctl daemon-reload"
        );
        if args.purge {
            println!("# would also remove the configuration directory and the service user");
        }
        return Ok(());
    }
    if !is_root() {
        bail!("kxn watch uninstall must run as root (try: sudo kxn watch uninstall)");
    }

    // The service may not be running or enabled; those failures are not errors here.
    let _ = Command::new("systemctl")
        .args(["disable", "--now", UNIT_NAME])
        .status();
    if Path::new(UNIT_PATH).exists() {
        std::fs::remove_file(UNIT_PATH).with_context(|| format!("cannot remove {UNIT_PATH}"))?;
        println!("removed {UNIT_PATH}");
    }
    run("systemctl", &["daemon-reload"])?;

    if args.purge {
        if Path::new("/etc/kxn").exists() {
            std::fs::remove_dir_all("/etc/kxn").context("cannot remove /etc/kxn")?;
            println!("removed /etc/kxn");
        }
        if user_exists(DEFAULT_USER) {
            run("userdel", &[DEFAULT_USER])?;
            println!("removed user '{DEFAULT_USER}'");
        }
    } else {
        println!("configuration kept in /etc/kxn (use --purge to remove it with the user)");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_runs_watch_with_config_as_service_user() {
        let unit = render_unit(
            Path::new("/usr/local/bin/kxn"),
            Path::new("/etc/kxn/kxn.toml"),
            "kxn",
        );
        assert!(
            unit.contains("ExecStart=/usr/local/bin/kxn watch --config-file /etc/kxn/kxn.toml\n")
        );
        assert!(unit.contains("User=kxn\n"));
        assert!(unit.contains("Group=kxn\n"));
        assert!(unit.contains("Restart=on-failure\n"));
        assert!(unit.contains("WantedBy=multi-user.target\n"));
    }

    #[test]
    fn unit_is_not_enabled_by_rendering_alone() {
        // Rendering never touches the system: the unit text carries no install side effect.
        let unit = render_unit(Path::new("/x/kxn"), Path::new("/etc/kxn/kxn.toml"), "kxn");
        assert!(!unit.contains("systemctl"));
    }

    #[test]
    fn example_configuration_is_embedded() {
        assert!(EXAMPLE_CONFIG.contains("kxn.toml"));
    }
}
