use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use std::path::PathBuf;

const DEFAULT_REPO: &str = "kexa-io/kxn-rules";
const DEFAULT_BRANCH: &str = "main";

#[derive(Args)]
pub struct RulesArgs {
    #[command(subcommand)]
    pub command: RulesCommand,
}

#[derive(Subcommand)]
pub enum RulesCommand {
    /// Download community rules from the kxn-rules repository
    Pull(PullArgs),
    /// List available rule sets from the repository
    List(ListRemoteArgs),
}

#[derive(Args)]
pub struct PullArgs {
    /// Target directory to download rules into
    #[arg(short, long, default_value = "./rules")]
    pub dir: PathBuf,

    /// GitHub repository (owner/repo)
    #[arg(long, default_value = DEFAULT_REPO)]
    pub repo: String,

    /// Branch or tag
    #[arg(long, default_value = DEFAULT_BRANCH)]
    pub branch: String,

    /// Only download specific providers (e.g. aws,kubernetes)
    #[arg(short, long, value_delimiter = ',')]
    pub providers: Vec<String>,

    /// Overwrite existing files
    #[arg(long)]
    pub force: bool,
}

#[derive(Args)]
pub struct ListRemoteArgs {
    /// GitHub repository (owner/repo)
    #[arg(long, default_value = DEFAULT_REPO)]
    pub repo: String,

    /// Branch or tag
    #[arg(long, default_value = DEFAULT_BRANCH)]
    pub branch: String,
}

pub async fn run(args: RulesArgs) -> Result<()> {
    match args.command {
        RulesCommand::Pull(pull_args) => run_pull(pull_args).await,
        RulesCommand::List(list_args) => run_list(list_args).await,
    }
}

async fn run_list(args: ListRemoteArgs) -> Result<()> {
    let url = format!(
        "https://api.github.com/repos/{}/git/trees/{}?recursive=1",
        args.repo, args.branch
    );

    let client = crate::alerts::shared_client();
    let resp: serde_json::Value = client
        .get(&url)
        .header("User-Agent", "kxn")
        .send()
        .await
        .context("Failed to fetch repository tree")?
        .json()
        .await
        .context("Failed to parse response")?;

    let tree = resp["tree"]
        .as_array()
        .context("Invalid repository tree response")?;

    // Group .toml files by directory
    let mut providers: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();

    for item in tree {
        let path = item["path"].as_str().unwrap_or("");
        if path.ends_with(".toml") && !path.starts_with('.') {
            let parts: Vec<&str> = path.split('/').collect();
            if parts.len() >= 2 {
                let provider = parts[0].to_string();
                let file = parts[1..].join("/");
                providers.entry(provider).or_default().push(file);
            }
        }
    }

    if providers.is_empty() {
        println!("No rules found in {}", args.repo);
        return Ok(());
    }

    println!("Available rules from {}:\n", args.repo);
    let mut total = 0;
    for (provider, files) in &providers {
        println!("  {}/ ({} files)", provider, files.len());
        for f in files {
            println!("    {}", f);
            total += 1;
        }
    }
    println!(
        "\n{} rule files across {} providers",
        total,
        providers.len()
    );
    println!("\nDownload: kxn rules pull");
    println!("Specific: kxn rules pull --providers aws,kubernetes");

    Ok(())
}

async fn run_pull(args: PullArgs) -> Result<()> {
    let url = format!(
        "https://api.github.com/repos/{}/git/trees/{}?recursive=1",
        args.repo, args.branch
    );

    let client = crate::alerts::shared_client();
    let resp: serde_json::Value = client
        .get(&url)
        .header("User-Agent", "kxn")
        .send()
        .await
        .context("Failed to fetch repository tree")?
        .json()
        .await
        .context("Failed to parse response")?;

    let tree = resp["tree"]
        .as_array()
        .context("Invalid repository tree response")?;

    // Collect .toml files to download
    let mut to_download: Vec<String> = Vec::new();
    for item in tree {
        let path = item["path"].as_str().unwrap_or("");
        if !path.ends_with(".toml") || path.starts_with('.') {
            continue;
        }

        // Filter by provider if specified
        if !args.providers.is_empty() {
            let provider = path.split('/').next().unwrap_or("");
            if !args.providers.iter().any(|p| p == provider) {
                continue;
            }
        }

        to_download.push(path.to_string());
    }

    if to_download.is_empty() {
        println!("No matching rules found.");
        return Ok(());
    }

    println!(
        "Downloading {} rule files from {}...",
        to_download.len(),
        args.repo
    );

    let mut downloaded = 0;
    let mut skipped = 0;

    for path in &to_download {
        let target = args.dir.join(path);

        // Check if file exists
        if target.exists() && !args.force {
            skipped += 1;
            continue;
        }

        // Create parent directories
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory {}", parent.display()))?;
        }

        // Download raw file
        let raw_url = format!(
            "https://raw.githubusercontent.com/{}/{}/{}",
            args.repo, args.branch, path
        );

        let content = client
            .get(&raw_url)
            .header("User-Agent", "kxn")
            .send()
            .await
            .with_context(|| format!("Failed to download {}", path))?
            .text()
            .await
            .with_context(|| format!("Failed to read {}", path))?;

        std::fs::write(&target, &content)
            .with_context(|| format!("Failed to write {}", target.display()))?;

        downloaded += 1;
    }

    println!("  {} downloaded, {} skipped (use --force to overwrite)", downloaded, skipped);
    println!("Rules saved to {}", args.dir.display());

    Ok(())
}
