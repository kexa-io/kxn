use anyhow::{anyhow, Context, Result};
use clap::{Args, Subcommand};
use std::path::PathBuf;

const DEFAULT_REPO: &str = "kexa-io/kxn-rules";
const DEFAULT_BRANCH: &str = "main";

/// Fetch the GitHub git-tree listing for a repo/branch and return the `tree`
/// array. Surfaces actionable errors (rate limit, 404, GitHub-side message)
/// instead of the previous opaque "Invalid repository tree response", and
/// honours `GITHUB_TOKEN` to lift the 60/hr unauthenticated rate limit.
async fn fetch_tree(
    client: &reqwest::Client,
    repo: &str,
    branch: &str,
) -> Result<Vec<serde_json::Value>> {
    let url = format!(
        "https://api.github.com/repos/{}/git/trees/{}?recursive=1",
        repo, branch
    );

    let mut req = client.get(&url).header("User-Agent", "kxn");
    if let Ok(token) = std::env::var("GITHUB_TOKEN") {
        if !token.is_empty() {
            req = req.bearer_auth(token);
        }
    }

    let resp = req
        .send()
        .await
        .with_context(|| format!("Failed to fetch repository tree from {}", url))?;

    let status = resp.status();
    let body = resp
        .text()
        .await
        .context("Failed to read GitHub API response body")?;

    let parsed: serde_json::Value = serde_json::from_str(&body).with_context(|| {
        format!(
            "GitHub API returned non-JSON response (HTTP {}). First 200 chars: {}",
            status,
            body.chars().take(200).collect::<String>()
        )
    })?;

    if !status.is_success() {
        let msg = parsed["message"].as_str().unwrap_or("(no message)");
        if status.as_u16() == 403 && msg.contains("rate limit") {
            return Err(anyhow!(
                "GitHub API rate limit exceeded for {}/{}. \
                 Set GITHUB_TOKEN (5000 req/hr authenticated, vs 60 unauthenticated) \
                 or retry later. GitHub said: {}",
                repo, branch, msg
            ));
        }
        return Err(anyhow!(
            "GitHub API error {} on {}/{}: {}",
            status, repo, branch, msg
        ));
    }

    if parsed["truncated"].as_bool() == Some(true) {
        tracing::warn!(
            repo = %repo, branch = %branch,
            "GitHub returned a truncated tree — some rule files may be missing. \
             Consider splitting the rules repo or using per-directory pulls."
        );
    }

    parsed["tree"]
        .as_array()
        .cloned()
        .ok_or_else(|| anyhow!(
            "GitHub response did not contain a 'tree' array (HTTP {}). Response keys: {:?}",
            status,
            parsed.as_object().map(|o| o.keys().collect::<Vec<_>>())
        ))
}

#[derive(Args)]
pub struct RulesArgs {
    #[command(subcommand)]
    pub command: RulesCommand,
}

#[derive(Subcommand)]
pub enum RulesCommand {
    /// Download community rules from the kxn-rules repository
    Pull(PullArgs),
    /// Update cached rules (force re-download)
    Update(UpdateArgs),
    /// List available rule sets from the repository
    List(ListRemoteArgs),
}

#[derive(Args)]
pub struct UpdateArgs {
    /// GitHub repository (owner/repo)
    #[arg(long, default_value = DEFAULT_REPO)]
    pub repo: String,

    /// Branch or tag
    #[arg(long, default_value = DEFAULT_BRANCH)]
    pub branch: String,
}

#[derive(Args)]
pub struct PullArgs {
    /// Target directory to download rules into (default: ~/.config/kxn/rules)
    #[arg(short, long)]
    pub dir: Option<PathBuf>,

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
        RulesCommand::Pull(pull_args) => { run_pull(pull_args).await?; Ok(()) },
        RulesCommand::Update(u) => {
            let pull_args = PullArgs {
                dir: None,
                repo: u.repo,
                branch: u.branch,
                providers: vec![],
                force: true, // force overwrite for update
            };
            run_pull(pull_args).await?;
            Ok(())
        },
        RulesCommand::List(list_args) => run_list(list_args).await,
    }
}

async fn run_list(args: ListRemoteArgs) -> Result<()> {
    let client = crate::alerts::shared_client();
    let tree = fetch_tree(client, &args.repo, &args.branch).await?;

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

/// Auto-pull rules to a directory (used by first-run auto-download).
/// Returns number of files downloaded.
pub async fn auto_pull(dir: &std::path::Path) -> Result<usize> {
    let args = PullArgs {
        dir: Some(dir.to_path_buf()),
        repo: DEFAULT_REPO.to_string(),
        branch: DEFAULT_BRANCH.to_string(),
        providers: vec![],
        force: false,
    };
    run_pull(args).await
}

fn default_rules_dir() -> PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("kxn")
        .join("rules")
}

async fn run_pull(args: PullArgs) -> Result<usize> {
    let dir = args.dir.unwrap_or_else(default_rules_dir);

    let client = crate::alerts::shared_client();
    let tree = fetch_tree(client, &args.repo, &args.branch).await?;

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
        return Ok(0);
    }

    println!(
        "Downloading {} rule files from {}...",
        to_download.len(),
        args.repo
    );

    let mut downloaded = 0;
    let mut skipped = 0;

    for path in &to_download {
        let target = dir.join(path);

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

    // Count total rules
    let mut total_rules = 0;
    for path in &to_download {
        let target = dir.join(path);
        if let Ok(content) = std::fs::read_to_string(&target) {
            total_rules += content.matches("[[rules]]").count();
        }
    }

    println!("  {} files downloaded ({} rules), {} skipped", downloaded, total_rules, skipped);
    println!("Rules saved to {}", dir.display());

    Ok(downloaded)
}
