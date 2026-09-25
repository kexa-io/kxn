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
    /// Check that every rule targets an object some collector actually produces
    Validate(ValidateArgs),
}

#[derive(Args)]
pub struct ValidateArgs {
    /// Rules directory (default: ./rules, then ~/.cache/kxn/rules)
    #[arg(short = 'R', long = "rules-dir")]
    pub dir: Option<PathBuf>,

    /// Machine-readable output
    #[arg(long)]
    pub json: bool,

    /// Report findings but always exit 0 (default: exit 1 when a rule can
    /// never be evaluated, so CI fails on it)
    #[arg(long)]
    pub no_fail: bool,
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
        RulesCommand::Validate(v) => run_validate(v),
    }
}

fn run_validate(args: ValidateArgs) -> Result<()> {
    use crate::table::{BOLD, DIM, GREEN, RED, RESET, YELLOW};

    let dir = crate::commands::monitor::find_rules_dir(&args.dir);
    let files = kxn_rules::parse_directory(&dir).map_err(|e| anyhow!("{}", e))?;
    if files.is_empty() {
        anyhow::bail!("No rule files found in {}", dir.display());
    }

    let catalog = Catalog::build();
    let report = validate_rules(&files, &catalog);

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return finish(&report, args.no_fail);
    }

    println!(
        "{BOLD}kxn rules validate{RESET} | {} | {} packs | {} rules",
        dir.display(),
        report.packs,
        report.rules
    );
    println!(
        "{DIM}catalogue: {} native providers, {} terraform profiles, {} objects{RESET}\n",
        catalog.providers,
        catalog.profiles,
        catalog.by_object.len()
    );
    if catalog.profiles == 0 {
        println!(
            "{YELLOW}note{RESET}  no terraform profile found next to the binary or in ./profiles — \
             objects provided by the Terraform bridge cannot be checked\n"
        );
    }

    if !report.unreachable.is_empty() {
        println!(
            "{RED}{BOLD}✗ {} rule(s) can never be evaluated{RESET} — no collector produces their object",
            report.unreachable.len()
        );
        let mut by_pack: std::collections::BTreeMap<&str, Vec<&Finding>> = Default::default();
        for f in &report.unreachable {
            by_pack.entry(f.pack.as_str()).or_default().push(f);
        }
        for (pack, findings) in by_pack {
            let provider = findings[0].provider.as_str();
            println!("\n  {BOLD}{}{RESET} {DIM}provider={}{RESET}", pack, provider);
            let mut by_object: std::collections::BTreeMap<&str, (usize, Option<&str>)> =
                Default::default();
            for f in findings {
                let e = by_object.entry(f.object.as_str()).or_insert((0, f.detail.as_deref()));
                e.0 += 1;
            }
            for (object, (count, closest)) in by_object {
                match closest {
                    Some(c) => println!(
                        "    {RED}{}{RESET}  {} rule(s)  {DIM}closest known object: {}{RESET}",
                        object, count, c
                    ),
                    None => println!("    {RED}{}{RESET}  {} rule(s)", object, count),
                }
            }
        }
        println!();
    }

    if !report.mismatched.is_empty() {
        println!(
            "{YELLOW}! {} rule(s) target an object their pack's provider does not produce{RESET}",
            report.mismatched.len()
        );
        for f in &report.mismatched {
            println!(
                "    {} {DIM}({}){RESET} → {} {DIM}produced by {}{RESET}",
                f.rule,
                f.provider,
                f.object,
                f.detail.as_deref().unwrap_or("?")
            );
        }
        println!();
    }

    if !report.not_compiled.is_empty() {
        for (provider, count) in &report.not_compiled {
            println!(
                "{DIM}note{RESET}  {} rule(s) for provider '{}' not checked — that provider is not compiled into this build",
                count, provider
            );
        }
        println!();
    }

    let reachable = report.rules - report.unreachable.len();
    if report.unreachable.is_empty() && report.mismatched.is_empty() {
        println!("{GREEN}✓ every rule targets an object a collector produces{RESET}");
    } else {
        println!(
            "{} of {} rules reachable, {} unreachable, {} mismatched{}",
            reachable,
            report.rules,
            report.unreachable.len(),
            report.mismatched.len(),
            if report.objectless > 0 {
                format!(", {} without an object (evaluated on the whole target)", report.objectless)
            } else {
                String::new()
            }
        );
    }

    finish(&report, args.no_fail)
}

fn finish(report: &Report, no_fail: bool) -> Result<()> {
    if !report.unreachable.is_empty() && !no_fail {
        std::process::exit(1);
    }
    Ok(())
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

// ─── kxn rules validate ─────────────────────────────────────────────────────

/// Every object a collector can produce, mapped to the providers producing it.
/// Built from the native providers' declared resource types and from the
/// Terraform profiles found on disk — no credentials, no network.
pub struct Catalog {
    by_object: std::collections::BTreeMap<String, std::collections::BTreeSet<String>>,
    providers: usize,
    profiles: usize,
}

impl Catalog {
    pub fn build() -> Self {
        let mut by_object: std::collections::BTreeMap<String, std::collections::BTreeSet<String>> =
            Default::default();
        let native = kxn_providers::native_catalog();
        for (provider, types) in &native {
            for t in *types {
                by_object
                    .entry((*t).to_string())
                    .or_default()
                    .insert((*provider).to_string());
            }
        }
        let profiles = kxn_providers::load_all_profiles();
        for (name, profile) in &profiles {
            for rt in profile.resource_types.keys() {
                by_object
                    .entry(rt.clone())
                    .or_default()
                    .insert(format!("terraform:{}", name));
            }
        }
        Self { by_object, providers: native.len(), profiles: profiles.len() }
    }

    /// Catalogue from an explicit list, so the checks can be exercised without
    /// depending on what this build happens to carry.
    #[cfg(test)]
    pub fn from_entries(entries: &[(&str, &[&str])], profiles: usize) -> Self {
        let mut by_object: std::collections::BTreeMap<String, std::collections::BTreeSet<String>> =
            Default::default();
        for (provider, types) in entries {
            for t in *types {
                by_object
                    .entry((*t).to_string())
                    .or_default()
                    .insert((*provider).to_string());
            }
        }
        Self { by_object, providers: entries.len(), profiles }
    }

    fn producers(&self, object: &str) -> Option<&std::collections::BTreeSet<String>> {
        self.by_object.get(object)
    }

    /// Native providers this build actually carries.
    fn compiled_providers(&self) -> std::collections::BTreeSet<String> {
        self.by_object
            .values()
            .flatten()
            .filter(|p| !p.starts_with("terraform:"))
            .cloned()
            .collect()
    }

    /// Known object whose name is closest to `object`, to turn "unknown object"
    /// into "did you mean". Only suggests a genuinely close name.
    fn closest(&self, object: &str) -> Option<&str> {
        self.by_object
            .keys()
            .map(|k| (edit_distance(k, object), k.as_str()))
            .filter(|(d, _)| *d * 3 <= object.len().max(1))
            .min_by_key(|(d, _)| *d)
            .map(|(_, k)| k)
    }
}

fn edit_distance(a: &str, b: &str) -> usize {
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0usize; b.len() + 1];
    for (i, ca) in a.iter().enumerate() {
        cur[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            cur[j + 1] = (prev[j] + cost).min(prev[j + 1] + 1).min(cur[j] + 1);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

/// Provider names a rule pack may use for the same collector.
fn canonical_provider(declared: &str) -> String {
    let d = declared.trim().trim_start_matches("hashicorp/");
    match d {
        "k8s" => "kubernetes",
        "gh" => "github",
        "gitea" => "forgejo",
        "gws" => "googleworkspace",
        "msgraph" => "microsoft.graph",
        "google" => "gcp",
        "prom" => "prometheus",
        other => other,
    }
    .to_string()
}

/// Does a pack declaring `declared` match a collector named `producer`?
fn provider_matches(declared: &str, producer: &str) -> bool {
    let declared = canonical_provider(declared);
    if declared == producer {
        return true;
    }
    match producer.strip_prefix("terraform:") {
        // `provider = "terraform"` means "whatever profile provides it".
        Some(profile) => declared == "terraform" || declared == profile,
        None => false,
    }
}

#[derive(serde::Serialize)]
pub struct Finding {
    pub pack: String,
    pub provider: String,
    pub rule: String,
    pub object: String,
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(serde::Serialize)]
pub struct Report {
    pub packs: usize,
    pub rules: usize,
    pub unreachable: Vec<Finding>,
    pub mismatched: Vec<Finding>,
    pub objectless: usize,
    /// Rules skipped because their provider is not compiled into this build
    /// (`oracle` behind its feature, `docker` off unix): provider → rule count.
    pub not_compiled: std::collections::BTreeMap<String, usize>,
}

/// Check every rule's `object` against the catalogue.
///
/// Two things are wrong and neither is visible at scan time: an object nothing
/// produces (the rule is silently skipped — a scan reports no violation because
/// nothing was ever checked), and an object produced only by a provider other
/// than the one the pack declares (the rule only fires on the wrong target).
pub fn validate_rules(files: &[(String, kxn_rules::RuleFile)], catalog: &Catalog) -> Report {
    let mut report = Report {
        packs: files.len(),
        rules: 0,
        unreachable: Vec::new(),
        mismatched: Vec::new(),
        objectless: 0,
        not_compiled: Default::default(),
    };
    let compiled = catalog.compiled_providers();

    for (pack, rf) in files {
        let declared = rf
            .metadata
            .as_ref()
            .and_then(|m| m.provider.clone())
            .unwrap_or_default();

        // A pack for a provider this build left out says nothing about the
        // rules: they are simply not checkable here.
        let canonical = canonical_provider(&declared);
        if !declared.is_empty()
            && kxn_providers::ALL_NATIVE_PROVIDERS.contains(&canonical.as_str())
            && !compiled.contains(&canonical)
        {
            report.rules += rf.rules.len();
            *report.not_compiled.entry(canonical).or_default() += rf.rules.len();
            continue;
        }

        for rule in &rf.rules {
            report.rules += 1;
            if rule.object.is_empty() {
                report.objectless += 1;
                continue;
            }
            match catalog.producers(&rule.object) {
                None => report.unreachable.push(Finding {
                    pack: pack.clone(),
                    provider: declared.clone(),
                    rule: rule.name.clone(),
                    object: rule.object.clone(),
                    kind: "no-collector",
                    detail: catalog.closest(&rule.object).map(|s| s.to_string()),
                }),
                Some(producers) => {
                    if !declared.is_empty()
                        && !producers.iter().any(|p| provider_matches(&declared, p))
                    {
                        report.mismatched.push(Finding {
                            pack: pack.clone(),
                            provider: declared.clone(),
                            rule: rule.name.clone(),
                            object: rule.object.clone(),
                            kind: "provider-mismatch",
                            detail: Some(
                                producers.iter().cloned().collect::<Vec<_>>().join(", "),
                            ),
                        });
                    }
                }
            }
        }
    }

    report
}

#[cfg(test)]
mod validate_tests {
    use super::*;

    fn catalog() -> Catalog {
        Catalog::from_entries(
            &[
                ("ssh", &["sshd_config", "users", "file_permissions"]),
                ("docker", &["docker_config"]),
                ("terraform:aws", &["ec2_instance", "iam_role"]),
            ],
            1,
        )
    }

    fn pack(name: &str, toml_src: &str) -> Vec<(String, kxn_rules::RuleFile)> {
        vec![(name.to_string(), kxn_rules::parse_string(toml_src).expect("valid pack"))]
    }

    const COND: &str = "[[rules.conditions]]\nproperty = \"x\"\ncondition = \"EQUAL\"\nvalue = 1\n";

    #[test]
    fn a_rule_whose_object_nothing_produces_is_reported() {
        let files = pack(
            "apache-cis",
            &format!(
                "[metadata]\nprovider = \"ssh\"\n\
                 [[rules]]\nname = \"a\"\nlevel = 2\nobject = \"apache_config\"\n{COND}"
            ),
        );
        let report = validate_rules(&files, &catalog());
        assert_eq!(report.unreachable.len(), 1);
        assert_eq!(report.unreachable[0].object, "apache_config");
        assert!(report.mismatched.is_empty());
    }

    #[test]
    fn a_near_miss_suggests_the_known_object() {
        let files = pack(
            "typo",
            &format!(
                "[metadata]\nprovider = \"ssh\"\n\
                 [[rules]]\nname = \"a\"\nlevel = 2\nobject = \"sshd_confg\"\n{COND}"
            ),
        );
        let report = validate_rules(&files, &catalog());
        assert_eq!(report.unreachable[0].detail.as_deref(), Some("sshd_config"));
    }

    #[test]
    fn a_rule_on_another_providers_object_is_a_mismatch_not_an_orphan() {
        let files = pack(
            "docker-cis",
            &format!(
                "[metadata]\nprovider = \"ssh\"\n\
                 [[rules]]\nname = \"a\"\nlevel = 2\nobject = \"docker_config\"\n{COND}"
            ),
        );
        let report = validate_rules(&files, &catalog());
        assert!(report.unreachable.is_empty());
        assert_eq!(report.mismatched.len(), 1);
        assert_eq!(report.mismatched[0].detail.as_deref(), Some("docker"));
    }

    #[test]
    fn terraform_packs_match_their_profile_by_either_name() {
        for declared in ["terraform", "aws", "hashicorp/aws"] {
            let files = pack(
                "aws-cis",
                &format!(
                    "[metadata]\nprovider = \"{declared}\"\n\
                     [[rules]]\nname = \"a\"\nlevel = 2\nobject = \"ec2_instance\"\n{COND}"
                ),
            );
            let report = validate_rules(&files, &catalog());
            assert!(report.unreachable.is_empty(), "{declared}");
            assert!(report.mismatched.is_empty(), "{declared}");
        }
    }

    #[test]
    fn a_provider_this_build_lacks_is_not_counted_against_the_rules() {
        let files = pack(
            "oracle-cis",
            &format!(
                "[metadata]\nprovider = \"oracle\"\n\
                 [[rules]]\nname = \"a\"\nlevel = 2\nobject = \"tablespaces\"\n{COND}"
            ),
        );
        let report = validate_rules(&files, &catalog());
        assert!(report.unreachable.is_empty());
        assert!(report.mismatched.is_empty());
        assert_eq!(report.not_compiled.get("oracle"), Some(&1));
    }

    #[test]
    fn a_rule_without_an_object_is_counted_apart() {
        let files = pack(
            "generic",
            &format!("[[rules]]\nname = \"a\"\nlevel = 2\n{COND}"),
        );
        let report = validate_rules(&files, &catalog());
        assert_eq!(report.objectless, 1);
        assert!(report.unreachable.is_empty());
    }

    #[test]
    fn a_clean_pack_reports_nothing() {
        let files = pack(
            "ssh-cis",
            &format!(
                "[metadata]\nprovider = \"ssh\"\n\
                 [[rules]]\nname = \"a\"\nlevel = 2\nobject = \"sshd_config\"\n{COND}"
            ),
        );
        let report = validate_rules(&files, &catalog());
        assert_eq!(report.rules, 1);
        assert!(report.unreachable.is_empty());
        assert!(report.mismatched.is_empty());
    }
}
