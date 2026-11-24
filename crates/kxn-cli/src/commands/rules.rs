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
    /// Target directory to download rules into (default: $XDG_CACHE_HOME/kxn/rules, usually ~/.cache/kxn/rules)
    #[arg(short, long)]
    pub dir: Option<PathBuf>,

    /// GitHub repository (owner/repo)
    #[arg(long, default_value = DEFAULT_REPO)]
    pub repo: String,

    /// Branch or tag
    #[arg(long, default_value = DEFAULT_BRANCH)]
    pub branch: String,

    /// Archive URL of rule packs (overrides `[rules] source` and --repo/--branch)
    #[arg(long)]
    pub source: Option<String>,

    /// Only download specific providers (e.g. aws,kubernetes)
    #[arg(short, long, value_delimiter = ',')]
    pub providers: Vec<String>,

    /// Download even if the source reports no change
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
                source: None,
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
        println!("  {}/ ({})", provider, crate::utils::count(files.len(), "file"));
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
/// A path from a remote listing, checked before it is joined to a local
/// directory.
///
/// `PathBuf::join` replaces the base when given an absolute path, so a listing
/// entry named `/home/user/.cargo/config.toml` would be written there, with
/// content the publisher controls. `..` climbs out the same way. Neither has
/// any legitimate use in a rules repository.
fn safe_relative_path(path: &str) -> Result<(), String> {
    let p = std::path::Path::new(path);
    if p.is_absolute() {
        return Err("absolute path".into());
    }
    for part in p.components() {
        match part {
            std::path::Component::Normal(_) => {}
            std::path::Component::CurDir => {}
            other => return Err(format!("path component {:?}", other)),
        }
    }
    // Windows drive letters and UNC prefixes reach here as Normal on unix.
    if path.contains(':') || path.contains('\\') {
        return Err("path separator or drive letter".into());
    }
    Ok(())
}

/// Returns number of files downloaded.
/// Default archive of community rules.
pub const DEFAULT_SOURCE: &str = "https://github.com/kexa-io/kxn-rules/archive/refs/heads/main.tar.gz";
/// Default interval between two checks of the source for changes.
const DEFAULT_REFRESH_SECS: i64 = 86_400;
/// Bookkeeping kept next to the downloaded rules.
const META_FILE: &str = ".kxn-rules-source.json";
/// An archive of rule packs is a few hundred KB; refuse anything absurd.
const MAX_ARCHIVE_BYTES: usize = 64 * 1024 * 1024;

/// Where community rules come from and how often they are checked.
#[derive(Debug, Clone, PartialEq)]
pub struct RulesSource {
    pub url: String,
    pub refresh_secs: i64,
}

/// `KXN_RULES_SOURCE` / `KXN_RULES_REFRESH`, else `[rules] source` /
/// `refresh` of the discovered kxn.toml, else the defaults.
pub fn rules_source() -> RulesSource {
    let cfg = crate::config::discover_config()
        .and_then(|p| crate::config::load_config(&p).ok())
        .map(|c| c.rules)
        .unwrap_or_default();
    let url = std::env::var("KXN_RULES_SOURCE")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or(cfg.source)
        .unwrap_or_else(|| DEFAULT_SOURCE.to_string());
    let refresh_secs = std::env::var("KXN_RULES_REFRESH")
        .ok()
        .or(cfg.refresh)
        .and_then(|r| kxn_rules::parse_duration_secs(&r).ok())
        .unwrap_or(DEFAULT_REFRESH_SECS);
    RulesSource { url, refresh_secs }
}

/// What `ensure_rules` did.
#[derive(Debug, PartialEq)]
pub enum Refresh {
    /// Checked recently: no request made.
    Fresh,
    /// The source answered 304: nothing downloaded.
    NotModified,
    /// The archive changed: this many rule files written.
    Updated(usize),
    /// The source could not be reached; the existing rules are used.
    Offline(String),
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct Meta {
    source: String,
    etag: Option<String>,
    last_modified: Option<String>,
    checked_at: i64,
}

fn read_meta(dir: &std::path::Path) -> Option<Meta> {
    serde_json::from_str(&std::fs::read_to_string(dir.join(META_FILE)).ok()?).ok()
}

fn has_rules(dir: &std::path::Path) -> bool {
    glob::glob(&dir.join("**/*.toml").to_string_lossy())
        .map(|mut g| g.any(|e| e.is_ok()))
        .unwrap_or(false)
}

/// Make `dir` hold the rules of `source`, downloading as little as possible:
/// nothing at all while the last check is younger than the refresh interval,
/// then one conditional request (`If-None-Match` / `If-Modified-Since`) for a
/// single archive, which the server answers 304 when nothing changed.
///
/// `check_now` ignores the refresh interval; `force` also ignores the ETag
/// and downloads the archive. With `providers`, only those provider
/// directories are extracted. `replace` swaps the whole directory (kxn's own
/// cache); otherwise files are written in place and nothing is deleted.
pub async fn ensure_rules(
    dir: &std::path::Path,
    source: &RulesSource,
    check_now: bool,
    force: bool,
    providers: &[String],
    replace: bool,
) -> Result<Refresh> {
    let now = chrono::Utc::now().timestamp();
    let meta = read_meta(dir).filter(|m| m.source == source.url);
    let present = has_rules(dir);

    if let Some(m) = &meta {
        let age = now - m.checked_at;
        if present && !check_now && !force && (source.refresh_secs <= 0 || age < source.refresh_secs) {
            return Ok(Refresh::Fresh);
        }
    }

    let client = crate::alerts::shared_client();
    let mut req = client.get(&source.url).header("User-Agent", "kxn");
    if present && !force {
        if let Some(m) = &meta {
            if let Some(etag) = &m.etag {
                req = req.header("If-None-Match", etag);
            }
            if let Some(lm) = &m.last_modified {
                req = req.header("If-Modified-Since", lm);
            }
        }
    }

    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) if present => return Ok(Refresh::Offline(e.to_string())),
        Err(e) => return Err(anyhow!("Failed to download rules from {}: {}", source.url, e)),
    };

    if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
        if let Some(mut m) = meta {
            m.checked_at = now;
            write_meta(dir, &m);
        }
        return Ok(Refresh::NotModified);
    }
    if !resp.status().is_success() {
        let msg = format!("{} answered {}", source.url, resp.status());
        if present {
            return Ok(Refresh::Offline(msg));
        }
        return Err(anyhow!("Failed to download rules: {}", msg));
    }

    let header = |name: &str| {
        resp.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(String::from)
    };
    let etag = header("etag");
    let last_modified = header("last-modified");
    let bytes = resp.bytes().await.context("Failed to read the rules archive")?;
    if bytes.len() > MAX_ARCHIVE_BYTES {
        anyhow::bail!("rules archive from {} is larger than {} bytes", source.url, MAX_ARCHIVE_BYTES);
    }

    let files = extract_rule_files(&bytes, providers)
        .with_context(|| format!("Failed to read the rules archive from {}", source.url))?;
    if files.is_empty() {
        anyhow::bail!("no .toml rule files in the archive from {}", source.url);
    }
    let written = files.len();
    install_files(dir, files, replace)?;
    if providers.is_empty() {
        write_meta(
            dir,
            &Meta { source: source.url.clone(), etag, last_modified, checked_at: now },
        );
    }
    Ok(Refresh::Updated(written))
}

fn write_meta(dir: &std::path::Path, meta: &Meta) {
    if let Ok(json) = serde_json::to_string_pretty(meta) {
        let _ = std::fs::write(dir.join(META_FILE), json);
    }
}

/// The `.toml` files of a `.tar.gz`, keyed by their path inside the archive
/// once the single top-level directory forges add (`kxn-rules-main/`) is
/// removed. Paths that would leave the destination are refused.
fn extract_rule_files(archive: &[u8], providers: &[String]) -> Result<Vec<(String, Vec<u8>)>> {
    use std::io::Read;
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(archive));
    let mut entries: Vec<(String, Vec<u8>)> = Vec::new();
    for entry in tar.entries()? {
        let mut entry = entry?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let path = entry.path()?.to_string_lossy().replace('\\', "/");
        if !path.ends_with(".toml") {
            continue;
        }
        let mut data = Vec::new();
        entry.read_to_end(&mut data)?;
        entries.push((path, data));
    }

    // Strip the archive's root directory when every entry shares it.
    let root = entries
        .first()
        .and_then(|(p, _)| p.split_once('/').map(|(r, _)| format!("{r}/")));
    let strip = root
        .as_ref()
        .filter(|r| entries.iter().all(|(p, _)| p.starts_with(r.as_str())));

    let mut out = Vec::new();
    for (path, data) in entries {
        let rel = match strip {
            Some(r) => path[r.len()..].to_string(),
            None => path,
        };
        let first = rel.split('/').next().unwrap_or_default();
        if rel.split('/').any(|seg| seg.starts_with('.')) {
            continue;
        }
        if !providers.is_empty() && !providers.iter().any(|p| p == first) {
            continue;
        }
        if let Err(why) = safe_relative_path(&rel) {
            eprintln!("  skipped {}: {}", rel, why);
            continue;
        }
        out.push((rel, data));
    }
    Ok(out)
}

/// Write the files into `dir`. With `replace`, build the new tree next to
/// it and swap, so a scan never sees half an update and packs removed
/// upstream disappear.
fn install_files(dir: &std::path::Path, files: Vec<(String, Vec<u8>)>, replace: bool) -> Result<()> {
    let write_all = |base: &std::path::Path| -> Result<()> {
        for (rel, data) in &files {
            let target = base.join(rel);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("Failed to create {}", parent.display()))?;
            }
            std::fs::write(&target, data)
                .with_context(|| format!("Failed to write {}", target.display()))?;
        }
        Ok(())
    };

    if !replace {
        return write_all(dir);
    }
    let parent = dir.parent().unwrap_or_else(|| std::path::Path::new("."));
    std::fs::create_dir_all(parent)?;
    let name = dir.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "rules".into());
    let staging = parent.join(format!(".{name}.new-{}", std::process::id()));
    let old = parent.join(format!(".{name}.old-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&staging);
    write_all(&staging)?;
    if dir.exists() {
        std::fs::rename(dir, &old).with_context(|| format!("Failed to move {}", dir.display()))?;
    }
    if let Err(e) = std::fs::rename(&staging, dir) {
        let _ = std::fs::rename(&old, dir);
        return Err(anyhow!("Failed to install rules into {}: {}", dir.display(), e));
    }
    let _ = std::fs::remove_dir_all(&old);
    Ok(())
}

/// Refresh kxn's own rules cache (non-interactive paths: quick scan,
/// remediate). Returns the number of files written.
pub async fn auto_pull(dir: &std::path::Path) -> Result<usize> {
    let source = rules_source();
    let replace = dir == default_rules_dir().as_path();
    match ensure_rules(dir, &source, false, false, &[], replace).await? {
        Refresh::Updated(n) => {
            eprintln!("Rules updated from {} ({})", source.url, crate::utils::count(n, "file"));
            Ok(n)
        }
        Refresh::Offline(why) => {
            eprintln!("Rules: could not check {} ({}); using the cached rules", source.url, why);
            Ok(0)
        }
        Refresh::Fresh | Refresh::NotModified => Ok(0),
    }
}

pub fn default_rules_dir() -> PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("kxn")
        .join("rules")
}

/// The archive URL for `--repo` / `--branch` given on the command line.
fn github_archive(repo: &str, branch: &str) -> String {
    format!("https://github.com/{repo}/archive/refs/heads/{branch}.tar.gz")
}

async fn run_pull(args: PullArgs) -> Result<usize> {
    let default_dir = default_rules_dir();
    let dir = args.dir.clone().unwrap_or_else(|| default_dir.clone());
    let mut source = rules_source();
    if let Some(url) = &args.source {
        source.url = url.clone();
    } else if args.repo != DEFAULT_REPO || args.branch != DEFAULT_BRANCH {
        source.url = github_archive(&args.repo, &args.branch);
    }

    println!("Rules: {}", source.url);
    let replace = dir == default_dir && args.providers.is_empty();
    let outcome = ensure_rules(&dir, &source, true, args.force, &args.providers, replace).await?;
    let written = match outcome {
        Refresh::Updated(n) => {
            println!("  {} rule files updated", n);
            n
        }
        Refresh::NotModified | Refresh::Fresh => {
            println!("  already up to date");
            0
        }
        Refresh::Offline(why) => {
            println!("  could not reach the source ({}); keeping the rules already there", why);
            0
        }
    };
    let total: usize = glob::glob(&dir.join("**/*.toml").to_string_lossy())
        .map(|g| {
            g.flatten()
                .filter_map(|p| std::fs::read_to_string(p).ok())
                .map(|c| c.matches("[[rules]]").count())
                .sum()
        })
        .unwrap_or(0);
    println!("Rules in {}: {} rules", dir.display(), total);
    Ok(written)
}

#[cfg(test)]
mod source_tests {
    use super::*;

    fn tarball(files: &[(&str, &str)]) -> Vec<u8> {
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast()));
        for (path, content) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, path, content.as_bytes()).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap()
    }

    #[test]
    fn archive_root_is_stripped_and_only_toml_kept() {
        let t = tarball(&[
            ("kxn-rules-main/aws/cis.toml", "a"),
            ("kxn-rules-main/ssh/cis.toml", "b"),
            ("kxn-rules-main/README.md", "x"),
            ("kxn-rules-main/.github/x.toml", "x"),
        ]);
        let mut files = extract_rule_files(&t, &[]).unwrap();
        files.sort();
        let names: Vec<_> = files.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(names, ["aws/cis.toml", "ssh/cis.toml"]);
    }

    #[test]
    fn provider_filter_keeps_only_those_directories() {
        let t = tarball(&[("r/aws/cis.toml", "a"), ("r/ssh/cis.toml", "b")]);
        let files = extract_rule_files(&t, &["ssh".to_string()]).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].0, "ssh/cis.toml");
    }

    #[test]
    fn replace_swaps_the_directory_and_drops_removed_packs() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("rules");
        std::fs::create_dir_all(dir.join("old")).unwrap();
        std::fs::write(dir.join("old/gone.toml"), "x").unwrap();
        install_files(&dir, vec![("aws/cis.toml".into(), b"a".to_vec())], true).unwrap();
        assert!(dir.join("aws/cis.toml").exists());
        assert!(!dir.join("old/gone.toml").exists());
    }

    #[test]
    fn in_place_install_keeps_other_files() {
        let base = tempfile::tempdir().unwrap();
        std::fs::write(base.path().join("mine.toml"), "x").unwrap();
        install_files(base.path(), vec![("aws/cis.toml".into(), b"a".to_vec())], false).unwrap();
        assert!(base.path().join("mine.toml").exists());
        assert!(base.path().join("aws/cis.toml").exists());
    }
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

#[cfg(test)]
mod path_tests {
    use super::*;

    #[test]
    fn accepts_a_normal_rules_path() {
        assert!(safe_relative_path("ssh/ssh-cis.toml").is_ok());
        assert!(safe_relative_path("aws-cis.toml").is_ok());
    }

    /// `PathBuf::join` throws the base away when handed an absolute path — the
    /// file would be written wherever the listing says.
    #[test]
    fn refuses_an_absolute_path() {
        assert!(safe_relative_path("/home/victim/.cargo/config.toml").is_err());
        assert_eq!(
            std::path::PathBuf::from("/tmp/rules").join("/etc/passwd"),
            std::path::PathBuf::from("/etc/passwd"),
            "c'est bien pour cela que le controle existe"
        );
    }

    #[test]
    fn refuses_climbing_out() {
        assert!(safe_relative_path("a/../../../x.toml").is_err());
        assert!(safe_relative_path("../x.toml").is_err());
    }

    #[test]
    fn refuses_windows_flavoured_paths() {
        assert!(safe_relative_path("C:/windows/x.toml").is_err());
        assert!(safe_relative_path("a\\..\\b.toml").is_err());
    }
}
