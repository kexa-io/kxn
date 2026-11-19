//! Tell interactive users when a newer kxn release exists.
//!
//! At most one check a day, cached in the kxn cache directory, made in the
//! background while the command runs: a command never waits for it. The
//! check reads where `github.com/kexa-io/kxn/releases/latest` redirects to,
//! not the GitHub API, so it has no rate limit and sends nothing but the
//! request itself. Silent in CI, when stderr is not a terminal, and with
//! `KXN_NO_UPDATE_CHECK=1`.

use std::io::IsTerminal;
use std::path::PathBuf;
use std::sync::Mutex;

/// The background check started by `start`, awaited by `finish`.
static PENDING: Mutex<Option<tokio::task::JoinHandle<()>>> = Mutex::new(None);

const LATEST_URL: &str = "https://github.com/kexa-io/kxn/releases/latest";
const CHECK_EVERY_SECS: i64 = 86_400;

#[derive(serde::Serialize, serde::Deserialize)]
struct Cache {
    checked_at: i64,
    latest: String,
}

fn cache_file() -> Option<PathBuf> {
    dirs::cache_dir().map(|d| d.join("kxn").join("update-check.json"))
}

fn enabled() -> bool {
    let off = |v: &str| std::env::var(v).map(|s| !s.is_empty() && s != "0").unwrap_or(false);
    !off("KXN_NO_UPDATE_CHECK") && !off("CI") && std::io::stderr().is_terminal()
}

/// `major.minor.patch` of a version or tag (`v0.58.0`); pre-releases and
/// anything unparsable give `None`, so they never trigger a notice.
fn parse(v: &str) -> Option<(u64, u64, u64)> {
    let v = v.trim().trim_start_matches('v');
    if v.contains('-') {
        return None;
    }
    let mut it = v.split('.').map(|p| p.parse::<u64>().ok());
    Some((it.next()??, it.next()??, it.next()??))
}

fn is_newer(latest: &str, current: &str) -> bool {
    matches!((parse(latest), parse(current)), (Some(l), Some(c)) if l > c)
}

fn upgrade_command() -> &'static str {
    match crate::commands::update::detect_install_method() {
        crate::commands::update::InstallMethod::Homebrew => "brew upgrade kxn",
        crate::commands::update::InstallMethod::Cargo => {
            "cargo install --git https://github.com/kexa-io/kxn kxn-cli"
        }
        _ => "kxn update --apply",
    }
}

/// Print the notice if the cached check already knows a newer release, and
/// refresh the cache in the background when it is older than a day.
pub fn start() {
    if !enabled() {
        return;
    }
    let Some(file) = cache_file() else { return };
    let current = env!("CARGO_PKG_VERSION");
    let cached: Option<Cache> = std::fs::read_to_string(&file)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok());

    if let Some(c) = &cached {
        if is_newer(&c.latest, current) {
            eprintln!(
                "\x1b[33m⚠  kxn {current} is outdated — {} is available. Upgrade: {}\x1b[0m",
                c.latest,
                upgrade_command()
            );
        }
    }

    let now = chrono::Utc::now().timestamp();
    if cached.as_ref().is_some_and(|c| now - c.checked_at < CHECK_EVERY_SECS) {
        return;
    }
    let handle = tokio::spawn(async move {
        if let Some(latest) = fetch_latest().await {
            if let Some(dir) = file.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            let cache = Cache { checked_at: now, latest };
            if let Ok(json) = serde_json::to_string(&cache) {
                let _ = std::fs::write(&file, json);
            }
        }
    });
    if let Ok(mut pending) = PENDING.lock() {
        *pending = Some(handle);
    }
}

/// Let a pending check finish before the process exits — a short command
/// would otherwise end before it and the cache would never be written. Waits
/// at most 2 s, only on the run that refreshes the daily cache.
pub async fn finish() {
    let handle = PENDING.lock().ok().and_then(|mut p| p.take());
    if let Some(h) = handle {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), h).await;
    }
}

/// The tag `releases/latest` redirects to (`…/releases/tag/v0.58.0`).
async fn fetch_latest() -> Option<String> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(5))
        .user_agent(concat!("kxn/", env!("CARGO_PKG_VERSION")))
        .build()
        .ok()?;
    let resp = client.head(LATEST_URL).send().await.ok()?;
    let location = resp.headers().get(reqwest::header::LOCATION)?.to_str().ok()?;
    let tag = location.rsplit('/').next()?.to_string();
    parse(&tag).map(|_| tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_higher_stable_release_counts() {
        assert!(is_newer("v0.59.0", "0.58.0"));
        assert!(is_newer("v1.0.0", "0.58.3"));
        assert!(!is_newer("v0.58.0", "0.58.0"));
        assert!(!is_newer("v0.57.9", "0.58.0"));
        assert!(!is_newer("v0.59.0-rc.1", "0.58.0"));
        assert!(!is_newer("garbage", "0.58.0"));
    }
}
