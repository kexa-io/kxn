//! Live SSH monitoring collectors: `auth_stats`, `fail2ban_status`, `listening_ports`.
//!
//! Every other collector in this crate reads *configuration* — a file on disk, a
//! daemon's dumped settings — which is the same a second later. These three read
//! the host's *current state*, so a stale or guessed answer is worse than no
//! answer at all: the rules they feed are `INF`/`EQUAL` thresholds on counters,
//! and a missing counter reads as `0`, i.e. "no brute force here".
//!
//! Hence the one rule this module never breaks: **an empty vector when the host
//! could not tell us.** No fail2ban on the box, no readable authentication
//! journal, no `ss`/`netstat` — the engine then reports the rule as not
//! evaluated, which is the truth. Emitting `ssh_failed_last_hour: 0` because we
//! failed to open a log file would be asserting the absence of an attack we
//! never looked for; that is the trap this whole module is built around.
//!
//! Each command is POSIX `sh`, never fails (stderr swallowed, every step
//! `||`-chained), works on both Debian- and RHEL-shaped hosts, and delimits its
//! sections with `###KXN_*###` markers. A source that actually produced data
//! terminates its section with `###KXN_READABLE###`; that marker — never the
//! mere presence of the section — is what tells the parsers a source exists.

use chrono::{DateTime, Datelike, Duration, FixedOffset, NaiveDate, NaiveTime, TimeZone};
use regex::Regex;
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::IpAddr;
use std::sync::LazyLock;

// --- Section markers -------------------------------------------------------

const MARK_READABLE: &str = "###KXN_READABLE###";
const MARK_HOST_TIME: &str = "###KXN_HOST_TIME###";
const MARK_JOURNAL_PROBE: &str = "###KXN_JOURNAL_PROBE###";
const MARK_JOURNAL: &str = "###KXN_JOURNAL###";
const MARK_AUTH_LOG: &str = "###KXN_AUTH_LOG###";
const MARK_SECURE: &str = "###KXN_SECURE###";
const MARK_F2B_JAILS: &str = "###KXN_F2B_JAILS###";
const MARK_F2B_SSHD: &str = "###KXN_F2B_SSHD###";
const MARK_PORTS: &str = "###KXN_PORTS###";

// --- Tuning ----------------------------------------------------------------

/// The window the `ssh-failed-logins-*` rules are written against.
const AUTH_WINDOW_SECONDS: i64 = 3600;

/// Upper bound on log lines pulled per source, per cycle.
///
/// These commands run on every watch tick, so the cost has to stay flat on a
/// host under attack — an unbounded `cat /var/log/auth.log` on a box being
/// brute-forced is tens of megabytes across the SSH channel every few seconds.
/// 5000 lines is roughly an hour of a *very* noisy sshd (a failed login costs
/// 2-3 lines, so ~2000 failures) while staying a few hundred kilobytes.
/// When the cap does bite, the counts become a lower bound — see
/// `window_complete` in the emitted object.
const LOG_TAIL_LINES: usize = 5000;

/// Attacker addresses are attached to the object for triage, but the list is
/// unbounded in the wild (a distributed scan is thousands of hosts), so only a
/// sample travels into reports and webhooks.
const MAX_REPORTED_IPS: usize = 20;

// --- Commands --------------------------------------------------------------

/// Authentication failures over the last hour.
///
/// Three sources are collected in one round trip and the parser picks the first
/// usable one, journal first: `journalctl --since` filters the window on the
/// host, so the count never depends on us reconstructing the host's timezone or
/// the year that text syslog omits.
///
/// `###KXN_JOURNAL_PROBE###` exists because an *empty* windowed journal is
/// ambiguous — a genuinely quiet hour and a journal we are not allowed to read
/// both look like zero lines. The probe pulls the single most recent sshd entry
/// of all time: if that comes back, the journal is readable and "zero failures
/// this hour" is a real observation rather than a silent permission error.
///
/// `sudo -n` fallbacks never prompt; when sudo is absent they just fail like
/// any other missing binary.
pub(crate) const AUTH_STATS_COMMAND: &str = "echo '###KXN_HOST_TIME###'; \
date '+%Y-%m-%dT%H:%M:%S%z' 2>/dev/null || true; \
echo '###KXN_JOURNAL_PROBE###'; \
{ journalctl -u ssh -u sshd -n 1 --no-pager -q --output=short-iso 2>/dev/null \
|| sudo -n journalctl -u ssh -u sshd -n 1 --no-pager -q --output=short-iso 2>/dev/null; } \
&& echo '###KXN_READABLE###' || true; \
echo '###KXN_JOURNAL###'; \
{ journalctl -u ssh -u sshd --since '1 hour ago' -n 5000 --no-pager -q --output=short-iso 2>/dev/null \
|| sudo -n journalctl -u ssh -u sshd --since '1 hour ago' -n 5000 --no-pager -q --output=short-iso 2>/dev/null; } \
&& echo '###KXN_READABLE###' || true; \
echo '###KXN_AUTH_LOG###'; \
{ tail -n 5000 /var/log/auth.log 2>/dev/null || sudo -n tail -n 5000 /var/log/auth.log 2>/dev/null; } \
&& echo '###KXN_READABLE###' || true; \
echo '###KXN_SECURE###'; \
{ tail -n 5000 /var/log/secure 2>/dev/null || sudo -n tail -n 5000 /var/log/secure 2>/dev/null; } \
&& echo '###KXN_READABLE###' || true";

/// fail2ban jail state.
///
/// The global `fail2ban-client status` is asked first and is the availability
/// test for the whole object: it fails identically whether the binary is
/// missing or the server socket is dead, and in both cases we know nothing. Only
/// once the server has answered does `status sshd` mean something — a jail that
/// is genuinely absent from a live fail2ban is a real finding, not missing data.
/// `ssh` is tried after `sshd` for pre-0.9 jail naming.
pub(crate) const FAIL2BAN_COMMAND: &str = "echo '###KXN_F2B_JAILS###'; \
{ fail2ban-client status 2>/dev/null || sudo -n fail2ban-client status 2>/dev/null; } \
&& echo '###KXN_READABLE###' || true; \
echo '###KXN_F2B_SSHD###'; \
{ fail2ban-client status sshd 2>/dev/null || sudo -n fail2ban-client status sshd 2>/dev/null \
|| fail2ban-client status ssh 2>/dev/null || sudo -n fail2ban-client status ssh 2>/dev/null; } \
&& echo '###KXN_READABLE###' || true";

/// TCP sockets in LISTEN state.
///
/// `-p` is kept because the process name is worth having when a human reads the
/// report, but nothing here needs root: without privileges `ss` simply omits the
/// process column and still exits 0. Plain `ss -lnt` / `netstat -lnt` follow for
/// hosts whose tool rejects `-p`.
pub(crate) const LISTENING_PORTS_COMMAND: &str = "echo '###KXN_PORTS###'; \
{ ss -lntp 2>/dev/null || ss -lnt 2>/dev/null || netstat -lntp 2>/dev/null || netstat -lnt 2>/dev/null; } \
&& echo '###KXN_READABLE###' || true";

// --- Section splitting -----------------------------------------------------

#[derive(Default)]
struct Section<'a> {
    lines: Vec<&'a str>,
    /// The source behind this section ran and exited 0.
    readable: bool,
}

/// Split marker-delimited output. Anything before the first marker is dropped:
/// a login banner or an MOTD on the remote shell must not be mistaken for data.
fn split_sections(output: &str) -> HashMap<&str, Section<'_>> {
    let mut sections: HashMap<&str, Section<'_>> = HashMap::new();
    let mut current = "";
    for raw in output.lines() {
        let trimmed = raw.trim();
        if trimmed == MARK_READABLE {
            sections.entry(current).or_default().readable = true;
            continue;
        }
        if trimmed.starts_with("###KXN_") && trimmed.ends_with("###") {
            current = trimmed;
            sections.entry(current).or_default();
            continue;
        }
        if current.is_empty() || trimmed.is_empty() {
            continue;
        }
        sections.entry(current).or_default().lines.push(raw);
    }
    sections
}

// --- Timestamps ------------------------------------------------------------

/// Absolute forms: RFC3339, and the `short-iso` journal/`date` spelling whose
/// offset carries no colon.
fn parse_absolute_timestamp(token: &str) -> Option<DateTime<FixedOffset>> {
    DateTime::parse_from_rfc3339(token)
        .ok()
        .or_else(|| DateTime::parse_from_str(token, "%Y-%m-%dT%H:%M:%S%z").ok())
        .or_else(|| DateTime::parse_from_str(token, "%Y-%m-%dT%H:%M:%S%.f%z").ok())
}

fn month_from_abbrev(token: &str) -> Option<u32> {
    match token.to_ascii_lowercase().as_str() {
        "jan" => Some(1),
        "feb" => Some(2),
        "mar" => Some(3),
        "apr" => Some(4),
        "may" => Some(5),
        "jun" => Some(6),
        "jul" => Some(7),
        "aug" => Some(8),
        "sep" => Some(9),
        "oct" => Some(10),
        "nov" => Some(11),
        "dec" => Some(12),
        _ => None,
    }
}

/// Timestamp at the head of a log line, resolved against the host's own clock.
///
/// Two shapes occur in practice: the ISO stamp rsyslog and `journalctl
/// --output=short-iso` emit, which is unambiguous, and the BSD syslog stamp
/// (`Sep 25 10:11:03`) which has neither a year nor an offset. The latter is
/// read in the host's timezone — never ours, the scanner is routinely in another
/// one — and dated with the host's current year, rolled back when that would
/// place the line in the future, which is what happens to December lines read on
/// the 1st of January.
fn line_timestamp(line: &str, host_now: &DateTime<FixedOffset>) -> Option<DateTime<FixedOffset>> {
    let mut tokens = line.split_whitespace();
    let first = tokens.next()?;

    if let Some(ts) = parse_absolute_timestamp(first) {
        return Some(ts);
    }

    let month = month_from_abbrev(first)?;
    let day: u32 = tokens.next()?.parse().ok()?;
    let time = NaiveTime::parse_from_str(tokens.next()?, "%H:%M:%S").ok()?;
    let date = NaiveDate::from_ymd_opt(host_now.year(), month, day)?;
    let stamped = host_now
        .timezone()
        .from_local_datetime(&date.and_time(time))
        .single()?;

    // More than a day ahead of the host means we stamped a line from last year.
    if stamped > *host_now + Duration::days(1) {
        let previous = NaiveDate::from_ymd_opt(host_now.year() - 1, month, day)?;
        return host_now
            .timezone()
            .from_local_datetime(&previous.and_time(time))
            .single();
    }
    Some(stamped)
}

// --- auth_stats ------------------------------------------------------------

static RE_SSHD_PID: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"sshd\[(\d+)\]").expect("static regex"));

/// The authentication methods sshd reports as `Failed <method> for ...`.
static RE_FAILED_AUTH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"Failed (?:password|publickey|keyboard-interactive|hostbased|none)\b")
        .expect("static regex")
});

struct FailureLine {
    pid: Option<u64>,
    ip: Option<String>,
    /// `true` for a real authentication failure, `false` for the bare
    /// `Invalid user` notice that precedes one.
    hard: bool,
}

/// Peer address of an sshd log line.
///
/// The last `from <addr>` wins: sshd echoes the attacker-supplied username
/// verbatim, so a username spelled `x from 10.0.0.1` would otherwise let a
/// remote peer choose which IP we attribute the failure to. sshd's own
/// `from <addr>` is always the trailing one.
fn extract_peer_ip(line: &str) -> Option<String> {
    let tail = line.rsplit(" from ").next()?;
    let token = tail.split_whitespace().next()?;
    token.parse::<IpAddr>().ok().map(|ip| ip.to_string())
}

fn classify_failure(line: &str) -> Option<FailureLine> {
    // `Invalid user` capitalised is sshd's own message; the lowercase
    // `invalid user` inside "Failed password for invalid user ..." is not.
    let hard = RE_FAILED_AUTH.is_match(line);
    if !hard && !line.contains("Invalid user ") {
        return None;
    }
    Some(FailureLine {
        pid: RE_SSHD_PID
            .captures(line)
            .and_then(|c| c.get(1))
            .and_then(|m| m.as_str().parse().ok()),
        ip: extract_peer_ip(line),
        hard,
    })
}

/// Count failures, resisting the double counting sshd's own verbosity invites.
///
/// A single rejected attempt on an unknown account writes both
/// `Invalid user admin from ...` and `Failed password for invalid user admin
/// from ...`, under the same connection pid. Counting both would double every
/// brute-force number, so an `Invalid user` line is only counted when its pid
/// produced no `Failed ...` line — and when the pid is unreadable, it is counted
/// anyway: over-counting trips a threshold rule, under-counting hides an attack.
fn count_failures(lines: &[FailureLine]) -> (u64, Vec<String>) {
    let pids_with_hard: HashSet<u64> = lines
        .iter()
        .filter(|l| l.hard)
        .filter_map(|l| l.pid)
        .collect();

    let mut count = 0u64;
    let mut ips: BTreeSet<String> = BTreeSet::new();
    for line in lines {
        let counted = line.hard || line.pid.is_none_or(|p| !pids_with_hard.contains(&p));
        if counted {
            count += 1;
        }
        // Every hostile line contributes its address, counted or de-duplicated:
        // the IP is distinct whether or not its second log line was suppressed.
        if let Some(ip) = &line.ip {
            ips.insert(ip.clone());
        }
    }
    (count, ips.into_iter().collect())
}

/// Journal entries are already restricted to the window by `--since`, so no
/// client-side clock arithmetic happens here — the source is usable as soon as
/// the probe proved the journal readable.
fn journal_failures(section: &Section<'_>) -> (Vec<FailureLine>, usize) {
    let mut failures = Vec::new();
    let mut scanned = 0usize;
    for line in &section.lines {
        // `-- No entries --`, `-- Boot ... --`: journalctl's own chatter.
        if line.trim_start().starts_with("--") {
            continue;
        }
        scanned += 1;
        if let Some(failure) = classify_failure(line) {
            failures.push(failure);
        }
    }
    (failures, scanned)
}

/// Text logs mix every PAM consumer (sudo, cron, login), so lines are kept only
/// when sshd wrote them, and only when their timestamp falls in the window.
///
/// Returns `None` when the file yielded no parseable timestamp at all: a log
/// that exists but says nothing datable (freshly rotated, or in a format we do
/// not read) is missing information, not a quiet host.
fn text_log_failures(
    section: &Section<'_>,
    host_now: &DateTime<FixedOffset>,
) -> Option<(Vec<FailureLine>, bool)> {
    let window_start = *host_now - Duration::seconds(AUTH_WINDOW_SECONDS);
    let mut failures = Vec::new();
    let mut oldest: Option<DateTime<FixedOffset>> = None;
    let mut dated = 0usize;

    for line in &section.lines {
        let Some(ts) = line_timestamp(line, host_now) else {
            continue;
        };
        dated += 1;
        if oldest.is_none_or(|o| ts < o) {
            oldest = Some(ts);
        }
        if ts < window_start || ts > *host_now + Duration::seconds(300) {
            // The 5 minute tolerance absorbs a log writer whose clock runs
            // slightly ahead of `date`; anything beyond that is not this hour.
            continue;
        }
        if !line.contains("sshd[") && !line.contains(" sshd:") {
            continue;
        }
        if let Some(failure) = classify_failure(line) {
            failures.push(failure);
        }
    }

    if dated == 0 {
        return None;
    }
    // The tail cap only actually hid something if the oldest line we received is
    // still inside the window — then the beginning of the hour was cut off.
    let complete =
        section.lines.len() < LOG_TAIL_LINES || oldest.is_none_or(|o| o < window_start);
    Some((failures, complete))
}

/// Failed SSH authentications over the last hour, or nothing at all.
///
/// Emits at most one object: `ssh_failed_last_hour` and `ssh_failed_unique_ips`
/// as numbers, plus the provenance fields a human needs to trust them. Emits
/// **no** object when no authentication log could be read — see the module note.
pub(crate) fn parse_auth_stats(output: &str) -> Vec<Value> {
    let sections = split_sections(output);
    let empty = Section::default();
    let get = |marker: &str| -> &Section<'_> { sections.get(marker).unwrap_or(&empty) };

    let host_now = get(MARK_HOST_TIME)
        .lines
        .first()
        .map(|l| l.trim())
        .and_then(parse_absolute_timestamp);

    let probe = get(MARK_JOURNAL_PROBE);
    let journal = get(MARK_JOURNAL);

    let (failures, source, complete) = if probe.readable && !probe.lines.is_empty() {
        let (failures, scanned) = journal_failures(journal);
        (failures, "journalctl", scanned < LOG_TAIL_LINES)
    } else {
        // Every remaining source is a text log whose BSD timestamps only mean
        // something relative to the host's own clock and timezone. Without
        // `date` we cannot say which lines belong to this hour, and a count over
        // the wrong window is exactly the invented number this module refuses.
        let Some(host_now) = host_now else {
            return Vec::new();
        };
        let debian = get(MARK_AUTH_LOG);
        let rhel = get(MARK_SECURE);
        let picked = [("/var/log/auth.log", debian), ("/var/log/secure", rhel)]
            .into_iter()
            .filter(|(_, section)| section.readable)
            .find_map(|(path, section)| {
                text_log_failures(section, &host_now).map(|(f, c)| (f, path, c))
            });
        match picked {
            Some(picked) => picked,
            None => return Vec::new(),
        }
    };

    let (failed, ips) = count_failures(&failures);
    let unique_ips = ips.len() as u64;

    vec![json!({
        "ssh_failed_last_hour": failed,
        "ssh_failed_unique_ips": unique_ips,
        "source": source,
        "window_seconds": AUTH_WINDOW_SECONDS,
        // False when the tail cap truncated the window: the two counts are then
        // a lower bound, so a passing threshold proves less than it looks.
        "window_complete": complete,
        "failed_ips": ips.iter().take(MAX_REPORTED_IPS).collect::<Vec<_>>(),
    })]
}

// --- fail2ban_status -------------------------------------------------------

/// Value of a `|- Label: <value>` row of `fail2ban-client` tree output.
fn f2b_field<'a>(section: &Section<'a>, label: &str) -> Option<&'a str> {
    section.lines.iter().find_map(|line| {
        let (head, value) = line.split_once(':')?;
        head.contains(label).then(|| value.trim())
    })
}

/// fail2ban's view of the SSH jail, or nothing when fail2ban cannot answer.
///
/// `sshd_jail_active: false` is only ever emitted for a *live* fail2ban that has
/// no SSH jail — a genuine finding. A fail2ban that is not installed, or whose
/// server is down, produces no object: the `ssh-fail2ban-running` rule on the
/// `services` object is what covers that case, and answering here too would turn
/// one missing daemon into a second, misleading violation.
pub(crate) fn parse_fail2ban(output: &str) -> Vec<Value> {
    let sections = split_sections(output);
    let empty = Section::default();
    let get = |marker: &str| -> &Section<'_> { sections.get(marker).unwrap_or(&empty) };

    let global = get(MARK_F2B_JAILS);
    if !global.readable {
        return Vec::new();
    }

    let jails: Vec<String> = f2b_field(global, "Jail list")
        .map(|list| {
            list.split(',')
                .map(|j| j.trim().to_string())
                .filter(|j| !j.is_empty())
                .collect()
        })
        .unwrap_or_default();

    let sshd = get(MARK_F2B_SSHD);
    let active = sshd.readable
        && sshd
            .lines
            .iter()
            .any(|l| l.contains("Status for the jail:"));

    let number = |label: &str| -> u64 {
        f2b_field(sshd, label)
            .and_then(|v| v.split_whitespace().next())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    };

    let banned_ips: Vec<String> = f2b_field(sshd, "Banned IP list")
        .map(|list| {
            list.split_whitespace()
                .take(MAX_REPORTED_IPS)
                .map(|ip| ip.to_string())
                .collect()
        })
        .unwrap_or_default();

    vec![json!({
        "sshd_jail_active": active,
        // A jail that does not exist has banned nobody; that zero is observed,
        // not assumed, because the server answered the global status query.
        "sshd_banned_count": if active { number("Currently banned") } else { 0 },
        "sshd_total_banned": if active { number("Total banned") } else { 0 },
        "sshd_currently_failed": if active { number("Currently failed") } else { 0 },
        "jails": jails,
        "banned_ips": banned_ips,
    })]
}

// --- listening_ports -------------------------------------------------------

/// Port of a `host:port` column, in any of the spellings the two tools use:
/// `0.0.0.0:22`, `[::]:22`, `*:22`, `127.0.0.1:6010`.
///
/// Peer columns (`0.0.0.0:*`, `:::*`) and header cells (`Address:Port`) fail the
/// numeric test, which is what keeps this from needing per-tool column indexes.
fn local_port(token: &str) -> Option<u16> {
    let (addr, port) = token.rsplit_once(':')?;
    if addr.is_empty() {
        return None;
    }
    port.parse().ok()
}

/// TCP ports in LISTEN state, or nothing when neither `ss` nor `netstat` exists.
///
/// Beyond the `port_22` the SSH pack asks for, every observed port is exposed
/// twice: as `port_<n>` and in the `ports` array. That is deliberate — a rule
/// author can then assert `port_443 EQUAL "LISTEN"`, or that an unexpected port
/// is absent, without anyone touching this collector or shipping a new binary.
/// The rules become data, which is the whole point of a TOML rule pack.
pub(crate) fn parse_listening_ports(output: &str) -> Vec<Value> {
    let sections = split_sections(output);
    let Some(section) = sections.get(MARK_PORTS).filter(|s| s.readable) else {
        return Vec::new();
    };

    let mut ports: BTreeSet<u16> = BTreeSet::new();
    for line in &section.lines {
        if !line.contains("LISTEN") {
            continue;
        }
        for token in line.split_whitespace() {
            if let Some(port) = local_port(token) {
                ports.insert(port);
            }
        }
    }

    // The tool ran but reported no listening socket at all — impossible on a
    // host we just reached over SSH, so this is a parse or permission failure
    // rather than a closed machine. Saying "port 22 is CLOSED" here would raise
    // a critical alert out of our own blindness.
    if ports.is_empty() {
        return Vec::new();
    }

    let mut object = serde_json::Map::new();
    object.insert(
        "ports".into(),
        Value::Array(ports.iter().map(|p| json!(p)).collect()),
    );
    for port in &ports {
        object.insert(format!("port_{}", port), Value::String("LISTEN".into()));
    }
    object
        .entry("port_22".to_string())
        .or_insert_with(|| Value::String("CLOSED".into()));

    vec![Value::Object(object)]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tail bound lives in two places — a Rust constant used for the
    /// truncation verdict and a literal inside the shell command. They must
    /// agree or `window_complete` lies.
    #[test]
    fn commands_are_bounded_and_never_fail() {
        assert!(AUTH_STATS_COMMAND.contains(&LOG_TAIL_LINES.to_string()));
        for cmd in [AUTH_STATS_COMMAND, FAIL2BAN_COMMAND, LISTENING_PORTS_COMMAND] {
            assert!(cmd.contains("2>/dev/null"), "stderr must be swallowed");
            assert!(cmd.contains("|| true"), "command must always exit 0");
            assert!(cmd.contains(MARK_READABLE));
        }
    }

    // --- auth_stats ---

    const AUTH_LOG_SAMPLE: &str = "\
Sep 25 09:58:01 web01 sshd[2101]: Invalid user admin from 203.0.113.4 port 52134
Sep 25 09:58:03 web01 sshd[2101]: Failed password for invalid user admin from 203.0.113.4 port 52134 ssh2
Sep 25 09:58:03 web01 sshd[2101]: Connection closed by invalid user admin 203.0.113.4 port 52134 [preauth]
Sep 25 10:02:11 web01 sshd[2140]: Failed password for root from 198.51.100.7 port 41022 ssh2
Sep 25 10:02:14 web01 sshd[2140]: Failed password for root from 198.51.100.7 port 41022 ssh2
Sep 25 10:05:00 web01 sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/systemctl restart nginx
Sep 25 10:07:42 web01 sshd[2199]: Invalid user test from 192.0.2.9 port 33110
Sep 25 10:07:45 web01 sshd[2199]: Failed password for invalid user test from 192.0.2.9 port 33110 ssh2
Sep 25 10:20:01 web01 sshd[2250]: Accepted publickey for deploy from 10.0.0.5 port 58822 ssh2: ED25519 SHA256:7Yb
Sep 25 08:15:00 web01 sshd[1900]: Failed password for invalid user oracle from 203.0.113.99 port 40000 ssh2";

    fn auth_output(host_time: &str, journal_probe: &str, journal: &str, auth_log: &str) -> String {
        let mut out = format!("###KXN_HOST_TIME###\n{}\n", host_time);
        out.push_str("###KXN_JOURNAL_PROBE###\n");
        if !journal_probe.is_empty() {
            out.push_str(journal_probe);
            out.push_str("\n###KXN_READABLE###\n");
        }
        out.push_str("###KXN_JOURNAL###\n");
        if !journal.is_empty() {
            out.push_str(journal);
            out.push_str("\n###KXN_READABLE###\n");
        }
        out.push_str("###KXN_AUTH_LOG###\n");
        if !auth_log.is_empty() {
            out.push_str(auth_log);
            out.push_str("\n###KXN_READABLE###\n");
        }
        out.push_str("###KXN_SECURE###\n");
        out
    }

    #[test]
    fn auth_stats_counts_debian_auth_log_within_the_hour() {
        let output = auth_output("2026-09-25T10:30:12+0200", "", "", AUTH_LOG_SAMPLE);
        let result = parse_auth_stats(&output);
        assert_eq!(result.len(), 1);
        let stats = &result[0];
        // Four `Failed password` lines in the window; the two `Invalid user`
        // notices share their pid with one, the 08:15 failure is an hour old,
        // and the sudo and Accepted lines are not failures.
        assert_eq!(stats["ssh_failed_last_hour"], 4);
        assert_eq!(stats["ssh_failed_unique_ips"], 3);
        assert_eq!(stats["source"], "/var/log/auth.log");
        assert_eq!(stats["window_complete"], true);
        let ips = stats["failed_ips"].as_array().unwrap();
        assert!(ips.iter().any(|ip| ip == "203.0.113.4"));
        assert!(
            !ips.iter().any(|ip| ip == "203.0.113.99"),
            "an IP seen only outside the window must not be reported"
        );
    }

    #[test]
    fn auth_stats_reads_rhel_secure_when_auth_log_is_absent() {
        let mut output = String::from("###KXN_HOST_TIME###\n2026-09-25T10:30:12+0200\n");
        output.push_str("###KXN_JOURNAL_PROBE###\n###KXN_JOURNAL###\n###KXN_AUTH_LOG###\n");
        output.push_str("###KXN_SECURE###\n");
        output.push_str(
            "Sep 25 10:11:12 rhel8 sshd[4410]: Failed password for invalid user admin from 203.0.113.4 port 52134 ssh2\n\
             Sep 25 10:11:20 rhel8 sshd[4412]: Failed password for root from 198.51.100.7 port 41022 ssh2\n",
        );
        output.push_str("###KXN_READABLE###\n");
        let result = parse_auth_stats(&output);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["ssh_failed_last_hour"], 2);
        assert_eq!(result[0]["ssh_failed_unique_ips"], 2);
        assert_eq!(result[0]["source"], "/var/log/secure");
    }

    #[test]
    fn auth_stats_prefers_the_journal_and_trusts_its_own_window() {
        let probe = "2026-09-25T10:20:01+0200 web01 sshd[2250]: Accepted publickey for deploy from 10.0.0.5 port 58822 ssh2: ED25519 SHA256:7Yb";
        let journal = "\
-- Logs begin at Tue 2026-09-01 08:00:00 CEST. --
2026-09-25T09:58:01+0200 web01 sshd[2101]: Invalid user admin from 203.0.113.4 port 52134
2026-09-25T09:58:03+0200 web01 sshd[2101]: Failed password for invalid user admin from 203.0.113.4 port 52134 ssh2
2026-09-25T10:02:11+0200 web01 sshd[2140]: Failed password for root from 198.51.100.7 port 41022 ssh2
2026-09-25T10:07:42+0200 web01 sshd[2199]: Invalid user test from 192.0.2.9 port 33110
2026-09-25T10:19:05+0200 web01 sshd[2244]: Failed publickey for git from 192.0.2.55 port 40100 ssh2: RSA SHA256:abc";
        // Both sources readable: the journal wins because its window was filtered
        // on the host, and the stale auth.log tail must not be counted twice.
        let output = auth_output("2026-09-25T10:30:12+0200", probe, journal, AUTH_LOG_SAMPLE);
        let result = parse_auth_stats(&output);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["source"], "journalctl");
        // 3 hard failures + the pid-2199 `Invalid user` that never produced one.
        assert_eq!(result[0]["ssh_failed_last_hour"], 4);
        assert_eq!(result[0]["ssh_failed_unique_ips"], 4);
    }

    #[test]
    fn auth_stats_reports_zero_only_when_a_source_proved_readable() {
        // A readable journal (the probe answered) with a genuinely quiet hour.
        let probe = "2026-09-25T10:20:01+0200 web01 sshd[2250]: Accepted publickey for deploy from 10.0.0.5 port 58822 ssh2: ED25519 SHA256:7Yb";
        let output = auth_output("2026-09-25T10:30:12+0200", probe, "", "");
        let result = parse_auth_stats(&output);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["ssh_failed_last_hour"], 0);
        assert_eq!(result[0]["ssh_failed_unique_ips"], 0);
    }

    #[test]
    fn auth_stats_is_empty_when_no_log_can_be_read() {
        // No journal, no auth.log, no secure: the host never told us anything.
        let output = auth_output("2026-09-25T10:30:12+0200", "", "", "");
        assert!(
            parse_auth_stats(&output).is_empty(),
            "an unreadable host must never be reported as attack-free"
        );
        assert!(parse_auth_stats("").is_empty());
    }

    #[test]
    fn auth_stats_is_empty_when_the_journal_is_silently_unreadable() {
        // journalctl exits 0 and prints nothing for a user outside the
        // systemd-journal group; without the probe this would read as zero.
        let mut output = String::from("###KXN_HOST_TIME###\n2026-09-25T10:30:12+0200\n");
        output.push_str("###KXN_JOURNAL_PROBE###\n###KXN_READABLE###\n");
        output.push_str("###KXN_JOURNAL###\n###KXN_READABLE###\n");
        output.push_str("###KXN_AUTH_LOG###\n###KXN_SECURE###\n");
        assert!(parse_auth_stats(&output).is_empty());
    }

    #[test]
    fn auth_stats_is_empty_for_a_readable_but_undatable_log() {
        // auth.log opened fine but was rotated a second ago: no line, nothing
        // observed about the last hour.
        let output = auth_output("2026-09-25T10:30:12+0200", "", "", "\n");
        assert!(parse_auth_stats(&output).is_empty());
    }

    #[test]
    fn auth_stats_is_empty_without_the_host_clock() {
        // BSD syslog stamps carry no year and no offset; without `date` the
        // window cannot be placed, so no number is worth emitting.
        let output = auth_output("", "", "", AUTH_LOG_SAMPLE);
        assert!(parse_auth_stats(&output).is_empty());
    }

    #[test]
    fn auth_stats_handles_the_new_year_rollover() {
        let output = auth_output(
            "2026-01-01T00:20:00+0100",
            "",
            "",
            "Dec 31 23:59:01 web01 sshd[9001]: Failed password for root from 203.0.113.4 port 41022 ssh2\n\
             Dec 31 22:00:00 web01 sshd[9000]: Failed password for root from 198.51.100.7 port 41022 ssh2",
        );
        let result = parse_auth_stats(&output);
        assert_eq!(result.len(), 1);
        // 23:59 of last year is 21 minutes ago; 22:00 is outside the hour.
        assert_eq!(result[0]["ssh_failed_last_hour"], 1);
        assert_eq!(result[0]["ssh_failed_unique_ips"], 1);
    }

    #[test]
    fn auth_stats_attributes_the_address_sshd_wrote_not_the_username() {
        let output = auth_output(
            "2026-09-25T10:30:12+0200",
            "",
            "",
            "Sep 25 10:29:00 web01 sshd[3000]: Failed password for invalid user x from 10.0.0.1 from 203.0.113.4 port 52134 ssh2",
        );
        let result = parse_auth_stats(&output);
        assert_eq!(result[0]["failed_ips"][0], "203.0.113.4");
    }

    // --- fail2ban_status ---

    const F2B_GLOBAL: &str = "\
Status
|- Number of jail:\t2
`- Jail list:\tsshd, nginx-http-auth";

    const F2B_SSHD: &str = "\
Status for the jail: sshd
|- Filter
|  |- Currently failed:\t2
|  |- Total failed:\t147
|  `- File list:\t/var/log/auth.log
`- Actions
   |- Currently banned:\t3
   |- Total banned:\t12
   `- Banned IP list:\t203.0.113.4 198.51.100.7 192.0.2.9";

    #[test]
    fn fail2ban_reads_a_live_sshd_jail() {
        let output = format!(
            "###KXN_F2B_JAILS###\n{}\n###KXN_READABLE###\n###KXN_F2B_SSHD###\n{}\n###KXN_READABLE###\n",
            F2B_GLOBAL, F2B_SSHD
        );
        let result = parse_fail2ban(&output);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["sshd_jail_active"], true);
        assert_eq!(result[0]["sshd_banned_count"], 3);
        assert_eq!(result[0]["sshd_total_banned"], 12);
        assert_eq!(result[0]["sshd_currently_failed"], 2);
        assert_eq!(result[0]["jails"][1], "nginx-http-auth");
        assert_eq!(result[0]["banned_ips"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn fail2ban_reports_a_missing_jail_on_a_live_server() {
        // fail2ban answers, but nothing guards SSH: a real finding, not a gap.
        let output = "###KXN_F2B_JAILS###\nStatus\n|- Number of jail:\t1\n`- Jail list:\tnginx-http-auth\n###KXN_READABLE###\n###KXN_F2B_SSHD###\n";
        let result = parse_fail2ban(output);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["sshd_jail_active"], false);
        assert_eq!(result[0]["sshd_banned_count"], 0);
    }

    #[test]
    fn fail2ban_is_empty_when_not_installed_or_not_answering() {
        // `fail2ban-client` missing, or the server socket dead: both leave the
        // global status section without its readable marker.
        let output = "###KXN_F2B_JAILS###\n###KXN_F2B_SSHD###\n";
        assert!(parse_fail2ban(output).is_empty());
        assert!(parse_fail2ban("").is_empty());
    }

    // --- listening_ports ---

    const SS_WITH_22: &str = "\
State     Recv-Q    Send-Q        Local Address:Port        Peer Address:Port   Process
LISTEN    0         4096              127.0.0.1:6379             0.0.0.0:*       users:((\"redis-server\",pid=712,fd=6))
LISTEN    0         128                 0.0.0.0:22               0.0.0.0:*       users:((\"sshd\",pid=801,fd=3))
LISTEN    0         511                       *:443                    *:*       users:((\"nginx\",pid=960,fd=7))
LISTEN    0         128                    [::]:22                  [::]:*       users:((\"sshd\",pid=801,fd=4))";

    #[test]
    fn listening_ports_marks_port_22_listening() {
        let output = format!("###KXN_PORTS###\n{}\n###KXN_READABLE###\n", SS_WITH_22);
        let result = parse_listening_ports(&output);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["port_22"], "LISTEN");
        assert_eq!(result[0]["port_443"], "LISTEN");
        assert_eq!(result[0]["port_6379"], "LISTEN");
        assert_eq!(result[0]["ports"], json!([22, 443, 6379]));
    }

    #[test]
    fn listening_ports_marks_port_22_closed_when_sshd_moved() {
        let output = "###KXN_PORTS###\n\
State     Recv-Q    Send-Q        Local Address:Port        Peer Address:Port   Process\n\
LISTEN    0         128                 0.0.0.0:2222             0.0.0.0:*       users:((\"sshd\",pid=801,fd=3))\n\
LISTEN    0         511                       *:80                     *:*       users:((\"nginx\",pid=960,fd=7))\n\
###KXN_READABLE###\n";
        let result = parse_listening_ports(output);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["port_22"], "CLOSED");
        assert_eq!(result[0]["port_2222"], "LISTEN");
        assert_eq!(result[0]["ports"], json!([80, 2222]));
    }

    #[test]
    fn listening_ports_reads_the_netstat_fallback() {
        let output = "###KXN_PORTS###\n\
Active Internet connections (only servers)\n\
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\n\
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      801/sshd\n\
tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN      1102/master\n\
tcp6       0      0 :::22                   :::*                    LISTEN      801/sshd\n\
###KXN_READABLE###\n";
        let result = parse_listening_ports(output);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["port_22"], "LISTEN");
        assert_eq!(result[0]["ports"], json!([22, 25]));
    }

    #[test]
    fn listening_ports_is_empty_without_ss_or_netstat() {
        assert!(parse_listening_ports("###KXN_PORTS###\n").is_empty());
        assert!(parse_listening_ports("").is_empty());
        // Tool ran but listed nothing — impossible on a host we just reached
        // over SSH, so we stay silent instead of alerting on port 22.
        let header_only = "###KXN_PORTS###\nState Recv-Q Send-Q Local Address:Port Peer Address:Port\n###KXN_READABLE###\n";
        assert!(parse_listening_ports(header_only).is_empty());
    }
}
