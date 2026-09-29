//! Linux OS-hardening collectors for the CIS Distribution-Independent
//! benchmark (`rules/linux-cis.toml`).
//!
//! Four objects nothing else produces: `pam_config`, `audit_config`,
//! `firewall_config`, `filesystem_config`. Each is one shell command run on the
//! remote host and one parser turning its stdout into a single JSON object.
//!
//! # Why an empty vector matters
//!
//! `kxn-rules` turns an empty resource list into `NotEvaluated::NoSuchResource`
//! — the rule is reported as "not evaluated" rather than as a pass or a
//! violation. A *missing property inside* an emitted object gets no such
//! treatment: `check_condition` substitutes `Value::String("")` for an absent
//! property, every comparison then fails, and the rule is reported as a
//! violation the host never committed. So the rule of the house is:
//!
//! * host cannot be judged at all (not Linux, tooling absent, output
//!   unreadable) → return `vec![]` and let the engine say "not evaluated";
//! * host can be judged → emit **every** field of the object, never a subset,
//!   filling each one with the value that reflects reality (a module nothing
//!   blacklists is `false`, a mount option nobody set is simply not in the
//!   option string, an unset `auditd.conf` key is an empty string).
//!
//! # Why markers
//!
//! Each command is a small POSIX `sh` script that can never fail — every probe
//! is guarded by `command -v`, every error stream is redirected, nothing is
//! chained with a bare `&&` that could abort the rest. The output is cut into
//! named sections by `###KXN-…###` lines so the parser never has to rely on
//! output ordering or on a probe having produced anything at all. Secondary
//! in-band flags use `%%…%%` so they do not look like section headers.

use regex::Regex;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

// ─── Commands ───────────────────────────────────────────────────────────────

/// Debian and RHEL disagree on where the PAM stack lives: Debian/Ubuntu split
/// it into `common-{auth,password,account}`, RHEL/CentOS/Fedora into
/// `system-auth` and `password-auth` (themselves symlinks maintained by
/// `authselect` on RHEL 8+). Both sets are concatenated into one section — a
/// PAM line carries its own type keyword (`auth`, `password`, …) so nothing is
/// lost by merging the files, and it keeps the parser free of per-distro
/// branches. `/etc/pam.d/su` is kept apart because CIS 5.4.1 is specifically
/// about *that* file and a `pam_wheel` line anywhere else would not restrict
/// `su`.
///
/// `ls -1 /etc/pam.d` is not used for any verdict; it is there so that a host
/// whose stack the parser could not read shows, in the raw output, whether PAM
/// exists at all and under which file names — the difference between "no PAM"
/// and "PAM with a layout we do not know" is the first thing an operator asks.
pub(crate) const PAM_COMMAND: &str = r#"
# These collectors describe a Linux host. On anything else — a macOS laptop
# reached through the `local` provider, a BSD box — there is nothing to read,
# and the work must not be done at all: the world-writable sweep below walked
# an entire disk for nine minutes before the parser concluded, correctly, that
# it had nothing. No marker is emitted, so the parser returns an empty list and
# the engine reports the rules as not evaluated.
[ -r /proc/mounts ] || exit 0
echo '###KXN-PAM-DIR###'
ls -1 /etc/pam.d 2>/dev/null
echo '###KXN-PAM-STACK###'
cat /etc/pam.d/common-password /etc/pam.d/common-auth /etc/pam.d/common-account 2>/dev/null
cat /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null
echo '###KXN-PAM-SU###'
cat /etc/pam.d/su 2>/dev/null
echo '###KXN-PWQUALITY###'
cat /etc/security/pwquality.conf 2>/dev/null
cat /etc/security/pwquality.conf.d/*.conf 2>/dev/null
echo '###KXN-PWHISTORY###'
cat /etc/security/pwhistory.conf 2>/dev/null
echo '###KXN-FAILLOCK###'
cat /etc/security/faillock.conf 2>/dev/null
echo '###KXN-PAM-END###'
"#;

/// `systemctl is-enabled`/`is-active` is the only portable way to tell whether
/// auditd and the log daemons are supposed to run; it is guarded by
/// `command -v` so that a non-systemd host produces an *empty* section instead
/// of a section full of `unknown`, which is what lets the parser fall back to
/// the process table rather than concluding "disabled" from a missing tool.
///
/// `auditctl -s` reports the *live* kernel backlog limit and is the
/// authoritative answer, but it needs root; `/etc/audit/rules.d/*.rules` and
/// `audit.rules` carry the `-b` that will be applied at boot, and
/// `/proc/cmdline` carries `audit_backlog_limit=` set by the bootloader. All
/// three land in the same sections and are consulted in that order of trust.
///
/// `syslog-ng` is probed alongside `rsyslog` because RHEL derivatives and
/// appliance images ship it as the rsyslog replacement; CIS 8.2.1 is satisfied
/// by either.
pub(crate) const AUDIT_COMMAND: &str = r#"
# These collectors describe a Linux host. On anything else — a macOS laptop
# reached through the `local` provider, a BSD box — there is nothing to read,
# and the work must not be done at all: the world-writable sweep below walked
# an entire disk for nine minutes before the parser concluded, correctly, that
# it had nothing. No marker is emitted, so the parser returns an empty list and
# the engine reports the rules as not evaluated.
[ -r /proc/mounts ] || exit 0
echo '###KXN-AUDIT-UNITS###'
if command -v systemctl >/dev/null 2>&1; then
  for u in auditd rsyslog syslog-ng systemd-journald; do
    printf '%s enabled=%s active=%s\n' "$u" "$(systemctl is-enabled "$u" 2>/dev/null || echo unknown)" "$(systemctl is-active "$u" 2>/dev/null || echo unknown)"
  done
fi
echo '###KXN-AUDIT-PROCS###'
ps -eo comm= 2>/dev/null | sort -u || ps 2>/dev/null
echo '###KXN-AUDITD-CONF###'
cat /etc/audit/auditd.conf 2>/dev/null
echo '###KXN-AUDIT-RULES###'
auditctl -s 2>/dev/null
cat /etc/audit/audit.rules 2>/dev/null
cat /etc/audit/rules.d/*.rules 2>/dev/null
echo '###KXN-AUDIT-CMDLINE###'
cat /proc/cmdline 2>/dev/null
echo '###KXN-AUDIT-END###'
"#;

/// Four firewall front-ends coexist in the wild and they can all be installed
/// at once (Ubuntu ships `ufw` on top of `iptables`, which on both families is
/// nowadays the `iptables-nft` shim over the same nftables engine). The command
/// probes each one and lets the parser decide which one is actually in charge.
///
/// `%%KXN-NFT-OK%%` / `%%KXN-IPT-OK%%` are emitted only when the corresponding
/// dump *succeeded*. That distinction is load-bearing: an empty `nft list
/// ruleset` from root means "nothing is filtering", while the same empty output
/// from an unprivileged account means "we were not allowed to look". Without
/// the flag the parser would read the second case as a wide-open firewall and
/// invent a violation.
pub(crate) const FIREWALL_COMMAND: &str = r#"
# These collectors describe a Linux host. On anything else — a macOS laptop
# reached through the `local` provider, a BSD box — there is nothing to read,
# and the work must not be done at all: the world-writable sweep below walked
# an entire disk for nine minutes before the parser concluded, correctly, that
# it had nothing. No marker is emitted, so the parser returns an empty list and
# the engine reports the rules as not evaluated.
[ -r /proc/mounts ] || exit 0
echo '###KXN-FW-TOOLS###'
for b in iptables nft ufw firewall-cmd; do command -v "$b" >/dev/null 2>&1 && echo "$b"; done
echo '###KXN-FW-UFW###'
command -v ufw >/dev/null 2>&1 && ufw status verbose 2>/dev/null
echo '###KXN-FW-FIREWALLD###'
if command -v firewall-cmd >/dev/null 2>&1; then
  echo "state=$(firewall-cmd --state 2>/dev/null || echo not-running)"
  KXN_ZONE=$(firewall-cmd --get-default-zone 2>/dev/null)
  echo "default-zone=$KXN_ZONE"
  [ -n "$KXN_ZONE" ] && firewall-cmd --info-zone="$KXN_ZONE" 2>/dev/null
fi
echo '###KXN-FW-NFT###'
if command -v nft >/dev/null 2>&1; then
  KXN_NFT=$(nft list ruleset 2>/dev/null) && echo '%%KXN-NFT-OK%%'
  printf '%s\n' "$KXN_NFT" | head -n 200
fi
echo '###KXN-FW-IPTABLES###'
if command -v iptables >/dev/null 2>&1; then
  KXN_IPT=$(iptables -S 2>/dev/null) && echo '%%KXN-IPT-OK%%'
  printf '%s\n' "$KXN_IPT" | head -n 200
fi
echo '###KXN-FW-SYSTEMD###'
if command -v systemctl >/dev/null 2>&1; then
  for u in ufw firewalld nftables iptables netfilter-persistent; do
    printf '%s enabled=%s active=%s\n' "$u" "$(systemctl is-enabled "$u" 2>/dev/null || echo unknown)" "$(systemctl is-active "$u" 2>/dev/null || echo unknown)"
  done
fi
echo '###KXN-FW-END###'
"#;

/// `findmnt` gives the cleanest `TARGET FSTYPE OPTIONS` triples but is absent
/// from busybox images and from some minimal RHEL installs, so
/// `/proc/self/mounts` (always there on Linux, no tool required) and finally
/// legacy `mount` output are collected as fallbacks.
///
/// Module state is read from the merged `modprobe --showconfig` where kmod
/// supports it, plus the raw drop-in directories: Debian keeps them in
/// `/etc/modprobe.d`, RHEL 8+ also ships vendor defaults in
/// `/usr/lib/modprobe.d`, and `/run/modprobe.d` holds runtime overrides.
/// `modprobe -n -v` is the dry run that reveals both an `install … /bin/true`
/// override and a module that simply does not exist for the running kernel.
/// `modprobe` lives in `/sbin`, which is not on a normal user's PATH on Debian,
/// hence the explicit fallback path.
///
/// The world-writable sweep is the expensive part. `find / -xdev …` alone would
/// miss exactly the partitions CIS wants separated (`/tmp`, `/var/tmp`), since
/// `-xdev` stops at a mount point — so the scan is repeated per candidate mount
/// and the parser de-duplicates the paths. It is bounded three ways: a 30s
/// `timeout` per target (when coreutils' `timeout` exists), a `head -n 300` cap
/// on the reported paths, and a fixed target list rather than every mount on
/// the box. `%%KXN-WW-COMPLETE%%` is printed only when no target was cut short
/// by the timeout, so the parser can tell "found nothing" from "did not finish".
pub(crate) const FILESYSTEM_COMMAND: &str = r#"
# These collectors describe a Linux host. On anything else — a macOS laptop
# reached through the `local` provider, a BSD box — there is nothing to read,
# and the work must not be done at all: the world-writable sweep below walked
# an entire disk for nine minutes before the parser concluded, correctly, that
# it had nothing. No marker is emitted, so the parser returns an empty list and
# the engine reports the rules as not evaluated.
[ -r /proc/mounts ] || exit 0
KXN_MP=$(command -v modprobe 2>/dev/null || echo /sbin/modprobe)
echo '###KXN-FS-MOUNTS###'
findmnt -rn -o TARGET,FSTYPE,OPTIONS 2>/dev/null
echo '###KXN-FS-PROCMOUNTS###'
cat /proc/self/mounts 2>/dev/null || mount 2>/dev/null
echo '###KXN-FS-MODCONF###'
"$KXN_MP" --showconfig 2>/dev/null
cat /etc/modprobe.conf 2>/dev/null
cat /etc/modprobe.d/* /run/modprobe.d/* /usr/lib/modprobe.d/* 2>/dev/null
echo '###KXN-FS-MOD-CRAMFS###'
"$KXN_MP" -n -v cramfs 2>&1 | head -n 3
echo '###KXN-FS-MOD-FREEVXFS###'
"$KXN_MP" -n -v freevxfs 2>&1 | head -n 3
echo '###KXN-FS-MOD-USBSTORAGE###'
"$KXN_MP" -n -v usb_storage 2>&1 | head -n 3
echo '###KXN-FS-WORLDWRITABLE###'
{ KXN_OK=1
  # Two independent bounds, because neither is enough on its own. `timeout` is
  # coreutils, not POSIX: on macOS or busybox the guard silently disappeared and
  # the sweep walked an entire disk — minutes of a scan cycle, on every cycle.
  # The depth cap is what actually bounds the work everywhere; the timeout stays
  # for the pathological directory that is shallow but enormous. Depth 8 covers
  # where world-writable directories are found in practice, and a sweep that was
  # cut short says so rather than reporting zero.
  command -v timeout >/dev/null 2>&1 && KXN_FIND='timeout 30 find' || { KXN_FIND=find; KXN_OK=0; }
  for m in / /tmp /var /var/tmp /var/log /home /dev/shm; do
    [ -d "$m" ] || continue
    $KXN_FIND "$m" -xdev -maxdepth 8 -type d -perm -0002 ! -perm -1000 -print 2>/dev/null
    KXN_RC=$?
    [ "$KXN_RC" = 124 ] && KXN_OK=0
    [ "$KXN_RC" = 137 ] && KXN_OK=0
  done
  [ "$KXN_OK" = 1 ] && echo '%%KXN-WW-COMPLETE%%'
} | head -n 300
echo '###KXN-FS-END###'
"#;

// ─── Shared helpers ─────────────────────────────────────────────────────────

/// Cut marker-delimited stdout into named sections. Anything before the first
/// marker is dropped, which also swallows a login banner an SSH target may
/// prepend to the first command's output.
fn sections(output: &str) -> BTreeMap<String, String> {
    let mut map: BTreeMap<String, String> = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("###KXN-") && trimmed.ends_with("###") {
            let name = trimmed.trim_matches('#').to_string();
            map.entry(name.clone()).or_default();
            current = Some(name);
            continue;
        }
        if let Some(name) = current.as_ref() {
            let body = map.entry(name.clone()).or_default();
            body.push_str(line);
            body.push('\n');
        }
    }
    map
}

fn sec<'a>(map: &'a BTreeMap<String, String>, name: &str) -> &'a str {
    map.get(name).map(String::as_str).unwrap_or("")
}

/// Configuration lines with comments removed and blanks dropped. `#` starts a
/// comment anywhere on the line in every file read here (PAM stacks,
/// `pwquality.conf`, `auditd.conf`, `modprobe.d` drop-ins).
fn live_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .map(|l| match l.find('#') {
            Some(i) => &l[..i],
            None => l,
        })
        .map(str::trim)
        .filter(|l| !l.is_empty())
}

/// Value of a `key=value` module argument on a PAM line, e.g. `minlen=14`.
fn arg_num(line: &str, key: &str) -> Option<i64> {
    line.split_whitespace().find_map(|tok| {
        tok.strip_prefix(key)
            .and_then(|rest| rest.strip_prefix('='))
            .and_then(|v| v.trim().parse::<i64>().ok())
    })
}

/// Last `key = value` in a `.conf` file. Last wins because drop-in directories
/// (`pwquality.conf.d`, `modprobe.d`) are concatenated after the base file and
/// are meant to override it.
fn conf_str(text: &str, key: &str) -> Option<String> {
    let mut found = None;
    for line in live_lines(text) {
        if let Some((k, v)) = line.split_once('=') {
            if k.trim().eq_ignore_ascii_case(key) {
                let v = v.trim();
                if !v.is_empty() {
                    found = Some(v.to_string());
                }
            }
        }
    }
    found
}

fn conf_num(text: &str, key: &str) -> Option<i64> {
    conf_str(text, key).and_then(|v| v.split_whitespace().next()?.parse::<i64>().ok())
}

/// `<unit> enabled=<state> active=<state>` as printed by the command above.
/// `None` means systemd could not be asked at all (empty section), which is a
/// different thing from a unit that exists and is off.
fn unit_running(section: &str, unit: &str) -> Option<bool> {
    let prefix = format!("{} ", unit);
    let line = section.lines().map(str::trim).find(|l| l.starts_with(&prefix))?;
    let mut enabled = "";
    let mut active = "";
    for tok in line.split_whitespace() {
        if let Some(v) = tok.strip_prefix("enabled=") {
            enabled = v;
        } else if let Some(v) = tok.strip_prefix("active=") {
            active = v;
        }
    }
    // `static` and `indirect` are the normal answers for units that cannot be
    // enabled but do run — systemd-journald is always `static`, and treating
    // that as "not enabled" would flag every host on CIS 8.2.1.
    let enabled_ok = matches!(
        enabled,
        "enabled" | "enabled-runtime" | "static" | "indirect" | "alias"
    );
    Some(enabled_ok || active == "active")
}

// ─── pam_config ─────────────────────────────────────────────────────────────

/// Sentinel for "no lockout is configured, so the number of allowed failures is
/// unbounded". `0` cannot be used: for `pam_faillock` and `pam_tally2` `deny=0`
/// means *lockout disabled*, and it would pass the rule's `INF_OR_EQUAL 5`.
const UNLIMITED_ATTEMPTS: i64 = 9999;

pub(crate) fn parse_pam(output: &str) -> Vec<Value> {
    let secs = sections(output);
    let stack = sec(&secs, "KXN-PAM-STACK");
    let su = sec(&secs, "KXN-PAM-SU");
    let pwq_conf = sec(&secs, "KXN-PWQUALITY");
    let pwh_conf = sec(&secs, "KXN-PWHISTORY");
    let faillock_conf = sec(&secs, "KXN-FAILLOCK");

    let live: Vec<&str> = live_lines(stack).collect();

    // Every field below is read off the PAM stack; without it nothing can be
    // concluded. An empty stack with a populated /etc/pam.d listing is the
    // signature of a host that uses PAM with a layout we do not know (macOS,
    // Solaris, a custom include tree) — guessing "no password policy" there
    // would manufacture five violations out of ignorance.
    if live.is_empty() {
        return Vec::new();
    }

    let has = |needle: &str| live.iter().any(|l| l.contains(needle));

    let pwquality = has("pam_pwquality.so");
    let cracklib = has("pam_cracklib.so");
    // CIS 5.2.2 predates pwquality; pam_cracklib is the same check under the
    // older name and still ships on long-lived RHEL 7 / Debian 9 hosts.
    let pwquality_enabled = pwquality || cracklib;

    let module_minlen = live
        .iter()
        .filter(|l| l.contains("pam_pwquality.so") || l.contains("pam_cracklib.so"))
        .find_map(|l| arg_num(l, "minlen"));
    let unix_minlen = live
        .iter()
        .filter(|l| l.contains("pam_unix.so"))
        .find_map(|l| arg_num(l, "minlen"));

    // Effective minimum length, in the order the stack actually resolves it:
    // a module argument overrides pwquality.conf, which overrides the library
    // default. With no quality module at all the only floor left is pam_unix's
    // own built-in 6 — that is the truth about the host, not a missing value.
    let password_min_length = if pwquality_enabled {
        module_minlen
            .or_else(|| conf_num(pwq_conf, "minlen"))
            .unwrap_or(if pwquality { 8 } else { 9 })
    } else {
        unix_minlen.unwrap_or(6)
    };

    let pwhistory = has("pam_pwhistory.so");
    let remember_arg = live
        .iter()
        .filter(|l| l.contains("pam_unix.so") || l.contains("pam_pwhistory.so"))
        .find_map(|l| arg_num(l, "remember"));
    // pam_pwhistory keeps 10 passwords when told nothing; pam_unix keeps none
    // unless `remember=` is spelled out, and a stack with neither module has no
    // history at all.
    let password_remember = remember_arg
        .or_else(|| conf_num(pwh_conf, "remember"))
        .unwrap_or(if pwhistory { 10 } else { 0 });

    let faillock = has("pam_faillock.so");
    let tally2 = has("pam_tally2.so");
    let deny_arg = live
        .iter()
        .filter(|l| l.contains("pam_faillock.so") || l.contains("pam_tally2.so"))
        .find_map(|l| arg_num(l, "deny"));
    // faillock.conf only matters when pam_faillock is actually in the stack:
    // RHEL ships the file on hosts where authselect has not wired the module
    // in, and reading a `deny = 3` from it there would report a lockout that
    // does not exist.
    let lockout_attempts = if faillock || tally2 {
        deny_arg
            .or_else(|| {
                if faillock {
                    conf_num(faillock_conf, "deny")
                } else {
                    None
                }
            })
            // pam_faillock's built-in default is 3; pam_tally2 without `deny`
            // counts failures but never locks.
            .unwrap_or(if faillock { 3 } else { UNLIMITED_ATTEMPTS })
    } else {
        UNLIMITED_ATTEMPTS
    };

    // Debian ships the pam_wheel line in /etc/pam.d/su commented out, RHEL
    // ships it enabled — so the comment stripping is the whole check. A line
    // carrying `deny` inverts the module's meaning and is not a restriction to
    // wheel. A missing /etc/pam.d/su means nothing restricts su: false.
    let su_restricted_to_wheel = live_lines(su).any(|l| {
        l.contains("pam_wheel.so")
            && l.split_whitespace().next() == Some("auth")
            && !l.contains("deny")
    });

    vec![json!({
        "password_min_length": password_min_length,
        "pwquality_enabled": pwquality_enabled,
        "password_remember": password_remember,
        "lockout_attempts": lockout_attempts,
        "su_restricted_to_wheel": su_restricted_to_wheel,
    })]
}

// ─── audit_config ───────────────────────────────────────────────────────────

/// Kernel default when nothing raises it — `audit_backlog_limit` starts at 64.
const DEFAULT_BACKLOG_LIMIT: i64 = 64;

pub(crate) fn parse_audit(output: &str) -> Vec<Value> {
    let secs = sections(output);
    let units = sec(&secs, "KXN-AUDIT-UNITS");
    let procs = sec(&secs, "KXN-AUDIT-PROCS");
    let auditd_conf = sec(&secs, "KXN-AUDITD-CONF");
    let rules = sec(&secs, "KXN-AUDIT-RULES");
    let cmdline = sec(&secs, "KXN-AUDIT-CMDLINE");

    // Not a single probe answered: no systemd, no process table, no
    // /etc/audit, no /proc/cmdline. That is not a Linux host we can judge.
    if units.trim().is_empty()
        && procs.trim().is_empty()
        && auditd_conf.trim().is_empty()
        && rules.trim().is_empty()
        && cmdline.trim().is_empty()
    {
        return Vec::new();
    }

    let proc_has = |name: &str| procs.lines().any(|l| l.trim() == name);

    let auditd_enabled = unit_running(units, "auditd").unwrap_or(false) || proc_has("auditd");
    let rsyslog_enabled = unit_running(units, "rsyslog").unwrap_or(false)
        || unit_running(units, "syslog-ng").unwrap_or(false)
        || proc_has("rsyslogd")
        || proc_has("syslog-ng");
    // `ps -eo comm` truncates at 15 characters, so journald shows up as
    // `systemd-journal`.
    let journald_enabled =
        unit_running(units, "systemd-journald").unwrap_or(false) || proc_has("systemd-journal");

    // Empty string when auditd.conf is absent: the key is genuinely unset, and
    // a host with no auditd.conf is already failing CIS 8.1.1 anyway. Values
    // are case-insensitive in auditd.conf (`KEEP_LOGS` is common), the rule
    // compares against the lowercase spelling.
    let max_log_file_action = conf_str(auditd_conf, "max_log_file_action")
        .map(|v| v.to_lowercase())
        .unwrap_or_default();

    let backlog_limit = auditctl_backlog(rules)
        .or_else(|| rules_backlog(rules))
        .or_else(|| cmdline_backlog(cmdline))
        .unwrap_or(DEFAULT_BACKLOG_LIMIT);

    vec![json!({
        "auditd_enabled": auditd_enabled,
        "max_log_file_action": max_log_file_action,
        "backlog_limit": backlog_limit,
        "rsyslog_enabled": rsyslog_enabled,
        "journald_enabled": journald_enabled,
    })]
}

/// `auditctl -s` prints `backlog_limit 8192` — the live kernel value, the one
/// that actually protects the host right now.
fn auditctl_backlog(section: &str) -> Option<i64> {
    section.lines().map(str::trim).find_map(|l| {
        let rest = l.strip_prefix("backlog_limit")?;
        rest.split_whitespace().next()?.parse::<i64>().ok()
    })
}

/// `-b 8192` in the persisted rules. The last one wins, exactly as auditctl
/// applies them.
fn rules_backlog(section: &str) -> Option<i64> {
    let mut found = None;
    for line in live_lines(section) {
        let toks: Vec<&str> = line.split_whitespace().collect();
        for w in toks.windows(2) {
            if w[0] == "-b" {
                if let Ok(n) = w[1].parse::<i64>() {
                    found = Some(n);
                }
            }
        }
    }
    found
}

/// `audit_backlog_limit=8192` on the kernel command line, set by the bootloader
/// so the limit applies before auditd starts.
fn cmdline_backlog(section: &str) -> Option<i64> {
    section
        .split_whitespace()
        .find_map(|tok| arg_num(tok, "audit_backlog_limit"))
}

// ─── firewall_config ────────────────────────────────────────────────────────

pub(crate) fn parse_firewall(output: &str) -> Vec<Value> {
    let secs = sections(output);
    let tools = sec(&secs, "KXN-FW-TOOLS");
    let ufw = sec(&secs, "KXN-FW-UFW");
    let firewalld = sec(&secs, "KXN-FW-FIREWALLD");
    let nft = sec(&secs, "KXN-FW-NFT");
    let ipt = sec(&secs, "KXN-FW-IPTABLES");

    // Cardinal rule: no iptables, no nft, no ufw, no firewall-cmd on the host
    // means there is no firewall stack to describe. Reporting
    // `firewall_installed: false` here would be a guess dressed up as a
    // finding — let the engine say "not evaluated" instead.
    let installed_tools: Vec<&str> = tools.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    if installed_tools.is_empty() {
        return Vec::new();
    }

    let ufw_active = ufw
        .lines()
        .map(str::trim)
        .any(|l| l.eq_ignore_ascii_case("status: active"));
    let firewalld_running = firewalld.lines().any(|l| l.trim() == "state=running");
    let nft_readable = nft.contains("%%KXN-NFT-OK%%");
    let ipt_readable = ipt.contains("%%KXN-IPT-OK%%");

    let nft_input = nft_input_chain(nft);
    let ipt_policy = ipt
        .lines()
        .map(str::trim)
        .find_map(|l| l.strip_prefix("-P INPUT "))
        .and_then(normalize_policy);
    let ipt_has_rules = ipt.lines().any(|l| l.trim_start().starts_with("-A INPUT"));

    // Which front-end is telling the truth about INPUT? The one that is
    // actually running. ufw and firewalld both program the layer below them, so
    // reading iptables/nft under an active ufw would report ufw's generated
    // chains instead of its policy.
    let policy = if ufw_active {
        ufw_default_incoming(ufw)
    } else if firewalld_running {
        firewalld_target(firewalld)
    } else {
        nft_input.as_ref().and_then(|c| c.policy.clone()).or(ipt_policy.clone())
    };

    let policy = match policy {
        Some(p) => p,
        // Nothing resolved a policy. If we were nonetheless able to read the
        // raw netfilter state (the OK flags) then the stack really is empty and
        // everything is accepted. If we could not read it — an unprivileged
        // account is the usual reason — we must not guess.
        None if nft_readable || ipt_readable => "ACCEPT".to_string(),
        None => return Vec::new(),
    };

    // A firewall front-end that is installed but has nothing loaded is not
    // "enabled", whatever its unit file says: ufw reports its own status,
    // firewalld its daemon state, and for the raw engines a non-ACCEPT INPUT
    // policy or at least one INPUT rule is the evidence that it is in use.
    let firewall_enabled = ufw_active
        || firewalld_running
        || nft_input.as_ref().map(|c| c.has_rules || c.policy.as_deref() != Some("ACCEPT")).unwrap_or(false)
        || ipt_policy.as_deref().map(|p| p != "ACCEPT").unwrap_or(false)
        || ipt_has_rules;

    // Reaching here means at least one front-end binary exists on the host and
    // at least one of them answered, so `firewall_installed` is settled: the
    // "nothing installed" case returned an empty vector at the top and is
    // reported as not evaluated rather than as a CIS 4.1.1 violation.
    vec![json!({
        "firewall_installed": true,
        "firewall_enabled": firewall_enabled,
        "input_default_policy": policy,
    })]
}

/// Map every front-end's vocabulary onto the three words the rule compares
/// against. firewalld wraps its own in `%%…%%` (`%%REJECT%%`), ufw says
/// `deny`/`allow`, nft lowercases everything.
fn normalize_policy(raw: &str) -> Option<String> {
    let cleaned = raw
        .trim()
        .trim_end_matches(';')
        .trim()
        .trim_matches('%')
        .to_uppercase();
    match cleaned.as_str() {
        "DROP" | "DENY" => Some("DROP".to_string()),
        "REJECT" => Some("REJECT".to_string()),
        "ACCEPT" | "ALLOW" => Some("ACCEPT".to_string()),
        _ => None,
    }
}

/// `Default: deny (incoming), allow (outgoing), disabled (routed)`
fn ufw_default_incoming(section: &str) -> Option<String> {
    for line in section.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("Default:") {
            continue;
        }
        for part in trimmed.trim_start_matches("Default:").split(',') {
            let part = part.trim();
            if let Some(word) = part.strip_suffix("(incoming)") {
                return normalize_policy(word);
            }
        }
    }
    None
}

/// firewalld's default zone target. `target: default` is not a no-op: packets
/// that match no rule in a `default` zone are rejected with an ICMP error, so
/// it normalizes to REJECT — which correctly fails a rule demanding DROP
/// rather than silently passing it.
fn firewalld_target(section: &str) -> Option<String> {
    for line in section.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("target:") {
            let rest = rest.trim();
            if rest.eq_ignore_ascii_case("default") {
                return Some("REJECT".to_string());
            }
            return normalize_policy(rest);
        }
    }
    None
}

struct NftInput {
    policy: Option<String>,
    has_rules: bool,
}

/// The base chain hooked on `input` carries its policy on its `type … hook
/// input …` line; nft omits `policy` entirely when it is the default `accept`.
fn nft_input_chain(section: &str) -> Option<NftInput> {
    let mut lines = section.lines().enumerate();
    let (idx, hook_line) = lines.find(|(_, l)| l.contains("hook input"))?;
    let policy = hook_line
        .split(';')
        .find_map(|part| part.trim().strip_prefix("policy "))
        .and_then(normalize_policy)
        .or_else(|| Some("ACCEPT".to_string()));
    // Anything between the hook line and the chain's closing brace that is not
    // a comment is a filtering rule.
    let has_rules = section
        .lines()
        .skip(idx + 1)
        .take_while(|l| l.trim() != "}")
        .any(|l| !l.trim().is_empty() && !l.trim().starts_with('#'));
    Some(NftInput { policy, has_rules })
}

// ─── filesystem_config ──────────────────────────────────────────────────────

/// Reported when the world-writable sweep was cut short by its timeout *and*
/// found nothing. Emitting `0` there would be a silent false pass on a
/// compliance check; omitting the property would make the engine compare
/// against an empty string and report a violation with no explanation. A
/// negative count is impossible in reality, so it fails the `EQUAL 0` rule
/// while making it obvious in the report that the scan did not finish.
const WW_SCAN_INCOMPLETE: i64 = -1;

pub(crate) fn parse_filesystem(output: &str) -> Vec<Value> {
    let secs = sections(output);
    let findmnt = sec(&secs, "KXN-FS-MOUNTS");
    let procmounts = sec(&secs, "KXN-FS-PROCMOUNTS");
    let modconf = sec(&secs, "KXN-FS-MODCONF");
    let ww = sec(&secs, "KXN-FS-WORLDWRITABLE");

    let mut mounts = mounts_from_findmnt(findmnt);
    if mounts.is_empty() {
        mounts = mounts_from_mount_table(procmounts);
    }
    // No mount table at all: not a Linux host, or the output never arrived.
    if mounts.is_empty() {
        return Vec::new();
    }

    // Later entries shadow earlier ones — that is how the kernel resolves
    // overlapping mounts, and bind mounts legitimately repeat a target.
    let mut by_target: BTreeMap<String, String> = BTreeMap::new();
    for (target, _fstype, opts) in &mounts {
        by_target.insert(target.clone(), opts.clone());
    }

    let is_mount = |p: &str| by_target.contains_key(p);

    // /tmp's effective options when it is not a partition of its own are the
    // root filesystem's, because that is where /tmp physically lives. Reporting
    // the real options (which will not contain noexec) is more honest than an
    // empty string, and it fails the rule for the right reason.
    let tmp_mount_options = by_target
        .get("/tmp")
        .or_else(|| by_target.get("/"))
        .cloned()
        .unwrap_or_default();

    let mut dirs: BTreeSet<&str> = BTreeSet::new();
    for line in ww.lines() {
        let t = line.trim();
        if t.starts_with('/') {
            dirs.insert(t);
        }
    }
    let ww_complete = ww.contains("%%KXN-WW-COMPLETE%%");
    let world_writable_dirs_without_sticky = if !dirs.is_empty() {
        // Even a truncated sweep that found something is conclusive: the host
        // has at least this many offending directories.
        dirs.len() as i64
    } else if ww_complete {
        0
    } else {
        WW_SCAN_INCOMPLETE
    };

    vec![json!({
        "tmp_separate_partition": is_mount("/tmp"),
        "var_separate_partition": is_mount("/var"),
        "var_log_separate_partition": is_mount("/var/log"),
        "home_separate_partition": is_mount("/home"),
        "tmp_mount_options": tmp_mount_options,
        "world_writable_dirs_without_sticky": world_writable_dirs_without_sticky,
        "cramfs_disabled": module_disabled(modconf, sec(&secs, "KXN-FS-MOD-CRAMFS"), "cramfs"),
        "freevxfs_disabled": module_disabled(modconf, sec(&secs, "KXN-FS-MOD-FREEVXFS"), "freevxfs"),
        "usb_storage_disabled": module_disabled(modconf, sec(&secs, "KXN-FS-MOD-USBSTORAGE"), "usb_storage"),
    })]
}

/// `findmnt -rn -o TARGET,FSTYPE,OPTIONS`
fn mounts_from_findmnt(text: &str) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() >= 3 && f[0].starts_with('/') {
            out.push((f[0].to_string(), f[1].to_string(), f[2].to_string()));
        }
    }
    out
}

/// `/proc/self/mounts` (`<src> <target> <fstype> <opts> 0 0`) with a fallback
/// for legacy `mount` output (`<src> on <target> type <fstype> (<opts>)`),
/// which is all busybox and very old userlands offer.
fn mounts_from_mount_table(text: &str) -> Vec<(String, String, String)> {
    let re = Regex::new(r"^(?P<src>.+?) on (?P<target>.+?) type (?P<fstype>\S+) \((?P<opts>[^)]*)\)").ok();
    let mut out = Vec::new();
    for line in text.lines() {
        if let Some(caps) = re.as_ref().and_then(|r| r.captures(line)) {
            let get = |n: &str| caps.name(n).map(|m| m.as_str().to_string()).unwrap_or_default();
            out.push((get("target"), get("fstype"), get("opts")));
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() >= 4 && f[1].starts_with('/') {
            out.push((f[1].to_string(), f[2].to_string(), f[3].to_string()));
        }
    }
    out
}

/// A filesystem/driver module counts as disabled when the host cannot load it
/// on demand: a `blacklist` entry, an `install … /bin/true` (or `/bin/false`)
/// override, or no such module built for the running kernel.
///
/// Note what this deliberately does *not* look at: whether the module is
/// currently loaded. A blacklisted module that was insmod'ed by hand before the
/// blacklist landed would still be reported as disabled here. The rule pack
/// asks about configuration, and `lsmod` state is a separate finding.
fn module_disabled(conf: &str, probe: &str, name: &str) -> bool {
    // modprobe treats `-` and `_` as interchangeable, and both spellings appear
    // in the wild for usb-storage.
    let norm = |s: &str| s.replace('-', "_");
    let target = norm(name);

    for line in live_lines(conf) {
        let mut toks = line.split_whitespace();
        let keyword = match toks.next() {
            Some(k) => k,
            None => continue,
        };
        let module = match toks.next() {
            Some(m) => m,
            None => continue,
        };
        if norm(module) != target {
            continue;
        }
        if keyword == "blacklist" {
            return true;
        }
        if keyword == "install" {
            let rest: Vec<&str> = toks.collect();
            let rest = rest.join(" ");
            let rest = rest.trim();
            if rest.contains("/bin/true")
                || rest.contains("/bin/false")
                || rest == "true"
                || rest == "false"
            {
                return true;
            }
        }
    }

    for line in probe.lines() {
        let t = line.trim();
        if t.starts_with("install ") && (t.contains("/bin/true") || t.contains("/bin/false")) {
            return true;
        }
        // `modprobe: FATAL: Module cramfs not found in directory …` — the
        // module was never built for this kernel, so nothing can load it.
        // A plain "not found" from the shell (modprobe itself missing) does not
        // match this and correctly leaves the verdict to the config files.
        if t.contains("FATAL: Module") && t.contains("not found") {
            return true;
        }
    }

    false
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn first(v: &[Value]) -> &Value {
        &v[0]
    }

    // ── pam_config ──────────────────────────────────────────────────────────

    /// RHEL 9 hardened by authselect: pwquality with minlen, pwhistory,
    /// faillock, and pam_wheel enabled on su.
    const PAM_HARDENED_RHEL: &str = r#"
###KXN-PAM-DIR###
config-util
fingerprint-auth
password-auth
postlogin
su
system-auth
###KXN-PAM-STACK###
auth        required                                     pam_env.so
auth        required                                     pam_faillock.so preauth silent deny=3 unlock_time=900
auth        sufficient                                   pam_unix.so nullok
auth        [default=die]                                pam_faillock.so authfail deny=3 unlock_time=900
auth        required                                     pam_deny.so
account     required                                     pam_faillock.so
account     required                                     pam_unix.so
password    requisite                                    pam_pwquality.so try_first_pass local_users_only minlen=14 retry=3
password    required                                     pam_pwhistory.so use_authtok remember=5
password    sufficient                                   pam_unix.so yescrypt shadow use_authtok
password    required                                     pam_deny.so
###KXN-PAM-SU###
#%PAM-1.0
auth		sufficient	pam_rootok.so
# Uncomment the following line to implicitly trust users in the "wheel" group.
#auth		sufficient	pam_wheel.so trust use_uid
auth		required	pam_wheel.so use_uid
auth		substack	system-auth
###KXN-PWQUALITY###
# Configuration for systemwide password quality limits
# minlen = 8
dcredit = -1
ucredit = -1
###KXN-PWHISTORY###
###KXN-FAILLOCK###
deny = 3
unlock_time = 900
###KXN-PAM-END###
"#;

    /// Stock Ubuntu 22.04: no quality module, no history, no lockout, su's
    /// pam_wheel line shipped commented out.
    const PAM_DEFAULT_UBUNTU: &str = r#"
###KXN-PAM-DIR###
chfn
common-account
common-auth
common-password
common-session
login
su
sudo
###KXN-PAM-STACK###
password	[success=1 default=ignore]	pam_unix.so obscure yescrypt
password	requisite			pam_deny.so
password	required			pam_permit.so
auth	[success=1 default=ignore]	pam_unix.so nullok
auth	requisite			pam_deny.so
auth	required			pam_permit.so
account	[success=1 new_authtok_reqd=done default=ignore]	pam_unix.so
###KXN-PAM-SU###
#%PAM-1.0
auth       sufficient pam_rootok.so
# auth       required   pam_wheel.so
# auth       required   pam_wheel.so group=admin
@include common-auth
@include common-account
###KXN-PWQUALITY###
###KXN-PWHISTORY###
###KXN-FAILLOCK###
###KXN-PAM-END###
"#;

    #[test]
    fn pam_hardened_rhel() {
        let v = parse_pam(PAM_HARDENED_RHEL);
        assert_eq!(v.len(), 1);
        let o = first(&v);
        assert_eq!(o["password_min_length"], json!(14));
        assert_eq!(o["pwquality_enabled"], json!(true));
        assert_eq!(o["password_remember"], json!(5));
        assert_eq!(o["lockout_attempts"], json!(3));
        assert_eq!(o["su_restricted_to_wheel"], json!(true));
    }

    #[test]
    fn pam_default_ubuntu() {
        let v = parse_pam(PAM_DEFAULT_UBUNTU);
        assert_eq!(v.len(), 1);
        let o = first(&v);
        // pam_unix's own floor, nothing else sets one.
        assert_eq!(o["password_min_length"], json!(6));
        assert_eq!(o["pwquality_enabled"], json!(false));
        assert_eq!(o["password_remember"], json!(0));
        assert_eq!(o["lockout_attempts"], json!(UNLIMITED_ATTEMPTS));
        assert_eq!(o["su_restricted_to_wheel"], json!(false));
    }

    #[test]
    fn pam_pwquality_conf_only() {
        // pwquality wired in with no module arguments: pwquality.conf decides.
        let out = "###KXN-PAM-DIR###\nsystem-auth\n###KXN-PAM-STACK###\n\
                   password requisite pam_pwquality.so try_first_pass\n\
                   ###KXN-PAM-SU###\n###KXN-PWQUALITY###\nminlen = 15\n\
                   ###KXN-PWHISTORY###\n###KXN-FAILLOCK###\n###KXN-PAM-END###\n";
        let v = parse_pam(out);
        assert_eq!(v[0]["password_min_length"], json!(15));
        assert_eq!(v[0]["pwquality_enabled"], json!(true));
    }

    #[test]
    fn pam_faillock_conf_without_module_is_not_a_lockout() {
        let out = "###KXN-PAM-DIR###\nsystem-auth\n###KXN-PAM-STACK###\n\
                   auth sufficient pam_unix.so nullok\n\
                   ###KXN-PAM-SU###\n###KXN-PWQUALITY###\n###KXN-PWHISTORY###\n\
                   ###KXN-FAILLOCK###\ndeny = 3\n###KXN-PAM-END###\n";
        assert_eq!(parse_pam(out)[0]["lockout_attempts"], json!(UNLIMITED_ATTEMPTS));
    }

    #[test]
    fn pam_unusable_output() {
        assert!(parse_pam("").is_empty());
        assert!(parse_pam("sh: 1: ls: not found\n").is_empty());
        // Markers present but every probe came back empty: no PAM on the host.
        assert!(parse_pam(
            "###KXN-PAM-DIR###\n###KXN-PAM-STACK###\n###KXN-PAM-SU###\n\
             ###KXN-PWQUALITY###\n###KXN-PWHISTORY###\n###KXN-FAILLOCK###\n###KXN-PAM-END###\n"
        )
        .is_empty());
    }

    #[test]
    fn pam_unknown_stack_layout_is_not_judged() {
        // macOS (and anything else with a PAM tree that is neither Debian's nor
        // RHEL's): /etc/pam.d is full, none of the files we know exist, and
        // /etc/pam.d/su is readable. Concluding "no password policy" from that
        // would invent five violations.
        let out = "###KXN-PAM-DIR###\nauthorization\nlogin\nsshd\nsu\nsudo\n\
                   ###KXN-PAM-STACK###\n\
                   ###KXN-PAM-SU###\n# su: auth account session\n\
                   auth       sufficient     pam_rootok.so\n\
                   ###KXN-PWQUALITY###\n###KXN-PWHISTORY###\n###KXN-FAILLOCK###\n\
                   ###KXN-PAM-END###\n";
        assert!(parse_pam(out).is_empty());
    }

    // ── audit_config ────────────────────────────────────────────────────────

    const AUDIT_HARDENED_RHEL: &str = r#"
###KXN-AUDIT-UNITS###
auditd enabled=enabled active=active
rsyslog enabled=enabled active=active
syslog-ng enabled=unknown active=inactive
systemd-journald enabled=static active=active
###KXN-AUDIT-PROCS###
auditd
rsyslogd
sshd
systemd
systemd-journal
###KXN-AUDITD-CONF###
#
# This file controls the configuration of the audit daemon
#
log_file = /var/log/audit/audit.log
log_format = ENRICHED
max_log_file = 8
num_logs = 5
max_log_file_action = keep_logs
space_left = 75
space_left_action = SYSLOG
###KXN-AUDIT-RULES###
enabled 1
failure 1
pid 1543
rate_limit 0
backlog_limit 8192
lost 0
backlog 0
backlog_wait_time 60000
-D
-b 8192
-f 1
-w /etc/passwd -p wa -k identity
###KXN-AUDIT-CMDLINE###
BOOT_IMAGE=(hd0,msdos1)/vmlinuz-5.14.0-362.el9 root=/dev/mapper/rhel-root ro audit=1 audit_backlog_limit=8192
###KXN-AUDIT-END###
"#;

    /// Stock Ubuntu cloud image: journald and rsyslog, no auditd at all.
    const AUDIT_DEFAULT_UBUNTU: &str = r#"
###KXN-AUDIT-UNITS###
auditd enabled=unknown active=inactive
rsyslog enabled=enabled active=active
syslog-ng enabled=unknown active=inactive
systemd-journald enabled=static active=active
###KXN-AUDIT-PROCS###
cron
rsyslogd
sshd
systemd
systemd-journal
###KXN-AUDITD-CONF###
###KXN-AUDIT-RULES###
###KXN-AUDIT-CMDLINE###
BOOT_IMAGE=/boot/vmlinuz-5.15.0-91-generic root=UUID=6c1b2a2e-1 ro console=tty1 console=ttyS0
###KXN-AUDIT-END###
"#;

    #[test]
    fn audit_hardened_rhel() {
        let v = parse_audit(AUDIT_HARDENED_RHEL);
        assert_eq!(v.len(), 1);
        let o = first(&v);
        assert_eq!(o["auditd_enabled"], json!(true));
        assert_eq!(o["max_log_file_action"], json!("keep_logs"));
        assert_eq!(o["backlog_limit"], json!(8192));
        assert_eq!(o["rsyslog_enabled"], json!(true));
        assert_eq!(o["journald_enabled"], json!(true));
    }

    #[test]
    fn audit_default_ubuntu() {
        let v = parse_audit(AUDIT_DEFAULT_UBUNTU);
        let o = first(&v);
        assert_eq!(o["auditd_enabled"], json!(false));
        assert_eq!(o["max_log_file_action"], json!(""));
        assert_eq!(o["backlog_limit"], json!(DEFAULT_BACKLOG_LIMIT));
        assert_eq!(o["rsyslog_enabled"], json!(true));
        assert_eq!(o["journald_enabled"], json!(true));
    }

    #[test]
    fn audit_backlog_from_kernel_cmdline_only() {
        // auditd installed, rules not yet loaded (auditctl unreadable as a
        // plain user) — the bootloader value is the next best truth.
        let out = "###KXN-AUDIT-UNITS###\nauditd enabled=enabled active=active\n\
                   ###KXN-AUDIT-PROCS###\nauditd\n###KXN-AUDITD-CONF###\n\
                   max_log_file_action = ROTATE\n###KXN-AUDIT-RULES###\n\
                   ###KXN-AUDIT-CMDLINE###\nro audit=1 audit_backlog_limit=16384\n\
                   ###KXN-AUDIT-END###\n";
        let v = parse_audit(out);
        assert_eq!(v[0]["backlog_limit"], json!(16384));
        assert_eq!(v[0]["max_log_file_action"], json!("rotate"));
    }

    #[test]
    fn audit_no_systemd_falls_back_to_process_table() {
        let out = "###KXN-AUDIT-UNITS###\n###KXN-AUDIT-PROCS###\nauditd\nsystemd-journal\n\
                   ###KXN-AUDITD-CONF###\n###KXN-AUDIT-RULES###\n###KXN-AUDIT-CMDLINE###\n\
                   ###KXN-AUDIT-END###\n";
        let v = parse_audit(out);
        assert_eq!(v[0]["auditd_enabled"], json!(true));
        assert_eq!(v[0]["rsyslog_enabled"], json!(false));
        assert_eq!(v[0]["journald_enabled"], json!(true));
    }

    #[test]
    fn audit_unusable_output() {
        assert!(parse_audit("").is_empty());
        assert!(parse_audit(
            "###KXN-AUDIT-UNITS###\n###KXN-AUDIT-PROCS###\n###KXN-AUDITD-CONF###\n\
             ###KXN-AUDIT-RULES###\n###KXN-AUDIT-CMDLINE###\n###KXN-AUDIT-END###\n"
        )
        .is_empty());
    }

    // ── firewall_config ─────────────────────────────────────────────────────

    const FW_HARDENED_UFW: &str = r#"
###KXN-FW-TOOLS###
iptables
nft
ufw
###KXN-FW-UFW###
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
###KXN-FW-FIREWALLD###
###KXN-FW-NFT###
%%KXN-NFT-OK%%
table inet filter {
	chain ufw-input {
	}
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
		iif "lo" accept
	}
}
###KXN-FW-IPTABLES###
%%KXN-IPT-OK%%
-P INPUT DROP
-P FORWARD DROP
-P OUTPUT ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
###KXN-FW-SYSTEMD###
ufw enabled=enabled active=active
firewalld enabled=unknown active=inactive
nftables enabled=disabled active=inactive
iptables enabled=unknown active=inactive
netfilter-persistent enabled=unknown active=inactive
###KXN-FW-END###
"#;

    /// Stock Debian: iptables present through the nft shim, nothing configured.
    const FW_DEFAULT_DEBIAN: &str = r#"
###KXN-FW-TOOLS###
iptables
nft
###KXN-FW-UFW###
###KXN-FW-FIREWALLD###
###KXN-FW-NFT###
%%KXN-NFT-OK%%
###KXN-FW-IPTABLES###
%%KXN-IPT-OK%%
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
###KXN-FW-SYSTEMD###
ufw enabled=unknown active=inactive
firewalld enabled=unknown active=inactive
nftables enabled=disabled active=inactive
iptables enabled=unknown active=inactive
netfilter-persistent enabled=unknown active=inactive
###KXN-FW-END###
"#;

    /// Stock RHEL: firewalld running, default zone `public` with target
    /// `default` — an implicit reject, not a drop.
    const FW_DEFAULT_RHEL_FIREWALLD: &str = r#"
###KXN-FW-TOOLS###
iptables
nft
firewall-cmd
###KXN-FW-UFW###
###KXN-FW-FIREWALLD###
state=running
default-zone=public
public (active)
  target: default
  icmp-block-inversion: no
  interfaces: eth0
  services: cockpit dhcpv6-client ssh
  ports:
  protocols:
###KXN-FW-NFT###
%%KXN-NFT-OK%%
table inet firewalld {
	chain filter_INPUT {
		type filter hook input priority filter + 10; policy accept;
		ct state established,related accept
	}
}
###KXN-FW-IPTABLES###
%%KXN-IPT-OK%%
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
###KXN-FW-SYSTEMD###
firewalld enabled=enabled active=active
###KXN-FW-END###
"#;

    #[test]
    fn firewall_hardened_ufw() {
        let v = parse_firewall(FW_HARDENED_UFW);
        assert_eq!(v.len(), 1);
        let o = first(&v);
        assert_eq!(o["firewall_installed"], json!(true));
        assert_eq!(o["firewall_enabled"], json!(true));
        assert_eq!(o["input_default_policy"], json!("DROP"));
    }

    #[test]
    fn firewall_default_debian() {
        let v = parse_firewall(FW_DEFAULT_DEBIAN);
        let o = first(&v);
        assert_eq!(o["firewall_installed"], json!(true));
        assert_eq!(o["firewall_enabled"], json!(false));
        assert_eq!(o["input_default_policy"], json!("ACCEPT"));
    }

    #[test]
    fn firewall_firewalld_default_zone_is_reject_not_drop() {
        let v = parse_firewall(FW_DEFAULT_RHEL_FIREWALLD);
        let o = first(&v);
        assert_eq!(o["firewall_enabled"], json!(true));
        assert_eq!(o["input_default_policy"], json!("REJECT"));
    }

    #[test]
    fn firewall_unusable_output() {
        // Nothing installed at all.
        assert!(parse_firewall("").is_empty());
        assert!(parse_firewall("###KXN-FW-TOOLS###\n###KXN-FW-UFW###\n###KXN-FW-END###\n").is_empty());
        // Tools present but every dump was refused (unprivileged account):
        // guessing ACCEPT here would invent a violation.
        let unprivileged = "###KXN-FW-TOOLS###\niptables\nnft\n###KXN-FW-UFW###\n\
                            ###KXN-FW-FIREWALLD###\n###KXN-FW-NFT###\n\
                            ###KXN-FW-IPTABLES###\n###KXN-FW-SYSTEMD###\n###KXN-FW-END###\n";
        assert!(parse_firewall(unprivileged).is_empty());
    }

    // ── filesystem_config ───────────────────────────────────────────────────

    const FS_HARDENED_RHEL: &str = r#"
###KXN-FS-MOUNTS###
/ xfs rw,relatime,attr2,inode64,logbufs=8,logbsize=32k,noquota
/boot xfs rw,nosuid,nodev,noexec,relatime,attr2,inode64,noquota
/tmp tmpfs rw,nosuid,nodev,noexec,relatime,seclabel,size=1048576k
/var xfs rw,nosuid,relatime,attr2,inode64,noquota
/var/log xfs rw,nosuid,nodev,noexec,relatime,attr2,inode64,noquota
/var/tmp xfs rw,nosuid,nodev,noexec,relatime,attr2,inode64,noquota
/home xfs rw,nosuid,nodev,relatime,attr2,inode64,noquota
###KXN-FS-PROCMOUNTS###
/dev/mapper/rhel-root / xfs rw,relatime,attr2,inode64,logbufs=8,logbsize=32k,noquota 0 0
tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,relatime,seclabel,size=1048576k 0 0
###KXN-FS-MODCONF###
blacklist cramfs
install cramfs /bin/true
blacklist freevxfs
install freevxfs /bin/true
blacklist usb-storage
install usb-storage /bin/true
###KXN-FS-MOD-CRAMFS###
install /bin/true
###KXN-FS-MOD-FREEVXFS###
install /bin/true
###KXN-FS-MOD-USBSTORAGE###
install /bin/true
###KXN-FS-WORLDWRITABLE###
%%KXN-WW-COMPLETE%%
###KXN-FS-END###
"#;

    /// Stock Ubuntu cloud image: single root partition, no module policy,
    /// freevxfs simply not built for the kernel, one offending directory.
    const FS_DEFAULT_UBUNTU: &str = r#"
###KXN-FS-MOUNTS###
/ ext4 rw,relatime,discard,errors=remount-ro
/boot/efi vfat rw,relatime,fmask=0077,dmask=0077,codepage=437
/run tmpfs rw,nosuid,nodev,noexec,relatime,size=98404k,mode=755
###KXN-FS-PROCMOUNTS###
/dev/sda1 / ext4 rw,relatime,discard,errors=remount-ro 0 0
/dev/sda15 /boot/efi vfat rw,relatime,fmask=0077,dmask=0077,codepage=437 0 0
###KXN-FS-MODCONF###
blacklist bcm43xx
alias net-pf-10 ipv6
###KXN-FS-MOD-CRAMFS###
insmod /lib/modules/5.15.0-91-generic/kernel/fs/cramfs/cramfs.ko
###KXN-FS-MOD-FREEVXFS###
modprobe: FATAL: Module freevxfs not found in directory /lib/modules/5.15.0-91-generic
###KXN-FS-MOD-USBSTORAGE###
insmod /lib/modules/5.15.0-91-generic/kernel/drivers/usb/storage/usb-storage.ko
###KXN-FS-WORLDWRITABLE###
/srv/uploads
%%KXN-WW-COMPLETE%%
###KXN-FS-END###
"#;

    #[test]
    fn filesystem_hardened_rhel() {
        let v = parse_filesystem(FS_HARDENED_RHEL);
        assert_eq!(v.len(), 1);
        let o = first(&v);
        assert_eq!(o["tmp_separate_partition"], json!(true));
        assert_eq!(o["var_separate_partition"], json!(true));
        assert_eq!(o["var_log_separate_partition"], json!(true));
        assert_eq!(o["home_separate_partition"], json!(true));
        let opts = o["tmp_mount_options"].as_str().unwrap_or("");
        assert!(opts.contains("noexec") && opts.contains("nosuid"), "{opts}");
        assert_eq!(o["world_writable_dirs_without_sticky"], json!(0));
        assert_eq!(o["cramfs_disabled"], json!(true));
        assert_eq!(o["freevxfs_disabled"], json!(true));
        assert_eq!(o["usb_storage_disabled"], json!(true));
    }

    #[test]
    fn filesystem_default_ubuntu() {
        let v = parse_filesystem(FS_DEFAULT_UBUNTU);
        let o = first(&v);
        assert_eq!(o["tmp_separate_partition"], json!(false));
        assert_eq!(o["var_separate_partition"], json!(false));
        assert_eq!(o["var_log_separate_partition"], json!(false));
        assert_eq!(o["home_separate_partition"], json!(false));
        // /tmp lives on / here, so / is what actually governs it.
        assert_eq!(
            o["tmp_mount_options"],
            json!("rw,relatime,discard,errors=remount-ro")
        );
        assert_eq!(o["world_writable_dirs_without_sticky"], json!(1));
        assert_eq!(o["cramfs_disabled"], json!(false));
        // Not built for this kernel: cannot be loaded, therefore disabled.
        assert_eq!(o["freevxfs_disabled"], json!(true));
        assert_eq!(o["usb_storage_disabled"], json!(false));
    }

    #[test]
    fn filesystem_falls_back_to_proc_mounts() {
        let out = "###KXN-FS-MOUNTS###\n###KXN-FS-PROCMOUNTS###\n\
                   /dev/sda1 / ext4 rw,relatime 0 0\n\
                   tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,relatime 0 0\n\
                   ###KXN-FS-MODCONF###\n###KXN-FS-MOD-CRAMFS###\n\
                   ###KXN-FS-MOD-FREEVXFS###\n###KXN-FS-MOD-USBSTORAGE###\n\
                   ###KXN-FS-WORLDWRITABLE###\n%%KXN-WW-COMPLETE%%\n###KXN-FS-END###\n";
        let v = parse_filesystem(out);
        assert_eq!(v[0]["tmp_separate_partition"], json!(true));
        assert_eq!(v[0]["tmp_mount_options"], json!("rw,nosuid,nodev,noexec,relatime"));
    }

    #[test]
    fn filesystem_falls_back_to_legacy_mount_output() {
        let out = "###KXN-FS-MOUNTS###\n###KXN-FS-PROCMOUNTS###\n\
                   /dev/sda1 on / type ext4 (rw,relatime,errors=remount-ro)\n\
                   tmpfs on /tmp type tmpfs (rw,nosuid,nodev,noexec)\n\
                   ###KXN-FS-MODCONF###\n###KXN-FS-MOD-CRAMFS###\n\
                   ###KXN-FS-MOD-FREEVXFS###\n###KXN-FS-MOD-USBSTORAGE###\n\
                   ###KXN-FS-WORLDWRITABLE###\n%%KXN-WW-COMPLETE%%\n###KXN-FS-END###\n";
        let v = parse_filesystem(out);
        assert_eq!(v[0]["tmp_separate_partition"], json!(true));
        assert_eq!(v[0]["tmp_mount_options"], json!("rw,nosuid,nodev,noexec"));
    }

    #[test]
    fn filesystem_truncated_sweep_is_not_reported_as_clean() {
        let out = "###KXN-FS-MOUNTS###\n/ ext4 rw,relatime\n###KXN-FS-PROCMOUNTS###\n\
                   ###KXN-FS-MODCONF###\n###KXN-FS-MOD-CRAMFS###\n###KXN-FS-MOD-FREEVXFS###\n\
                   ###KXN-FS-MOD-USBSTORAGE###\n###KXN-FS-WORLDWRITABLE###\n###KXN-FS-END###\n";
        let v = parse_filesystem(out);
        assert_eq!(
            v[0]["world_writable_dirs_without_sticky"],
            json!(WW_SCAN_INCOMPLETE)
        );
    }

    #[test]
    fn filesystem_duplicate_paths_counted_once() {
        // The sweep visits / and then /tmp separately; a directory on the root
        // filesystem below an unmounted /tmp would otherwise be double counted.
        let out = "###KXN-FS-MOUNTS###\n/ ext4 rw,relatime\n###KXN-FS-PROCMOUNTS###\n\
                   ###KXN-FS-MODCONF###\n###KXN-FS-MOD-CRAMFS###\n###KXN-FS-MOD-FREEVXFS###\n\
                   ###KXN-FS-MOD-USBSTORAGE###\n###KXN-FS-WORLDWRITABLE###\n\
                   /tmp/shared\n/tmp/shared\n/opt/drop\n%%KXN-WW-COMPLETE%%\n###KXN-FS-END###\n";
        assert_eq!(
            parse_filesystem(out)[0]["world_writable_dirs_without_sticky"],
            json!(2)
        );
    }

    #[test]
    fn filesystem_unusable_output() {
        assert!(parse_filesystem("").is_empty());
        // Markers but no mount table: not a Linux host we can judge.
        assert!(parse_filesystem(
            "###KXN-FS-MOUNTS###\n###KXN-FS-PROCMOUNTS###\n###KXN-FS-MODCONF###\n\
             ###KXN-FS-MOD-CRAMFS###\n###KXN-FS-MOD-FREEVXFS###\n###KXN-FS-MOD-USBSTORAGE###\n\
             ###KXN-FS-WORLDWRITABLE###\n###KXN-FS-END###\n"
        )
        .is_empty());
    }

    // ── command sanity ──────────────────────────────────────────────────────

    #[test]
    fn commands_declare_every_section_their_parser_reads() {
        for (cmd, markers) in [
            (
                PAM_COMMAND,
                vec![
                    "###KXN-PAM-DIR###",
                    "###KXN-PAM-STACK###",
                    "###KXN-PAM-SU###",
                    "###KXN-PWQUALITY###",
                    "###KXN-PWHISTORY###",
                    "###KXN-FAILLOCK###",
                ],
            ),
            (
                AUDIT_COMMAND,
                vec![
                    "###KXN-AUDIT-UNITS###",
                    "###KXN-AUDIT-PROCS###",
                    "###KXN-AUDITD-CONF###",
                    "###KXN-AUDIT-RULES###",
                    "###KXN-AUDIT-CMDLINE###",
                ],
            ),
            (
                FIREWALL_COMMAND,
                vec![
                    "###KXN-FW-TOOLS###",
                    "###KXN-FW-UFW###",
                    "###KXN-FW-FIREWALLD###",
                    "###KXN-FW-NFT###",
                    "###KXN-FW-IPTABLES###",
                    "###KXN-FW-SYSTEMD###",
                ],
            ),
            (
                FILESYSTEM_COMMAND,
                vec![
                    "###KXN-FS-MOUNTS###",
                    "###KXN-FS-PROCMOUNTS###",
                    "###KXN-FS-MODCONF###",
                    "###KXN-FS-MOD-CRAMFS###",
                    "###KXN-FS-MOD-FREEVXFS###",
                    "###KXN-FS-MOD-USBSTORAGE###",
                    "###KXN-FS-WORLDWRITABLE###",
                ],
            ),
        ] {
            for m in markers {
                assert!(cmd.contains(m), "{m} missing from command");
            }
        }
    }
}

/// Account-level audit counts for CIS 6.2.
///
/// These controls ask about the account database as a whole — how many accounts
/// have UID 0, how many have an empty password — not about one account, so they
/// cannot be answered from the per-user list. The rules read them as aggregates
/// and the collector produced none, so each was scored against all 26 users and
/// failed 26 times on a host where every one of them holds.
///
/// `/etc/shadow` is the gate: these are privileged host audits, and a scanner
/// that cannot read the shadow file cannot answer them. It then returns nothing
/// and the rules report as not evaluated, rather than guessing.
pub const USER_AUDIT_COMMAND: &str = r#"[ -r /proc/mounts ] || exit 0
[ -r /etc/shadow ] || exit 0
echo '###KXN_UID0###'
awk -F: '$3 == 0 { n++ } END { print n+0 }' /etc/passwd
echo '###KXN_EMPTYPW###'
awk -F: '($2 == "" || $2 == "!") && $1 != "root" { n++ } END { print n+0 }' /etc/shadow
echo '###KXN_HOMEPERMS###'
n=0
awk -F: '$3 >= 1000 && $6 != "" { print $6 }' /etc/passwd | while read -r h; do
  [ -d "$h" ] || continue
  m=$(stat -c '%a' "$h" 2>/dev/null) || continue
  case "$m" in *[2367]) echo x ;; esac
done | wc -l
echo '###KXN_FORWARD###'
awk -F: '$6 != "" { print $6 }' /etc/passwd | while read -r h; do [ -f "$h/.forward" ] && echo x; done | wc -l
echo '###KXN_NETRC###'
awk -F: '$6 != "" { print $6 }' /etc/passwd | while read -r h; do [ -f "$h/.netrc" ] && echo x; done | wc -l
"#;

/// Parse [`USER_AUDIT_COMMAND`]. Empty output means the shadow file was not
/// readable, so there is nothing to judge.
pub fn parse_user_audit(output: &str) -> Vec<Value> {
    let section = |marker: &str| -> Option<i64> {
        output
            .split(marker)
            .nth(1)?
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty() && !l.starts_with("###"))
            .and_then(|l| l.parse::<i64>().ok())
    };

    let uid_zero = match section("###KXN_UID0###") {
        Some(v) => v,
        None => return Vec::new(),
    };

    let mut map = serde_json::Map::new();
    map.insert("uid_zero_accounts".into(), json!(uid_zero));
    for (marker, key) in [
        ("###KXN_EMPTYPW###", "empty_password_count"),
        ("###KXN_HOMEPERMS###", "insecure_home_count"),
        ("###KXN_FORWARD###", "forward_file_count"),
        ("###KXN_NETRC###", "netrc_file_count"),
    ] {
        if let Some(v) = section(marker) {
            map.insert(key.into(), json!(v));
        }
    }
    vec![Value::Object(map)]
}

#[cfg(test)]
mod user_audit_tests {
    use super::*;

    #[test]
    fn reads_every_count() {
        let out = "###KXN_UID0###\n1\n###KXN_EMPTYPW###\n0\n###KXN_HOMEPERMS###\n2\n\
                   ###KXN_FORWARD###\n0\n###KXN_NETRC###\n1\n";
        let v = &parse_user_audit(out)[0];
        assert_eq!(v["uid_zero_accounts"], json!(1));
        assert_eq!(v["empty_password_count"], json!(0));
        assert_eq!(v["insecure_home_count"], json!(2));
        assert_eq!(v["netrc_file_count"], json!(1));
    }

    /// The command exits without output when `/etc/shadow` cannot be read. No
    /// object must be produced then: a zero would say "no account has an empty
    /// password" on the strength of not having looked.
    #[test]
    fn an_unreadable_shadow_file_produces_nothing() {
        assert!(parse_user_audit("").is_empty());
        assert!(parse_user_audit("\n").is_empty());
    }
}
