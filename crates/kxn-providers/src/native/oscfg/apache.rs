//! Apache HTTP Server collector: turns a remote host's httpd configuration into
//! the `apache_config` / `apache_permissions` objects the CIS Apache ruleset
//! (`rules/apache-cis.toml`) is written against.
//!
//! Two ideas drive everything here.
//!
//! 1. **Silence must stay silent.** If Apache is not installed, both parsers
//!    return an empty vector. The engine then reports the rules as *not
//!    evaluated* instead of inventing 31 violations on a database server that
//!    never ran a web server in its life. The same applies when Apache is
//!    installed but its configuration could not be read at all (unreadable
//!    files, restricted shell): no data is not the same as bad data.
//!
//! 2. **A missing directive is real information.** Once Apache *is* installed,
//!    an absent directive is not "unknown" — the server behaves according to a
//!    documented compiled-in default, and that default is very often exactly
//!    what the CIS control is trying to catch (a config with no `ServerTokens`
//!    line leaks the full version banner). So every field below falls back to
//!    the value httpd actually uses, each one justified in a comment.

use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

// Markers, not separators: the shell command emits them unconditionally so the
// parser can tell "section present but empty" from "command never got that far"
// (a truncated SSH channel, a shell that died mid-pipeline).
const MARKER_PRESENT: &str = "###KXN_APACHE_PRESENT###";
const MARKER_MODULES: &str = "###KXN_MODULES###";
const MARKER_ENVVARS: &str = "###KXN_ENVVARS###";
const MARKER_CONFIG: &str = "###KXN_CONFIG###";
const MARKER_CONF_STAT: &str = "###KXN_CONF_STAT###";
const MARKER_DOCROOT_STAT: &str = "###KXN_DOCROOT_STAT###";

/// Stand-in for "unlimited" on the `Limit*` directives. Apache spells unlimited
/// as `0`, which would sail through a `INF_OR_EQUAL 1048576` check while
/// meaning the exact opposite of what the control wants. Reporting the largest
/// value Apache itself accepts keeps the comparison honest.
const UNLIMITED: i64 = 2_147_483_647;

/// One shot, never fails, works on both packaging families.
///
/// Distribution split this has to absorb:
///   * Debian/Ubuntu: `/etc/apache2/apache2.conf`, fragments split across
///     `mods-enabled/*.load` (the `LoadModule` lines — *not* in `*.conf`),
///     `mods-enabled/*.conf`, `conf-enabled/*.conf`, `sites-enabled/*.conf`,
///     control binary `apache2ctl`, runtime identity in `/etc/apache2/envvars`.
///   * RHEL/CentOS/Fedora: `/etc/httpd/conf/httpd.conf`, `conf.modules.d/*.conf`
///     then `conf.d/*.conf`, control binary `apachectl`/`httpd`.
///
/// The `cat` order mirrors the include order of each distribution's main file,
/// because Apache's rule for most directives is "last one wins" and the CIS
/// findings live precisely in the overriding fragments (Debian ships its
/// `ServerTokens` in `conf-enabled/security.conf`, long after `apache2.conf`).
///
/// Everything is failure-tolerant: absent globs expand to literal patterns that
/// `cat` rejects on stderr, every stderr is discarded, and the command ends with
/// `exit 0` so a non-zero status from the last `cat` can never be mistaken for a
/// transport error by the caller.
pub(crate) const CONFIG_COMMAND: &str = "if command -v apache2ctl >/dev/null 2>&1 || command -v apachectl >/dev/null 2>&1 || command -v httpd >/dev/null 2>&1 || command -v apache2 >/dev/null 2>&1 || [ -f /etc/apache2/apache2.conf ] || [ -f /etc/httpd/conf/httpd.conf ]; then \
     echo '###KXN_APACHE_PRESENT###'; \
     echo '###KXN_MODULES###'; \
     (sudo -n apache2ctl -M || sudo -n httpd -M || apache2ctl -M || apachectl -M || httpd -M) 2>/dev/null; \
     echo '###KXN_ENVVARS###'; \
     cat /etc/apache2/envvars /etc/sysconfig/httpd /etc/default/apache2 2>/dev/null; \
     echo '###KXN_CONFIG###'; \
     cat /etc/apache2/apache2.conf /etc/apache2/ports.conf /etc/apache2/mods-enabled/*.load /etc/apache2/mods-enabled/*.conf /etc/apache2/conf-enabled/*.conf /etc/apache2/sites-enabled/*.conf /etc/httpd/conf/httpd.conf /etc/httpd/conf.modules.d/*.conf /etc/httpd/conf.d/*.conf 2>/dev/null; \
   else \
     echo '###KXN_APACHE_ABSENT###'; \
   fi; \
   exit 0";

/// Ownership/mode of the main configuration file plus every `DocumentRoot` the
/// configuration mentions.
///
/// Presence is decided on the configuration file alone here (not on the
/// binaries): without a config file there is nothing whose permissions could be
/// judged, and guessing a path would produce a verdict about a file that does
/// not exist. `/var/www/html` and `/var/www` are appended as candidates because
/// a `DocumentRoot` may legitimately be absent from the config (both families
/// compile in `/var/www/html` as the default document root); the `[ -d ]` guard
/// drops the ones that are not really there, and also drops any unexpanded
/// `${...}` variable the grep may have picked up.
pub(crate) const PERMISSIONS_COMMAND: &str = "if [ -f /etc/apache2/apache2.conf ] || [ -f /etc/httpd/conf/httpd.conf ]; then \
     echo '###KXN_APACHE_PRESENT###'; \
     echo '###KXN_CONF_STAT###'; \
     stat -c '%a %U %G %n' /etc/apache2/apache2.conf /etc/httpd/conf/httpd.conf 2>/dev/null; \
     echo '###KXN_DOCROOT_STAT###'; \
     for d in $(grep -rhiE '^[[:space:]]*DocumentRoot[[:space:]]+' /etc/apache2 /etc/httpd 2>/dev/null | awk '{print $2}' | tr -d '\\042' | sort -u) /var/www/html /var/www; do \
       [ -d \"$d\" ] && stat -c '%a %n' \"$d\" 2>/dev/null; \
     done; \
   else \
     echo '###KXN_APACHE_ABSENT###'; \
   fi; \
   exit 0";

// ─── Section slicing ────────────────────────────────────────────────────────

/// Everything between `marker` and the next `###KXN_` marker. Slicing on the
/// marker prefix rather than on a fixed list keeps the parser working if the
/// command later grows a section.
fn section<'a>(output: &'a str, marker: &str) -> &'a str {
    let rest = match output.find(marker) {
        Some(idx) => &output[idx + marker.len()..],
        None => return "",
    };
    match rest.find("###KXN_") {
        Some(end) => &rest[..end],
        None => rest,
    }
}

// ─── Lexing ─────────────────────────────────────────────────────────────────

/// Split an Apache directive line into arguments the way httpd does: runs of
/// whitespace separate tokens, double quotes group them, and a backslash
/// escapes the next character inside quotes. Needed because half the values we
/// extract contain spaces (`"max-age=31536000; includeSubDomains"`, a
/// `LogFormat` string) and naive `split_whitespace` would shred them.
///
/// Note that `#` is deliberately *not* treated as a comment introducer here:
/// Apache only honours comments on lines whose first non-blank character is
/// `#`, so stripping a trailing `#` would corrupt values such as `User #-1`.
fn tokenize(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut started = false;
    let mut in_quotes = false;
    let mut escaped = false;

    for ch in input.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' if in_quotes => escaped = true,
            '"' => {
                in_quotes = !in_quotes;
                started = true;
            }
            c if c.is_whitespace() && !in_quotes => {
                if started {
                    tokens.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            c => {
                current.push(c);
                started = true;
            }
        }
    }
    if started {
        tokens.push(current);
    }
    tokens
}

// ─── Environment variables ──────────────────────────────────────────────────

/// Debian's `apache2.conf` does not contain a runtime identity, it contains
/// `User ${APACHE_RUN_USER}`, resolved from `/etc/apache2/envvars` at startup.
/// Without this expansion the CIS 5.1/5.2 regexes would fail on every single
/// Debian host — a pure parsing artefact, not a finding.
fn parse_envvars(text: &str) -> BTreeMap<String, String> {
    let mut vars = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line).trim();
        let (key, value) = match line.split_once('=') {
            Some(pair) => pair,
            None => continue,
        };
        let key = key.trim();
        if key.is_empty()
            || !key
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            continue;
        }
        let value = value.trim().trim_matches('"').trim_matches('\'');
        vars.insert(key.to_string(), value.to_string());
    }
    // Fallback for the one case where the gap is a false positive rather than a
    // finding: `envvars` exists but was not readable over this SSH session. The
    // Debian package has shipped www-data for both since forever; when the file
    // *is* readable its real values win, so a host that deliberately runs as
    // root is still caught.
    vars.entry("APACHE_RUN_USER".to_string())
        .or_insert_with(|| "www-data".to_string());
    vars.entry("APACHE_RUN_GROUP".to_string())
        .or_insert_with(|| "www-data".to_string());
    vars
}

/// Substitute `${NAME}` occurrences; unknown names are left verbatim so the
/// reader of a finding can see that the value was never resolved.
fn expand_vars(value: &str, vars: &BTreeMap<String, String>) -> String {
    if !value.contains("${") {
        return value.to_string();
    }
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        match after.find('}') {
            Some(end) => {
                let name = &after[..end];
                match vars.get(name) {
                    Some(resolved) => out.push_str(resolved),
                    None => {
                        out.push_str("${");
                        out.push_str(name);
                        out.push('}');
                    }
                }
                rest = &after[end + 1..];
            }
            None => {
                // Unterminated `${` — emit the remainder as-is and stop.
                out.push_str(&rest[start..]);
                return out;
            }
        }
    }
    out.push_str(rest);
    out
}

// ─── Configuration scan ─────────────────────────────────────────────────────

/// Blocks that scope a directive to a subtree instead of the server. A
/// `Timeout` inside `<IfModule>` or `<VirtualHost>` still describes how the
/// server behaves, so those are transparent; a `Require` inside `<Directory
/// /srv/private>` describes one directory and must never be mistaken for the
/// server-wide default.
fn is_container(tag: &str) -> bool {
    matches!(
        tag,
        "directory"
            | "directorymatch"
            | "location"
            | "locationmatch"
            | "files"
            | "filesmatch"
            | "limit"
            | "limitexcept"
            | "proxy"
            | "proxymatch"
            | "requireall"
            | "requireany"
            | "requirenone"
            | "if"
            | "else"
            | "elseif"
    )
}

#[derive(Default)]
struct ConfigScan {
    /// Server-scope directives, lowercased name → last value seen. "Last wins"
    /// is Apache's own rule for repeated single-value directives.
    globals: BTreeMap<String, String>,
    /// Response headers, normalized name → value.
    headers: BTreeMap<String, String>,
    /// `(format, nickname)` pairs, in file order.
    log_formats: Vec<(String, Option<String>)>,
    /// Arguments of the last `CustomLog`/`TransferLog`.
    last_custom_log: Option<Vec<String>>,
    /// Modules named by `LoadModule`, used when `-M` was not available.
    load_modules: BTreeSet<String>,
    /// Any `Options` directive that switches directory listing on.
    options_indexes: bool,
    /// `Some(true)` = `<Directory />` explicitly denies, `Some(false)` = it
    /// explicitly grants, `None` = no verdict found in that block.
    root_dir_denied: Option<bool>,
    root_loc_denied: Option<bool>,
    root_allow_override: Option<String>,
    /// Most permissive `AllowOverride` seen outside `<Directory />`.
    other_allow_override: Option<String>,
}

/// Innermost scoping block, if any — `("directory", "/")` for a directive
/// sitting directly in `<Directory />`. Looking at the innermost *container*
/// rather than the innermost `<Directory>` matters: a `Require` inside
/// `<Directory /> <Files x>` governs `x`, not the root.
fn innermost_container(stack: &[(String, String)]) -> Option<(&str, &str)> {
    stack
        .iter()
        .rev()
        .find(|(tag, _)| is_container(tag))
        .map(|(tag, arg)| (tag.as_str(), arg.as_str()))
}

fn scan_config(text: &str, vars: &BTreeMap<String, String>) -> ConfigScan {
    let mut scan = ConfigScan::default();
    let mut stack: Vec<(String, String)> = Vec::new();

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(inner) = line.strip_prefix("</") {
            let tag = inner.trim_end_matches('>').trim().to_ascii_lowercase();
            // Unwind to the matching opener only. Concatenating many files can
            // yield a stray closing tag (a fragment read halfway, an `IfDefine`
            // the packager left open); collapsing the whole stack on one of
            // those would silently reparent every following directive.
            if let Some(pos) = stack.iter().rposition(|(open, _)| *open == tag) {
                stack.truncate(pos);
            }
            continue;
        }

        if let Some(inner) = line.strip_prefix('<') {
            let tokens = tokenize(inner.trim_end_matches('>'));
            let tag = tokens
                .first()
                .map(|t| t.to_ascii_lowercase())
                .unwrap_or_default();
            // `<Directory "/">` and `<Directory />` are the same block; the
            // tokenizer already removed the quotes.
            let arg = tokens.get(1).cloned().unwrap_or_default();
            stack.push((tag, arg));
            continue;
        }

        let tokens = tokenize(line);
        let name = match tokens.first() {
            Some(first) => first.to_ascii_lowercase(),
            None => continue,
        };
        let args: Vec<String> = tokens[1..]
            .iter()
            .map(|arg| expand_vars(arg, vars))
            .collect();
        let value = args.join(" ");
        let scope = innermost_container(&stack);
        let in_root_dir = scope == Some(("directory", "/"));
        let in_root_loc = scope == Some(("location", "/"));

        match name.as_str() {
            "loadmodule" => {
                if let Some(module) = args.first() {
                    scan.load_modules.insert(module.to_ascii_lowercase());
                }
            }
            "options" => {
                for token in &args {
                    let lowered = token.to_ascii_lowercase();
                    let (negated, option) = match lowered.strip_prefix('-') {
                        Some(rest) => (true, rest),
                        None => (false, lowered.strip_prefix('+').unwrap_or(&lowered)),
                    };
                    // `All` is not a synonym of "everything reasonable": it
                    // means every option except MultiViews, Indexes included.
                    // A config that never mentions Options at all is fine —
                    // 2.4's default is `FollowSymlinks`, listings off.
                    if !negated && (option == "indexes" || option == "all") {
                        scan.options_indexes = true;
                    }
                }
            }
            "allowoverride" => {
                if in_root_dir {
                    scan.root_allow_override = Some(value.clone());
                } else if !value.eq_ignore_ascii_case("none") {
                    // Keep the worst offender: `All` beats `AuthConfig` when
                    // deciding what to report as the effective posture.
                    let replace = scan
                        .other_allow_override
                        .as_deref()
                        .is_none_or(|current| !current.eq_ignore_ascii_case("all"));
                    if replace {
                        scan.other_allow_override = Some(value.clone());
                    }
                }
            }
            "require" => {
                let lowered = value.to_ascii_lowercase();
                let verdict = if lowered.starts_with("all denied") {
                    Some(true)
                } else if lowered.starts_with("all granted") {
                    Some(false)
                } else {
                    // `Require ip 10.0.0.0/8`, `Require valid-user`… restrict
                    // access without being the blanket deny CIS asks for, so
                    // they leave the verdict untouched rather than claiming a
                    // deny that is not there.
                    None
                };
                if let Some(denied) = verdict {
                    if in_root_dir {
                        scan.root_dir_denied = Some(denied);
                    } else if in_root_loc {
                        scan.root_loc_denied = Some(denied);
                    }
                }
            }
            "deny" => {
                // 2.2-era syntax still found on long-lived hosts, and still
                // honoured when mod_access_compat is loaded.
                if value.to_ascii_lowercase().starts_with("from all") {
                    if in_root_dir {
                        scan.root_dir_denied = Some(true);
                    } else if in_root_loc {
                        scan.root_loc_denied = Some(true);
                    }
                }
            }
            "header" => apply_header(&args, &mut scan.headers),
            "logformat" => {
                if let Some(format) = args.first() {
                    scan.log_formats
                        .push((format.clone(), args.get(1).cloned()));
                }
            }
            "customlog" | "transferlog" => {
                scan.last_custom_log = Some(args.clone());
            }
            _ => {
                if scope.is_none() {
                    scan.globals.insert(name, value);
                }
            }
        }
    }

    scan
}

/// `Header [condition] action name [value] [env=...]`. The optional condition
/// keyword in front (`always` is the one CIS remediations use, because the
/// default `onsuccess` table skips error responses) has to be stepped over
/// before the action can be read.
fn apply_header(args: &[String], headers: &mut BTreeMap<String, String>) {
    let mut idx = 0;
    while let Some(token) = args.get(idx) {
        let lowered = token.to_ascii_lowercase();
        if lowered == "always" || lowered == "onsuccess" || lowered == "early" {
            idx += 1;
        } else {
            break;
        }
    }
    let action = match args.get(idx) {
        Some(action) => action.to_ascii_lowercase(),
        None => return,
    };
    let name = match args.get(idx + 1) {
        Some(name) => normalize_header_name(name),
        None => return,
    };
    match action.as_str() {
        "set" | "setifempty" | "append" | "add" | "merge" => {
            headers.insert(name, args.get(idx + 2).cloned().unwrap_or_default());
        }
        // A later `unset` really does remove the header from responses, so it
        // must not leave a stale "compliant" value behind.
        "unset" => {
            headers.remove(&name);
        }
        // `edit`/`echo` rewrite an existing value with a regex; there is no
        // literal value to report, so they are ignored on purpose.
        _ => {}
    }
}

fn normalize_header_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

// ─── Module list ────────────────────────────────────────────────────────────

/// `apache2ctl -M` prints `Loaded Modules:` followed by ` name_module (shared)`.
/// Only lines that actually name a module are kept, so a header line or a
/// leftover warning cannot inflate the count the CIS "minimize modules" control
/// compares against.
fn parse_module_list(text: &str) -> BTreeSet<String> {
    let mut modules = BTreeSet::new();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        if let Some(name) = parts.next() {
            if name.ends_with("_module") {
                modules.insert(name.to_ascii_lowercase());
            }
        }
    }
    modules
}

// ─── Value normalization ────────────────────────────────────────────────────

/// Apache parses directive keywords case-insensitively, but the CIS rules
/// compare strings exactly. A host hardened with `ServerTokens prod` is
/// compliant and must not be failed over its capitalization, so known keywords
/// are rendered in the spelling the documentation (and the rule) uses.
fn canonical_server_tokens(raw: Option<&str>) -> String {
    // Documented default is `Full`: with no directive, httpd advertises its
    // version and loaded modules — exactly the disclosure CIS 2.3 targets.
    let value = raw.unwrap_or("Full");
    match value.to_ascii_lowercase().as_str() {
        "prod" | "productonly" => "Prod",
        "major" => "Major",
        "minor" => "Minor",
        "min" | "minimal" => "Min",
        "os" => "OS",
        "full" => "Full",
        _ => return value.to_string(),
    }
    .to_string()
}

fn canonical_server_signature(raw: Option<&str>) -> String {
    // Documented default is `Off`; a host that never touched the directive is
    // genuinely compliant with CIS 2.4 (Debian's security.conf, which sets it
    // to `On`, is part of what gets concatenated, so a real `On` still shows).
    let value = raw.unwrap_or("Off");
    match value.to_ascii_lowercase().as_str() {
        "on" => "On",
        "off" => "Off",
        "email" => "EMail",
        _ => return value.to_string(),
    }
    .to_string()
}

fn canonical_on_off(raw: Option<&str>, default_value: &str) -> String {
    let value = raw.unwrap_or(default_value);
    match value.to_ascii_lowercase().as_str() {
        "on" | "true" | "yes" | "1" => "on".to_string(),
        "off" | "false" | "no" | "0" => "off".to_string(),
        other => other.to_string(),
    }
}

/// `LogLevel` may carry per-module levels (`LogLevel warn ssl:info`); only the
/// first, module-less token is the server level the control is about.
fn core_log_level(raw: Option<&str>) -> String {
    // Documented default is `warn`.
    let value = raw.unwrap_or("warn");
    value
        .split_whitespace()
        .find(|token| !token.contains(':'))
        .unwrap_or("warn")
        .to_ascii_lowercase()
}

fn number_or_default(raw: Option<&str>, default_value: i64, zero_is_unlimited: bool) -> Value {
    let parsed = raw
        .and_then(|value| value.split_whitespace().next())
        .and_then(|value| value.parse::<i64>().ok());
    let number = parsed.unwrap_or(default_value);
    if zero_is_unlimited && number == 0 {
        return json!(UNLIMITED);
    }
    json!(number)
}

/// Keep only the cipher selectors that are actually *enabled*.
///
/// This is the one place where echoing the raw directive would be actively
/// misleading: the recommended suite `HIGH:!aNULL:!MD5:!RC4:!3DES:!EXPORT`
/// contains the substrings `MD5`, `RC4`, `DES` and `EXPORT` and would fail
/// every `NOT_INCLUDE` in CIS 7.3 precisely *because* it forbids them. Dropping
/// the `!`/`-` prefixed (i.e. removed) selectors leaves `HIGH`, while a genuinely
/// weak `ALL:+RC4:+MD5` keeps its weak selectors and is still caught.
fn enabled_ciphers(raw: &str) -> String {
    raw.split(':')
        .map(str::trim)
        .filter(|token| !token.is_empty() && !token.starts_with('!') && !token.starts_with('-'))
        .collect::<Vec<_>>()
        .join(":")
}

/// The format a rule should be judged on is the one the access log actually
/// uses: resolve the nickname referenced by the last `CustomLog`, fall back to
/// an inline format string, then to a defined `combined`, then to Apache's
/// documented default.
///
/// The value is reported exactly as the file writes it — the status code is
/// `%>s` in every stock format, and the rule matches it with a regex rather
/// than the collector rewriting it, which would make the report disagree with
/// the server's own configuration.
fn raw_log_format(scan: &ConfigScan) -> String {
    let nickname_or_inline = scan
        .last_custom_log
        .as_ref()
        .and_then(|args| args.get(1))
        .cloned();

    if let Some(reference) = nickname_or_inline {
        if let Some((format, _)) = scan
            .log_formats
            .iter()
            .rev()
            .find(|(_, nickname)| nickname.as_deref() == Some(reference.as_str()))
        {
            return String::from(format);
        }
        // `CustomLog logs/access_log "%h %l %u %t ..."` — the format is inline
        // rather than a nickname.
        if reference.contains('%') {
            return String::from(&reference);
        }
    }

    if let Some((format, _)) = scan
        .log_formats
        .iter()
        .rev()
        .find(|(_, nickname)| nickname.as_deref() == Some("combined"))
    {
        return String::from(format);
    }
    if let Some((format, _)) = scan.log_formats.last() {
        return String::from(format);
    }
    // Documented default of the LogFormat directive: the Common Log Format,
    // which has no User-Agent — so a server that defines nothing fails CIS 6.4,
    // correctly.
    String::from("%h %l %u %t \"%r\" %>s %b")
}

// ─── Public parsers ─────────────────────────────────────────────────────────

/// Render `apache_config`: one object, or none at all when Apache is absent.
pub(crate) fn parse_config(output: &str) -> Vec<Value> {
    if !output.contains(MARKER_PRESENT) {
        return Vec::new();
    }

    let config_text = section(output, MARKER_CONFIG);
    if config_text.trim().is_empty() {
        // Binaries exist but not a single configuration byte came back
        // (unreadable files, a shell that refused the `cat`). Defaulting all 28
        // fields here would manufacture a wall of findings out of a read error.
        return Vec::new();
    }

    let vars = parse_envvars(section(output, MARKER_ENVVARS));
    let scan = scan_config(config_text, &vars);

    // `-M` is the truth (it includes statically linked modules and resolves
    // conditional includes); counting `LoadModule` lines is the fallback for
    // when the control binary needed root and we were not root.
    let mut modules = parse_module_list(section(output, MARKER_MODULES));
    if modules.is_empty() {
        modules = scan.load_modules.clone();
    }

    let global = |key: &str| scan.globals.get(key).map(String::as_str);
    let header = |key: &str| {
        scan.headers
            .get(key)
            .cloned()
            // No header directive means the header is simply not sent; the
            // empty string fails every header rule, which is the truth.
            .unwrap_or_default()
    };

    let root_directory_access = if scan.root_dir_denied == Some(true) {
        "denied"
    } else {
        // No `<Directory />` block at all is not "unknown": httpd 2.4 requires
        // no authorization where none is configured, so the filesystem root is
        // reachable. That absence is the finding CIS 3.1 is after.
        "allowed"
    };
    let default_access = if scan.root_dir_denied == Some(true) || scan.root_loc_denied == Some(true)
    {
        "denied"
    } else {
        "allowed"
    };

    // CIS 3.2 is written about the root directory, but an `AllowOverride All`
    // on the document root is the same weakness one level down, so it is
    // surfaced when the root block itself says nothing. Documented default is
    // `None` (since 2.3.9), which is what an untouched server really does.
    let allow_override = scan
        .root_allow_override
        .clone()
        .or_else(|| scan.other_allow_override.clone())
        .unwrap_or_else(|| "None".to_string());

    // mod_ssl's documented default depends on the OpenSSL build, so its
    // absence says nothing useful either way.
    let ssl_cipher_suite_raw = global("sslciphersuite").unwrap_or("DEFAULT").to_string();
    let ssl_cipher_suite = enabled_ciphers(&ssl_cipher_suite_raw);

    let config = json!({
        "servertokens": canonical_server_tokens(global("servertokens")),
        "serversignature": canonical_server_signature(global("serversignature")),
        "options_indexes": if scan.options_indexes { "enabled" } else { "disabled" },
        "loaded_modules_count": modules.len() as i64,
        "root_directory_access": root_directory_access,
        "allowoverride": allow_override,
        "default_access": default_access,
        "loglevel": core_log_level(global("loglevel")),
        // Documented default `logs/error_log`: httpd always writes an error log,
        // so this rule can only fail on an explicit `ErrorLog /dev/null`-style
        // emptying, which is exactly right.
        "errorlog": global("errorlog").unwrap_or("logs/error_log"),
        // No default: without CustomLog or TransferLog there is no access log at
        // all, and the empty string is what makes CIS 6.3 fire.
        "customlog": scan
            .last_custom_log
            .as_ref()
            .map(|args| args.join(" "))
            .unwrap_or_default(),
        // Raw, as the file has it. CIS 6.4 is expressed against
        // `%>s` too, so nothing here needs rewriting.
        "logformat": raw_log_format(&scan),
        // Raw on purpose, unlike the cipher suite: the rule needs to see both
        // the `-all` prefix and any leftover `SSLv3`, and mod_ssl's documented
        // default `all -SSLv3` legitimately fails both checks.
        "sslprotocol": global("sslprotocol").unwrap_or("all -SSLv3"),
        // Both: the directive as written, and the selectors it actually
        // enables. A hardened `HIGH:!aNULL:!MD5:!RC4` contains the substrings
        // MD5 and RC4 *because it forbids them*, so a rule asserting the
        // absence of a weak cipher has to read the enabled list — and an
        // operator reading a report needs the original.
        "sslciphersuite": ssl_cipher_suite_raw,
        "sslciphersuite_enabled": ssl_cipher_suite,
        // Documented default is `off` — the client's cipher preference wins,
        // which is what CIS 7.4 wants flagged.
        "sslhonorcipherorder": canonical_on_off(global("sslhonorcipherorder"), "off"),
        "header_strict_transport_security": header("strict_transport_security"),
        "header_x_frame_options": header("x_frame_options"),
        "header_x_content_type_options": header("x_content_type_options"),
        "header_x_xss_protection": header("x_xss_protection"),
        // Documented defaults: Timeout 60 (fails the 10s control, as intended),
        // KeepAliveTimeout 5 and MaxKeepAliveRequests 100 (both already
        // compliant on an untouched server).
        "timeout": number_or_default(global("timeout"), 60, false),
        "keepalivetimeout": number_or_default(global("keepalivetimeout"), 5, false),
        "maxkeepaliverequests": number_or_default(global("maxkeepaliverequests"), 100, true),
        // LimitRequestBody defaults to 0 = unlimited, LimitRequestFields to 100;
        // both spell "no limit" as 0, hence the sentinel.
        "limitrequestbody": number_or_default(global("limitrequestbody"), 0, true),
        "limitrequestfields": number_or_default(global("limitrequestfields"), 100, true),
        // Documented default is `#-1`, i.e. "inherit the identity that started
        // httpd" — root, in practice. It fails the regex, which is correct.
        "user": global("user").unwrap_or("#-1"),
        "group": global("group").unwrap_or("#-1"),
        // CIS 5.4 accepts "disabled *or* restricted"; only the first half can be
        // decided from the module list, so a mod_status that is loaded but
        // locked down behind `Require ip` is reported as enabled and needs an
        // exception rather than a code change.
        "mod_info_enabled": if modules.contains("info_module") { "yes" } else { "no" },
        "mod_status_enabled": if modules.contains("status_module") { "yes" } else { "no" },
    });

    vec![config]
}

/// Render `apache_permissions`: one object, or none when Apache is absent or
/// nothing could be stat'ed.
pub(crate) fn parse_permissions(output: &str) -> Vec<Value> {
    if !output.contains(MARKER_PRESENT) {
        return Vec::new();
    }

    // `stat -c '%a %U %G %n'`, main configuration file first. Both distribution
    // paths are passed to a single stat, so the first surviving line is the one
    // that exists on this host.
    let mut owner: Option<String> = None;
    let mut mode: Option<String> = None;
    for line in section(output, MARKER_CONF_STAT).lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        mode = Some(fields[0].to_string());
        owner = Some(fields[1].to_string());
        break;
    }

    let (mode, owner) = match (mode, owner) {
        (Some(mode), Some(owner)) => (mode, owner),
        // Config file gone between the two commands, or stat unavailable: no
        // evidence, no verdict.
        _ => return Vec::new(),
    };

    // `stat -c %a` drops leading zeros (`0644` prints as `644`, but `0044`
    // prints as `44`), and the CIS regex expects exactly three octal digits.
    // Padding restores the comparison; a four-digit mode carrying setuid/setgid
    // bits is left alone so it still fails, which is the desired outcome.
    let permissions = if mode.len() < 3 {
        format!("{:0>3}", mode)
    } else {
        mode
    };

    // `stat -c '%a %n'` per document root. World-writable is the `2` bit of the
    // last octal digit; a sticky-bit directory (`1777`) is still caught because
    // only the trailing digit is inspected.
    let mut world_writable = false;
    for line in section(output, MARKER_DOCROOT_STAT).lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.is_empty() {
            continue;
        }
        if let Some(last_digit) = fields[0].chars().last().and_then(|c| c.to_digit(8)) {
            if last_digit & 0b010 != 0 {
                world_writable = true;
                break;
            }
        }
    }

    vec![json!({
        "httpd_conf_owner": owner,
        "httpd_conf_permissions": permissions,
        "docroot_world_writable": if world_writable { "yes" } else { "no" },
    })]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RHEL/CentOS layout, hardened by hand: every CIS control should pass.
    const HARDENED_RHEL: &str = r#"###KXN_APACHE_PRESENT###
###KXN_MODULES###
Loaded Modules:
 core_module (static)
 so_module (static)
 http_module (static)
 mpm_event_module (shared)
 authz_core_module (shared)
 log_config_module (shared)
 headers_module (shared)
 ssl_module (shared)
###KXN_ENVVARS###
###KXN_CONFIG###
ServerRoot "/etc/httpd"
Listen 80
User apache
Group apache
ServerAdmin root@localhost
ServerTokens prod
ServerSignature off
Timeout 10
KeepAlive On
MaxKeepAliveRequests 500
KeepAliveTimeout 15
LimitRequestBody 1048576
LimitRequestFields 100

<Directory />
    AllowOverride None
    Require all denied
    Options -Indexes -FollowSymLinks
</Directory>

DocumentRoot "/var/www/html"

<Directory "/var/www/html">
    Options -Indexes
    AllowOverride None
    Require all granted
</Directory>

<Files ".ht*">
    Require all denied
</Files>

ErrorLog "logs/error_log"
LogLevel warn

<IfModule log_config_module>
    LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" combined
    LogFormat "%h %l %u %t \"%r\" %>s %b" common
    CustomLog "logs/access_log" combined
</IfModule>

<IfModule mod_ssl.c>
    SSLProtocol -all +TLSv1.2 +TLSv1.3
    SSLCipherSuite HIGH:!aNULL:!MD5:!RC4:!3DES:!EXPORT
    SSLHonorCipherOrder on
</IfModule>

<IfModule mod_headers.c>
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    Header always set X-Frame-Options SAMEORIGIN
    Header always set X-Content-Type-Options nosniff
    Header always set X-XSS-Protection "1; mode=block"
</IfModule>
"#;

    /// Debian/Ubuntu stock install: apache2.conf plus the mods-enabled `.load`
    /// lines and the default vhost, with `apache2ctl -M` unavailable.
    const DEFAULT_DEBIAN: &str = r#"###KXN_APACHE_PRESENT###
###KXN_MODULES###
###KXN_ENVVARS###
export APACHE_RUN_USER=www-data
export APACHE_RUN_GROUP=www-data
export APACHE_PID_FILE=/var/run/apache2$SUFFIX/apache2.pid
export APACHE_RUN_DIR=/var/run/apache2$SUFFIX
export APACHE_LOG_DIR=/var/log/apache2$SUFFIX
###KXN_CONFIG###
DefaultRuntimeDir ${APACHE_RUN_DIR}
PidFile ${APACHE_PID_FILE}
Timeout 300
KeepAlive On
MaxKeepAliveRequests 100
KeepAliveTimeout 5
User ${APACHE_RUN_USER}
Group ${APACHE_RUN_GROUP}
HostnameLookups Off
ErrorLog ${APACHE_LOG_DIR}/error.log
LogLevel warn

<Directory />
	Options FollowSymLinks
	AllowOverride None
	Require all denied
</Directory>

<Directory /usr/share>
	AllowOverride None
	Require all granted
</Directory>

<Directory /var/www/>
	Options Indexes FollowSymLinks
	AllowOverride None
	Require all granted
</Directory>

AccessFileName .htaccess

<FilesMatch "^\.ht">
	Require all denied
</FilesMatch>

LogFormat "%v:%p %h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" vhost_combined
LogFormat "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" combined
LogFormat "%h %l %u %t \"%r\" %>s %O" common
LoadModule authz_core_module /usr/lib/apache2/modules/mod_authz_core.so
LoadModule dir_module /usr/lib/apache2/modules/mod_dir.so
LoadModule mpm_event_module /usr/lib/apache2/modules/mod_mpm_event.so
LoadModule status_module /usr/lib/apache2/modules/mod_status.so
LoadModule info_module /usr/lib/apache2/modules/mod_info.so
#LoadModule dav_module /usr/lib/apache2/modules/mod_dav.so
<VirtualHost *:80>
	ServerAdmin webmaster@localhost
	DocumentRoot /var/www/html
	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
"#;

    #[test]
    fn hardened_rhel_server_satisfies_every_control() {
        let parsed = parse_config(HARDENED_RHEL);
        assert_eq!(parsed.len(), 1);
        let config = &parsed[0];

        // Lowercase keywords in the file, canonical spelling in the object.
        assert_eq!(config["servertokens"], "Prod");
        assert_eq!(config["serversignature"], "Off");
        assert_eq!(config["options_indexes"], "disabled");
        assert_eq!(config["loaded_modules_count"], 8);
        assert_eq!(config["root_directory_access"], "denied");
        assert_eq!(config["allowoverride"], "None");
        assert_eq!(config["default_access"], "denied");
        assert_eq!(config["loglevel"], "warn");
        assert_eq!(config["errorlog"], "logs/error_log");
        assert_eq!(config["customlog"], "logs/access_log combined");

        // Reported exactly as the file writes it. The status code is `%>s` in
        // every stock format, and the rule matches it with a regex rather than
        // the collector rewriting the value.
        let log_format = config["logformat"].as_str().unwrap_or_default();
        for needle in ["%h", "%r", "%>s", "%{User-Agent}i"] {
            assert!(log_format.contains(needle), "missing {needle} in {log_format}");
        }

        assert_eq!(config["sslprotocol"], "-all +TLSv1.2 +TLSv1.3");
        // Negated selectors dropped, otherwise `!MD5` would fail NOT_INCLUDE MD5.
        assert_eq!(config["sslciphersuite"], "HIGH:!aNULL:!MD5:!RC4:!3DES:!EXPORT");
        assert_eq!(config["sslciphersuite_enabled"], "HIGH");
        let ciphers = config["sslciphersuite_enabled"].as_str().unwrap_or_default();
        for forbidden in ["NULL", "DES", "RC4", "MD5", "EXPORT"] {
            assert!(!ciphers.contains(forbidden));
        }
        assert_eq!(config["sslhonorcipherorder"], "on");

        assert_eq!(
            config["header_strict_transport_security"],
            "max-age=31536000; includeSubDomains"
        );
        assert_eq!(config["header_x_frame_options"], "SAMEORIGIN");
        assert_eq!(config["header_x_content_type_options"], "nosniff");
        assert_eq!(config["header_x_xss_protection"], "1; mode=block");

        assert_eq!(config["timeout"], 10);
        assert_eq!(config["keepalivetimeout"], 15);
        assert_eq!(config["maxkeepaliverequests"], 500);
        assert_eq!(config["limitrequestbody"], 1_048_576);
        assert_eq!(config["limitrequestfields"], 100);
        assert_eq!(config["user"], "apache");
        assert_eq!(config["group"], "apache");
        assert_eq!(config["mod_info_enabled"], "no");
        assert_eq!(config["mod_status_enabled"], "no");
    }

    #[test]
    fn stock_debian_server_reports_the_real_weaknesses() {
        let parsed = parse_config(DEFAULT_DEBIAN);
        assert_eq!(parsed.len(), 1);
        let config = &parsed[0];

        // Nothing sets these: the documented defaults are what the server does.
        assert_eq!(config["servertokens"], "Full");
        assert_eq!(config["serversignature"], "Off");
        assert_eq!(config["sslprotocol"], "all -SSLv3");
        assert_eq!(config["sslhonorcipherorder"], "off");
        assert_eq!(config["timeout"], 300);
        assert_eq!(config["keepalivetimeout"], 5);
        assert_eq!(config["maxkeepaliverequests"], 100);
        // `LimitRequestBody` absent means unlimited, reported as the sentinel so
        // the "1 MiB or less" control actually fails.
        assert_eq!(config["limitrequestbody"], UNLIMITED);
        assert_eq!(config["limitrequestfields"], 100);

        // `Options Indexes` in <Directory /var/www/>.
        assert_eq!(config["options_indexes"], "enabled");
        // envvars expansion, otherwise this would read `${APACHE_RUN_USER}`.
        assert_eq!(config["user"], "www-data");
        assert_eq!(config["group"], "www-data");
        // mods-enabled fallback: `-M` gave nothing, the commented-out dav line
        // is not counted.
        assert_eq!(config["loaded_modules_count"], 5);
        assert_eq!(config["mod_status_enabled"], "yes");
        assert_eq!(config["mod_info_enabled"], "yes");

        // No `Header` directive anywhere.
        assert_eq!(config["header_x_frame_options"], "");
        assert_eq!(config["header_strict_transport_security"], "");
        assert_eq!(config["header_x_content_type_options"], "");
        assert_eq!(config["header_x_xss_protection"], "");

        // The <Directory /> block is compliant even on a stock install.
        assert_eq!(config["root_directory_access"], "denied");
        assert_eq!(config["default_access"], "denied");
        assert_eq!(config["allowoverride"], "None");

        // Logging comes from the vhost, with the nickname resolved.
        let error_log = config["errorlog"].as_str().unwrap_or_default();
        assert!(error_log.ends_with("/error.log"), "{error_log}");
        let custom_log = config["customlog"].as_str().unwrap_or_default();
        assert!(custom_log.contains("/access.log"), "{custom_log}");
        // Reported exactly as the file writes it — `%>s` included.
        let log_format = config["logformat"].as_str().unwrap_or_default();
        assert!(log_format.contains("%{User-Agent}i"), "{log_format}");
        assert!(log_format.contains("%>s") || log_format.contains("%s"), "{log_format}");
        // `combined`, not `vhost_combined` and not `common`.
        assert!(!log_format.starts_with("%v:%p"), "{log_format}");
    }

    #[test]
    fn apache_absent_yields_no_object_at_all() {
        // The host answered, Apache simply is not there.
        assert!(parse_config("###KXN_APACHE_ABSENT###\n").is_empty());
        assert!(parse_permissions("###KXN_APACHE_ABSENT###\n").is_empty());
        // The command produced nothing (no shell, closed channel, timeout).
        assert!(parse_config("").is_empty());
        assert!(parse_permissions("").is_empty());
        assert!(parse_config("\n  \n").is_empty());
    }

    #[test]
    fn installed_but_unreadable_config_yields_no_object() {
        // Binaries found, every `cat` denied: reporting 28 defaults here would
        // be inventing findings out of a permission error.
        let output = "###KXN_APACHE_PRESENT###\n###KXN_MODULES###\n###KXN_ENVVARS###\n###KXN_CONFIG###\n";
        assert!(parse_config(output).is_empty());
    }

    #[test]
    fn last_directive_wins_and_comments_are_ignored() {
        let output = "###KXN_APACHE_PRESENT###\n###KXN_CONFIG###\n\
                      # ServerTokens Prod\n\
                      ServerTokens OS\n\
                      Timeout 60\n\
                        #Timeout 10\n\
                      ServerTokens Full\n\
                      Timeout 8\n";
        let config = &parse_config(output)[0];
        assert_eq!(config["servertokens"], "Full");
        assert_eq!(config["timeout"], 8);
    }

    #[test]
    fn directives_scoped_to_a_subtree_do_not_become_server_settings() {
        // A per-directory LogLevel/Timeout must not overwrite the server value,
        // and a deny on some random directory is not a deny on the root.
        let output = "###KXN_APACHE_PRESENT###\n###KXN_CONFIG###\n\
                      LogLevel warn\n\
                      <Directory /srv/private>\n\
                        LogLevel debug\n\
                        Require all denied\n\
                        AllowOverride AuthConfig\n\
                      </Directory>\n";
        let config = &parse_config(output)[0];
        assert_eq!(config["loglevel"], "warn");
        assert_eq!(config["root_directory_access"], "allowed");
        assert_eq!(config["default_access"], "allowed");
        // Surfaced from the non-root block, since <Directory /> says nothing.
        assert_eq!(config["allowoverride"], "AuthConfig");
    }

    #[test]
    fn quoted_root_directory_and_legacy_deny_are_understood() {
        let output = "###KXN_APACHE_PRESENT###\n###KXN_CONFIG###\n\
                      <Directory \"/\">\n\
                        Order deny,allow\n\
                        Deny from all\n\
                        AllowOverride All\n\
                      </Directory>\n";
        let config = &parse_config(output)[0];
        assert_eq!(config["root_directory_access"], "denied");
        assert_eq!(config["allowoverride"], "All");
    }

    #[test]
    fn a_files_block_inside_the_root_directory_is_not_the_root() {
        let output = "###KXN_APACHE_PRESENT###\n###KXN_CONFIG###\n\
                      <Directory />\n\
                        <Files secret.txt>\n\
                          Require all denied\n\
                        </Files>\n\
                      </Directory>\n";
        let config = &parse_config(output)[0];
        assert_eq!(config["root_directory_access"], "allowed");
    }

    #[test]
    fn header_unset_after_set_clears_the_value() {
        let output = "###KXN_APACHE_PRESENT###\n###KXN_CONFIG###\n\
                      Header always set X-Frame-Options SAMEORIGIN\n\
                      Header always unset X-Frame-Options\n";
        let config = &parse_config(output)[0];
        assert_eq!(config["header_x_frame_options"], "");
    }

    #[test]
    fn permissions_hardened_host() {
        let output = "###KXN_APACHE_PRESENT###\n\
                      ###KXN_CONF_STAT###\n\
                      644 root root /etc/httpd/conf/httpd.conf\n\
                      ###KXN_DOCROOT_STAT###\n\
                      755 /var/www/html\n";
        let parsed = parse_permissions(output);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0]["httpd_conf_owner"], "root");
        assert_eq!(parsed[0]["httpd_conf_permissions"], "644");
        assert_eq!(parsed[0]["docroot_world_writable"], "no");
    }

    #[test]
    fn permissions_world_writable_docroot_and_short_mode() {
        let output = "###KXN_APACHE_PRESENT###\n\
                      ###KXN_CONF_STAT###\n\
                      44 www-data www-data /etc/apache2/apache2.conf\n\
                      ###KXN_DOCROOT_STAT###\n\
                      755 /var/www\n\
                      777 /var/www/html\n";
        let parsed = parse_permissions(output);
        assert_eq!(parsed[0]["httpd_conf_owner"], "www-data");
        // Left-padded so the three-octal-digit regex can be applied at all.
        assert_eq!(parsed[0]["httpd_conf_permissions"], "044");
        assert_eq!(parsed[0]["docroot_world_writable"], "yes");
    }

    #[test]
    fn permissions_without_any_stat_output_is_not_a_verdict() {
        let output = "###KXN_APACHE_PRESENT###\n###KXN_CONF_STAT###\n###KXN_DOCROOT_STAT###\n";
        assert!(parse_permissions(output).is_empty());
    }

    #[test]
    fn tokenizer_keeps_quoted_values_whole() {
        let tokens = tokenize(r#"Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains""#);
        assert_eq!(tokens.len(), 5);
        assert_eq!(tokens[4], "max-age=31536000; includeSubDomains");
    }

    #[test]
    fn weak_cipher_suite_survives_the_negation_filter() {
        let output = "###KXN_APACHE_PRESENT###\n###KXN_CONFIG###\n\
                      SSLCipherSuite ALL:+RC4:+MD5:!aNULL\n";
        let config = &parse_config(output)[0];
        // The directive as written stays reportable, while the enabled list is
        // what a rule asserts on: `!aNULL` forbids, it does not allow.
        assert_eq!(config["sslciphersuite"], "ALL:+RC4:+MD5:!aNULL");
        assert_eq!(config["sslciphersuite_enabled"], "ALL:+RC4:+MD5");
    }

    #[test]
    fn commands_are_marker_delimited_and_cover_both_distributions() {
        for command in [CONFIG_COMMAND, PERMISSIONS_COMMAND] {
            assert!(command.contains(MARKER_PRESENT));
            assert!(command.contains("###KXN_APACHE_ABSENT###"));
            assert!(command.contains("/etc/apache2"));
            assert!(command.contains("/etc/httpd"));
            assert!(command.ends_with("exit 0"));
            // A single logical line: the Rust continuations must not leak
            // newlines into the remote shell.
            assert!(!command.contains('\n'));
        }
    }
}
