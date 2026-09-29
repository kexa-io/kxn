//! nginx configuration collector for the SSH provider.
//!
//! Turns a remote host's *resolved* nginx configuration into the two objects
//! the CIS nginx ruleset is written against: `nginx_config` and
//! `nginx_permissions`.
//!
//! Two properties of the rule engine drive every design choice here:
//!
//!   * An empty result array means "nothing produces this object", which the
//!     engine reports as *not evaluated*. A one-element array means "here is
//!     the host's web server, judge it". So when nginx is not installed we
//!     must return nothing at all — anything else invents findings about a
//!     web server that does not exist.
//!   * A *missing property* on an object that does exist is not neutral: the
//!     evaluator resolves it to the empty string and then applies the
//!     condition. `EQUAL "off"` on a missing directive therefore fails. That
//!     is why an installed-but-unconfigured nginx must be described with
//!     nginx's own documented defaults: they are exactly what the CIS
//!     controls are asking about (an omitted `server_tokens` really does leak
//!     the version, an omitted `ssl_stapling` really is disabled).

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

/// Dump the *resolved* configuration: `nginx -T` expands every `include`
/// (conf.d/*.conf, sites-enabled/*, snippets/*) and prints the result, which
/// is the only way to see directives that live outside nginx.conf without
/// reimplementing nginx's include resolution.
///
/// `nginx -T` needs to read the config as root and fails on some hardened
/// hosts, hence the `cat` fallback over the conventional layout. The fallback
/// may duplicate nginx.conf's content when `nginx -T` fails *after* printing
/// part of it; duplicates are harmless because every field below is derived
/// by "first wins" or "worst wins", both idempotent.
///
/// The whole thing is guarded so that a host without nginx prints nothing at
/// all: no binary and no /etc/nginx/nginx.conf means no output, means no
/// object, means the rules are reported as not evaluated.
pub(crate) const CONFIG_COMMAND: &str = r#"if command -v nginx >/dev/null 2>&1 || [ -f /etc/nginx/nginx.conf ]; then nginx -T 2>/dev/null || cat /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf /etc/nginx/sites-enabled/* 2>/dev/null; fi"#;

/// Three `---SEP---`-delimited sections, in order: the main config file, the
/// conf.d directory, then one line per private key referenced by an
/// `ssl_certificate_key` directive.
///
/// Positional sections rather than path matching: the key paths are arbitrary
/// (`/etc/letsencrypt/live/*/privkey.pem`, `/etc/ssl/private/...`), so the
/// parser cannot tell a key apart from the config file by looking at its name.
///
/// `tr -d '\042\047'` strips the double and single quotes nginx allows around
/// a path; the octal escapes avoid nesting quotes inside this shell one-liner.
/// `[ -f "$f" ]` skips non-file key sources such as `engine:...` or `data:...`.
pub(crate) const PERMISSIONS_COMMAND: &str = r#"if command -v nginx >/dev/null 2>&1 || [ -f /etc/nginx/nginx.conf ]; then stat -c '%n %a' /etc/nginx/nginx.conf 2>/dev/null; echo '---SEP---'; stat -c '%n %a' /etc/nginx/conf.d 2>/dev/null; echo '---SEP---'; { nginx -T 2>/dev/null || cat /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf /etc/nginx/sites-enabled/* 2>/dev/null; } | sed -n 's/^[[:space:]]*ssl_certificate_key[[:space:]]\{1,\}//p' | sed 's/;.*$//' | tr -d '\042\047' | sed 's/[[:space:]]*$//' | sort -u | while read -r f; do [ -f "$f" ] && stat -c '%n %a' "$f" 2>/dev/null; done; fi"#;

// ─── Documented nginx defaults ──────────────────────────────────────────────
//
// Every constant below is the value nginx applies when the directive is
// absent, taken from the directive reference. They are what the host actually
// serves, so reporting them is reporting the truth — not guessing.

/// `user nobody;` — the master process drops privileges to this user unless
/// the build overrode it (`--user=`, which distro packages do use). Either way
/// the documented default is a non-root account.
const DEFAULT_USER: &str = "nobody";
/// `server_tokens on;` — the version is emitted in error pages and the
/// `Server` header until it is explicitly turned off. This default is the
/// whole point of CIS 2.5.1.
const DEFAULT_SERVER_TOKENS: &str = "on";
/// `autoindex off;`
const DEFAULT_AUTOINDEX: &str = "off";
/// `worker_connections 512;`
const DEFAULT_WORKER_CONNECTIONS: i64 = 512;
/// `access_log logs/access.log combined;` — logging is on by default.
const DEFAULT_ACCESS_LOG: &str = "logs/access.log combined";
/// `error_log logs/error.log error;`
const DEFAULT_ERROR_LOG: &str = "logs/error.log";
/// ...whose severity half defaults to `error`.
const DEFAULT_ERROR_LOG_LEVEL: &str = "error";
/// The built-in `combined` format, which nginx uses when no `log_format` is
/// declared. It already contains `$request`.
const DEFAULT_LOG_FORMAT: &str =
    "$remote_addr - $remote_user [$time_local] \"$request\" $status $body_bytes_sent \"$http_referer\" \"$http_user_agent\"";
/// `ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;` — the historical default.
/// nginx 1.23.4 dropped TLSv1/TLSv1.1 from it, but the build in front of us is
/// unknown, so we report the permissive documented default: an explicit
/// `ssl_protocols` line is what CIS 4.1.x actually wants, and a host that
/// relies on the compiled-in default is exactly the case the control targets.
const DEFAULT_SSL_PROTOCOLS: &str = "TLSv1 TLSv1.1 TLSv1.2 TLSv1.3";
/// `ssl_prefer_server_ciphers off;`
const DEFAULT_SSL_PREFER_SERVER_CIPHERS: &str = "off";
/// `ssl_ciphers HIGH:!aNULL:!MD5;`
const DEFAULT_SSL_CIPHERS: &str = "HIGH:!aNULL:!MD5";
/// `ssl_stapling off;`
const DEFAULT_SSL_STAPLING: &str = "off";
/// `client_max_body_size 1m;` — the default is already a restriction.
const DEFAULT_CLIENT_MAX_BODY_SIZE: &str = "1m";
/// `client_body_timeout 60s;`
const DEFAULT_CLIENT_BODY_TIMEOUT: f64 = 60.0;
/// `client_header_timeout 60s;`
const DEFAULT_CLIENT_HEADER_TIMEOUT: f64 = 60.0;
/// `keepalive_timeout 75s;`
const DEFAULT_KEEPALIVE_TIMEOUT: f64 = 75.0;
/// Headers the proxy module never forwards from an upstream response, with no
/// configuration at all. `Server` is in that list, so an unconfigured nginx
/// genuinely does hide the upstream `Server` header — reporting an empty
/// `proxy_hide_header` would manufacture a violation of CIS 5.3.2.
/// `X-Powered-By` is *not* in the list, which is why CIS 5.3.1 exists.
const DEFAULT_PROXY_HIDDEN_HEADERS: &str =
    "Date Server X-Pad X-Accel-Expires X-Accel-Redirect X-Accel-Limit-Rate X-Accel-Buffering X-Accel-Charset";

// ─── Configuration ──────────────────────────────────────────────────────────

/// One parsed nginx statement, i.e. everything up to the terminating `;`.
struct Directive {
    name: String,
    args: Vec<String>,
    /// Nesting level of the enclosing blocks (0 = main context).
    depth: usize,
    /// Set when the statement lives inside a `location` or `if` block, where
    /// per-route overrides are normal and must not be read as host-wide policy.
    routed: bool,
}

impl Directive {
    fn arg(&self, i: usize) -> Option<&str> {
        self.args.get(i).map(|s| s.as_str())
    }

    /// All arguments joined back with single spaces. Used for directives whose
    /// value is a list (`ssl_protocols TLSv1.2 TLSv1.3`) and which the rules
    /// test as one string.
    fn joined(&self) -> String {
        self.args.join(" ")
    }
}

pub(crate) fn parse_config(output: &str) -> Vec<Value> {
    // No configuration text at all: the guard in CONFIG_COMMAND produced
    // nothing, so nginx is not installed on this host. Returning an empty
    // array is what makes the engine say "not evaluated" instead of scoring 30
    // failed controls against a machine that serves nothing.
    if !has_content(output) {
        return Vec::new();
    }

    let directives = tokenize(output);

    let mut server_tokens: Vec<String> = Vec::new();
    let mut autoindex: Vec<String> = Vec::new();
    let mut ssl_protocols: Vec<String> = Vec::new();
    let mut ssl_prefer: Vec<String> = Vec::new();
    let mut ssl_stapling: Vec<String> = Vec::new();
    let mut access_log: Vec<String> = Vec::new();
    let mut log_formats: Vec<String> = Vec::new();
    let mut proxy_hidden: Vec<String> = Vec::new();
    // First occurrence wins: a header set once in `http` and refined per
    // server cannot be collapsed into a single value, and the rules test the
    // value with an anchored regex, so concatenating occurrences would fail
    // every multi-server config.
    let mut headers: BTreeMap<String, String> = BTreeMap::new();
    let mut user: Option<String> = None;
    let mut ssl_ciphers: Option<String> = None;
    let mut client_max_body_size: Option<String> = None;
    // Worst case wins for the numeric limits: one lax block is enough to keep
    // a connection open, so the maximum observed value is the host's exposure.
    let mut worker_connections: Option<i64> = None;
    let mut client_body_timeout: Option<f64> = None;
    let mut client_header_timeout: Option<f64> = None;
    let mut keepalive_timeout: Option<f64> = None;
    // Shallowest `error_log` wins: the main-context one governs the whole
    // server, a per-server one only its virtual host.
    let mut error_log: Option<(usize, String, Option<String>)> = None;

    for d in &directives {
        match d.name.as_str() {
            "user" => {
                // `user nginx nginx;` carries an optional group; only the
                // account matters for CIS 2.3.1.
                if user.is_none() {
                    if let Some(v) = d.arg(0) {
                        user = Some(v.to_string());
                    }
                }
            }
            "server_tokens" => push_arg(&mut server_tokens, d),
            "autoindex" => push_arg(&mut autoindex, d),
            "worker_connections" => {
                if let Some(n) = d.arg(0).and_then(|v| v.parse::<i64>().ok()) {
                    worker_connections = Some(worker_connections.map_or(n, |cur: i64| cur.max(n)));
                }
            }
            "access_log" => {
                // `access_log off;` inside a `location` is the usual way to
                // silence health checks and says nothing about the host's
                // logging policy, so only unrouted occurrences are considered.
                if !d.routed {
                    push_arg(&mut access_log, d);
                }
            }
            "error_log" => {
                let target = d.arg(0).unwrap_or_default().to_string();
                if target.is_empty() {
                    continue;
                }
                let level = d.arg(1).map(|s| s.to_string());
                let better = match &error_log {
                    Some((depth, _, _)) => d.depth < *depth,
                    None => true,
                };
                if better {
                    error_log = Some((d.depth, target, level));
                }
            }
            "log_format" => {
                // First argument names the format; `escape=json` may follow.
                // The rule only looks for `$request`, so every declared format
                // is concatenated — if any of them records the request line,
                // the traceability control is satisfied.
                let value = d.args.iter().skip(1).cloned().collect::<Vec<_>>().join(" ");
                if !value.is_empty() {
                    log_formats.push(value);
                }
            }
            "ssl_protocols" => ssl_protocols.push(d.joined()),
            "ssl_prefer_server_ciphers" => push_arg(&mut ssl_prefer, d),
            "ssl_ciphers" => {
                if ssl_ciphers.is_none() {
                    let v = d.joined();
                    if !v.is_empty() {
                        ssl_ciphers = Some(v);
                    }
                }
            }
            "ssl_stapling" => push_arg(&mut ssl_stapling, d),
            "add_header" => {
                if let Some((key, value)) = parse_add_header(d) {
                    headers.entry(key).or_insert(value);
                }
            }
            "client_max_body_size" => {
                if client_max_body_size.is_none() {
                    if let Some(v) = d.arg(0) {
                        client_max_body_size = Some(v.to_string());
                    }
                }
            }
            "client_body_timeout" => take_max_time(&mut client_body_timeout, d),
            "client_header_timeout" => take_max_time(&mut client_header_timeout, d),
            // `keepalive_timeout 65s 65s;` — the second value is the
            // `Keep-Alive` header sent to the client, not the timeout.
            "keepalive_timeout" => take_max_time(&mut keepalive_timeout, d),
            "proxy_hide_header" => {
                if let Some(v) = d.arg(0) {
                    if !proxy_hidden.iter().any(|h| h == v) {
                        proxy_hidden.push(v.to_string());
                    }
                }
            }
            _ => {}
        }
    }

    let mut map = Map::new();

    map.insert(
        "user".into(),
        Value::String(user.unwrap_or_else(|| DEFAULT_USER.to_string())),
    );
    map.insert(
        "server_tokens".into(),
        Value::String(
            worst_of(&server_tokens, |v| v == "off")
                .unwrap_or(DEFAULT_SERVER_TOKENS)
                .to_string(),
        ),
    );
    map.insert(
        "autoindex".into(),
        Value::String(
            worst_of(&autoindex, |v| v == "off")
                .unwrap_or(DEFAULT_AUTOINDEX)
                .to_string(),
        ),
    );
    map.insert(
        "worker_connections".into(),
        json!(worker_connections.unwrap_or(DEFAULT_WORKER_CONNECTIONS)),
    );
    map.insert(
        "access_log".into(),
        Value::String(
            worst_of(&access_log, |v| v != "off")
                .unwrap_or(DEFAULT_ACCESS_LOG)
                .to_string(),
        ),
    );

    let (error_log_target, error_log_level) = match error_log {
        // `error_log off;` does not disable logging, it writes to a file
        // literally named "off" — a classic nginx trap. Either way the
        // directive is present, which is all CIS 3.2 asks.
        Some((_, target, level)) => (
            target,
            level.unwrap_or_else(|| DEFAULT_ERROR_LOG_LEVEL.to_string()),
        ),
        None => (
            DEFAULT_ERROR_LOG.to_string(),
            DEFAULT_ERROR_LOG_LEVEL.to_string(),
        ),
    };
    map.insert("error_log".into(), Value::String(error_log_target));
    map.insert("error_log_level".into(), Value::String(error_log_level));

    map.insert(
        "log_format".into(),
        Value::String(if log_formats.is_empty() {
            DEFAULT_LOG_FORMAT.to_string()
        } else {
            log_formats.join(" ")
        }),
    );

    map.insert(
        "ssl_protocols".into(),
        Value::String(
            worst_of(&ssl_protocols, |v| {
                v.split_whitespace()
                    .all(|p| p == "TLSv1.2" || p == "TLSv1.3")
            })
            .unwrap_or(DEFAULT_SSL_PROTOCOLS)
            .to_string(),
        ),
    );
    map.insert(
        "ssl_prefer_server_ciphers".into(),
        Value::String(
            worst_of(&ssl_prefer, |v| v == "on")
                .unwrap_or(DEFAULT_SSL_PREFER_SERVER_CIPHERS)
                .to_string(),
        ),
    );
    // Both forms. A hardened `HIGH:!aNULL:!MD5` contains the substring NULL
    // *because it forbids it*, so a rule asserting the absence of a weak
    // cipher has to read the enabled selectors — while an operator reading a
    // report needs the directive as written.
    let ssl_ciphers = ssl_ciphers.unwrap_or_else(|| DEFAULT_SSL_CIPHERS.to_string());
    map.insert(
        "ssl_ciphers_enabled".into(),
        Value::String(enabled_ciphers(&ssl_ciphers)),
    );
    map.insert("ssl_ciphers".into(), Value::String(ssl_ciphers));
    map.insert(
        "ssl_stapling".into(),
        Value::String(
            worst_of(&ssl_stapling, |v| v == "on")
                .unwrap_or(DEFAULT_SSL_STAPLING)
                .to_string(),
        ),
    );

    for (key, value) in headers {
        map.insert(key, Value::String(value));
    }

    // The headers the CIS controls judge are published even when nginx sends
    // none, as the empty string they are.
    //
    // Leaving them out produced the same verdict — the engine reads a missing
    // property as an empty string — but by the implicit path rather than by a
    // measurement, and that path is what produced every other wrong finding in
    // this provider: a rule asking about something the collector does not
    // publish looks exactly like a rule asking about something that is not
    // configured. Stating the absence keeps the two apart, and lets a property
    // audit over the packs stay silent when nothing is wrong.
    for header in [
        "add_header_strict_transport_security",
        "add_header_x_frame_options",
        "add_header_x_content_type_options",
        "add_header_x_xss_protection",
        "add_header_content_security_policy",
        "add_header_referrer_policy",
    ] {
        map.entry(header.to_string())
            .or_insert_with(|| Value::String(String::new()));
    }

    map.insert(
        "client_max_body_size".into(),
        Value::String(
            client_max_body_size.unwrap_or_else(|| DEFAULT_CLIENT_MAX_BODY_SIZE.to_string()),
        ),
    );
    map.insert(
        "client_body_timeout".into(),
        seconds_value(client_body_timeout.unwrap_or(DEFAULT_CLIENT_BODY_TIMEOUT)),
    );
    map.insert(
        "client_header_timeout".into(),
        seconds_value(client_header_timeout.unwrap_or(DEFAULT_CLIENT_HEADER_TIMEOUT)),
    );
    map.insert(
        "keepalive_timeout".into(),
        seconds_value(keepalive_timeout.unwrap_or(DEFAULT_KEEPALIVE_TIMEOUT)),
    );

    // Single string because both proxy rules are substring tests; the
    // built-in hidden headers come first since they apply with or without
    // configuration.
    let mut hidden = DEFAULT_PROXY_HIDDEN_HEADERS.to_string();
    for h in proxy_hidden {
        if !hidden.split_whitespace().any(|known| known == h) {
            hidden.push(' ');
            hidden.push_str(&h);
        }
    }
    map.insert("proxy_hide_header".into(), Value::String(hidden));

    vec![Value::Object(map)]
}

/// `add_header X-Frame-Options "SAMEORIGIN" always;` → `("add_header_x_frame_options", "SAMEORIGIN")`.
///
/// `always` is a modifier (send the header on error responses too), never part
/// of the value, and the rules match the value with anchored regexes, so it
/// has to go.
fn parse_add_header(d: &Directive) -> Option<(String, String)> {
    let name = d.arg(0)?;
    if name.is_empty() {
        return None;
    }
    let mut parts: Vec<&str> = d.args.iter().skip(1).map(|s| s.as_str()).collect();
    if parts.last() == Some(&"always") {
        parts.pop();
    }
    if parts.is_empty() {
        return None;
    }
    let key = format!(
        "add_header_{}",
        name.to_ascii_lowercase().replace(['-', '.'], "_")
    );
    Some((key, parts.join(" ")))
}

fn push_arg(sink: &mut Vec<String>, d: &Directive) {
    if let Some(v) = d.arg(0) {
        sink.push(v.to_ascii_lowercase());
    }
}

fn take_max_time(slot: &mut Option<f64>, d: &Directive) {
    if let Some(secs) = d.arg(0).and_then(parse_nginx_time) {
        *slot = Some(slot.map_or(secs, |cur: f64| cur.max(secs)));
    }
}

/// Pick the value the auditor should be shown when a directive appears more
/// than once: the first one that is *not* compliant, so a single lax block is
/// never hidden behind a hardened one; the first value otherwise.
fn worst_of(values: &[String], secure: impl Fn(&str) -> bool) -> Option<&str> {
    values
        .iter()
        .find(|v| !secure(v))
        .or_else(|| values.first())
        .map(|s| s.as_str())
}

/// nginx durations are not plain numbers: `60`, `60s`, `1m`, `1m30s`, `500ms`
/// and `1h` are all legal, and the rules compare against a number of seconds.
/// A bare number means seconds (the default unit for the timeouts we read).
///
/// `m` is minutes and `M` is months — the mapping is case sensitive, and `ms`
/// must be matched before `m` or half a second becomes half a minute.
fn parse_nginx_time(raw: &str) -> Option<f64> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let chars: Vec<char> = raw.chars().collect();
    let mut i = 0;
    let mut total = 0.0f64;
    let mut saw_number = false;

    while i < chars.len() {
        let start = i;
        while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '.') {
            i += 1;
        }
        if i == start {
            return None; // a unit with no quantity in front of it
        }
        let number: f64 = chars[start..i].iter().collect::<String>().parse().ok()?;
        saw_number = true;

        let unit_start = i;
        while i < chars.len() && chars[i].is_ascii_alphabetic() {
            i += 1;
        }
        let unit: String = chars[unit_start..i].iter().collect();
        let multiplier = match unit.as_str() {
            "" | "s" => 1.0,
            "ms" => 0.001,
            "m" => 60.0,
            "h" => 3600.0,
            "d" => 86_400.0,
            "w" => 604_800.0,
            "M" => 2_592_000.0,  // nginx counts a month as 30 days
            "y" => 31_536_000.0, // ...and a year as 365
            _ => return None,
        };
        total += number * multiplier;
    }

    if saw_number {
        Some(total)
    } else {
        None
    }
}

/// Emit whole seconds as an integer so reports read `60` rather than `60.0`;
/// sub-second timeouts (`500ms`) keep their fractional part.
fn seconds_value(secs: f64) -> Value {
    if secs.is_finite() && secs.fract() == 0.0 && secs.abs() < 9e15 {
        json!(secs as i64)
    } else {
        json!(secs)
    }
}

/// True when the dump contains at least one line of actual configuration.
/// `nginx -T` prefixes every included file with a `# configuration file ...`
/// banner, so a comment-only output means we got the banners of an unreadable
/// config — or nothing at all — and must not claim nginx is there.
fn has_content(output: &str) -> bool {
    output.lines().any(|line| {
        let line = line.trim();
        !line.is_empty() && !line.starts_with('#')
    })
}

/// Split a configuration dump into statements.
///
/// Hand-written rather than line-based because nginx configuration is not a
/// line-oriented format, and the differences bite exactly where the CIS rules
/// look:
///
///   * `add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;`
///     contains a semicolon *inside* a quoted string — splitting on `;` first
///     would truncate the value and fail the HSTS control on a compliant host.
///   * `add_header Content-Security-Policy "default-src 'self'" always;` nests
///     single quotes inside double quotes.
///   * `#` starts a comment anywhere outside quotes, including mid-line.
///   * A `log_format` may span several physical lines.
fn tokenize(input: &str) -> Vec<Directive> {
    let mut out = Vec::new();
    let mut block_stack: Vec<String> = Vec::new();
    let mut tokens: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut started = false;
    let mut quote: Option<char> = None;
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if let Some(q) = quote {
            match c {
                // nginx allows \" and \' to embed the delimiter.
                '\\' => {
                    if let Some(escaped) = chars.next() {
                        current.push(escaped);
                        started = true;
                    }
                }
                _ if c == q => quote = None,
                _ => {
                    current.push(c);
                    started = true;
                }
            }
            continue;
        }

        match c {
            '\'' | '"' => {
                // An empty quoted argument is still an argument.
                quote = Some(c);
                started = true;
            }
            '#' => {
                for n in chars.by_ref() {
                    if n == '\n' {
                        break;
                    }
                }
                flush(&mut tokens, &mut current, &mut started);
            }
            ';' => {
                flush(&mut tokens, &mut current, &mut started);
                let taken = std::mem::take(&mut tokens);
                let mut it = taken.into_iter();
                if let Some(name) = it.next() {
                    out.push(Directive {
                        name: name.to_ascii_lowercase(),
                        args: it.collect(),
                        depth: block_stack.len(),
                        routed: block_stack
                            .iter()
                            .any(|b| b == "location" || b == "if" || b == "limit_except"),
                    });
                }
            }
            '{' => {
                flush(&mut tokens, &mut current, &mut started);
                let head = tokens
                    .first()
                    .map(|t| t.to_ascii_lowercase())
                    .unwrap_or_default();
                block_stack.push(head);
                tokens.clear();
            }
            '}' => {
                flush(&mut tokens, &mut current, &mut started);
                tokens.clear();
                block_stack.pop();
            }
            _ if c.is_whitespace() => flush(&mut tokens, &mut current, &mut started),
            _ => {
                current.push(c);
                started = true;
            }
        }
    }

    out
}

fn flush(tokens: &mut Vec<String>, current: &mut String, started: &mut bool) {
    if *started {
        tokens.push(std::mem::take(current));
        *started = false;
    }
}

// ─── Permissions ────────────────────────────────────────────────────────────

pub(crate) fn parse_permissions(output: &str) -> Vec<Value> {
    let mut sections = output.split("---SEP---");
    let main_conf = sections.next().unwrap_or("");
    let conf_d = sections.next().unwrap_or("");
    let ssl_keys = sections.next().unwrap_or("");

    let mut map = Map::new();

    if let Some(mode) = first_mode(main_conf) {
        map.insert("nginx_conf_permissions".into(), Value::String(mode));
    }
    if let Some(mode) = first_mode(conf_d) {
        map.insert("conf_d_permissions".into(), Value::String(mode));
    }
    // The control is about the weakest key on the box, so the most permissive
    // mode wins. Octal modes are only a partial order (0640 and 0604 are
    // incomparable); comparing their numeric value is a deliberate
    // approximation that still ranks any group/other bit above 0400.
    let mut worst_key: Option<(u32, String)> = None;
    for line in ssl_keys.lines() {
        if let Some(mode) = mode_of(line) {
            let weight = u32::from_str_radix(&mode, 8).unwrap_or(0);
            let more_permissive = match &worst_key {
                Some((worst, _)) => weight > *worst,
                None => true,
            };
            if more_permissive {
                worst_key = Some((weight, mode));
            }
        }
    }
    // No `ssl_certificate_key` anywhere means no private key to protect, so the
    // field is left out rather than fabricated. The control accepts that
    // omission explicitly — on its own the absence would be read as an empty
    // string and fail the permission check on a host with no TLS at all.
    if let Some((_, mode)) = worst_key {
        map.insert("ssl_key_permissions".into(), Value::String(mode));
    }

    // Nothing could be stat'ed at all — nginx is not installed, or the
    // account cannot see /etc/nginx. Either way there is nothing to judge.
    if map.is_empty() {
        return Vec::new();
    }

    vec![Value::Object(map)]
}

fn first_mode(section: &str) -> Option<String> {
    section.lines().find_map(mode_of)
}

/// `stat -c '%n %a'` prints `<path> <mode>`; the mode is the last field
/// because a path may contain spaces. `%a` drops leading zeros (`0640` →
/// `640`, `0040` → `40`), and the rules match three octal digits, so the value
/// is padded back. A setuid/sticky bit widens it to four digits, which the
/// rules then reject — correctly, as no nginx config file should carry one.
fn mode_of(line: &str) -> Option<String> {
    let mode = line.split_whitespace().last()?;
    if mode.is_empty() || !mode.chars().all(|c| c.is_digit(8)) {
        return None;
    }
    Some(if mode.len() < 3 {
        format!("{:0>3}", mode)
    } else {
        mode.to_string()
    })
}


/// The selectors a cipher string actually enables: a `!` or `-` prefix removes
/// an algorithm, so those tokens must not be read as allowing it.
fn enabled_ciphers(raw: &str) -> String {
    raw.split(':')
        .map(str::trim)
        .filter(|t| !t.is_empty() && !t.starts_with('!') && !t.starts_with('-'))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real-world hardened virtual host, the shape a compliant server takes.
    const HARDENED: &str = r#"
# configuration file /etc/nginx/nginx.conf:
user www-data;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;
    server_tokens off;
    autoindex off;

    sendfile on;
    keepalive_timeout 20s;
    client_body_timeout 10s;
    client_header_timeout 10s;
    client_max_body_size 1m;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_stapling on;
    ssl_stapling_verify on;

    proxy_hide_header X-Powered-By;
    proxy_hide_header X-AspNet-Version;

    server {
        listen 443 ssl http2;
        server_name example.com;

        ssl_certificate     /etc/nginx/ssl/example.com.crt;
        ssl_certificate_key /etc/nginx/ssl/example.com.key;

        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-XSS-Protection "1; mode=block" always;
        add_header Content-Security-Policy "default-src 'self'; frame-ancestors 'none'" always;
        add_header Referrer-Policy strict-origin-when-cross-origin always;

        location /healthz {
            access_log off;   # noise, not a policy change
            return 200 "ok";
        }
    }
}
"#;

    /// Stock Debian/Ubuntu nginx.conf: nothing about TLS, headers or tokens.
    const DEFAULTS: &str = r#"
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 768;
    # multi_accept on;
}

http {
    sendfile on;
    tcp_nopush on;
    types_hash_max_size 2048;
    # server_tokens off;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    gzip on;

    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
"#;

    fn field<'a>(v: &'a Value, key: &str) -> &'a Value {
        v.get(key)
            .unwrap_or_else(|| panic!("missing field `{}` in {}", key, v))
    }

    #[test]
    fn hardened_server_reports_its_own_values() {
        let out = parse_config(HARDENED);
        assert_eq!(out.len(), 1);
        let c = &out[0];

        assert_eq!(field(c, "user"), "www-data");
        assert_eq!(field(c, "server_tokens"), "off");
        assert_eq!(field(c, "autoindex"), "off");
        assert_eq!(field(c, "worker_connections"), 1024);
        assert_eq!(field(c, "access_log"), "/var/log/nginx/access.log");
        assert_eq!(field(c, "error_log"), "/var/log/nginx/error.log");
        assert_eq!(field(c, "error_log_level"), "warn");
        assert!(field(c, "log_format")
            .as_str()
            .unwrap_or_default()
            .contains("$request"));
        assert_eq!(field(c, "ssl_protocols"), "TLSv1.2 TLSv1.3");
        assert_eq!(field(c, "ssl_prefer_server_ciphers"), "on");
        assert_eq!(field(c, "ssl_stapling"), "on");
        assert_eq!(field(c, "client_max_body_size"), "1m");
        assert_eq!(field(c, "client_body_timeout"), 10);
        assert_eq!(field(c, "client_header_timeout"), 10);
        assert_eq!(field(c, "keepalive_timeout"), 20);

        // The semicolon inside the quoted HSTS value must survive.
        assert_eq!(
            field(c, "add_header_strict_transport_security"),
            "max-age=31536000; includeSubDomains"
        );
        assert_eq!(field(c, "add_header_x_frame_options"), "SAMEORIGIN");
        assert_eq!(field(c, "add_header_x_content_type_options"), "nosniff");
        assert_eq!(field(c, "add_header_x_xss_protection"), "1; mode=block");
        // Single quotes nested inside the double-quoted CSP value.
        assert_eq!(
            field(c, "add_header_content_security_policy"),
            "default-src 'self'; frame-ancestors 'none'"
        );
        assert_eq!(
            field(c, "add_header_referrer_policy"),
            "strict-origin-when-cross-origin"
        );

        let hidden = field(c, "proxy_hide_header").as_str().unwrap_or_default();
        assert!(hidden.contains("X-Powered-By"));
        assert!(hidden.contains("Server"));
    }

    #[test]
    fn access_log_off_inside_a_location_is_not_the_host_policy() {
        let c = &parse_config(HARDENED)[0];
        assert_ne!(field(c, "access_log"), "off");
    }

    #[test]
    fn access_log_off_at_http_level_is_reported() {
        let cfg = "http {\n  access_log off;\n  server { listen 80; }\n}\n";
        let c = &parse_config(cfg)[0];
        assert_eq!(field(c, "access_log"), "off");
    }

    #[test]
    fn stock_config_reports_documented_defaults() {
        let out = parse_config(DEFAULTS);
        assert_eq!(out.len(), 1);
        let c = &out[0];

        // Present in the file.
        assert_eq!(field(c, "user"), "www-data");
        assert_eq!(field(c, "worker_connections"), 768);

        // Absent: nginx's own defaults, which is what CIS is checking.
        assert_eq!(field(c, "server_tokens"), "on");
        assert_eq!(field(c, "autoindex"), "off");
        assert_eq!(field(c, "ssl_prefer_server_ciphers"), "off");
        assert_eq!(field(c, "ssl_stapling"), "off");
        assert_eq!(field(c, "keepalive_timeout"), 75);
        assert_eq!(field(c, "client_body_timeout"), 60);
        assert_eq!(field(c, "client_header_timeout"), 60);
        assert_eq!(field(c, "client_max_body_size"), "1m");
        assert_eq!(field(c, "error_log_level"), "error");
        assert_ne!(field(c, "error_log"), "");
        assert_ne!(field(c, "access_log"), "off");
        assert!(field(c, "log_format")
            .as_str()
            .unwrap_or_default()
            .contains("$request"));

        // A commented-out `server_tokens off;` must not be read as configured.
        assert_eq!(field(c, "server_tokens"), "on");

        // No security header was configured, and the absence is stated rather
        // than left to the engine's empty-string fallback: the verdict is the
        // same, but a rule asking about an unpublished field no longer looks
        // like a rule asking about an unconfigured one.
        assert_eq!(field(c, "add_header_x_frame_options"), "");
        assert_eq!(field(c, "add_header_content_security_policy"), "");
        assert_eq!(field(c, "add_header_strict_transport_security"), "");
    }

    #[test]
    fn no_nginx_produces_no_object() {
        assert!(parse_config("").is_empty());
        assert!(parse_config("   \n\n  ").is_empty());
        // Only `nginx -T` banners: the config itself was unreadable.
        assert!(parse_config("# configuration file /etc/nginx/nginx.conf:\n").is_empty());
        assert!(parse_permissions("").is_empty());
        assert!(parse_permissions("---SEP---\n---SEP---\n").is_empty());
    }

    #[test]
    fn durations_are_normalised_to_seconds() {
        let cfg = r#"
http {
    keepalive_timeout 1m;
    client_body_timeout 90s;
    client_header_timeout 1m30s;
    server { listen 80; }
}
"#;
        let c = &parse_config(cfg)[0];
        assert_eq!(field(c, "keepalive_timeout"), 60);
        assert_eq!(field(c, "client_body_timeout"), 90);
        assert_eq!(field(c, "client_header_timeout"), 90);
    }

    #[test]
    fn time_units_cover_the_nginx_grammar() {
        assert_eq!(parse_nginx_time("60"), Some(60.0));
        assert_eq!(parse_nginx_time("60s"), Some(60.0));
        assert_eq!(parse_nginx_time("1m"), Some(60.0));
        assert_eq!(parse_nginx_time("1m30s"), Some(90.0));
        assert_eq!(parse_nginx_time("1h"), Some(3600.0));
        // `ms` must not be read as minutes.
        assert_eq!(parse_nginx_time("500ms"), Some(0.5));
        assert_eq!(parse_nginx_time("2M"), Some(5_184_000.0));
        assert_eq!(parse_nginx_time(""), None);
        assert_eq!(parse_nginx_time("abc"), None);
        assert_eq!(parse_nginx_time("10z"), None);
    }

    #[test]
    fn sub_second_timeout_keeps_its_fraction() {
        let cfg = "http { client_body_timeout 500ms; }";
        let c = &parse_config(cfg)[0];
        assert_eq!(field(c, "client_body_timeout").as_f64(), Some(0.5));
    }

    #[test]
    fn the_laxest_value_wins_when_a_directive_repeats() {
        let cfg = r#"
http {
    server_tokens off;
    keepalive_timeout 10s;
    worker_connections 512;
    server {
        server_tokens on;
        keepalive_timeout 300s;
    }
}
events { worker_connections 4096; }
"#;
        let c = &parse_config(cfg)[0];
        assert_eq!(field(c, "server_tokens"), "on");
        assert_eq!(field(c, "keepalive_timeout"), 300);
        assert_eq!(field(c, "worker_connections"), 4096);
    }

    #[test]
    fn weak_protocols_win_over_a_hardened_block() {
        let cfg = r#"
http {
    server { ssl_protocols TLSv1.2 TLSv1.3; }
    server { ssl_protocols TLSv1 TLSv1.1 TLSv1.2; }
}
"#;
        let c = &parse_config(cfg)[0];
        assert_eq!(field(c, "ssl_protocols"), "TLSv1 TLSv1.1 TLSv1.2");
    }

    #[test]
    fn comments_and_quoted_hashes_are_told_apart() {
        let cfg = r##"
http {
    # server_tokens on;
    add_header X-Colour "#00ff00" always;   # trailing comment
    server_tokens off;
}
"##;
        let c = &parse_config(cfg)[0];
        assert_eq!(field(c, "server_tokens"), "off");
        assert_eq!(field(c, "add_header_x_colour"), "#00ff00");
    }

    #[test]
    fn main_context_error_log_wins_over_a_server_one() {
        let cfg = r#"
error_log /var/log/nginx/error.log warn;
http {
    server { error_log /var/log/nginx/vhost.log debug; }
}
"#;
        let c = &parse_config(cfg)[0];
        assert_eq!(field(c, "error_log"), "/var/log/nginx/error.log");
        assert_eq!(field(c, "error_log_level"), "warn");
    }

    #[test]
    fn permissions_are_mapped_by_section() {
        let output = "/etc/nginx/nginx.conf 644\n---SEP---\n/etc/nginx/conf.d 755\n---SEP---\n/etc/nginx/ssl/a.key 400\n/etc/letsencrypt/live/x/privkey.pem 640\n";
        let out = parse_permissions(output);
        assert_eq!(out.len(), 1);
        let p = &out[0];
        assert_eq!(field(p, "nginx_conf_permissions"), "644");
        assert_eq!(field(p, "conf_d_permissions"), "755");
        // 640 is the most permissive of the two keys.
        assert_eq!(field(p, "ssl_key_permissions"), "640");
    }

    #[test]
    fn permissions_omit_the_key_field_when_no_key_is_configured() {
        let output = "/etc/nginx/nginx.conf 600\n---SEP---\n/etc/nginx/conf.d 750\n---SEP---\n";
        let p = &parse_permissions(output)[0];
        assert_eq!(field(p, "nginx_conf_permissions"), "600");
        assert!(p.get("ssl_key_permissions").is_none());
    }

    #[test]
    fn short_modes_are_padded_to_three_octal_digits() {
        let output = "/etc/nginx/nginx.conf 40\n---SEP---\n---SEP---\n";
        let p = &parse_permissions(output)[0];
        assert_eq!(field(p, "nginx_conf_permissions"), "040");
    }
}

#[cfg(test)]
mod header_default_tests {
    use super::*;

    /// Publishing the absent headers must not overwrite one that is actually
    /// configured — the whole point is to state absence, not to erase presence.
    #[test]
    fn a_configured_header_survives_the_absent_default() {
        let dump = "# configuration file /etc/nginx/nginx.conf:\n\
                    http {\n\
                      add_header X-Frame-Options \"SAMEORIGIN\" always;\n\
                      add_header Strict-Transport-Security \"max-age=31536000\" always;\n\
                    }\n";
        let parsed = parse_config(dump);
        let c = parsed[0].as_object().expect("object");
        assert_eq!(c["add_header_x_frame_options"], "SAMEORIGIN");
        assert_eq!(
            c["add_header_strict_transport_security"], "max-age=31536000"
        );
        // The ones nobody configured are present and empty, not missing.
        assert_eq!(c["add_header_referrer_policy"], "");
        assert_eq!(c["add_header_x_content_type_options"], "");
    }
}
