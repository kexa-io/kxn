//! Output formatters for scan results: text, json, csv, toml, html, minimal (colorized).

use crate::commands::watch::ScanSummary;
use serde_json::Value;

pub fn format_output(summary: &ScanSummary, format: &str, uri: &str) -> String {
    match format {
        "json" => format_json(summary, uri),
        "csv" => format_csv(summary),
        "toml" => format_toml(summary, uri),
        "html" => format_html(summary, uri),
        "minimal" => format_minimal(summary, uri),
        _ => format_text(summary),
    }
}

fn level_label(level: u8) -> &'static str {
    match level {
        0 => "info",
        1 => "warn",
        2 => "ERROR",
        _ => "FATAL",
    }
}

fn level_color(level: u8) -> &'static str {
    match level {
        0 => "\x1b[36m",  // cyan
        1 => "\x1b[33m",  // yellow
        2 => "\x1b[31m",  // red
        _ => "\x1b[35m",  // magenta
    }
}

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";

// ── Text (default, same as before) ──────────────────────────────────────────

fn format_text(summary: &ScanSummary) -> String {
    let mut out = String::new();
    if summary.failed == 0 {
        out.push_str(&format!(
            "ALL PASSED | {}/{} rules | {}ms\n",
            summary.passed, summary.total, summary.duration_ms
        ));
    } else {
        out.push_str(&format!(
            "FAILED | {}/{} passed | {} violations | {}ms\n\n",
            summary.passed, summary.total, summary.failed, summary.duration_ms
        ));
        for v in &summary.violations {
            out.push_str(&format!("  [{}] {}\n", level_label(v.level), v.rule));
            out.push_str(&format!("        {}\n", v.description));
            if !v.compliance.is_empty() {
                let refs: Vec<String> = v
                    .compliance
                    .iter()
                    .map(|c| format!("{} {}", c.framework, c.control))
                    .collect();
                out.push_str(&format!("        Compliance: {}\n", refs.join(", ")));
            }
            for msg in &v.messages {
                out.push_str(&format!("        {}\n", msg));
            }
            out.push('\n');
        }
    }
    out
}

// ── JSON ────────────────────────────────────────────────────────────────────

fn format_json(summary: &ScanSummary, uri: &str) -> String {
    let out = serde_json::json!({
        "target": uri,
        "provider": summary.provider,
        "total": summary.total,
        "passed": summary.passed,
        "failed": summary.failed,
        "by_level": {
            "info": summary.by_level[0],
            "warning": summary.by_level[1],
            "error": summary.by_level[2],
            "fatal": summary.by_level[3],
        },
        "duration_ms": summary.duration_ms,
        "violations": summary.violations,
    });
    serde_json::to_string_pretty(&out).unwrap_or_default()
}

// ── CSV ─────────────────────────────────────────────────────────────────────

fn format_csv(summary: &ScanSummary) -> String {
    let mut out = String::from("level,rule,description,compliance,object_type,resource,message\n");
    for v in &summary.violations {
        let compliance: String = v
            .compliance
            .iter()
            .map(|c| format!("{} {}", c.framework, c.control))
            .collect::<Vec<_>>()
            .join("; ");
        let resource = resource_name(&v.object_content);
        let message = v.messages.join(" | ");
        out.push_str(&format!(
            "{},{},{},{},{},{},{}\n",
            csv_escape(level_label(v.level)),
            csv_escape(&v.rule),
            csv_escape(&v.description),
            csv_escape(&compliance),
            csv_escape(&v.object_type),
            csv_escape(&resource),
            csv_escape(&message),
        ));
    }
    out
}

// ── TOML ────────────────────────────────────────────────────────────────────

fn format_toml(summary: &ScanSummary, uri: &str) -> String {
    let mut out = format!(
        "[summary]\ntarget = \"{}\"\nprovider = \"{}\"\ntotal = {}\npassed = {}\nfailed = {}\nduration_ms = {}\n\n",
        uri, summary.provider, summary.total, summary.passed, summary.failed, summary.duration_ms
    );
    for v in &summary.violations {
        out.push_str("[[violations]]\n");
        out.push_str(&format!("rule = \"{}\"\n", v.rule));
        out.push_str(&format!("level = \"{}\"\n", level_label(v.level)));
        out.push_str(&format!("description = \"{}\"\n", v.description.replace('"', "'")));
        let resource = resource_name(&v.object_content);
        if !resource.is_empty() {
            out.push_str(&format!("resource = \"{}\"\n", resource));
        }
        if !v.compliance.is_empty() {
            let refs: Vec<String> = v
                .compliance
                .iter()
                .map(|c| format!("\"{}\"", format!("{} {}", c.framework, c.control)))
                .collect();
            out.push_str(&format!("compliance = [{}]\n", refs.join(", ")));
        }
        if !v.messages.is_empty() {
            out.push_str(&format!("message = \"{}\"\n", v.messages.join(" | ").replace('"', "'")));
        }
        out.push('\n');
    }
    out
}

// ── Minimal (colorized) ────────────────────────────────────────────────────

fn format_minimal(summary: &ScanSummary, uri: &str) -> String {
    let mut out = String::new();

    // Header
    let status_color = if summary.failed == 0 { GREEN } else { RED };
    out.push_str(&format!(
        "{BOLD}{}{RESET} {DIM}|{RESET} {}{}/{}{RESET} {DIM}|{RESET} {}ms\n",
        uri,
        status_color,
        summary.passed,
        summary.total,
        summary.duration_ms,
    ));

    if summary.failed == 0 {
        out.push_str(&format!("{GREEN}{BOLD}  ALL PASSED{RESET}\n"));
        return out;
    }

    // Level summary bar
    let (info, warn, err, fatal) = (
        summary.by_level[0],
        summary.by_level[1],
        summary.by_level[2],
        summary.by_level[3],
    );
    if fatal > 0 {
        out.push_str(&format!("  \x1b[35m{fatal} fatal{RESET}"));
    }
    if err > 0 {
        out.push_str(&format!("  {RED}{err} error{RESET}"));
    }
    if warn > 0 {
        out.push_str(&format!("  \x1b[33m{warn} warn{RESET}"));
    }
    if info > 0 {
        out.push_str(&format!("  \x1b[36m{info} info{RESET}"));
    }
    out.push('\n');

    // Violations grouped by level (fatal first)
    let mut sorted = summary.violations.clone();
    sorted.sort_by(|a, b| b.level.cmp(&a.level));

    for v in &sorted {
        let color = level_color(v.level);
        let resource = resource_name(&v.object_content);
        let resource_str = if resource.is_empty() {
            String::new()
        } else {
            format!(" {DIM}({resource}){RESET}")
        };
        out.push_str(&format!(
            "  {color}{:5}{RESET} {BOLD}{}{RESET}{}\n",
            level_label(v.level),
            v.rule,
            resource_str,
        ));
    }

    out
}

// ── HTML ────────────────────────────────────────────────────────────────────

fn format_html(summary: &ScanSummary, uri: &str) -> String {
    let status_class = if summary.failed == 0 { "pass" } else { "fail" };
    let (info, warn, err, fatal) = (
        summary.by_level[0],
        summary.by_level[1],
        summary.by_level[2],
        summary.by_level[3],
    );

    let mut rows = String::new();
    for v in &summary.violations {
        let lvl = level_label(v.level);
        let lvl_class = match v.level {
            0 => "info", 1 => "warn", 2 => "error", _ => "fatal",
        };
        let compliance: String = v
            .compliance
            .iter()
            .map(|c| format!("<span class=\"badge\">{} {}</span>", html_escape(&c.framework), html_escape(&c.control)))
            .collect::<Vec<_>>()
            .join(" ");
        let resource = resource_name(&v.object_content);
        let message = v.messages.join(" | ");
        rows.push_str(&format!(
            "    <tr class=\"{lvl_class}\"><td><span class=\"level {lvl_class}\">{lvl}</span></td><td>{}</td><td>{}</td><td>{compliance}</td><td>{}</td><td class=\"msg\">{}</td></tr>\n",
            html_escape(&v.rule),
            html_escape(&v.description),
            html_escape(&resource),
            html_escape(&message),
        ));
    }

    format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>kxn scan — {target}</title>
<style>
:root {{ --bg:#0d1117; --fg:#c9d1d9; --border:#30363d; --card:#161b22; --info:#58a6ff; --warn:#d29922; --error:#f85149; --fatal:#bc8cff; --pass:#3fb950; }}
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif; background:var(--bg); color:var(--fg); padding:2rem; }}
h1 {{ font-size:1.5rem; margin-bottom:.5rem; }}
.summary {{ display:flex; gap:1.5rem; margin:1rem 0; flex-wrap:wrap; }}
.stat {{ background:var(--card); border:1px solid var(--border); border-radius:8px; padding:1rem 1.5rem; }}
.stat .val {{ font-size:1.8rem; font-weight:700; }}
.stat .lbl {{ font-size:.85rem; opacity:.7; }}
.stat.fail .val {{ color:var(--error); }}
.stat.pass .val {{ color:var(--pass); }}
.levels {{ display:flex; gap:.75rem; margin:1rem 0; }}
.levels span {{ padding:.25rem .75rem; border-radius:4px; font-size:.85rem; font-weight:600; }}
.levels .fatal {{ background:rgba(188,140,255,.15); color:var(--fatal); }}
.levels .error {{ background:rgba(248,81,73,.15); color:var(--error); }}
.levels .warn {{ background:rgba(210,153,34,.15); color:var(--warn); }}
.levels .info {{ background:rgba(88,166,255,.15); color:var(--info); }}
table {{ width:100%; border-collapse:collapse; margin-top:1.5rem; font-size:.9rem; }}
th {{ text-align:left; padding:.6rem .8rem; border-bottom:2px solid var(--border); font-weight:600; }}
td {{ padding:.5rem .8rem; border-bottom:1px solid var(--border); vertical-align:top; }}
tr:hover {{ background:var(--card); }}
.level {{ display:inline-block; padding:.15rem .5rem; border-radius:3px; font-size:.75rem; font-weight:700; text-transform:uppercase; }}
.level.fatal {{ background:rgba(188,140,255,.2); color:var(--fatal); }}
.level.error {{ background:rgba(248,81,73,.2); color:var(--error); }}
.level.warn {{ background:rgba(210,153,34,.2); color:var(--warn); }}
.level.info {{ background:rgba(88,166,255,.2); color:var(--info); }}
.badge {{ display:inline-block; padding:.1rem .4rem; border-radius:3px; font-size:.75rem; background:var(--card); border:1px solid var(--border); margin:.1rem; }}
.msg {{ font-family:monospace; font-size:.8rem; opacity:.8; max-width:400px; word-break:break-all; }}
footer {{ margin-top:2rem; font-size:.8rem; opacity:.5; }}
</style>
</head>
<body>
<h1>kxn scan &mdash; {target}</h1>
<p>Provider: {provider} &bull; {duration}ms</p>

<div class="summary">
  <div class="stat {status_class}"><div class="val">{passed}/{total}</div><div class="lbl">passed</div></div>
  <div class="stat fail"><div class="val">{failed}</div><div class="lbl">violations</div></div>
</div>

<div class="levels">
  {level_badges}
</div>

<table>
<thead><tr><th>Level</th><th>Rule</th><th>Description</th><th>Compliance</th><th>Resource</th><th>Message</th></tr></thead>
<tbody>
{rows}</tbody>
</table>

<footer>Generated by kxn v{version} &mdash; {timestamp}</footer>
</body>
</html>"#,
        target = html_escape(uri),
        provider = html_escape(&summary.provider),
        duration = summary.duration_ms,
        status_class = status_class,
        passed = summary.passed,
        total = summary.total,
        failed = summary.failed,
        level_badges = {
            let mut b = String::new();
            if fatal > 0 { b.push_str(&format!("<span class=\"fatal\">{fatal} fatal</span>")); }
            if err > 0 { b.push_str(&format!("<span class=\"error\">{err} error</span>")); }
            if warn > 0 { b.push_str(&format!("<span class=\"warn\">{warn} warn</span>")); }
            if info > 0 { b.push_str(&format!("<span class=\"info\">{info} info</span>")); }
            b
        },
        rows = rows,
        version = env!("CARGO_PKG_VERSION"),
        timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M UTC"),
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn resource_name(content: &Value) -> String {
    // Try common name fields
    for key in ["name", "id", "url", "host", "cve_id"] {
        if let Some(s) = content.get(key).and_then(|v| v.as_str()) {
            return s.to_string();
        }
    }
    String::new()
}
