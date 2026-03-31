//! Output formatters for scan results: text, json, csv, toml, minimal (colorized).

use crate::commands::watch::ScanSummary;
use serde_json::Value;

pub fn format_output(summary: &ScanSummary, format: &str, uri: &str) -> String {
    match format {
        "json" => format_json(summary, uri),
        "csv" => format_csv(summary),
        "toml" => format_toml(summary, uri),
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
