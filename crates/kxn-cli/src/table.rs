//! Table formatter — renders data as aligned columns with colors.
//! Used by scan output (text mode) and remediate.

pub const RESET: &str = "\x1b[0m";
pub const BOLD: &str = "\x1b[1m";
pub const DIM: &str = "\x1b[2m";
pub const RED: &str = "\x1b[31m";
pub const GREEN: &str = "\x1b[32m";
pub const YELLOW: &str = "\x1b[33m";
pub const MAGENTA: &str = "\x1b[35m";
pub const CYAN: &str = "\x1b[36m";

pub fn level_color(level: u8) -> &'static str {
    match level {
        0 => CYAN,
        1 => YELLOW,
        2 => RED,
        _ => MAGENTA,
    }
}

pub fn level_label(level: u8) -> &'static str {
    match level {
        0 => "INFO",
        1 => "WARN",
        2 => "ERROR",
        _ => "FATAL",
    }
}

/// Truncate a string to max chars, append "..." if truncated.
pub fn trunc(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max.saturating_sub(3)])
    }
}

/// Print a separator line matching column widths.
fn separator(widths: &[usize]) {
    let parts: Vec<String> = widths.iter().map(|w| "─".repeat(*w)).collect();
    println!("{DIM}{}─{}{RESET}", parts.join("─┼─"), "");
}

/// Print a header row.
fn header(cols: &[&str], widths: &[usize]) {
    let parts: Vec<String> = cols
        .iter()
        .zip(widths.iter())
        .map(|(col, w)| format!("{BOLD}{:width$}{RESET}", col, width = w))
        .collect();
    println!("{}", parts.join(" │ "));
    separator(widths);
}

/// Scan result row
pub struct ScanRow {
    pub num: usize,
    pub level: u8,
    pub rule: String,
    pub description: String,
    pub resource: String,
    pub compliance: String,
    pub message: String,
}

/// Remediate result row
pub struct RemediateRow {
    pub num: usize,
    pub level: u8,
    pub rule: String,
    pub description: String,
    pub remediation: String,
    pub message: String,
}

/// Print scan results as a table.
pub fn print_scan_table(rows: &[ScanRow], total: usize, passed: usize, failed: usize, duration_ms: u128, uri: &str) {
    // Summary header
    let status = if failed == 0 {
        format!("{GREEN}{BOLD}ALL PASSED{RESET}")
    } else {
        format!("{RED}{BOLD}{} violations{RESET}", failed)
    };
    println!(
        "\n{BOLD}{}{RESET} {DIM}|{RESET} {}/{} passed {DIM}|{RESET} {} {DIM}|{RESET} {}ms\n",
        uri, passed, total, status, duration_ms
    );

    if rows.is_empty() {
        return;
    }

    let widths = [4, 5, 36, 20, 30];
    header(&["#", "Level", "Rule", "Resource", "Message"], &widths);

    for row in rows {
        let lc = level_color(row.level);
        let ll = level_label(row.level);
        println!(
            "{DIM}{:>4}{RESET} │ {lc}{:5}{RESET} │ {BOLD}{}{RESET} │ {DIM}{}{RESET} │ {DIM}{}{RESET}",
            row.num,
            ll,
            trunc(&row.rule, widths[2]),
            trunc(&row.resource, widths[3]),
            trunc(&row.message, widths[4]),
        );
    }
    println!();
}

/// Print remediate results grouped by category with clean formatting.
pub fn print_remediate_table(rows: &[RemediateRow]) {
    if rows.is_empty() {
        println!("No remediable violations found.");
        return;
    }

    // Count by level
    let fatal = rows.iter().filter(|r| r.level >= 3).count();
    let error = rows.iter().filter(|r| r.level == 2).count();
    let warn = rows.iter().filter(|r| r.level == 1).count();

    println!();
    println!(
        "  {BOLD}{} remediable violations{RESET}  {DIM}│{RESET}  {MAGENTA}{} fatal{RESET}  {RED}{} error{RESET}  {YELLOW}{} warn{RESET}",
        rows.len(), fatal, error, warn
    );
    println!();

    // Group by category (prefix before first dash-separated number or second dash)
    let mut current_category = String::new();

    for row in rows {
        // Extract category from rule name (e.g., "apache-cis" from "apache-cis-2.3-server-tokens")
        let category = row.rule
            .splitn(3, '-')
            .take(2)
            .collect::<Vec<_>>()
            .join("-");

        if category != current_category {
            if !current_category.is_empty() {
                println!();
            }
            println!("  {DIM}── {}{RESET}", category.to_uppercase());
            current_category = category;
        }

        let lc = level_color(row.level);
        let ll = level_label(row.level);

        println!(
            "  {DIM}{:>3}{RESET}  {lc}{:5}{RESET}  {BOLD}{}{RESET}",
            row.num, ll, row.rule
        );
        println!(
            "  {DIM}   {RESET}         {}{RESET}",
            row.description
        );
        println!(
            "  {DIM}   {RESET}         {CYAN}{}{RESET}",
            row.remediation
        );
    }

    println!();
    println!("  {DIM}─────────────────────────────────────────{RESET}");
    println!();
    println!("  {DIM}Apply:{RESET}");
    println!("    kxn remediate <URI> {CYAN}--rule 1{RESET}                {DIM}single fix{RESET}");
    println!("    kxn remediate <URI> {CYAN}--rule 1 --rule 3{RESET}       {DIM}multiple{RESET}");
    println!("    kxn remediate <URI> {CYAN}--apply-filter ssh-cis{RESET}  {DIM}by category{RESET}");
    println!("    kxn remediate <URI> {CYAN}--rule 1 --dry-run{RESET}      {DIM}preview only{RESET}");
    println!();
}
