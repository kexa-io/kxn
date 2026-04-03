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

/// Print remediate results as a table.
pub fn print_remediate_table(rows: &[RemediateRow]) {
    if rows.is_empty() {
        println!("No remediable violations found.");
        return;
    }

    println!(
        "\n{BOLD}{} remediable violations:{RESET}\n",
        rows.len()
    );

    let widths = [4, 5, 36, 50, 40];
    header(&["#", "Level", "Rule", "Remediation", "Message"], &widths);

    for row in rows {
        let lc = level_color(row.level);
        let ll = level_label(row.level);
        println!(
            "{DIM}{:>4}{RESET} │ {lc}{:5}{RESET} │ {BOLD}{}{RESET} │ {CYAN}{}{RESET} │ {DIM}{}{RESET}",
            row.num,
            ll,
            trunc(&row.rule, widths[2]),
            trunc(&row.remediation, widths[3]),
            trunc(&row.message, widths[4]),
        );
    }

    println!(
        "\n{DIM}To apply:{RESET}"
    );
    println!("  kxn remediate <URI> {CYAN}--rule 1{RESET}              {DIM}# apply single{RESET}");
    println!("  kxn remediate <URI> {CYAN}--rule 1 --rule 3{RESET}     {DIM}# apply multiple{RESET}");
    println!("  kxn remediate <URI> {CYAN}--apply-filter ssh-cis{RESET} {DIM}# apply matching{RESET}");
    println!("  kxn remediate <URI> {CYAN}--rule 1 --dry-run{RESET}    {DIM}# preview{RESET}");
    println!();
}
