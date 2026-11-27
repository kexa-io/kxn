//! Per-control summary of a scan, for the frameworks named with `--framework`.
//!
//! An auditor reads a scan by control (NIS2 21.2.h, SOC 2 CC6.1, GDPR art. 32),
//! not by rule. For each control of each framework this counts the rules of
//! the loaded packs that map to it, and how many of them passed, failed or
//! could not be evaluated on this target.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use kxn_rules::{same_framework, RuleFile};

use crate::commands::watch::ScanSummary;
use crate::table::{BOLD, DIM, GREEN, RED, RESET};

struct Control {
    /// Every wording of the section seen for this control, with its count:
    /// the report shows the most common one.
    sections: BTreeMap<String, usize>,
    rules: BTreeSet<String>,
}

impl Control {
    fn section(&self) -> &str {
        self.sections
            .iter()
            .max_by_key(|(_, n)| **n)
            .map(|(s, _)| s.as_str())
            .unwrap_or("")
    }
}

/// Natural order of control ids: `21.2.b` < `21.2.j`, `CC6.1` < `CC6.10`, `5` < `25` < `32.1.a`.
fn control_key(id: &str) -> Vec<(u8, u64, String)> {
    let mut key = Vec::new();
    let mut num = String::new();
    let mut txt = String::new();
    for ch in id.chars() {
        if ch.is_ascii_digit() {
            if !txt.is_empty() {
                key.push((1, 0, std::mem::take(&mut txt)));
            }
            num.push(ch);
        } else {
            if !num.is_empty() {
                key.push((0, num.parse().unwrap_or(u64::MAX), String::new()));
                num.clear();
            }
            txt.push(ch);
        }
    }
    if !num.is_empty() {
        key.push((0, num.parse().unwrap_or(u64::MAX), String::new()));
    }
    if !txt.is_empty() {
        key.push((1, 0, txt));
    }
    key
}

/// The frameworks the rules of `files` map to with a control id, most used
/// first: what `--compliance` reports on. A framework whose blocks name no
/// control (a bare `framework = "CIS"`, the control being in the rule name)
/// has no per-control table to show and is left out.
pub fn frameworks_in(files: &[(String, RuleFile)]) -> Vec<String> {
    let mut count: BTreeMap<String, BTreeSet<&str>> = BTreeMap::new();
    for (_, rf) in files {
        for rule in &rf.rules {
            for c in rule.compliance.iter().filter(|c| !c.control.is_empty()) {
                let known = count.keys().find(|k| same_framework(k, &c.framework)).cloned();
                count.entry(known.unwrap_or_else(|| c.framework.clone())).or_default().insert(&rule.name);
            }
        }
    }
    let mut v: Vec<(String, usize)> = count.into_iter().map(|(k, r)| (k, r.len())).collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    v.into_iter().map(|(k, _)| k).collect()
}

pub fn render(files: &[(String, RuleFile)], summary: &ScanSummary, frameworks: &[String]) -> String {
    let failing: HashSet<&str> = summary.violations.iter().map(|v| v.rule.as_str()).collect();
    let skipped: HashSet<&str> = summary.not_evaluated_rules.iter().map(String::as_str).collect();
    let mut out = String::new();

    for wanted in frameworks {
        let mut name: Option<String> = None;
        let mut controls: BTreeMap<String, Control> = BTreeMap::new();
        for (_, rf) in files {
            for rule in &rf.rules {
                for c in rule.compliance.iter().filter(|c| same_framework(wanted, &c.framework)) {
                    name.get_or_insert_with(|| c.framework.clone());
                    let id = if c.control.is_empty() { "-".to_string() } else { c.control.clone() };
                    let entry = controls.entry(id).or_insert_with(|| Control {
                        sections: BTreeMap::new(),
                        rules: BTreeSet::new(),
                    });
                    if let Some(sec) = c.section.as_deref().filter(|s| !s.is_empty()) {
                        *entry.sections.entry(sec.to_string()).or_default() += 1;
                    }
                    entry.rules.insert(rule.name.clone());
                }
            }
        }
        let Some(name) = name else {
            out.push_str(&format!("\n{BOLD}{wanted}{RESET}: no rule of these packs maps to it\n"));
            continue;
        };

        let mut ids: Vec<&String> = controls.keys().collect();
        ids.sort_by_key(|id| control_key(id));
        let all: BTreeSet<&String> = controls.values().flat_map(|c| c.rules.iter()).collect();
        let n_fail = all.iter().filter(|r| failing.contains(r.as_str())).count();
        let n_skip = all.iter().filter(|r| !failing.contains(r.as_str()) && skipped.contains(r.as_str())).count();
        out.push_str(&format!(
            "\n{BOLD}{name}{RESET} {DIM}|{RESET} {} controls {DIM}|{RESET} {} rules: {GREEN}{} passed{RESET}, {RED}{} failed{RESET}, {} not evaluated\n",
            ids.len(),
            all.len(),
            all.len() - n_fail - n_skip,
            n_fail,
            n_skip
        ));
        out.push_str(&format!(
            "{BOLD}  {:10}  {:58}  {:>6}  {:>6}  {:>6}{RESET}\n",
            "Control", "Section", "Pass", "Fail", "N/E"
        ));
        for id in ids {
            let c = &controls[id];
            let fail = c.rules.iter().filter(|r| failing.contains(r.as_str())).count();
            let skip = c
                .rules
                .iter()
                .filter(|r| !failing.contains(r.as_str()) && skipped.contains(r.as_str()))
                .count();
            let pass = c.rules.len() - fail - skip;
            let section: String = c.section().chars().take(58).collect();
            let fail_cell = if fail > 0 {
                format!("{RED}{fail:>6}{RESET}")
            } else {
                format!("{fail:>6}")
            };
            out.push_str(&format!("  {id:10}  {section:58}  {pass:>6}  {fail_cell}  {skip:>6}\n"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::watch::Violation;

    fn files() -> Vec<(String, RuleFile)> {
        let rf: RuleFile = kxn_rules::parse_string(
            r#"
[[rules]]
name = "a"
description = "a"
level = 1
object = "o"
[[rules.conditions]]
property = "x"
condition = "EQUAL"
value = 1
[[rules.compliance]]
framework = "NIS2"
control = "21.2.h"
section = "Cryptography"
[[rules.compliance]]
framework = "SOC2"
control = "CC6.7"

[[rules]]
name = "b"
description = "b"
level = 1
object = "o"
[[rules.conditions]]
property = "x"
condition = "EQUAL"
value = 1
[[rules.compliance]]
framework = "NIS2"
control = "21.2.b"
section = "Incident handling"

[[rules]]
name = "c"
description = "c"
level = 1
object = "p"
[[rules.conditions]]
property = "x"
condition = "EQUAL"
value = 1
[[rules.compliance]]
framework = "NIS2"
control = "21.2.b"
"#,
        )
        .unwrap();
        vec![("pack".into(), rf)]
    }

    fn strip(s: &str) -> String {
        regex::Regex::new(r"\x1b\[[0-9;]*m").unwrap().replace_all(s, "").to_string()
    }

    #[test]
    fn counts_pass_fail_and_not_evaluated_per_control() {
        let summary = ScanSummary {
            violations: vec![Violation { rule: "a".into(), ..Default::default() }],
            not_evaluated_rules: vec!["c".into()],
            ..Default::default()
        };
        let out = strip(&render(&files(), &summary, &["nis2".into()]));
        assert!(out.contains("NIS2 | 2 controls | 3 rules: 1 passed, 1 failed, 1 not evaluated"), "{out}");
        // 21.2.b comes before 21.2.h, with b passed and c not evaluated.
        let b = out.find("21.2.b").unwrap();
        let h = out.find("21.2.h").unwrap();
        assert!(b < h);
        assert!(out.lines().any(|l| l.contains("21.2.b") && l.split_whitespace().rev().take(3).collect::<Vec<_>>() == ["1", "0", "1"]), "{out}");
        assert!(out.lines().any(|l| l.contains("21.2.h") && l.split_whitespace().rev().take(3).collect::<Vec<_>>() == ["0", "1", "0"]), "{out}");
    }

    #[test]
    fn unknown_framework_says_so() {
        let out = strip(&render(&files(), &ScanSummary::default(), &["GDPR".into()]));
        assert!(out.contains("GDPR: no rule of these packs maps to it"), "{out}");
    }

    #[test]
    fn compliance_lists_frameworks_with_controls_most_used_first() {
        // NIS2 maps 3 rules, SOC2 one.
        assert_eq!(frameworks_in(&files()), vec!["NIS2".to_string(), "SOC2".to_string()]);
    }

    #[test]
    fn controls_sort_naturally() {
        let mut ids = vec!["CC6.10", "CC6.2", "32.1.a", "5", "25", "CC6.1"];
        ids.sort_by_key(|id| control_key(id));
        assert_eq!(ids, vec!["5", "25", "32.1.a", "CC6.1", "CC6.2", "CC6.10"]);
    }
}
