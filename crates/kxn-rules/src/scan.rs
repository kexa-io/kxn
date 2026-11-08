//! The scan loop — one implementation, used by every entry point.
//!
//! Deciding which resources a rule judges, whether the rule applies to the
//! target at all, and what to do when the object was never collected, used to
//! be written seven times: `kxn scan`, `kxn watch`, `kxn check`, the webhook
//! server, two MCP tools and the WASM build. They had drifted apart on three
//! axes — the rule-pack provider guard, the `apply_to` filter, and what happens
//! when the object is missing — so the same rules answered differently
//! depending on which command asked.
//!
//! The semantics below are the union of what those paths meant to do:
//!
//! - a pack that declares a provider is only evaluated against a target of that
//!   provider (a `postgresql-cis` rule says nothing about an SSH host);
//! - `apply_to` is always honoured — it is part of the rule, not of the caller;
//! - a rule whose `object` is empty judges the whole gathered payload;
//! - a rule whose `object` was not collected produces **no verdict**, and says
//!   why. Judging it against the whole payload — which three of the seven paths
//!   did — reads every property as missing and invents violations.

use kxn_core::{check_rule, Rule, SubResultScan};
use serde::Serialize;
use serde_json::Value;

use crate::types::RuleFile;

/// Why a rule produced no verdict on a target.
///
/// Two of these are ordinary and two are not: a pack aimed at another provider
/// or a resource type the target simply does not have says nothing about the
/// target's compliance, while an object nothing collects or a collection that
/// failed means the check never happened — and a scan that reports "no
/// violations" for those is lying by omission.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum NotEvaluated {
    /// The rule pack targets another provider than the scanned target.
    NotApplicable {
        pack_provider: String,
        target_provider: String,
    },
    /// The object is collectable, but this target has no such resource — the
    /// service is not installed, the account has none of them.
    NoSuchResource { object: String },
    /// No collector produces this object at all: the rule can never fire.
    ObjectNotCollected { object: String },
    /// Collection failed, so the resource judged would not be the real one.
    CollectionFailed { object: String, error: String },
}

impl NotEvaluated {
    /// Does this deserve the operator's attention? A missing resource does not;
    /// a rule that can never run, or data that could not be read, does.
    pub fn is_alarming(&self) -> bool {
        matches!(
            self,
            NotEvaluated::ObjectNotCollected { .. } | NotEvaluated::CollectionFailed { .. }
        )
    }

    pub fn object(&self) -> Option<&str> {
        match self {
            NotEvaluated::NoSuchResource { object }
            | NotEvaluated::ObjectNotCollected { object }
            | NotEvaluated::CollectionFailed { object, .. } => Some(object),
            NotEvaluated::NotApplicable { .. } => None,
        }
    }
}

/// What the scan reports, one event at a time. Callers build their own output
/// from these — a table, a webhook payload, a SARIF run — instead of each
/// re-deriving them from a loop of their own.
pub enum Event<'a> {
    Pass {
        pack: &'a str,
        rule: &'a Rule,
        resource: &'a Value,
    },
    Violation {
        pack: &'a str,
        rule: &'a Rule,
        resource: &'a Value,
        failures: Vec<SubResultScan>,
    },
    NotEvaluated {
        pack: &'a str,
        rule: &'a Rule,
        reason: NotEvaluated,
    },
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Totals {
    pub passed: usize,
    pub failed: usize,
    /// Rules that produced no verdict, whatever the reason.
    pub not_evaluated: usize,
    /// Of those, the ones that mean a check did not happen.
    pub not_evaluated_alarming: usize,
}

impl Totals {
    pub fn evaluated(&self) -> usize {
        self.passed + self.failed
    }
}

#[derive(Default)]
pub struct ScanOptions<'a> {
    /// Provider the target is scanned with. Enables the pack guard; `None`
    /// evaluates every pack, which is what `kxn check` on a JSON file wants.
    pub target_provider: Option<&'a str>,
    /// Objects some collector can produce. Lets a missing object be told apart:
    /// known but absent means the target has none, unknown means nothing would
    /// ever collect it. `None` reports every missing object as absent, without
    /// accusing the rule.
    pub known_objects: Option<&'a std::collections::BTreeSet<String>>,
}


/// The objects a rule set actually reads.
///
/// Collecting everything a provider can produce is the difference between a
/// scan of seconds and one of minutes: a Kubernetes CIS run references twelve
/// objects out of the seventy the provider offers, and the other fifty-eight
/// include the expensive ones — a log read per pod, kubelet stats per node,
/// Helm payloads. An empty result means "could not tell", and the caller
/// should fall back to collecting everything rather than collecting nothing.
pub fn needed_objects(files: &[(String, RuleFile)]) -> std::collections::BTreeSet<String> {
    files
        .iter()
        .flat_map(|(_, rf)| rf.rules.iter().map(|r| r.object.clone()))
        .filter(|o| !o.is_empty())
        .collect()
}

/// Resources of `object` inside a gathered payload.
pub fn extract_resources<'a>(root: &'a Value, object: &str) -> Vec<&'a Value> {
    if object.is_empty() {
        return vec![];
    }
    match root.get(object) {
        Some(Value::Array(arr)) => arr.iter().collect(),
        Some(val) => vec![val],
        None => vec![],
    }
}

/// A collector that failed leaves `{"error": "..."}` where the resources should
/// be. Judging that object would report the failure as a violation of whatever
/// the rule happens to check.
fn collection_error(items: &[&Value]) -> Option<String> {
    if items.len() != 1 {
        return None;
    }
    let obj = items[0].as_object()?;
    if obj.len() != 1 {
        return None;
    }
    obj.get("error")?.as_str().map(String::from)
}

/// Run every rule of every pack against every gathered payload.
pub fn scan<'a, F>(
    files: &'a [(String, RuleFile)],
    resources: &'a [Value],
    opts: &ScanOptions<'_>,
    mut on_event: F,
) -> Totals
where
    F: FnMut(Event<'a>),
{
    let mut totals = Totals::default();

    for (pack, rule_file) in files {
        let pack_provider = rule_file
            .metadata
            .as_ref()
            .and_then(|m| m.provider.as_deref())
            .unwrap_or("");

        // A pack written for another provider says nothing here: object names
        // overlap (`services`, `users`, `logs`), so evaluating it anyway judges
        // unrelated resources.
        if let (Some(target), false) = (opts.target_provider, pack_provider.is_empty()) {
            if !provider_matches(pack_provider, target) {
                for rule in &rule_file.rules {
                    totals.not_evaluated += 1;
                    on_event(Event::NotEvaluated {
                        pack,
                        rule,
                        reason: NotEvaluated::NotApplicable {
                            pack_provider: pack_provider.to_string(),
                            target_provider: target.to_string(),
                        },
                    });
                }
                continue;
            }
        }

        for rule in &rule_file.rules {
            for resource in resources {
                let targets: Vec<&Value> = if rule.object.is_empty() {
                    vec![resource]
                } else {
                    let items = extract_resources(resource, &rule.object);

                    if let Some(error) = collection_error(&items) {
                        totals.not_evaluated += 1;
                        totals.not_evaluated_alarming += 1;
                        on_event(Event::NotEvaluated {
                            pack,
                            rule,
                            reason: NotEvaluated::CollectionFailed {
                                object: rule.object.clone(),
                                error,
                            },
                        });
                        continue;
                    }

                    if items.is_empty() {
                        let known = opts
                            .known_objects
                            .map(|k| k.contains(&rule.object))
                            .unwrap_or(true);
                        let reason = if known {
                            NotEvaluated::NoSuchResource {
                                object: rule.object.clone(),
                            }
                        } else {
                            NotEvaluated::ObjectNotCollected {
                                object: rule.object.clone(),
                            }
                        };
                        totals.not_evaluated += 1;
                        if reason.is_alarming() {
                            totals.not_evaluated_alarming += 1;
                        }
                        on_event(Event::NotEvaluated { pack, rule, reason });
                        continue;
                    }
                    items
                };

                for target in targets {
                    if !rule.matches_apply_to(target) {
                        continue;
                    }
                    let failures: Vec<SubResultScan> = check_rule(&rule.conditions, target)
                        .into_iter()
                        .filter(|r| !r.result)
                        .collect();

                    if failures.is_empty() {
                        totals.passed += 1;
                        on_event(Event::Pass {
                            pack,
                            rule,
                            resource: target,
                        });
                    } else {
                        totals.failed += 1;
                        on_event(Event::Violation {
                            pack,
                            rule,
                            resource: target,
                            failures,
                        });
                    }
                }
            }
        }
    }

    totals
}

/// Provider names a pack may use for the same collector.
fn provider_matches(pack_provider: &str, target_provider: &str) -> bool {
    let canonical = |p: &str| -> String {
        let p = p.trim().trim_start_matches("hashicorp/");
        match p {
            "k8s" => "kubernetes",
            // Terraform names the Azure provider after the ARM API, not the
            // cloud: `hashicorp/azurerm` and `azure` are the same target.
            "azurerm" => "azure",
            "gh" => "github",
            "gitea" => "forgejo",
            "gws" => "googleworkspace",
            "msgraph" => "microsoft.graph",
            "google" => "gcp",
            "prom" => "prometheus",
            other => other,
        }
        .to_string()
    };
    let pack = canonical(pack_provider);
    let target = canonical(target_provider);
    // `provider = "terraform"` means "whichever profile provides it".
    pack == target || pack == "terraform"
}

#[cfg(test)]
mod tests {
    /// Every `provider` string the shipped rule packs declare must resolve to a
    /// provider that exists, or the pack is silently skipped on every target.
    /// `azure-secrets-rotation.toml` declares `hashicorp/azurerm`, which used
    /// to canonicalise to `azurerm` and never match the `azure` target.
    #[test]
    fn shipped_pack_provider_names_match_their_target() {
        for (pack, target) in [
            ("hashicorp/azurerm", "azure"),
            ("hashicorp/aws", "aws"),
            ("hashicorp/google", "gcp"),
            ("k8s", "kubernetes"),
            ("gws", "googleworkspace"),
        ] {
            assert!(
                provider_matches(pack, target),
                "pack provider {pack} should apply to a {target} target"
            );
        }
    }

    /// The guard must still separate providers that merely look alike.
    #[test]
    fn unrelated_providers_stay_separate() {
        assert!(!provider_matches("azure", "aws"));
        assert!(!provider_matches("microsoft.graph", "azure"));
        assert!(!provider_matches("postgresql", "mysql"));
    }

    use super::*;
    use serde_json::json;

    const COND: &str = "[[rules.conditions]]\nproperty = \"port\"\ncondition = \"EQUAL\"\nvalue = 22\n";

    fn pack(name: &str, src: &str) -> Vec<(String, RuleFile)> {
        vec![(name.to_string(), crate::parse_string(src).expect("valid pack"))]
    }

    fn rule(object: &str) -> String {
        format!(
            "[[rules]]\nname = \"r\"\nlevel = 2\nobject = \"{object}\"\n{COND}"
        )
    }

    fn collect<'a>(
        files: &'a [(String, RuleFile)],
        resources: &'a [Value],
        opts: &ScanOptions<'_>,
    ) -> (Totals, Vec<NotEvaluated>) {
        let mut reasons = Vec::new();
        let totals = scan(files, resources, opts, |e| {
            if let Event::NotEvaluated { reason, .. } = e {
                reasons.push(reason);
            }
        });
        (totals, reasons)
    }

    #[test]
    fn judges_the_resources_of_its_object() {
        let files = pack("ssh-cis", &rule("sshd_config"));
        let data = vec![json!({ "sshd_config": [{ "port": 22 }, { "port": 2222 }] })];
        let (totals, _) = collect(&files, &data, &ScanOptions::default());
        assert_eq!((totals.passed, totals.failed), (1, 1));
    }

    /// The bug this module exists to kill: three of the seven previous loops
    /// fell back to judging the *whole* gathered payload when the object was
    /// missing, so every property read as absent and the rule invented a
    /// violation.
    #[test]
    fn an_absent_object_is_never_judged_against_the_whole_payload() {
        let files = pack("apache-cis", &rule("apache_config"));
        let data = vec![json!({ "sshd_config": [{ "port": 22 }] })];
        let (totals, reasons) = collect(&files, &data, &ScanOptions::default());
        assert_eq!((totals.passed, totals.failed), (0, 0));
        assert_eq!(totals.not_evaluated, 1);
        assert_eq!(reasons[0].object(), Some("apache_config"));
    }

    /// Absent because the target has none of them, or absent because nothing
    /// would ever collect it — only the catalogue can tell, and only the second
    /// deserves attention.
    #[test]
    fn the_catalogue_separates_a_missing_resource_from_a_missing_collector() {
        let files = pack("apache-cis", &rule("apache_config"));
        let data = vec![json!({ "sshd_config": [] })];

        let mut known = std::collections::BTreeSet::new();
        known.insert("apache_config".to_string());
        let (t1, r1) = collect(
            &files,
            &data,
            &ScanOptions {
                known_objects: Some(&known),
                ..Default::default()
            },
        );
        assert!(matches!(r1[0], NotEvaluated::NoSuchResource { .. }));
        assert_eq!(t1.not_evaluated_alarming, 0);

        let empty = std::collections::BTreeSet::new();
        let (t2, r2) = collect(
            &files,
            &data,
            &ScanOptions {
                known_objects: Some(&empty),
                ..Default::default()
            },
        );
        assert!(matches!(r2[0], NotEvaluated::ObjectNotCollected { .. }));
        assert_eq!(t2.not_evaluated_alarming, 1);
    }

    /// A failed collection leaves `{"error": ...}` behind; judging it reports
    /// the failure as a violation of whatever the rule checks.
    #[test]
    fn a_failed_collection_is_reported_not_judged() {
        let files = pack("ssh-cis", &rule("sshd_config"));
        let data = vec![json!({ "sshd_config": [{ "error": "connection refused" }] })];
        let (totals, reasons) = collect(&files, &data, &ScanOptions::default());
        assert_eq!((totals.passed, totals.failed), (0, 0));
        assert_eq!(totals.not_evaluated_alarming, 1);
        match &reasons[0] {
            NotEvaluated::CollectionFailed { error, .. } => assert_eq!(error, "connection refused"),
            other => panic!("attendu CollectionFailed, obtenu {other:?}"),
        }
    }

    #[test]
    fn a_pack_for_another_provider_is_not_applicable() {
        let files = pack(
            "postgresql-cis",
            &format!("[metadata]\nprovider = \"postgresql\"\n{}", rule("settings")),
        );
        let data = vec![json!({ "settings": [{ "port": 5432 }] })];
        let (totals, reasons) = collect(
            &files,
            &data,
            &ScanOptions {
                target_provider: Some("ssh"),
                ..Default::default()
            },
        );
        assert_eq!((totals.passed, totals.failed), (0, 0));
        assert!(matches!(reasons[0], NotEvaluated::NotApplicable { .. }));
        assert_eq!(totals.not_evaluated_alarming, 0, "ce n'est pas une panne");
    }

    #[test]
    fn provider_aliases_and_terraform_packs_match() {
        assert!(provider_matches("kubernetes", "k8s"));
        assert!(provider_matches("hashicorp/aws", "aws"));
        assert!(provider_matches("terraform", "azure"), "un pack terraform vise le profil");
        assert!(!provider_matches("postgresql", "ssh"));
    }

    /// `apply_to` belongs to the rule; two of the previous loops ignored it and
    /// judged every resource of the object.
    #[test]
    fn apply_to_is_always_honoured() {
        let src = format!(
            "[[rules]]\nname = \"r\"\nlevel = 2\nobject = \"services\"\napply_to = \"name=sshd\"\n{COND}"
        );
        let files = pack("ssh-cis", &src);
        let data = vec![json!({ "services": [
            { "name": "sshd", "port": 22 },
            { "name": "httpd", "port": 80 }
        ] })];
        let (totals, _) = collect(&files, &data, &ScanOptions::default());
        assert_eq!((totals.passed, totals.failed), (1, 0), "seul sshd est juge");
    }

    #[test]
    fn a_rule_without_an_object_judges_the_whole_payload() {
        let files = pack("generic", &format!("[[rules]]\nname = \"r\"\nlevel = 2\n{COND}"));
        let data = vec![json!({ "port": 22 })];
        let (totals, _) = collect(&files, &data, &ScanOptions::default());
        assert_eq!((totals.passed, totals.failed), (1, 0));
    }
}

#[cfg(test)]
mod shipped_rule_layout_tests {
    /// `apply_to` written after a `[[rules.compliance]]` header belongs to that
    /// sub-table, not to the rule, and serde drops it without a word — the
    /// filter then matches nothing and the rule is scored against every
    /// resource of its object. It happened twice while aiming rules at one
    /// file of `file_permissions`, and the only symptom was a rule firing five
    /// times instead of once.
    #[test]
    fn apply_to_belongs_to_the_rule_not_to_a_sub_table() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../rules")
            .canonicalize()
            .expect("rules directory");

        let mut misplaced = Vec::new();
        for entry in std::fs::read_dir(&dir).expect("read rules") {
            let path = entry.expect("entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("read file");
            for block in text.split("[[rules]]").skip(1) {
                let Some(at) = block.find("apply_to") else {
                    continue;
                };
                let first_sub = block.find("\n  [[rules.");
                if first_sub.is_some_and(|sub| at > sub) {
                    let name = block
                        .lines()
                        .find_map(|l| l.trim().strip_prefix("name = "))
                        .unwrap_or("?")
                        .to_string();
                    misplaced.push(format!("{}: {name}", path.display()));
                }
            }
        }
        assert!(
            misplaced.is_empty(),
            "apply_to is nested inside a sub-table and will be ignored:\n  {}",
            misplaced.join("\n  ")
        );
    }
}
