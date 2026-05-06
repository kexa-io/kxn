use anyhow::{Context, Result};
use clap::Args;
use kxn_providers::{native_provider_names, create_native_provider, load_profile, merge_extra, ProviderAddress, TerraformProvider};
use std::collections::{HashMap, HashSet};
use tracing::warn;

/// Heuristic: a Terraform data source is "list-style" (takes only the
/// project/region scope and returns an array) when its name is plural and
/// it isn't a single-resource lookup (iam_policy, iam_binding, _iam_member,
/// individual _identity, …). Used by `--resource-type list` to auto-skip
/// data sources that need a `name` parameter and would 4xx on every cycle.
fn is_list_style_data_source(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    // Filter out single-resource lookup patterns.
    let single_resource_markers = [
        "_iam_policy",
        "_iam_binding",
        "_iam_member",
        "_iam_audit_config",
        "_caller_identity",
        "_account_alias",
        "_account_alternate_contact",
        "_default_service_account",
        "_organization\\b",
        "_organization_service_account",
    ];
    for m in single_resource_markers {
        if lower.contains(m.trim_end_matches("\\b")) {
            return false;
        }
    }
    // Plural-ish endings that indicate list-style data sources.
    lower.ends_with('s')
        || lower.ends_with("ies")
        || lower.ends_with("indexes")
        || lower.ends_with("clusters")
        || lower.ends_with("buckets")
        || lower.ends_with("instances")
        || lower.ends_with("queues")
        || lower.ends_with("topics")
        || lower.ends_with("rules")
}


#[derive(Args)]
pub struct GatherArgs {
    /// Provider name or address (e.g. "http", "mysql", "postgresql", "mongodb", "hashicorp/aws")
    #[arg(short, long)]
    pub provider: String,

    /// Resource type, or "all" to gather all types in parallel
    #[arg(short = 't', long = "resource-type")]
    pub resource_type: String,

    /// Provider config JSON (e.g. '{"URL":"https://example.com"}')
    #[arg(short = 'C', long = "provider-config", default_value = "{}")]
    pub provider_config: String,

    /// Provider version (Terraform providers only)
    #[arg(long)]
    pub version: Option<String>,

    /// Show verbose output
    #[arg(short, long)]
    pub verbose: bool,
}

pub async fn run(args: GatherArgs) -> Result<()> {
    let config: serde_json::Value =
        serde_json::from_str(&args.provider_config).context("Invalid config JSON")?;

    let native_names = native_provider_names();

    if native_names.contains(&args.provider.as_str()) {
        let provider = create_native_provider(&args.provider, config)
            .map_err(|e| anyhow::anyhow!("{}", e))?;

        if args.resource_type == "all" {
            // Parallel gather of all resource types
            let types = provider
                .resource_types()
                .await
                .map_err(|e| anyhow::anyhow!("{}", e))?;

            let provider_ref = &provider;
            let mut handles = Vec::new();

            for rt in types {
                handles.push(async move {
                    let result = provider_ref.gather(&rt).await;
                    (rt, result)
                });
            }

            let results = futures::future::join_all(handles).await;

            let mut output: HashMap<String, serde_json::Value> = HashMap::new();
            for (rt, result) in results {
                match result {
                    Ok(resources) => {
                        output.insert(rt, serde_json::Value::Array(resources));
                    }
                    Err(e) => {
                        output.insert(rt, serde_json::json!({"error": format!("{}", e)}));
                    }
                }
            }

            if args.verbose {
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("{}", serde_json::to_string(&output)?);
            }
        } else {
            let resources = provider
                .gather(&args.resource_type)
                .await
                .map_err(|e| anyhow::anyhow!("{}", e))?;

            if args.verbose {
                println!("{}", serde_json::to_string_pretty(&resources)?);
            } else {
                println!("{}", serde_json::to_string(&resources)?);
            }
        }
    } else if let Some(profile) = load_profile(&args.provider) {
        // Profile-based provider path (e.g. o365, workspace)
        gather_profile(profile, config, &args).await?;
    } else {
        // Terraform provider path
        let address =
            ProviderAddress::parse(&args.provider).map_err(|e| anyhow::anyhow!("{}", e))?;

        let user_config = config.clone();
        let mut provider = TerraformProvider::new(
            address,
            config,
            args.version.as_deref(),
        )
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

        if args.resource_type == "all" || args.resource_type == "list" {
            // For "list" mode, only call data sources that look list-style
            // (plural name, no _iam_*, no _binding, no _policy_*) so we skip
            // lookup-style data sources that need a `name`/`id` parameter and
            // would fail with 4xx every time.
            let list_only = args.resource_type == "list";

            let mut output: HashMap<String, serde_json::Value> = HashMap::new();

            // Special path for the Azure Terraform provider: per-resource
            // data sources (azurerm_storage_account, azurerm_cosmosdb_account,
            // …) require a `name`/`resource_group_name` and crash the gRPC
            // bridge after a few missing-field errors. The `azurerm_resources`
            // data source lists by ARM type without requiring a name —
            // discover the list of ARM types live from the subscription's
            // `/providers` endpoint, then call azurerm_resources for each.
            let is_azure = matches!(args.provider.as_str(), "hashicorp/azurerm" | "azurerm");
            if list_only && is_azure {
                let sub_id = user_config
                    .get("subscription_id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .or_else(|| std::env::var("ARM_SUBSCRIPTION_ID").ok())
                    .or_else(|| std::env::var("AZURE_SUBSCRIPTION_ID").ok())
                    .ok_or_else(|| anyhow::anyhow!(
                        "Azure list mode requires `subscription_id` in --provider-config or ARM_SUBSCRIPTION_ID env var"
                    ))?;
                let arm_types = kxn_providers::azure_arm::list_resource_types(&sub_id)
                    .await
                    .map_err(|e| anyhow::anyhow!("ARM /providers discovery failed: {}", e))?;
                for arm_type in &arm_types {
                    let extra = serde_json::json!({ "type": arm_type });
                    let merged = merge_extra(&user_config, &extra);
                    let cfg = provider
                        .build_data_source_config("azurerm_resources", merged)
                        .await
                        .map_err(|e| anyhow::anyhow!("{}", e))?;
                    match provider.read_data_source("azurerm_resources", cfg).await {
                        Ok(Some(v)) => {
                            output.insert(arm_type.clone(), v);
                        }
                        Ok(None) => {}
                        Err(e) => {
                            warn!("azurerm_resources type='{}' failed: {}", arm_type, e);
                            output.insert(
                                arm_type.clone(),
                                serde_json::json!({"error": e.to_string()}),
                            );
                        }
                    }
                }
                if args.verbose {
                    println!("{}", serde_json::to_string_pretty(&output)?);
                } else {
                    println!("{}", serde_json::to_string(&output)?);
                }
                provider.stop().await.ok();
                return Ok(());
            }

            // Gather all data sources in parallel
            let ds_types: Vec<String> = provider.data_source_types().to_vec();
            let rt_types: Vec<String> = provider.resource_types().to_vec();

            for ds in &ds_types {
                if list_only && !is_list_style_data_source(ds) {
                    continue;
                }
                let ds_config = provider.build_data_source_config(ds, user_config.clone()).await
                    .map_err(|e| anyhow::anyhow!("{}", e))?;
                match provider.read_data_source(ds, ds_config).await {
                    Ok(Some(v)) => { output.insert(format!("data.{}", ds), v); }
                    Ok(None) => {}
                    Err(e) => {
                        warn!("Failed to gather data source '{}': {}", ds, e);
                        output.insert(format!("data.{}", ds), serde_json::json!({"error": e.to_string()}));
                    }
                }
            }

            // In list mode, skip provider resources entirely — read_resource
            // with empty state just returns the schema default and pollutes
            // the output. Resources (vs data sources) only make sense for a
            // specific resource state.
            if !list_only {
                for rt in &rt_types {
                    match provider.read_resource(rt, serde_json::json!({})).await {
                        Ok(Some(v)) => { output.insert(rt.clone(), v); }
                        Ok(None) => {}
                        Err(e) => {
                            warn!("Failed to gather resource '{}': {}", rt, e);
                        }
                    }
                }
            }

            if args.verbose {
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("{}", serde_json::to_string(&output)?);
            }
        } else {
            let resource_type = &args.resource_type;

            // Explicit data. prefix forces ReadDataSource
            let is_explicit_data = resource_type.starts_with("data.");
            let type_name = if is_explicit_data {
                &resource_type[5..]
            } else {
                resource_type
            };

            // Auto-detect: check schema to determine if it's a data source or resource
            let is_data_source = is_explicit_data
                || provider.data_source_types().contains(&type_name.to_string());

            let result = if is_data_source {
                let ds_config = provider.build_data_source_config(type_name, user_config).await
                    .map_err(|e| anyhow::anyhow!("{}", e))?;
                provider.read_data_source(type_name, ds_config).await
            } else {
                let state = serde_json::json!({});
                provider.read_resource(type_name, state).await
            };

            match result {
                Ok(Some(value)) => {
                    if args.verbose {
                        println!("{}", serde_json::to_string_pretty(&value)?);
                    } else {
                        println!("{}", serde_json::to_string(&value)?);
                    }
                }
                Ok(None) => {
                    println!("No resource state returned");
                }
                Err(e) => {
                    anyhow::bail!("Gather failed: {}", e);
                }
            }
        }

        provider.stop().await.ok();
    }

    Ok(())
}

use kxn_providers::Profile;

/// Gather resources using a profile (multi-provider, config-driven).
async fn gather_profile(
    profile: Profile,
    user_config: serde_json::Value,
    args: &GatherArgs,
) -> Result<()> {
    if args.resource_type == "all" {
        // Determine which TF providers we need to start
        let needed: HashSet<&str> = profile
            .resource_types
            .values()
            .map(|rt| rt.provider.as_str())
            .collect();

        // Start each TF provider once
        let mut tf_providers: HashMap<String, TerraformProvider> = HashMap::new();
        for alias in &needed {
            let tf_ref = profile.providers.get(*alias).ok_or_else(|| {
                anyhow::anyhow!("Profile '{}': provider alias '{}' not found", profile.name, alias)
            })?;
            let addr = ProviderAddress::parse(&tf_ref.address)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            let p = TerraformProvider::new(addr, user_config.clone(), tf_ref.version.as_deref())
                .await
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            tf_providers.insert(alias.to_string(), p);
        }

        // Gather all resource types
        let mut output: HashMap<String, serde_json::Value> = HashMap::new();
        for (rt_name, rt_def) in &profile.resource_types {
            let p = tf_providers.get_mut(&rt_def.provider).ok_or_else(|| {
                anyhow::anyhow!("Provider alias '{}' not found in started providers", rt_def.provider)
            })?;
            let merged = merge_extra(&user_config, &rt_def.extra);
            let ds_config = p
                .build_data_source_config(&rt_def.data_source, merged)
                .await
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            match p.read_data_source(&rt_def.data_source, ds_config).await {
                Ok(Some(v)) => {
                    output.insert(rt_name.clone(), v);
                }
                Ok(None) => {}
                Err(e) => {
                    warn!("Profile '{}': failed to gather '{}': {}", profile.name, rt_name, e);
                    output.insert(
                        rt_name.clone(),
                        serde_json::json!({"error": e.to_string()}),
                    );
                }
            }
        }

        if args.verbose {
            println!("{}", serde_json::to_string_pretty(&output)?);
        } else {
            println!("{}", serde_json::to_string(&output)?);
        }

        // Stop all providers
        for (_, mut p) in tf_providers {
            p.stop().await.ok();
        }
    } else {
        // Single resource type
        let rt_def = profile
            .resource_types
            .get(&args.resource_type)
            .ok_or_else(|| {
                let available: Vec<&str> = profile.resource_types.keys().map(|s| s.as_str()).collect();
                anyhow::anyhow!(
                    "Unknown resource type '{}' for profile '{}'. Available: {:?}",
                    args.resource_type,
                    profile.name,
                    available
                )
            })?;

        let tf_ref = profile.providers.get(&rt_def.provider).ok_or_else(|| {
            anyhow::anyhow!(
                "Profile '{}': provider alias '{}' not found",
                profile.name,
                rt_def.provider
            )
        })?;

        let addr =
            ProviderAddress::parse(&tf_ref.address).map_err(|e| anyhow::anyhow!("{}", e))?;
        let mut p = TerraformProvider::new(addr, user_config.clone(), tf_ref.version.as_deref())
            .await
            .map_err(|e| anyhow::anyhow!("{}", e))?;

        let merged = merge_extra(&user_config, &rt_def.extra);
        let ds_config = p
            .build_data_source_config(&rt_def.data_source, merged)
            .await
            .map_err(|e| anyhow::anyhow!("{}", e))?;

        match p.read_data_source(&rt_def.data_source, ds_config).await {
            Ok(Some(value)) => {
                if args.verbose {
                    println!("{}", serde_json::to_string_pretty(&value)?);
                } else {
                    println!("{}", serde_json::to_string(&value)?);
                }
            }
            Ok(None) => {
                println!("No data returned");
            }
            Err(e) => {
                anyhow::bail!("Gather failed for '{}': {}", args.resource_type, e);
            }
        }

        p.stop().await.ok();
    }

    Ok(())
}
