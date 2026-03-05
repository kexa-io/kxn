use anyhow::Result;
use clap::Args;
use kxn_providers::{native_provider_names, ProviderRegistry};

#[derive(Args)]
pub struct ListProvidersArgs {
    /// Filter by provider name
    #[arg(short, long)]
    pub provider: Option<String>,
}

pub fn run(args: ListProvidersArgs) -> Result<()> {
    // Native providers
    let native = native_provider_names();
    println!("Native providers:");
    for name in &native {
        if let Some(filter) = &args.provider {
            if !name.contains(filter.as_str()) {
                continue;
            }
        }
        println!("  {} (built-in)", name);
    }

    // Terraform cached providers
    let registry = ProviderRegistry::new().map_err(|e| anyhow::anyhow!("{}", e))?;
    let cached = registry.list_cached().map_err(|e| anyhow::anyhow!("{}", e))?;

    if cached.is_empty() {
        println!("\nNo cached Terraform providers.");
        println!("Use `kxn gather --provider hashicorp/aws ...` to download a provider.");
    } else {
        println!("\nCached Terraform providers:");
        for (addr, version) in &cached {
            if let Some(filter) = &args.provider {
                if !addr.name.contains(filter) && !addr.namespace.contains(filter) {
                    continue;
                }
            }
            println!("  {}/{} v{}", addr.namespace, addr.name, version);
        }
    }

    Ok(())
}
