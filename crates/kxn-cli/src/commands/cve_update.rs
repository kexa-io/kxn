use anyhow::Result;
use clap::Args;
use kxn_providers::cve_db::CveDb;

#[derive(Args)]
pub struct CveUpdateArgs {
    /// Sync only KEV (skip NVD and EPSS)
    #[arg(long)]
    pub kev_only: bool,

    /// Sync only EPSS (skip NVD and KEV)
    #[arg(long)]
    pub epss_only: bool,

    /// NVD API key (increases rate limit from 5 to 50 req/30s)
    #[arg(long)]
    pub nvd_api_key: Option<String>,

    /// Show database stats after sync
    #[arg(short, long)]
    pub verbose: bool,
}

pub async fn run(args: CveUpdateArgs) -> Result<()> {
    let db =
        CveDb::open_or_create().map_err(|e| anyhow::anyhow!("{}", e))?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()?;

    if args.kev_only {
        let count = db
            .sync_kev(&client)
            .await
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        println!("KEV: {} entries synced", count);
    } else if args.epss_only {
        let count = db
            .sync_epss(&client)
            .await
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        println!("EPSS: {} entries synced", count);
    } else {
        // Full sync: KEV + EPSS + NVD
        let kev = db
            .sync_kev(&client)
            .await
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        println!("KEV: {} entries synced", kev);

        let epss = db
            .sync_epss(&client)
            .await
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        println!("EPSS: {} entries synced", epss);

        let nvd = db
            .sync_nvd(&client, args.nvd_api_key.as_deref())
            .await
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        println!("NVD: {} CVEs synced", nvd);
    }

    if args.verbose {
        let stats = db.stats().map_err(|e| anyhow::anyhow!("{}", e))?;
        println!(
            "\n{}",
            serde_json::to_string_pretty(&stats)?
        );
    }

    Ok(())
}
