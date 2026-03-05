//! Terraform Provider Registry Client
//!
//! Downloads and caches Terraform providers from the HashiCorp registry.

use crate::error::ProviderError;
use flate2::read::GzDecoder;
use reqwest::Client;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use tracing::{debug, info};
use zip::ZipArchive;

const REGISTRY_URL: &str = "https://registry.terraform.io";

/// Provider address in the format: namespace/name (e.g., hashicorp/aws)
#[derive(Debug, Clone)]
pub struct ProviderAddress {
    pub hostname: String,
    pub namespace: String,
    pub name: String,
}

impl ProviderAddress {
    pub fn new(namespace: &str, name: &str) -> Self {
        Self {
            hostname: "registry.terraform.io".to_string(),
            namespace: namespace.to_string(),
            name: name.to_string(),
        }
    }

    /// Parse from string like "hashicorp/aws" or "registry.terraform.io/hashicorp/aws"
    pub fn parse(s: &str) -> Result<Self, ProviderError> {
        let parts: Vec<&str> = s.split('/').collect();
        match parts.len() {
            2 => Ok(Self::new(parts[0], parts[1])),
            3 => Ok(Self {
                hostname: parts[0].to_string(),
                namespace: parts[1].to_string(),
                name: parts[2].to_string(),
            }),
            _ => Err(ProviderError::InvalidConfig(format!(
                "Invalid provider address: {}",
                s
            ))),
        }
    }

    pub fn full_name(&self) -> String {
        format!("{}/{}/{}", self.hostname, self.namespace, self.name)
    }
}

/// Registry API response for provider versions
#[derive(Debug, Deserialize)]
struct VersionsResponse {
    versions: Vec<VersionInfo>,
}

#[derive(Debug, Deserialize)]
struct VersionInfo {
    version: String,
    protocols: Vec<String>,
    platforms: Vec<PlatformInfo>,
}

#[derive(Debug, Deserialize)]
struct PlatformInfo {
    os: String,
    arch: String,
}

/// Registry API response for download info
#[derive(Debug, Deserialize)]
struct DownloadResponse {
    protocols: Vec<String>,
    os: String,
    arch: String,
    filename: String,
    download_url: String,
    shasum: String,
    shasums_url: String,
    shasums_signature_url: String,
}

/// Manages downloading and caching of Terraform providers
pub struct ProviderRegistry {
    client: Client,
    cache_dir: PathBuf,
}

impl ProviderRegistry {
    pub fn new() -> Result<Self, ProviderError> {
        let cache_dir = Self::default_cache_dir()?;
        fs::create_dir_all(&cache_dir)
            .map_err(|e| ProviderError::Api(format!("Failed to create cache dir: {}", e)))?;

        Ok(Self {
            client: Client::new(),
            cache_dir,
        })
    }

    pub fn with_cache_dir(cache_dir: PathBuf) -> Result<Self, ProviderError> {
        fs::create_dir_all(&cache_dir)
            .map_err(|e| ProviderError::Api(format!("Failed to create cache dir: {}", e)))?;

        Ok(Self {
            client: Client::new(),
            cache_dir,
        })
    }

    fn default_cache_dir() -> Result<PathBuf, ProviderError> {
        let home = dirs::home_dir()
            .ok_or_else(|| ProviderError::InvalidConfig("Cannot find home directory".to_string()))?;
        Ok(home.join(".kxn").join("providers"))
    }

    /// Get the path to a provider binary, downloading if necessary
    pub async fn get_provider(
        &self,
        address: &ProviderAddress,
        version: Option<&str>,
    ) -> Result<PathBuf, ProviderError> {
        // Map Rust OS constants to Terraform registry names
        let os = match std::env::consts::OS {
            "macos" => "darwin",
            other => other,
        };
        let arch = match std::env::consts::ARCH {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            other => other,
        };

        // Determine version to use
        let version = match version {
            Some(v) => v.to_string(),
            None => self.get_latest_version(address).await?,
        };

        // Check if already cached
        let provider_dir = self.cache_dir
            .join(&address.hostname)
            .join(&address.namespace)
            .join(&address.name)
            .join(&version)
            .join(format!("{}_{}", os, arch));

        let binary_name = if os == "windows" {
            format!("terraform-provider-{}_{}.exe", address.name, version)
        } else {
            format!("terraform-provider-{}_{}", address.name, version)
        };
        let binary_path = provider_dir.join(&binary_name);

        if binary_path.exists() {
            debug!("Provider {} v{} found in cache", address.full_name(), version);
            return Ok(binary_path);
        }

        // Download the provider
        info!(
            "Downloading provider {} v{} for {}_{}",
            address.full_name(),
            version,
            os,
            arch
        );

        let download_info = self
            .get_download_info(address, &version, os, arch)
            .await?;

        // Create directory
        fs::create_dir_all(&provider_dir)
            .map_err(|e| ProviderError::Api(format!("Failed to create provider dir: {}", e)))?;

        // Download and extract
        self.download_and_extract(&download_info, &provider_dir)
            .await?;

        // Find the binary (name might vary slightly)
        let binary_path = self.find_provider_binary(&provider_dir, &address.name)?;

        // Make executable on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&binary_path)
                .map_err(|e| ProviderError::Api(format!("Failed to get permissions: {}", e)))?
                .permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&binary_path, perms)
                .map_err(|e| ProviderError::Api(format!("Failed to set permissions: {}", e)))?;
        }

        info!("Provider {} v{} ready at {:?}", address.full_name(), version, binary_path);
        Ok(binary_path)
    }

    async fn get_latest_version(&self, address: &ProviderAddress) -> Result<String, ProviderError> {
        let url = format!(
            "{}/v1/providers/{}/{}/versions",
            REGISTRY_URL, address.namespace, address.name
        );

        debug!("Fetching versions from: {}", url);

        let response: VersionsResponse = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| ProviderError::Api(format!("Failed to fetch versions: {}", e)))?
            .json()
            .await
            .map_err(|e| ProviderError::Api(format!("Failed to parse versions: {}", e)))?;

        // Filter for protocol 5.x or 6.x (both use tfplugin6 gRPC) and get latest
        let latest = response
            .versions
            .into_iter()
            .filter(|v| v.protocols.iter().any(|p| p.starts_with("5.") || p.starts_with("6.")))
            .max_by(|a, b| {
                version_compare::compare(&a.version, &b.version)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .ok_or_else(|| {
                ProviderError::NotFound(format!(
                    "No compatible version found for {}",
                    address.full_name()
                ))
            })?;

        Ok(latest.version)
    }

    async fn get_download_info(
        &self,
        address: &ProviderAddress,
        version: &str,
        os: &str,
        arch: &str,
    ) -> Result<DownloadResponse, ProviderError> {
        let url = format!(
            "{}/v1/providers/{}/{}/{}/download/{}/{}",
            REGISTRY_URL, address.namespace, address.name, version, os, arch
        );

        debug!("Fetching download info from: {}", url);

        self.client
            .get(&url)
            .send()
            .await
            .map_err(|e| ProviderError::Api(format!("Failed to fetch download info: {}", e)))?
            .json()
            .await
            .map_err(|e| ProviderError::Api(format!("Failed to parse download info: {}", e)))
    }

    async fn download_and_extract(
        &self,
        info: &DownloadResponse,
        dest_dir: &Path,
    ) -> Result<(), ProviderError> {
        debug!("Downloading from: {}", info.download_url);

        let response = self
            .client
            .get(&info.download_url)
            .send()
            .await
            .map_err(|e| ProviderError::Api(format!("Download failed: {}", e)))?;

        let bytes = response
            .bytes()
            .await
            .map_err(|e| ProviderError::Api(format!("Failed to read download: {}", e)))?;

        // Verify checksum
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let hash = hex::encode(hasher.finalize());
        if hash != info.shasum {
            return Err(ProviderError::Api(format!(
                "Checksum mismatch: expected {}, got {}",
                info.shasum, hash
            )));
        }
        debug!("Checksum verified");

        // Extract based on file type
        if info.filename.ends_with(".zip") {
            self.extract_zip(&bytes, dest_dir)?;
        } else if info.filename.ends_with(".tar.gz") || info.filename.ends_with(".tgz") {
            self.extract_tar_gz(&bytes, dest_dir)?;
        } else {
            return Err(ProviderError::Api(format!(
                "Unknown archive format: {}",
                info.filename
            )));
        }

        Ok(())
    }

    fn extract_zip(&self, data: &[u8], dest_dir: &Path) -> Result<(), ProviderError> {
        let cursor = io::Cursor::new(data);
        let mut archive = ZipArchive::new(cursor)
            .map_err(|e| ProviderError::Api(format!("Failed to open zip: {}", e)))?;

        for i in 0..archive.len() {
            let mut file = archive
                .by_index(i)
                .map_err(|e| ProviderError::Api(format!("Failed to read zip entry: {}", e)))?;

            let outpath = dest_dir.join(file.name());

            if file.name().ends_with('/') {
                fs::create_dir_all(&outpath).ok();
            } else {
                if let Some(parent) = outpath.parent() {
                    fs::create_dir_all(parent).ok();
                }
                let mut outfile = File::create(&outpath)
                    .map_err(|e| ProviderError::Api(format!("Failed to create file: {}", e)))?;
                io::copy(&mut file, &mut outfile)
                    .map_err(|e| ProviderError::Api(format!("Failed to extract file: {}", e)))?;
            }
        }

        Ok(())
    }

    fn extract_tar_gz(&self, data: &[u8], dest_dir: &Path) -> Result<(), ProviderError> {
        let cursor = io::Cursor::new(data);
        let gz = GzDecoder::new(cursor);
        let mut archive = tar::Archive::new(gz);

        archive
            .unpack(dest_dir)
            .map_err(|e| ProviderError::Api(format!("Failed to extract tar.gz: {}", e)))?;

        Ok(())
    }

    fn find_provider_binary(&self, dir: &Path, name: &str) -> Result<PathBuf, ProviderError> {
        for entry in fs::read_dir(dir)
            .map_err(|e| ProviderError::Api(format!("Failed to read dir: {}", e)))?
        {
            let entry =
                entry.map_err(|e| ProviderError::Api(format!("Failed to read entry: {}", e)))?;
            let file_name = entry.file_name();
            let file_name_str = file_name.to_string_lossy();

            if file_name_str.starts_with("terraform-provider-")
                && file_name_str.contains(name)
                && !file_name_str.ends_with(".sig")
            {
                return Ok(entry.path());
            }
        }

        Err(ProviderError::NotFound(format!(
            "Provider binary not found in {:?}",
            dir
        )))
    }

    /// List cached providers
    pub fn list_cached(&self) -> Result<Vec<(ProviderAddress, String)>, ProviderError> {
        let mut providers = Vec::new();

        if !self.cache_dir.exists() {
            return Ok(providers);
        }

        // Walk the cache directory structure
        for hostname_entry in fs::read_dir(&self.cache_dir).into_iter().flatten().flatten() {
            let hostname = hostname_entry.file_name().to_string_lossy().to_string();

            for namespace_entry in fs::read_dir(hostname_entry.path()).into_iter().flatten().flatten() {
                let namespace = namespace_entry.file_name().to_string_lossy().to_string();

                for name_entry in fs::read_dir(namespace_entry.path()).into_iter().flatten().flatten() {
                    let name = name_entry.file_name().to_string_lossy().to_string();

                    for version_entry in fs::read_dir(name_entry.path()).into_iter().flatten().flatten() {
                        let version = version_entry.file_name().to_string_lossy().to_string();

                        providers.push((
                            ProviderAddress {
                                hostname: hostname.clone(),
                                namespace: namespace.clone(),
                                name: name.clone(),
                            },
                            version,
                        ));
                    }
                }
            }
        }

        Ok(providers)
    }
}

// Simple version comparison (semver-like)
mod version_compare {
    use std::cmp::Ordering;

    pub fn compare(a: &str, b: &str) -> Option<Ordering> {
        let parse = |s: &str| -> Vec<u64> {
            s.trim_start_matches('v')
                .split(|c: char| !c.is_ascii_digit())
                .filter_map(|p| p.parse().ok())
                .collect()
        };

        let va = parse(a);
        let vb = parse(b);

        Some(va.cmp(&vb))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;

    #[test]
    fn test_provider_address_parse() {
        let addr = ProviderAddress::parse("hashicorp/aws").unwrap();
        assert_eq!(addr.namespace, "hashicorp");
        assert_eq!(addr.name, "aws");
        assert_eq!(addr.hostname, "registry.terraform.io");

        let addr = ProviderAddress::parse("registry.terraform.io/hashicorp/azurerm").unwrap();
        assert_eq!(addr.namespace, "hashicorp");
        assert_eq!(addr.name, "azurerm");
    }

    #[test]
    fn test_version_compare() {
        assert_eq!(
            version_compare::compare("1.0.0", "2.0.0"),
            Some(Ordering::Less)
        );
        assert_eq!(
            version_compare::compare("1.10.0", "1.9.0"),
            Some(Ordering::Greater)
        );
    }
}
