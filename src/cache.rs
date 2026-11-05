//! On-disk cache for the discovered API catalog.
//!
//! `listApis` is filtered by the caller's role, so the cache is keyed by endpoint *and*
//! identity (API key or user@domain): two accounts on the same server never share a catalog.
//! The key is a SHA-256 hash, so no credentials end up in file names or contents.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::discovery::ApiCatalog;

const FORMAT_VERSION: u32 = 1;

/// Where and for how long discovered catalogs are kept.
#[derive(Debug, Clone)]
pub struct DiscoveryCache {
    dir: PathBuf,
    ttl: Option<Duration>,
}

#[derive(Serialize, Deserialize)]
struct CacheFile {
    format: u32,
    endpoint: String,
    catalog: ApiCatalog,
}

impl DiscoveryCache {
    /// Caches in `dir`, with a TTL of 24 hours.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            ttl: Some(Duration::from_secs(24 * 3600)),
        }
    }

    /// Caches in the platform cache directory (`~/.cache/cloudstack-rs` on Linux,
    /// `~/Library/Caches/cloudstack-rs` on macOS).
    pub fn default_location() -> Option<Self> {
        dirs::cache_dir().map(|d| Self::new(d.join("cloudstack-rs")))
    }

    /// How long a cached catalog stays valid; `None` keeps it until [`crate::Client::refresh_catalog`].
    pub fn ttl(mut self, ttl: Option<Duration>) -> Self {
        self.ttl = ttl;
        self
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The cache file for an endpoint and identity.
    pub fn path_for(&self, endpoint: &str, identity: &str) -> PathBuf {
        let mut h = Sha256::new();
        h.update(endpoint.as_bytes());
        h.update([0]);
        h.update(identity.as_bytes());
        let hex: String = h.finalize().iter().take(16).map(|b| format!("{b:02x}")).collect();
        self.dir.join(format!("{hex}.json"))
    }

    pub(crate) fn load(&self, endpoint: &str, identity: &str) -> Option<ApiCatalog> {
        let path = self.path_for(endpoint, identity);
        let data = std::fs::read(&path).ok()?;
        let file: CacheFile = match serde_json::from_slice(&data) {
            Ok(f) => f,
            Err(e) => {
                tracing::debug!(path = %path.display(), error = %e, "ignoring unreadable API cache");
                return None;
            }
        };
        if file.format != FORMAT_VERSION || file.endpoint != endpoint {
            return None;
        }
        if let Some(ttl) = self.ttl {
            let age = chrono::Utc::now().signed_duration_since(file.catalog.fetched_at());
            if age.to_std().is_ok_and(|age| age > ttl) {
                tracing::debug!(path = %path.display(), "API cache expired");
                return None;
            }
        }
        Some(file.catalog)
    }

    pub(crate) fn store(&self, endpoint: &str, identity: &str, catalog: &ApiCatalog) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        let path = self.path_for(endpoint, identity);
        let file = CacheFile {
            format: FORMAT_VERSION,
            endpoint: endpoint.to_owned(),
            catalog: catalog.clone(),
        };
        // Write then rename, so concurrent readers never see a half-written file.
        let tmp = path.with_extension(format!("tmp{}", std::process::id()));
        std::fs::write(&tmp, serde_json::to_vec(&file)?)?;
        std::fs::rename(&tmp, &path)
    }
}
