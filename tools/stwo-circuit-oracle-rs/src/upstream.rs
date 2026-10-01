//! Read-only access to data files of a `proving` checkout.
//!
//! Subcommands that consume upstream data (compiled AIR JSON, sample evaluations) read it through
//! [`ProvingRoot`], which records the size and SHA-256 of every file. The aggregate of those
//! records is compared against a digest pinned in the subcommand, so a checkout at any other
//! revision, or with edited data, is rejected instead of silently producing different vectors.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};

use crate::checkpoint::{InputRecord, sha256_hex};

const INPUTS_DOMAIN: &[u8] = b"STWO_CIRCUIT_ORACLE_INPUTS_V1\0";

/// Aggregate digest of `outputs/compiled_{casm,circuit}_air/**` (compiled JSON and sample
/// evaluations) at `proving@5a7c5ed`.
pub const PINNED_COMPILED_AIR_SHA256: &str =
    "26f92c880e6e3f7ac3bdaab0f781d936770af9d51299e8b59036d53438ed6516";

pub struct ProvingRoot {
    root: PathBuf,
    records: Vec<InputRecord>,
}

impl ProvingRoot {
    pub fn open(root: &Path) -> Result<Self> {
        let manifest = root.join("Cargo.toml");
        ensure!(
            manifest.is_file(),
            "{} is not a proving checkout",
            root.display()
        );
        Ok(Self {
            root: root.to_path_buf(),
            records: Vec::new(),
        })
    }

    /// Reads `relative` (a `/`-separated path under the root) and records its digest.
    pub fn read(&mut self, relative: &str) -> Result<Vec<u8>> {
        let path = self.root.join(relative);
        let bytes =
            std::fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
        self.records.push(InputRecord {
            path: relative.to_owned(),
            bytes: bytes.len() as u64,
            sha256: sha256_hex(&bytes),
        });
        Ok(bytes)
    }

    /// The `.json` files below `relative`, as sorted `/`-separated paths relative to the root.
    pub fn json_files(&self, relative: &str) -> Result<Vec<String>> {
        let mut files = Vec::new();
        let mut pending = vec![self.root.join(relative)];
        while let Some(directory) = pending.pop() {
            let entries = std::fs::read_dir(&directory)
                .with_context(|| format!("failed to list {}", directory.display()))?;
            for entry in entries {
                let path = entry?.path();
                if path.is_dir() {
                    pending.push(path);
                } else if path.extension().is_some_and(|ext| ext == "json") {
                    let relative = path.strip_prefix(&self.root)?;
                    let components: Vec<String> = relative
                        .components()
                        .map(|c| c.as_os_str().to_string_lossy().into_owned())
                        .collect();
                    files.push(components.join("/"));
                }
            }
        }
        files.sort();
        Ok(files)
    }

    /// Returns the sorted input records without an aggregate pin. For data files that
    /// `scripts/check_upstream_pins.py` authenticates against their checked-in copies (the
    /// circuit registries), whose recorded digests it compares.
    pub fn into_records(mut self) -> Vec<InputRecord> {
        self.records.sort_by(|a, b| a.path.cmp(&b.path));
        self.records
    }

    /// Returns the sorted input records after checking their aggregate against `pinned`:
    /// `SHA-256(INPUTS_DOMAIN || for each record: path || 0x00 || bytes (u64 LE) || sha256)`.
    pub fn finish(mut self, pinned: &str) -> Result<Vec<InputRecord>> {
        self.records.sort_by(|a, b| a.path.cmp(&b.path));
        let mut hasher = Sha256::new();
        hasher.update(INPUTS_DOMAIN);
        for record in &self.records {
            hasher.update(record.path.as_bytes());
            hasher.update([0u8]);
            hasher.update(record.bytes.to_le_bytes());
            hasher.update(hex::decode(&record.sha256)?);
        }
        let aggregate = hex::encode(hasher.finalize());
        ensure!(
            aggregate == pinned,
            "upstream inputs under {} have aggregate digest {aggregate}, expected {pinned}; \
             the checkout is not proving@{}",
            self.root.display(),
            crate::checkpoint::PROVING_REVISION,
        );
        Ok(self.records)
    }
}
