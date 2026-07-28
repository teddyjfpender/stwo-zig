//! Exact official bincode and bzip2 transport oracle.

use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result};
use bzip2::read::BzDecoder;
use cairo_air::CairoProofForRustVerifier;
use cairo_air::utils::deserialize_proof_from_file;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleHasher;

use crate::ProofFormat;

pub fn serialize_blake2s_proof(path: &Path, format: ProofFormat) -> Result<Vec<u8>> {
    let proof: CairoProofForRustVerifier<Blake2sMerkleHasher> =
        deserialize_proof_from_file(path, format.upstream())
            .context("failed to deserialize Blake2s Cairo proof")?;
    bincode::serialize(&proof).context("failed to bincode-serialize Blake2s Cairo proof")
}

pub fn decompress(path: &Path) -> Result<Vec<u8>> {
    let file =
        std::fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut decoder = BzDecoder::new(file);
    let mut bytes = Vec::new();
    decoder
        .read_to_end(&mut bytes)
        .context("failed to decompress Cairo binary proof")?;
    Ok(bytes)
}
