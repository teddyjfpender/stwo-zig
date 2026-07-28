//! Maintainer utility for converting an official Rust-JSON proof into the
//! compressed binary format used by the committed oracle smoke vector.

use std::path::PathBuf;

use cairo_air::CairoProofForRustVerifier;
use cairo_air::utils::{ProofFormat, binary_serialize_to_file, deserialize_proof_from_file};
use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleHasher;

fn main() -> anyhow::Result<()> {
    let mut arguments = std::env::args_os().skip(1).map(PathBuf::from);
    let input = arguments
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing Rust-JSON input path"))?;
    let output = arguments
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing binary output path"))?;
    anyhow::ensure!(arguments.next().is_none(), "too many arguments");

    let proof: CairoProofForRustVerifier<Blake2sMerkleHasher> =
        deserialize_proof_from_file(&input, ProofFormat::Json)?;
    let file = std::fs::File::options()
        .write(true)
        .create_new(true)
        .open(&output)?;
    binary_serialize_to_file(&proof, &file)?;
    file.sync_all()?;
    Ok(())
}
