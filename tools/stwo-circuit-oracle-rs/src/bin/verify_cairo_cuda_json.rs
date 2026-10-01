//! Independently verify a Cairo CUDA proof with the pinned Rust verifier.
//!
//! The Zig JSON writer retains its legacy PCS config field names. Normalize
//! only that config shape before deserializing the proof into Rust's official
//! CairoProofForRustVerifier type; every proof field remains untouched.

use anyhow::{Context, Result, ensure};
use cairo_air::air::CairoProofForRustVerifier;
use cairo_air::verifier::verify_cairo_ex;
use serde_json::Value;
use sha2::{Digest, Sha256};
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sMerkleHasher};

fn normalize_config(document: &mut Value) -> Result<()> {
    let config = document
        .get_mut("stark_proof")
        .and_then(|proof| proof.get_mut("config"))
        .and_then(Value::as_object_mut)
        .context("missing Stark proof PCS config")?;
    if config.contains_key("trace_lifting_log_size") {
        return Ok(());
    }
    let pow_bits = config.remove("pow_bits").context("missing PoW bits")?;
    let lifting = config
        .remove("min_lifting_log_size")
        .context("missing lifting height")?;
    config
        .get_mut("fri_config")
        .and_then(Value::as_object_mut)
        .context("missing FRI config")?
        .insert("pow_bits".to_owned(), pow_bits);
    config.insert("trace_lifting_log_size".to_owned(), lifting.clone());
    config.insert("preprocessed_lifting_log_size".to_owned(), lifting);
    Ok(())
}

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .context("usage: verify_cairo_cuda_json PROOF.json [EXPECTED_BINARY_SHA256]")?;
    let expected = args.next();
    ensure!(args.next().is_none(), "unexpected extra argument");
    let mut document: Value =
        serde_json::from_slice(&std::fs::read(&path)?).context("invalid proof JSON")?;
    normalize_config(&mut document)?;
    let proof: CairoProofForRustVerifier<Blake2sMerkleHasher> =
        serde_json::from_value(document).context("invalid Cairo proof shape")?;
    let binary = bincode::serialize(&proof)?;
    let digest = format!("{:x}", Sha256::digest(&binary));
    if let Some(expected) = expected {
        ensure!(
            digest == expected,
            "canonical proof differs from pinned Rust binary"
        );
    }
    verify_cairo_ex::<Blake2sM31MerkleChannel>(proof, true)
        .context("pinned Rust Cairo verifier rejected proof")?;
    println!(
        "RUST_CAIRO_VERIFIER=accepted binary_bytes={} binary_sha256={digest}",
        binary.len()
    );
    Ok(())
}
