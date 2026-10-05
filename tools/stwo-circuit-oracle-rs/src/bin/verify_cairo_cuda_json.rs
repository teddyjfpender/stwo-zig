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
use stwo::core::fields::m31::M31;
use stwo::core::vcs_lifted::MerkleHasherLifted;
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
    let next = args.next();
    let is_receipt = next.as_deref() == Some("--receipt");
    let expected = if is_receipt { None } else { next };
    let receipt_flag = if is_receipt {
        Some("--receipt".to_owned())
    } else {
        args.next()
    };
    let receipt = match receipt_flag {
        None => None,
        Some(flag) if flag == "--receipt" => {
            Some(args.next().context("--receipt requires a path")?)
        }
        Some(_) => anyhow::bail!("unexpected extra argument"),
    };
    ensure!(args.next().is_none(), "unexpected extra argument");
    let proof_bytes = std::fs::read(&path)?;
    let mut document: Value = serde_json::from_slice(&proof_bytes).context("invalid proof JSON")?;
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
    let (_, _, program_claim) = proof.claim.public_data.pack_into_u32s();
    let mut hasher = Blake2sMerkleHasher::default();
    let program_words = program_claim
        .iter()
        .map(|word| M31::from_u32_unchecked(*word))
        .collect::<Vec<_>>();
    hasher.update_leaf(&program_words);
    let program_root = hex::encode(MerkleHasherLifted::finalize(hasher).0);
    let public_output =
        cairo_air::utils::get_verification_output(&proof.claim.public_data.public_memory)
            .output
            .iter()
            .map(|felt| {
                let encoded = hex::encode(felt.to_bytes_be());
                let trimmed = encoded.trim_start_matches('0');
                if trimmed.is_empty() {
                    "0x0".to_owned()
                } else {
                    format!("0x{trimmed}")
                }
            })
            .collect::<Vec<_>>();
    let config = &proof.stark_proof.config;
    let queries = config.fri_config.n_queries;
    let pow_bits = config.fri_config.pow_bits;
    verify_cairo_ex::<Blake2sM31MerkleChannel>(proof, true)
        .context("pinned Rust Cairo verifier rejected proof")?;
    if let Some(path) = receipt {
        let value = serde_json::json!({
            "schema": "stwo-circuit-oracle-pinned-cairo-verdict-v1",
            "verified": true,
            "proof_sha256": hex::encode(Sha256::digest(&proof_bytes)),
            "binary_sha256": digest,
            "program_root_blake2s": program_root,
            "public_output": public_output,
            "queries": queries,
            "pow_bits": pow_bits,
        });
        std::fs::write(path, serde_json::to_vec_pretty(&value)?)?;
    }
    println!(
        "RUST_CAIRO_VERIFIER=accepted binary_bytes={} binary_sha256={digest}",
        binary.len()
    );
    Ok(())
}
