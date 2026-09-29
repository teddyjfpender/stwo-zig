//! Byte-level formats outside the field arithmetic: the ZK-blinding RNG, the felt252 word
//! encoding of leaf output preimages, and the `leaf_proof_format` JSON wire types.

use anyhow::{Context, Result};
use leaf_proof_format::{DigestHex, SerializedLeafProof};
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use serde::Serialize;
use starknet_types_core::felt::Felt;
use starknet_types_core::hash::Blake2Felt252;
use stwo::core::vcs_lifted::Hasher;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleHasher;

use crate::checkpoint::hex32;

/// Enough draws to cross two 64-word block-buffer refills of `rand_chacha` 0.3.
const CHACHA_DRAWS: usize = 136;

#[derive(Serialize)]
pub struct ChaChaVector {
    pub name: &'static str,
    pub seed: String,
    /// `ChaCha20Rng::from_seed(seed)` followed by `next_u32()` calls, as `add_zk_blinding` draws.
    pub next_u32: Vec<u32>,
}

#[derive(Serialize)]
pub struct Felt252Vector {
    /// Decimal felts, as in a leaf's `output_preimage`.
    pub preimage: Vec<String>,
    /// `Blake2Felt252::encode_felts_to_u32s`.
    pub words: Vec<u32>,
    /// Blake2s over the little-endian bytes of `words`: the leaf output digest.
    pub output_digest: String,
}

#[derive(Serialize)]
pub struct LeafProofVector {
    pub proof_bytes_hex: String,
    /// `serde_json::to_string_pretty(&SerializedLeafProof)`, exactly as `leaf_prover` writes it.
    pub pretty_json: String,
}

#[derive(Serialize)]
pub struct DigestHexVector {
    pub bytes: String,
    /// `serde_json::to_string(&DigestHex::from(bytes))`.
    pub json: String,
}

#[derive(Serialize)]
pub struct FormatsSection {
    pub chacha20_rng: Vec<ChaChaVector>,
    pub felt252_encoding: Vec<Felt252Vector>,
    pub digest_hex: Vec<DigestHexVector>,
    pub serialized_leaf_proof: Vec<LeafProofVector>,
}

fn chacha(name: &'static str, seed: [u8; 32]) -> ChaChaVector {
    let mut rng = ChaCha20Rng::from_seed(seed);
    ChaChaVector {
        name,
        seed: hex32(seed),
        next_u32: (0..CHACHA_DRAWS).map(|_| rng.next_u32()).collect(),
    }
}

fn felt252_vector(preimage: &[&str]) -> Result<Felt252Vector> {
    let felts = preimage
        .iter()
        .map(|felt| Felt::from_dec_str(felt).with_context(|| format!("invalid felt {felt}")))
        .collect::<Result<Vec<_>>>()?;
    let words = Blake2Felt252::encode_felts_to_u32s(&felts);
    Ok(Felt252Vector {
        preimage: preimage.iter().map(|felt| felt.to_string()).collect(),
        output_digest: hex32(Blake2sMerkleHasher::hash_u32s(&words).0),
        words,
    })
}

pub fn formats_section() -> Result<FormatsSection> {
    // A realistic trace-root seed: the little-endian bytes of a Blake2s digest.
    let trace_root = Blake2sMerkleHasher::hash_u32s(&[0, 1, 2, 3, 0x1234_5678, u32::MAX, 7, 8, 9]);
    let chacha20_rng = vec![
        chacha("zero_seed", [0; 32]),
        chacha("ascending_seed", std::array::from_fn(|i| i as u8)),
        chacha("blake2s_digest_seed", trace_root.0),
    ];

    const STARK_PRIME_MINUS_ONE: &str =
        "3618502788666131213697322783095070105623107215331596699973092056135872020480";
    let felt252_encoding = [
        &[][..],
        &["0"],
        &["1"],
        &["9223372036854775807"],
        &["9223372036854775808"],
        &[STARK_PRIME_MINUS_ONE],
        &[
            "42",
            "9223372036854775808",
            "0",
            STARK_PRIME_MINUS_ONE,
            "18446744073709551616",
        ],
    ]
    .into_iter()
    .map(felt252_vector)
    .collect::<Result<_>>()?;

    let digest_hex = [trace_root.0, std::array::from_fn(|i| i as u8), [0xff; 32]]
        .into_iter()
        .map(|bytes| {
            Ok(DigestHexVector {
                bytes: hex32(bytes),
                json: serde_json::to_string(&DigestHex::from(bytes))?,
            })
        })
        .collect::<Result<_>>()?;

    let serialized_leaf_proof = (0..=5u8)
        .map(|len| {
            let proof: Vec<u8> = (0..len).map(|i| 0xf0 ^ i.wrapping_mul(37)).collect();
            let value = SerializedLeafProof {
                circuit_preprocessed_root: DigestHex::from(trace_root.0),
                circuit_hash: DigestHex::from(std::array::from_fn::<u8, 32, _>(|i| i as u8)),
                proof: proof.clone(),
            };
            Ok(LeafProofVector {
                proof_bytes_hex: hex::encode(&proof),
                pretty_json: serde_json::to_string_pretty(&value)?,
            })
        })
        .collect::<Result<_>>()?;

    Ok(FormatsSection {
        chacha20_rng,
        felt252_encoding,
        digest_hex,
        serialized_leaf_proof,
    })
}
