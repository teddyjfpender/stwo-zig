//! Byte-level formats outside the field arithmetic: the ZK-blinding RNG, the felt252 word
//! encoding of leaf output preimages, the `leaf_proof_format` JSON wire types, and the base64
//! encoding those wire types use for proof bytes.

use anyhow::{Context, Result, ensure};
use leaf_proof_format::{DigestHex, SerializedLeafProof};
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use serde::Serialize;
use serde_with::base64::Base64;
use serde_with::serde_as;
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
pub struct Base64Vector {
    pub bytes_hex: String,
    /// `serde_with::base64::Base64` (the default `Standard` alphabet, `Padded`), exactly as
    /// `SerializedLeafProof::proof` is encoded.
    pub base64: String,
}

/// The `proof` field encoding of `leaf_proof_format::SerializedLeafProof`.
#[serde_as]
#[derive(Serialize)]
struct Base64Field(#[serde_as(as = "Base64")] Vec<u8>);

/// RFC 4648 section 4 (standard alphabet, `=` padding), written out so that a `serde_with` bump
/// that changes the default alphabet or padding fails here instead of silently changing vectors.
fn rfc4648_standard_padded(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let word = chunk.iter().enumerate().fold(0u32, |acc, (i, byte)| {
            acc | (u32::from(*byte) << (16 - 8 * i))
        });
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[((word >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn base64_vector(bytes: Vec<u8>) -> Result<Base64Vector> {
    let json = serde_json::to_string(&Base64Field(bytes.clone()))?;
    let base64: String = serde_json::from_str(&json)?;
    ensure!(
        base64 == rfc4648_standard_padded(&bytes),
        "serde_with Base64 is no longer the standard padded alphabet"
    );
    Ok(Base64Vector {
        bytes_hex: hex::encode(&bytes),
        base64,
    })
}

/// Lengths 0-5, 32 and 64 cover every padding case; `0xfb 0xff` and `0x3e 0x3f` force the `+` and
/// `/` characters that distinguish the standard alphabet from the URL-safe one.
fn base64_section() -> Result<Vec<Base64Vector>> {
    let mut inputs: Vec<Vec<u8>> = [0usize, 1, 2, 3, 4, 5, 32, 64]
        .into_iter()
        .map(|len| {
            (0..len)
                .map(|i| (i as u8).wrapping_mul(73) ^ 0xa5)
                .collect()
        })
        .collect();
    inputs.push(vec![0xfb, 0xff]);
    inputs.push(vec![0xf8, 0x3e, 0x3f]);
    let vectors = inputs
        .into_iter()
        .map(base64_vector)
        .collect::<Result<Vec<_>>>()?;
    let all = vectors
        .iter()
        .map(|v| v.base64.as_str())
        .collect::<String>();
    ensure!(
        all.contains('+') && all.contains('/') && all.contains('='),
        "base64 vectors must exercise '+', '/' and '=' padding"
    );
    Ok(vectors)
}

#[derive(Serialize)]
pub struct Base64DecodeVector {
    pub base64: String,
    /// The bytes `serde_with::base64::Base64` decodes (`DecodePaddingMode::Indifferent`), or
    /// `None` when it rejects the text.
    pub bytes_hex: Option<String>,
}

/// The `proof` field decoding of `leaf_proof_format::SerializedLeafProof`.
#[serde_as]
#[derive(serde::Deserialize)]
struct Base64DecodeField(#[serde_as(as = "Base64")] Vec<u8>);

/// Padding variants (none, partial, full, excess, misplaced), trailing bits and bad lengths.
fn base64_decode_section() -> Result<Vec<Base64DecodeVector>> {
    let texts = [
        "", "8A", "8A=", "8A==", "8A===", "8NU", "8NU=", "8NU==", "8NV=", "8N==", "8===", "=",
        "8A=A", "AAAA", "AAAA=", "AAAAA", "AAAAAA", "AAAAAA=", "AAAAAAA", "+/+/", "-_-_", "8N U",
    ];
    let vectors: Vec<_> = texts
        .into_iter()
        .map(|text| {
            let json = serde_json::to_string(text)?;
            let decoded: Option<Base64DecodeField> = serde_json::from_str(&json).ok();
            Ok(Base64DecodeVector {
                base64: text.to_string(),
                bytes_hex: decoded.map(|field| hex::encode(field.0)),
            })
        })
        .collect::<Result<_>>()?;
    ensure!(
        vectors.iter().any(|v| v.bytes_hex.is_none())
            && vectors.iter().filter(|v| v.bytes_hex.is_some()).count() >= 8,
        "base64 decode vectors must cover accepted and rejected texts"
    );
    Ok(vectors)
}

#[derive(Serialize)]
pub struct FeltFromDecStrVector {
    pub text: String,
    /// `Felt::from_dec_str(text)` in decimal, or `None` when it is rejected. Upstream's release
    /// profile compiles out lambdaworks' `debug_assert` on the digit add, so values past 2^256
    /// can wrap.
    pub felt: Option<String>,
}

fn felt_from_dec_str_section() -> Vec<FeltFromDecStrVector> {
    const TWO_POW_256: &str =
        "115792089237316195423570985008687907853269984665640564039457584007913129639936";
    const TWO_POW_256_PLUS_3: &str =
        "115792089237316195423570985008687907853269984665640564039457584007913129639939";
    const TWO_POW_256_PLUS_4: &str =
        "115792089237316195423570985008687907853269984665640564039457584007913129639940";
    const STARK_PRIME: &str =
        "3618502788666131213697322783095070105623107215331596699973092056135872020481";
    let minus_plus_3 = format!("-{TWO_POW_256_PLUS_3}");
    let texts = [
        "0", "-0", "-5", "007", "", "-", "+1", "0x1", "--5", " 1", "1 ", STARK_PRIME,
        TWO_POW_256, TWO_POW_256_PLUS_3, TWO_POW_256_PLUS_4, minus_plus_3.as_str(),
        "1157920892373161954235709850086879078532699846656405640394575840079131296399360",
    ];
    texts
        .into_iter()
        .map(|text| FeltFromDecStrVector {
            text: text.to_string(),
            felt: Felt::from_dec_str(text).ok().map(|felt| felt.to_string()),
        })
        .collect()
}

#[derive(Serialize)]
pub struct FormatsSection {
    pub chacha20_rng: Vec<ChaChaVector>,
    pub felt252_encoding: Vec<Felt252Vector>,
    pub felt_from_dec_str: Vec<FeltFromDecStrVector>,
    pub digest_hex: Vec<DigestHexVector>,
    pub serialized_leaf_proof: Vec<LeafProofVector>,
    pub base64: Vec<Base64Vector>,
    pub base64_decode: Vec<Base64DecodeVector>,
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
        // Past 2^256: the release-build digit add wraps (see `felt_from_dec_str`).
        &[
            "115792089237316195423570985008687907853269984665640564039457584007913129639939",
            "-3",
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
        felt_from_dec_str: felt_from_dec_str_section(),
        digest_hex,
        serialized_leaf_proof,
        base64: base64_section()?,
        base64_decode: base64_decode_section()?,
    })
}
