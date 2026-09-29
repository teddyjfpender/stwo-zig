//! Blake2s `Hasher` vectors (`hash_u32s`, `hash_u32s_followed_by_digest`, `concat_and_hash`,
//! `reduce_to_m31`) and the circuit hash, both host-side and in-circuit.
//!
//! Every upstream golden that exists for these functions is re-derived here and asserted; a
//! mismatch aborts the oracle, so a committed checkpoint always agrees with the pinned tests.

use anyhow::{Result, ensure};
use circuit_verifier::circuit_components::PerComponent;
use circuit_verifier::circuit_hash::{compute_circuit_hash, config_words};
use circuits::blake::{BLAKE2S_DIGEST_N_WORDS, HashValue};
use circuits::context::TraceContext;
use circuits::ivalue::IValue;
use circuits::ops::Guess;
use serde::Serialize;
use starknet_ff::FieldElement;
use stwo::core::fields::m31::P;
use stwo::core::fields::qm31::QM31;
use stwo::core::vcs::blake2_hash::{Blake2sHash, Blake2sHasherGeneric, reduce_to_m31};
use stwo::core::vcs_lifted::Hasher;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleHasher;
use stwo::core::vcs_lifted::poseidon252_merkle::Poseidon252MerkleHasher;

use crate::checkpoint::hex32;
use crate::goldens;
use crate::primitives::UpstreamExpectation;

#[derive(Serialize)]
pub struct HasherVector {
    pub hasher: &'static str,
    pub words: Vec<u32>,
    pub hash_u32s: String,
    pub followed_by_digest: String,
    pub hash_u32s_followed_by_digest: String,
}

#[derive(Serialize)]
pub struct ConcatVector {
    pub hasher: &'static str,
    pub left: String,
    pub right: String,
    pub concat_and_hash: String,
}

#[derive(Serialize)]
pub struct ReduceVector {
    pub input: String,
    pub output: String,
}

#[derive(Serialize)]
pub struct CircuitHashVector {
    pub name: &'static str,
    pub log_blowup_factor: u32,
    /// Component log sizes in `ComponentList` order.
    pub component_log_sizes: [u32; 11],
    pub config_words: Vec<u32>,
    pub preprocessed_root: String,
    /// `Blake2sMerkleHasher::hash_u32s_followed_by_digest(config_words, root)`.
    pub circuit_hash: String,
    /// The same hash built in-circuit by `circuit_verifier::circuit_hash::compute_circuit_hash`,
    /// read back as eight little-endian words.
    pub in_circuit_words: [u32; 8],
}

#[derive(Serialize)]
pub struct HashingSection {
    pub hashers: Vec<HasherVector>,
    pub concat_and_hash: Vec<ConcatVector>,
    pub reduce_to_m31: Vec<ReduceVector>,
    pub circuit_hash: Vec<CircuitHashVector>,
}

fn le_words(hash: Blake2sHash) -> [u32; 8] {
    std::array::from_fn(|i| u32::from_le_bytes(hash.0[i * 4..i * 4 + 4].try_into().unwrap()))
}

fn hex_digest(hex: &str) -> Result<Blake2sHash> {
    let bytes: [u8; 32] = hex::decode(hex)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("digest is not 32 bytes"))?;
    Ok(Blake2sHash(bytes))
}

fn word_sets() -> Vec<Vec<u32>> {
    vec![
        vec![],
        vec![1],
        vec![1, 0],
        goldens::HASHER_TEST_WORDS.to_vec(),
        (0..12)
            .map(|i| 0x0101_0101u32.wrapping_mul(i + 1))
            .collect(),
        (0..16).map(|i| P - i).collect(),
        (0..17).map(|i| u32::MAX - i).collect(),
    ]
}

fn hasher_vectors<const M: bool>(name: &'static str, suffix: Blake2sHash) -> Vec<HasherVector> {
    word_sets()
        .into_iter()
        .map(|words| HasherVector {
            hasher: name,
            hash_u32s: hex32(Blake2sHasherGeneric::<M>::hash_u32s(&words).0),
            followed_by_digest: hex32(suffix.0),
            hash_u32s_followed_by_digest: hex32(
                Blake2sHasherGeneric::<M>::hash_u32s_followed_by_digest(&words, suffix).0,
            ),
            words,
        })
        .collect()
}

fn circuit_hash_vector(
    name: &'static str,
    sizes: PerComponent<u32>,
    log_blowup_factor: u32,
    root: Blake2sHash,
) -> Result<CircuitHashVector> {
    let words = config_words(log_blowup_factor, &sizes);
    let host = Blake2sMerkleHasher::hash_u32s_followed_by_digest(&words, root);

    let mut context = TraceContext::default();
    let root_vars = HashValue::<QM31>::from(root).guess(&mut context);
    let hash = compute_circuit_hash(&mut context, &sizes, log_blowup_factor, &root_vars);
    let in_circuit_words: [u32; BLAKE2S_DIGEST_N_WORDS] =
        std::array::from_fn(|i| context.get(*hash[i].get()).unpack_u32());
    ensure!(
        le_words(host) == in_circuit_words,
        "{name}: host and in-circuit hashes differ"
    );

    Ok(CircuitHashVector {
        name,
        log_blowup_factor,
        component_log_sizes: sizes.into_array(),
        config_words: words.to_vec(),
        preprocessed_root: hex32(root.0),
        circuit_hash: hex32(host.0),
        in_circuit_words,
    })
}

fn check(
    expectations: &mut Vec<UpstreamExpectation>,
    source: &'static str,
    name: &'static str,
    expected: String,
    actual: String,
) -> Result<()> {
    ensure!(
        expected == actual,
        "{source}::{name}: expected {expected}, oracle computed {actual}"
    );
    expectations.push(UpstreamExpectation {
        source,
        name,
        value: actual,
    });
    Ok(())
}

fn circuit_hash_vectors(
    expectations: &mut Vec<UpstreamExpectation>,
) -> Result<Vec<CircuitHashVector>> {
    let ascending = Blake2sHash::from(std::array::from_fn::<u32, 8, _>(|i| i as u32));
    let golden = circuit_hash_vector(
        "circuit_hash_test_golden",
        goldens::component_sizes(goldens::CIRCUIT_HASH_TEST_GATES),
        goldens::CIRCUIT_HASH_TEST_LOG_BLOWUP,
        ascending,
    )?;
    check(
        expectations,
        goldens::CIRCUIT_HASH_TEST,
        "compute_circuit_hash_matches_golden",
        format!("{:08x?}", goldens::CIRCUIT_HASH_TEST_WORDS),
        format!("{:08x?}", golden.in_circuit_words),
    )?;

    let mut vectors = vec![golden];
    for entry in &goldens::REGISTRY_ENTRIES {
        let vector = circuit_hash_vector(
            entry.name,
            goldens::component_sizes(entry.gates),
            1,
            Blake2sHash::from(entry.preprocessed_root),
        )?;
        check(
            expectations,
            entry.registry,
            entry.name,
            format!("{:08x?}", entry.circuit_hash),
            format!("{:08x?}", vector.in_circuit_words),
        )?;
        vectors.push(vector);
    }
    Ok(vectors)
}

pub fn hashing_section(expectations: &mut Vec<UpstreamExpectation>) -> Result<HashingSection> {
    let upstream_digest = hex_digest(goldens::HASHER_TEST_HASH_U32S)?;
    check(
        expectations,
        goldens::HASHER_TEST,
        "blake2s_hash_u32s",
        goldens::HASHER_TEST_HASH_U32S.into(),
        hex32(Blake2sMerkleHasher::hash_u32s(&goldens::HASHER_TEST_WORDS).0),
    )?;
    check(
        expectations,
        goldens::HASHER_TEST,
        "blake2s_hash_u32s_followed_by_digest",
        goldens::HASHER_TEST_FOLLOWED_BY_DIGEST.into(),
        hex32(
            Blake2sMerkleHasher::hash_u32s_followed_by_digest(
                &goldens::HASHER_TEST_WORDS,
                upstream_digest,
            )
            .0,
        ),
    )?;

    let mut hashers = hasher_vectors::<false>("blake2s", upstream_digest);
    hashers.extend(hasher_vectors::<true>("blake2s_m31", upstream_digest));

    let left = Blake2sHash::from(std::array::from_fn::<u32, 8, _>(|i| i as u32));
    let right = Blake2sHash::from([P, P + 1, u32::MAX, 0x8000_0000, P - 1, 0, 1, 2]);
    let concat_and_hash = vec![
        ConcatVector {
            hasher: "blake2s",
            left: hex32(left.0),
            right: hex32(right.0),
            concat_and_hash: hex32(Blake2sHasherGeneric::<false>::concat_and_hash(&left, &right).0),
        },
        ConcatVector {
            hasher: "blake2s_m31",
            left: hex32(left.0),
            right: hex32(right.0),
            concat_and_hash: hex32(Blake2sHasherGeneric::<true>::concat_and_hash(&left, &right).0),
        },
    ];

    let reduce_to_m31 = [
        [0, 1, P - 1, P, P + 1, 0x8000_0000, u32::MAX, 12345],
        [0xffff_fffe, 0x7fff_fffe, 0xdead_beef, 0, P, P, u32::MAX, 1],
    ]
    .into_iter()
    .map(|words| {
        let input = Blake2sHash::from(words);
        ReduceVector {
            input: hex32(input.0),
            output: hex32(reduce_to_m31(input.0)),
        }
    })
    .collect();

    let circuit_hash = circuit_hash_vectors(expectations)?;

    let poseidon_hash = Poseidon252MerkleHasher::hash_u32s_followed_by_digest(
        &config_words(1, &goldens::component_sizes(goldens::POSEIDON_TEST_GATES)),
        FieldElement::from_hex_be(goldens::POSEIDON_TEST_ROOT)?,
    );
    check(
        expectations,
        goldens::POSEIDON_TEST,
        "poseidon252_root",
        goldens::POSEIDON_TEST_HASH.into(),
        format!("{poseidon_hash:x}"),
    )?;

    Ok(HashingSection {
        hashers,
        concat_and_hash,
        reduce_to_m31,
        circuit_hash,
    })
}
