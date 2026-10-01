//! Blake2s Fiat-Shamir channel transcripts for both output variants.
//!
//! Each script starts from `Channel::default()` and records, after every operation, the drawn
//! values and the channel digest. The scripts pin the operation encodings (`mix_u32s`,
//! `mix_felts`, `mix_u64`, `MerkleChannel::mix_hash`, `FriConfig::mix_into`), the draw counter
//! reset on every mix, and the order sensitivity of consecutive mixes.

use serde::Serialize;
use stwo::core::channel::{Blake2sChannelGeneric, Channel, MerkleChannel};
use stwo::core::fields::m31::P;
use stwo::core::fields::qm31::QM31;
use stwo::core::fri::FriConfig;
use stwo::core::vcs::blake2_hash::Blake2sHash;
use stwo::core::vcs_lifted::blake2_merkle::{
    Blake2sM31MerkleChannel, Blake2sMerkleChannel, Blake2sMerkleHasher,
};

use crate::checkpoint::{U64Record, hex32, qm31};

/// The lane label of `Blake2sChannel` + `Blake2sMerkleChannel` (the root fold lane).
pub const BLAKE2S_LANE: &str = "blake2s";
/// The lane label of `Blake2sM31Channel` + `Blake2sM31MerkleChannel` (leaves, internal folds).
pub const BLAKE2S_M31_LANE: &str = "blake2s_m31";

#[derive(Clone, Copy, Serialize)]
pub struct FriConfigRecord {
    pub pow_bits: u32,
    pub log_blowup_factor: u32,
    pub log_last_layer_degree_bound: u32,
    pub n_queries: usize,
    pub fold_step: u32,
}

impl FriConfigRecord {
    fn config(self) -> FriConfig {
        FriConfig::new(
            self.pow_bits,
            self.log_last_layer_degree_bound,
            self.log_blowup_factor,
            self.n_queries,
            self.fold_step,
        )
    }
}

/// The circuit FRI configurations of the shipped registry definitions
/// (`circuit_registry_definitions/**/circuit_fri_config.json` and the canonical_small registry),
/// followed by the FRI configuration of the leaf Cairo proof (`cairo_prover_params`).
const FRI_CONFIGS: [(&str, FriConfigRecord); 4] = [
    (
        "fri_config_production",
        FriConfigRecord {
            pow_bits: 26,
            log_blowup_factor: 1,
            log_last_layer_degree_bound: 0,
            n_queries: 70,
            fold_step: 4,
        },
    ),
    (
        "fri_config_privacy_large_proofs",
        FriConfigRecord {
            pow_bits: 26,
            log_blowup_factor: 2,
            log_last_layer_degree_bound: 0,
            n_queries: 35,
            fold_step: 4,
        },
    ),
    (
        "fri_config_canonical_small",
        FriConfigRecord {
            pow_bits: 26,
            log_blowup_factor: 1,
            log_last_layer_degree_bound: 0,
            n_queries: 35,
            fold_step: 4,
        },
    ),
    (
        "fri_config_cairo_leaf",
        FriConfigRecord {
            pow_bits: 26,
            log_blowup_factor: 1,
            log_last_layer_degree_bound: 0,
            n_queries: 70,
            fold_step: 1,
        },
    ),
];

#[derive(Clone)]
enum Op {
    MixU32s(Vec<u32>),
    MixFelts(Vec<QM31>),
    MixU64(u64),
    MixHash([u8; 32]),
    MixFriConfig(FriConfigRecord),
    DrawU32s,
    DrawSecureFelt,
    DrawSecureFelts(usize),
}

#[derive(Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum OpRecord {
    MixU32s {
        words: Vec<u32>,
        digest: String,
    },
    MixFelts {
        felts: Vec<[u32; 4]>,
        digest: String,
    },
    MixU64 {
        value: U64Record,
        digest: String,
    },
    MixHash {
        hash: String,
        digest: String,
    },
    MixFriConfig {
        config: FriConfigRecord,
        digest: String,
    },
    DrawU32s {
        words: Vec<u32>,
        digest: String,
    },
    DrawSecureFelt {
        felt: [u32; 4],
        digest: String,
    },
    DrawSecureFelts {
        n_felts: usize,
        felts: Vec<[u32; 4]>,
        digest: String,
    },
}

#[derive(Serialize)]
pub struct ScriptRecord {
    pub lane: &'static str,
    pub name: &'static str,
    pub initial_digest: String,
    pub ops: Vec<OpRecord>,
}

fn run_script<
    const M: bool,
    MC: MerkleChannel<C = Blake2sChannelGeneric<M>, H = Blake2sMerkleHasher>,
>(
    lane: &'static str,
    name: &'static str,
    ops: &[Op],
) -> ScriptRecord {
    let mut channel = Blake2sChannelGeneric::<M>::default();
    let digest = |channel: &Blake2sChannelGeneric<M>| hex32(channel.digest().0);
    let initial_digest = digest(&channel);
    let records = ops
        .iter()
        .cloned()
        .map(|op| match op {
            Op::MixU32s(words) => {
                channel.mix_u32s(&words);
                OpRecord::MixU32s {
                    words,
                    digest: digest(&channel),
                }
            }
            Op::MixFelts(felts) => {
                channel.mix_felts(&felts);
                OpRecord::MixFelts {
                    felts: felts.into_iter().map(qm31).collect(),
                    digest: digest(&channel),
                }
            }
            Op::MixU64(value) => {
                channel.mix_u64(value);
                OpRecord::MixU64 {
                    value: value.into(),
                    digest: digest(&channel),
                }
            }
            Op::MixHash(bytes) => {
                MC::mix_hash(&mut channel, Blake2sHash(bytes));
                OpRecord::MixHash {
                    hash: hex32(bytes),
                    digest: digest(&channel),
                }
            }
            Op::MixFriConfig(config) => {
                config.config().mix_into(&mut channel);
                OpRecord::MixFriConfig {
                    config,
                    digest: digest(&channel),
                }
            }
            Op::DrawU32s => {
                let words = channel.draw_u32s();
                OpRecord::DrawU32s {
                    words,
                    digest: digest(&channel),
                }
            }
            Op::DrawSecureFelt => {
                let felt = qm31(channel.draw_secure_felt());
                OpRecord::DrawSecureFelt {
                    felt,
                    digest: digest(&channel),
                }
            }
            Op::DrawSecureFelts(n_felts) => {
                let felts = channel
                    .draw_secure_felts(n_felts)
                    .into_iter()
                    .map(qm31)
                    .collect();
                OpRecord::DrawSecureFelts {
                    n_felts,
                    felts,
                    digest: digest(&channel),
                }
            }
        })
        .collect();
    ScriptRecord {
        lane,
        name,
        initial_digest,
        ops: records,
    }
}

fn words_to_bytes(words: [u32; 8]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (chunk, word) in bytes.chunks_exact_mut(4).zip(words) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

/// A digest whose words straddle `P`, so an `M31`-reduced and an unreduced mix would differ.
fn high_word_digest() -> [u8; 32] {
    words_to_bytes([
        P,
        P + 1,
        u32::MAX,
        0x8000_0000,
        P - 1,
        0xdead_beef,
        0x7fff_fff0,
        0xffff_0000,
    ])
}

fn sample_felts() -> Vec<QM31> {
    vec![
        QM31::from_u32_unchecked(P - 1, 0, 1, 1 << 30),
        QM31::from_u32_unchecked(1_923_782, 1_923_783, 0, 7),
    ]
}

/// The canonical_small leaf preprocessed root, packed per word as `(lo16, hi16, 0, 0)` the way
/// the circuit claim mixes its output digest.
fn packed_digest_words() -> Vec<QM31> {
    [
        0xadaf_43d6u32,
        0xbee3_9095,
        0x90ce_b891,
        0x73c8_a22d,
        0x4c06_753c,
        0xd546_9618,
        0x6cb5_a946,
        0x5425_c597,
    ]
    .into_iter()
    .map(|w| QM31::from_u32_unchecked(w & 0xffff, w >> 16, 0, 0))
    .collect()
}

fn scripts() -> Vec<(&'static str, Vec<Op>)> {
    let words: Vec<u32> = (1..=9).collect();
    let ascending: [u8; 32] = std::array::from_fn(|i| i as u8);
    let mut scripts = vec![
        (
            "draws_from_default",
            vec![
                Op::DrawU32s,
                Op::DrawU32s,
                Op::DrawSecureFelt,
                Op::DrawSecureFelts(5),
                Op::DrawSecureFelts(4),
            ],
        ),
        (
            "mix_u32s_then_felts",
            vec![
                Op::MixU32s(words.clone()),
                Op::MixFelts(sample_felts()),
                Op::DrawSecureFelt,
            ],
        ),
        (
            "mix_felts_then_u32s",
            vec![
                Op::MixFelts(sample_felts()),
                Op::MixU32s(words),
                Op::DrawSecureFelt,
            ],
        ),
        (
            "mix_resets_draw_counter",
            vec![
                Op::DrawU32s,
                Op::DrawU32s,
                Op::MixU64(0x1111_2222_3333_4444),
                Op::DrawU32s,
                Op::MixU32s(vec![]),
                Op::DrawU32s,
                Op::MixFelts(vec![]),
                Op::DrawSecureFelt,
            ],
        ),
        (
            "mix_hash",
            vec![
                Op::MixHash(ascending),
                Op::DrawSecureFelt,
                Op::MixHash(high_word_digest()),
                Op::DrawU32s,
            ],
        ),
        (
            "circuit_transcript_preamble_shape",
            vec![
                Op::MixFelts(vec![QM31::from_u32_unchecked(0, 0, 0, 0)]),
                Op::MixFriConfig(FRI_CONFIGS[2].1),
                Op::MixHash(ascending),
                Op::MixHash(high_word_digest()),
                Op::MixFelts(packed_digest_words()),
                Op::MixHash(ascending),
                Op::MixU64((5u64 << 32) | 0x000a_bcde),
                Op::DrawSecureFelt,
                Op::DrawSecureFelt,
            ],
        ),
    ];
    for (name, config) in FRI_CONFIGS {
        scripts.push((name, vec![Op::MixFriConfig(config), Op::DrawSecureFelt]));
    }
    scripts
}

pub fn channel_scripts() -> Vec<ScriptRecord> {
    let mut records = Vec::new();
    for (name, ops) in scripts() {
        records.push(run_script::<false, Blake2sMerkleChannel>(
            BLAKE2S_LANE,
            name,
            &ops,
        ));
        records.push(run_script::<true, Blake2sM31MerkleChannel>(
            BLAKE2S_M31_LANE,
            name,
            &ops,
        ));
    }
    records
}
