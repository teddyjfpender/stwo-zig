use anyhow::{ensure, Result};
use serde::Deserialize;
use stwo::core::{
    fields::{
        m31::{M31, P},
        qm31::{SecureField as Q, QM31},
    },
    fri::{FriConfig, FriLayerProof, FriProof},
    pcs::{quotients::CommitmentSchemeProof, PcsConfig, TreeVec},
    poly::line::LinePoly,
    proof::StarkProof,
    vcs::blake2_hash::Blake2sHash,
    vcs_lifted::{blake2_merkle::Blake2sMerkleHasher, verifier::MerkleDecommitmentLifted},
};
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cell {
    pub address: u64,
    pub initial: u64,
    #[serde(rename = "final")]
    pub final_value: u64,
    pub readable: bool,
    pub writable: bool,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Statement {
    pub program_base: u64,
    pub program: Vec<u32>,
    #[serde(default)]
    pub program_addresses: Vec<u64>,
    pub initial_pc: u64,
    pub final_pc: u64,
    pub initial_registers: [u64; 32],
    pub final_registers: [u64; 32],
    pub memory: Vec<Cell>,
    pub steps: u32,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub path: Vec<u64>,
    pub register_clocks: [u16; 32],
    pub memory_clocks: Vec<u16>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pow_bits: u32,
    fri_config: Fri,
    #[serde(default)]
    lifting_log_size: Option<u32>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fri {
    log_blowup_factor: u32,
    log_last_layer_degree_bound: u32,
    n_queries: usize,
    fold_step: u32,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decommit {
    hash_witness: Vec<[u8; 32]>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Layer {
    fri_witness: Vec<[u32; 4]>,
    decommitment: Decommit,
    commitment: [u8; 32],
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FriWire {
    first_layer: Layer,
    inner_layers: Vec<Layer>,
    last_layer_poly: Vec<[u32; 4]>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Wire {
    config: Config,
    commitments: Vec<[u8; 32]>,
    sampled_values: Vec<Vec<Vec<[u32; 4]>>>,
    decommitments: Vec<Decommit>,
    queried_values: Vec<Vec<Vec<u32>>>,
    proof_of_work: u64,
    fri_proof: FriWire,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub metadata: Metadata,
    pub proof: Wire,
}
pub type Proof = StarkProof<Blake2sMerkleHasher>;
pub fn config() -> PcsConfig {
    PcsConfig {
        pow_bits: 26,
        fri_config: FriConfig::new(0, 1, 70),
    }
}
pub fn m(x: u32) -> Result<M31> {
    ensure!(x < P, "noncanonical M31");
    Ok(M31(x))
}
pub fn q(x: [u32; 4]) -> Result<Q> {
    Ok(QM31::from_m31(m(x[0])?, m(x[1])?, m(x[2])?, m(x[3])?))
}
fn decommit(w: Decommit) -> MerkleDecommitmentLifted<Blake2sMerkleHasher> {
    MerkleDecommitmentLifted {
        hash_witness: w.hash_witness.into_iter().map(Blake2sHash).collect(),
    }
}
fn layer(w: Layer) -> Result<FriLayerProof<Blake2sMerkleHasher>> {
    Ok(FriLayerProof {
        fri_witness: w.fri_witness.into_iter().map(q).collect::<Result<_>>()?,
        decommitment: decommit(w.decommitment),
        commitment: Blake2sHash(w.commitment),
    })
}
impl Wire {
    pub fn decode(self) -> Result<Proof> {
        let c = &self.config;
        ensure!(
            c.pow_bits == 26
                && c.fri_config.log_blowup_factor == 1
                && c.fri_config.log_last_layer_degree_bound == 0
                && c.fri_config.n_queries == 70
                && c.fri_config.fold_step == 1
                && c.lifting_log_size.is_none(),
            "wrong security configuration"
        );
        ensure!(
            self.commitments.len() == 4
                && self.sampled_values.len() == 4
                && self.queried_values.len() == 4
                && self.decommitments.len() == 4,
            "wrong tree count"
        );
        for (tree, count) in [21, 643, 36, 16].into_iter().enumerate() {
            ensure!(
                self.sampled_values[tree].len() == count
                    && self.queried_values[tree].len() == count,
                "wrong column count"
            );
            for (col, values) in self.sampled_values[tree].iter().enumerate() {
                ensure!(
                    values.len() == if tree == 2 && col >= 32 { 2 } else { 1 },
                    "wrong opening mask"
                );
            }
            for values in &self.queried_values[tree] {
                ensure!(!values.is_empty() && values.len() <= 70, "query count");
            }
        }
        Ok(StarkProof(CommitmentSchemeProof {
            config: config(),
            commitments: TreeVec::new(self.commitments.into_iter().map(Blake2sHash).collect()),
            sampled_values: TreeVec::new(
                self.sampled_values
                    .into_iter()
                    .map(|t| {
                        t.into_iter()
                            .map(|c| c.into_iter().map(q).collect::<Result<_>>())
                            .collect::<Result<_>>()
                    })
                    .collect::<Result<_>>()?,
            ),
            queried_values: TreeVec::new(
                self.queried_values
                    .into_iter()
                    .map(|t| {
                        t.into_iter()
                            .map(|c| c.into_iter().map(m).collect::<Result<_>>())
                            .collect::<Result<_>>()
                    })
                    .collect::<Result<_>>()?,
            ),
            decommitments: TreeVec::new(self.decommitments.into_iter().map(decommit).collect()),
            proof_of_work: self.proof_of_work,
            fri_proof: FriProof {
                first_layer: layer(self.fri_proof.first_layer)?,
                inner_layers: self
                    .fri_proof
                    .inner_layers
                    .into_iter()
                    .map(layer)
                    .collect::<Result<_>>()?,
                last_layer_poly: LinePoly::new(
                    self.fri_proof
                        .last_layer_poly
                        .into_iter()
                        .map(q)
                        .collect::<Result<_>>()?,
                ),
            },
        }))
    }
}
