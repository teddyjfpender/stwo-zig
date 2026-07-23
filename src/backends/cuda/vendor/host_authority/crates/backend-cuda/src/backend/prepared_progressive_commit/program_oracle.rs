//! CPU-only semantic oracle and deterministic fixtures for [`CommitProgram`].

use stwo::core::vcs::blake2_hash::{Blake2sHash, Blake2sHasherGeneric};

use super::program::{CommitProgram, CommitProgramError};
use crate::backend::progressive_commit::{full_lifting_leaf_oracle, progressive_leaf_oracle};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitProgramOracleLayer {
    pub log_size: u32,
    pub hashes: Vec<Blake2sHash>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitProgramOracle {
    pub leaf_hashes: Vec<Blake2sHash>,
    pub retained_layers_bottom_up: Vec<CommitProgramOracleLayer>,
    pub root: Blake2sHash,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitProgramFixture {
    pub seed: u64,
    pub evaluations: Vec<Vec<u32>>,
    pub oracle: CommitProgramOracle,
}

impl CommitProgram {
    /// Independent semantic oracle over caller-supplied canonical evaluations.
    pub fn oracle(
        &self,
        evaluations: &[Vec<u32>],
    ) -> Result<CommitProgramOracle, CommitProgramError> {
        let plan = &self.requirements().leaves.plan;
        let leaves = progressive_leaf_oracle(plan, evaluations)?;
        let reference = full_lifting_leaf_oracle(plan, evaluations)?;
        if leaves != reference {
            return Err(CommitProgramError::InvalidRetainedLayerOrder);
        }
        let expected_layers = self.retained_layers_bottom_up();
        let mut current = leaves.clone();
        let mut retained = Vec::with_capacity(expected_layers.len());
        let mut retained_index = 0usize;
        for log_size in (0..self.identity().config.lifting_log_size).rev() {
            current = current
                .chunks_exact(2)
                .map(|children| {
                    Blake2sHasherGeneric::<false>::concat_and_hash(&children[0], &children[1])
                })
                .collect();
            if expected_layers
                .get(retained_index)
                .is_some_and(|layer| layer.log_size == log_size)
            {
                retained.push(CommitProgramOracleLayer {
                    log_size,
                    hashes: current.clone(),
                });
                retained_index += 1;
            }
        }
        if retained_index != expected_layers.len() || current.len() != 1 {
            return Err(CommitProgramError::InvalidRetainedLayerOrder);
        }
        Ok(CommitProgramOracle {
            leaf_hashes: leaves,
            retained_layers_bottom_up: retained,
            root: current[0],
        })
    }

    /// Deterministic replay fixture. Values are canonical M31 words and remain
    /// proof data, never part of program identity.
    pub fn fixture(&self, seed: u64) -> Result<CommitProgramFixture, CommitProgramError> {
        let mut state = seed;
        let evaluations = self
            .requirements()
            .leaves
            .plan
            .columns
            .iter()
            .map(|column| {
                (0..1usize << column.evaluation_log_size)
                    .map(|_| {
                        state = state
                            .wrapping_mul(6_364_136_223_846_793_005)
                            .wrapping_add(1_442_695_040_888_963_407);
                        (state % 0x7fff_ffff) as u32
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let oracle = self.oracle(&evaluations)?;
        Ok(CommitProgramFixture {
            seed,
            evaluations,
            oracle,
        })
    }
}
