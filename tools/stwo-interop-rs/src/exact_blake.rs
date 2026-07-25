//! Exact Blake proof routing through the pinned upstream example AIR.

use crate::blake::air::transport::{
    prove as prove_upstream, verify as verify_upstream, TransportBlakeProof,
};
use crate::model::{BlakeStatement, ProveMode};
use anyhow::{bail, Result};
use stwo::core::pcs::PcsConfig;
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher};

const N_ROUNDS: u32 = 10;

pub(crate) fn prove(
    config: PcsConfig,
    log_size: u32,
    n_rounds: u32,
    _prove_mode: ProveMode,
    include_all_preprocessed_columns: bool,
) -> Result<(BlakeStatement, StarkProof<Blake2sMerkleHasher>)> {
    validate_request(log_size, n_rounds, include_all_preprocessed_columns)?;
    let proof = prove_upstream::<Blake2sMerkleChannel>(log_size, config);
    Ok((
        BlakeStatement {
            log_size: proof.log_size,
            scheduler_claimed_sum: proof.scheduler_claimed_sum,
            round_claimed_sums: proof.round_claimed_sums,
            xor_claimed_sums: proof.xor_claimed_sums,
        },
        proof.stark_proof,
    ))
}

pub(crate) fn verify(
    _config: PcsConfig,
    statement: BlakeStatement,
    proof: StarkProof<Blake2sMerkleHasher>,
) -> Result<()> {
    verify_upstream::<Blake2sMerkleChannel>(TransportBlakeProof {
        log_size: statement.log_size,
        scheduler_claimed_sum: statement.scheduler_claimed_sum,
        round_claimed_sums: statement.round_claimed_sums,
        xor_claimed_sums: statement.xor_claimed_sums,
        stark_proof: proof,
    })
    .map_err(Into::into)
}

fn validate_request(
    log_size: u32,
    n_rounds: u32,
    include_all_preprocessed_columns: bool,
) -> Result<()> {
    if log_size < 4 {
        bail!("exact Blake log size must be at least 4");
    }
    if n_rounds != N_ROUNDS {
        bail!("exact Blake requires ten rounds");
    }
    if include_all_preprocessed_columns {
        bail!("exact upstream Blake does not expose prove_ex preprocessed-column expansion");
    }
    Ok(())
}
