//! Transport-only access to the pinned upstream Blake proof.

use stwo::core::channel::MerkleChannel;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::PcsConfig;
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
use stwo::core::verifier::VerificationError;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::BackendForChannel;

use super::{prove_blake, verify_blake, BlakeProof, BlakeStatement0, BlakeStatement1};

pub struct TransportBlakeProof<H: MerkleHasherLifted> {
    pub log_size: u32,
    pub scheduler_claimed_sum: SecureField,
    pub round_claimed_sums: [SecureField; 2],
    pub xor_claimed_sums: [SecureField; 5],
    pub stark_proof: StarkProof<H>,
}

pub fn prove<MC: MerkleChannel>(log_size: u32, config: PcsConfig) -> TransportBlakeProof<MC::H>
where
    SimdBackend: BackendForChannel<MC>,
{
    let BlakeProof {
        stmt0,
        stmt1,
        stark_proof,
    } = prove_blake::<MC>(log_size, config);
    let BlakeStatement0 { log_size } = stmt0;
    let BlakeStatement1 {
        scheduler_claimed_sum,
        round_claimed_sums,
        xor12_claimed_sum,
        xor9_claimed_sum,
        xor8_claimed_sum,
        xor7_claimed_sum,
        xor4_claimed_sum,
    } = stmt1;

    TransportBlakeProof {
        log_size,
        scheduler_claimed_sum,
        round_claimed_sums: round_claimed_sums
            .try_into()
            .expect("pinned Blake has exactly two round components"),
        xor_claimed_sums: [
            xor12_claimed_sum,
            xor9_claimed_sum,
            xor8_claimed_sum,
            xor7_claimed_sum,
            xor4_claimed_sum,
        ],
        stark_proof,
    }
}

pub fn verify<MC: MerkleChannel>(
    proof: TransportBlakeProof<MC::H>,
) -> Result<(), VerificationError> {
    verify_blake::<MC>(BlakeProof {
        stmt0: BlakeStatement0 {
            log_size: proof.log_size,
        },
        stmt1: BlakeStatement1 {
            scheduler_claimed_sum: proof.scheduler_claimed_sum,
            round_claimed_sums: proof.round_claimed_sums.into(),
            xor12_claimed_sum: proof.xor_claimed_sums[0],
            xor9_claimed_sum: proof.xor_claimed_sums[1],
            xor8_claimed_sum: proof.xor_claimed_sums[2],
            xor7_claimed_sum: proof.xor_claimed_sums[3],
            xor4_claimed_sum: proof.xor_claimed_sums[4],
        },
        stark_proof: proof.stark_proof,
    })
}
