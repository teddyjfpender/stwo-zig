//! `prove-lifted-example`: the PCS prover at explicit tree heights on a small AIR.
//!
//! The Cairo leaf proofs of small programs commit every tree at its natural height (the fixed
//! 2^20-row tables fill the canonical_small preprocessed domain), so they never lift a trace
//! tree. This checkpoint does: `test_wide_fib_prove_with_blake` of `crates/examples` at
//! proving@5a7c5ed (wide Fibonacci, 100 columns, `FriConfig::default()`, an empty preprocessed
//! tree at height 0, `Blake2sM31MerkleChannel`, no configuration mix), proved with the trace
//! trees committed at `log_n_rows + log_blowup_factor + lift` for several `lift`s and verified
//! with `stwo::core::verifier::verify`. Each case records `bincode(StarkProof)` and the
//! per-stage values of the `prove-cairo` checkpoint.

use anyhow::{Context, Result};
use itertools::Itertools;
use num_traits::{One, Zero};
use serde::Serialize;
use stwo::core::air::Component;
use stwo::core::channel::Blake2sM31Channel;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::fri::FriConfig;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
use stwo::core::verifier::verify;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::poly::circle::PolyOps;
use stwo::prover::{CommitmentSchemeProver, prove};
use stwo_constraint_framework::TraceLocationAllocator;
use stwo_examples::wide_fibonacci::{
    FibInput, WideFibonacciComponent, WideFibonacciEval, generate_trace,
};

use crate::checkpoint::{Envelope, U64Record, hex32, sha256_hex};

const FIB_SEQUENCE_LENGTH: usize = 100;
const LOG_N_ROWS: u32 = 5;
const LIFTS: [u32; 3] = [0, 1, 3];

#[derive(Serialize)]
struct Case {
    log_n_rows: u32,
    sequence_len: u32,
    trace_lifting_log_size: u32,
    preprocessed_lifting_log_size: u32,
    commitments: Vec<String>,
    proof_of_work: U64Record,
    fri_inner_layer_roots: Vec<String>,
    sampled_values_sha256: String,
    stark_proof_bytes: u64,
    stark_proof_sha256: String,
}

#[derive(Serialize)]
struct Body {
    fri_config: [u64; 5],
    cases: Vec<Case>,
}

fn prove_case(lift: u32) -> Result<Case> {
    let fri_config = FriConfig::default();
    let config = PcsConfig {
        fri_config,
        trace_lifting_log_size: LOG_N_ROWS + fri_config.log_blowup_factor + lift,
        preprocessed_lifting_log_size: 0,
    };
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(config.trace_lifting_log_size.max(LOG_N_ROWS + 1 + fri_config.log_blowup_factor))
            .circle_domain()
            .half_coset,
    );
    let channel = &mut Blake2sM31Channel::default();
    let mut scheme = CommitmentSchemeProver::<SimdBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    let mut tree_builder = scheme.tree_builder();
    tree_builder.extend_evals(vec![]);
    tree_builder.commit(channel);
    let inputs = (0..1u32 << LOG_N_ROWS)
        .map(|i| FibInput { a: BaseField::one(), b: BaseField::from_u32_unchecked(i) })
        .collect_vec();
    let mut tree_builder = scheme.tree_builder();
    tree_builder.extend_evals(generate_trace::<FIB_SEQUENCE_LENGTH, SimdBackend>(&inputs));
    tree_builder.commit(channel);
    let component = WideFibonacciComponent::new(
        &mut TraceLocationAllocator::default(),
        WideFibonacciEval::<FIB_SEQUENCE_LENGTH> { log_n_rows: LOG_N_ROWS },
        SecureField::zero(),
    );
    let proof = prove::<SimdBackend, Blake2sM31MerkleChannel>(&[&component], channel, scheme)
        .map_err(|error| anyhow::anyhow!("prove failed: {error:?}"))?;

    let verifier_channel = &mut Blake2sM31Channel::default();
    let verifier = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);
    let sizes = component.trace_log_degree_bounds();
    verifier.commit(proof.commitments[0], &sizes[0], verifier_channel);
    verifier.commit(proof.commitments[1], &sizes[1], verifier_channel);
    verify(&[&component], verifier_channel, verifier, proof.clone())
        .map_err(|error| anyhow::anyhow!("verify rejected the lifted proof: {error:?}"))?;

    let bytes = bincode::serialize(&proof).context("bincode serialization failed")?;
    let stark = &proof.0;
    Ok(Case {
        log_n_rows: LOG_N_ROWS,
        sequence_len: FIB_SEQUENCE_LENGTH as u32,
        trace_lifting_log_size: config.trace_lifting_log_size,
        preprocessed_lifting_log_size: config.preprocessed_lifting_log_size,
        commitments: stark.commitments.iter().map(|root| hex32(root.as_ref())).collect(),
        proof_of_work: stark.proof_of_work.into(),
        fri_inner_layer_roots: stark
            .fri_proof
            .inner_layers
            .iter()
            .map(|layer| hex32(layer.commitment.as_ref()))
            .collect(),
        sampled_values_sha256: sha256_hex(bincode::serialize(&stark.sampled_values)?),
        stark_proof_bytes: bytes.len() as u64,
        stark_proof_sha256: sha256_hex(&bytes),
    })
}

pub fn run() -> Result<Vec<u8>> {
    let fri = FriConfig::default();
    let body = Body {
        fri_config: [
            fri.pow_bits as u64,
            fri.log_blowup_factor as u64,
            fri.log_last_layer_degree_bound as u64,
            fri.n_queries as u64,
            fri.fold_step as u64,
        ],
        cases: LIFTS.iter().map(|&lift| prove_case(lift)).collect::<Result<_>>()?,
    };
    crate::output::json(&Envelope::new("r10-lift", "prove-lifted-example", vec![], body))
}
