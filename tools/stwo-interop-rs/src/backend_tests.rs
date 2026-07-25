use crate::model::{PoseidonStatement, ProveMode, WideFibonacciStatement};
use crate::proving::{
    poseidon_prove, poseidon_verify, wide_fibonacci_prove, wide_fibonacci_verify,
};
use crate::wire::proof_to_wire;
use stwo::core::fri::FriConfig;
use stwo::core::pcs::PcsConfig;
use stwo::prover::backend::cpu::CpuBackend;
use stwo::prover::backend::simd::SimdBackend;

#[test]
fn scalar_and_simd_paths_emit_the_same_verified_proof() {
    let config = PcsConfig {
        pow_bits: 0,
        fri_config: FriConfig::new(0, 1, 3),
    };
    let statement = WideFibonacciStatement {
        log_n_rows: 5,
        sequence_len: 8,
    };
    let (_, scalar) =
        wide_fibonacci_prove::<CpuBackend>(config, statement, ProveMode::Prove, false).unwrap();
    let (_, simd) =
        wide_fibonacci_prove::<SimdBackend>(config, statement, ProveMode::Prove, false).unwrap();

    let scalar_wire = serde_json::to_vec(&proof_to_wire(&scalar).unwrap()).unwrap();
    let simd_wire = serde_json::to_vec(&proof_to_wire(&simd).unwrap()).unwrap();
    assert_eq!(scalar_wire, simd_wire);
    wide_fibonacci_verify(config, statement, scalar).unwrap();
    wide_fibonacci_verify(config, statement, simd).unwrap();
}

#[test]
fn exact_poseidon_backends_and_prove_modes_emit_the_same_verified_proof() {
    let config = PcsConfig {
        pow_bits: 0,
        fri_config: FriConfig::new(0, 1, 3),
    };
    let request = PoseidonStatement {
        log_n_instances: 8,
        claimed_sum: Default::default(),
    };
    let (statement, scalar) =
        poseidon_prove::<CpuBackend>(config, request, ProveMode::Prove, false).unwrap();
    let (simd_statement, simd) =
        poseidon_prove::<SimdBackend>(config, request, ProveMode::Prove, false).unwrap();
    let (extended_statement, extended) =
        poseidon_prove::<SimdBackend>(config, request, ProveMode::ProveEx, true).unwrap();

    assert_eq!(statement.claimed_sum, simd_statement.claimed_sum);
    assert_eq!(statement.claimed_sum, extended_statement.claimed_sum);
    let scalar_wire = serde_json::to_vec(&proof_to_wire(&scalar).unwrap()).unwrap();
    let simd_wire = serde_json::to_vec(&proof_to_wire(&simd).unwrap()).unwrap();
    let extended_wire = serde_json::to_vec(&proof_to_wire(&extended).unwrap()).unwrap();
    assert_eq!(scalar_wire, simd_wire);
    assert_eq!(scalar_wire, extended_wire);
    assert_eq!(scalar_wire.len(), 112_247);
    assert_eq!(scalar.0.commitments.len(), 4);
    assert_eq!(scalar.0.sampled_values[1].len(), 1_264);
    assert_eq!(scalar.0.sampled_values[2].len(), 32);
    assert_eq!(scalar.0.sampled_values[3].len(), 16);
    poseidon_verify(config, statement, scalar).unwrap();
    poseidon_verify(config, statement, simd).unwrap();
    poseidon_verify(config, statement, extended).unwrap();
}
