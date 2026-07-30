use crate::model::{ProveMode, WideFibonacciStatement};
use crate::proving::{wide_fibonacci_prove, wide_fibonacci_verify};
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
