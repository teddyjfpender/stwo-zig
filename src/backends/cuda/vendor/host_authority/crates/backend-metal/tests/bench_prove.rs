//! Wall-clock prove benchmark over the testkit reference AIR (16-column wide-fib).
//!
//! Ignored by default. Run one backend per process so peak-RSS measurements don't
//! contaminate each other:
//!
//! ```bash
//! BENCH_LOG_N_ROWS=20 cargo test --release --features parallel -p stwo-backend-metal \
//!     --test bench_prove -- --ignored --nocapture bench_metal
//! ```
//!
//! The first iteration is reported separately as "cold" (it includes Metal shader
//! compilation and twiddle-cache warmup); subsequent iterations are the steady state.

use std::time::Instant;

use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleChannel;
use stwo::prover::backend::simd::SimdBackend;
use stwo_backend_metal::MetalBackend;
use stwo_backend_testkit::{generate_reference_trace, prove_reference};

const N_ITERS: usize = 3;

fn run<B>(name: &str)
where
    B: stwo::prover::backend::BackendForChannel<Blake2sMerkleChannel>
        + stwo_constraint_framework::FrameworkBackend
        + stwo::prover::backend::FromSimdColumns,
{
    let log_n_rows: u32 = std::env::var("BENCH_LOG_N_ROWS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(18);
    let n_rows = 1u64 << log_n_rows;
    let trace = generate_reference_trace(log_n_rows);

    let mut times_ms = Vec::new();
    for iter in 0..N_ITERS {
        let start = Instant::now();
        let proof = prove_reference::<B, Blake2sMerkleChannel>(trace.clone());
        let elapsed = start.elapsed().as_secs_f64() * 1000.0;
        times_ms.push(elapsed);
        // Keep the proof alive through timing so its drop isn't attributed to prove.
        drop(proof);
        println!(
            "{name} log_n_rows={log_n_rows} iter={iter} ms={elapsed:.1} rows_per_s={:.0}",
            n_rows as f64 / (elapsed / 1000.0)
        );
    }
    let warm: Vec<f64> = times_ms[1..].to_vec();
    let warm_best = warm.iter().cloned().fold(f64::INFINITY, f64::min);
    println!(
        "RESULT {name} log_n_rows={log_n_rows} cold_ms={:.1} warm_best_ms={warm_best:.1} warm_rows_per_s={:.0}",
        times_ms[0],
        n_rows as f64 / (warm_best / 1000.0)
    );
}

#[test]
#[ignore = "benchmark; run explicitly with --ignored"]
fn bench_metal() {
    run::<MetalBackend>("metal");
}

#[test]
#[ignore = "benchmark; run explicitly with --ignored"]
fn bench_simd() {
    run::<SimdBackend>("simd");
}
