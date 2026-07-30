//! Wall-clock prove benchmark over the testkit reference AIR (requires CUDA).
//!
//! ```bash
//! BENCH_LOG_N_ROWS=18 cargo test --release -p stwo-backend-cuda --test bench_prove \
//!     -- --ignored --nocapture
//! ```

use std::time::Instant;

use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleChannel;
use stwo::prover::backend::simd::SimdBackend;
use stwo_backend_cuda::CudaBackend;
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
        .unwrap_or(16);
    let n_rows = 1u64 << log_n_rows;
    let trace = generate_reference_trace(log_n_rows);

    let mut best = f64::INFINITY;
    for iter in 0..N_ITERS {
        let start = Instant::now();
        let proof = prove_reference::<B, Blake2sMerkleChannel>(trace.clone());
        let elapsed = start.elapsed().as_secs_f64() * 1000.0;
        drop(proof);
        if iter > 0 {
            best = best.min(elapsed);
        }
        println!("{name} log_n_rows={log_n_rows} iter={iter} ms={elapsed:.1}");
    }
    let (free, total) = stwo_backend_cuda::gpu_memory_info();
    println!(
        "RESULT {name} log_n_rows={log_n_rows} warm_best_ms={best:.1} warm_rows_per_s={:.0} vram_used_mb={}",
        n_rows as f64 / (best / 1000.0),
        if total > 0 { (total - free) / (1024 * 1024) } else { 0 }
    );
}

#[test]
#[ignore = "benchmark; run explicitly with --ignored on a CUDA machine"]
fn bench_cuda() {
    if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
        eprintln!("skipping: kernels not built");
        return;
    }
    run::<CudaBackend>("cuda");
}

#[test]
#[ignore = "benchmark; run explicitly with --ignored"]
fn bench_simd() {
    run::<SimdBackend>("simd");
}
