use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use itertools::Itertools;
use num_traits::{One, Zero};
use rayon::prelude::*;
use serde::Serialize;
use sha2::{Digest, Sha256};
use stwo::core::air::Component;
use stwo::core::channel::Blake2sM31Channel;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
use stwo::core::verifier::verify;
use stwo::prover::backend::cpu::CpuBackend;
use stwo::prover::poly::circle::PolyOps;
use stwo::prover::{prove, CommitmentSchemeProver};
use stwo_constraint_framework::{FrameworkComponent, TraceLocationAllocator};
use stwo_examples::wide_fibonacci::generate_trace_cpu_parallel;
use stwo_examples::wide_fibonacci::{FibInput, WideFibonacciEval};

const PEER_REPOSITORY: &str = "https://github.com/ClementWalter/stwo";
const PEER_COMMIT: &str = "07ea1ccca13351028da94e66babf79e7ce91437f";
const N_COLUMNS: usize = 100;

#[derive(Serialize)]
struct TimingScope {
    prove: &'static str,
    verify: &'static str,
    total: &'static str,
    exclusions: &'static str,
}

#[derive(Serialize)]
struct Report {
    schema: &'static str,
    peer_repository: &'static str,
    peer_source_commit: &'static str,
    backend: &'static str,
    backend_type: &'static str,
    cargo_features: Vec<&'static str>,
    log_n_instances: u32,
    instances: u64,
    n_columns: usize,
    warmups: usize,
    samples: usize,
    rayon_threads: usize,
    timing_scope: TimingScope,
    metal_device_admitted: bool,
    trace_generation_backend: &'static str,
    prove_samples_ms: Vec<f64>,
    verify_samples_ms: Vec<f64>,
    verified_request_samples_ms: Vec<f64>,
    prove_median_ms: f64,
    verify_median_ms: f64,
    verified_request_median_ms: f64,
    row_mhz: f64,
    proof_size_bytes: usize,
    commitments: usize,
    security_bits: u32,
    fri_queries: usize,
    pow_bits: u32,
    log_blowup_factor: u32,
    log_last_layer_degree_bound: u32,
    fold_step: u32,
    proof_canonical_sha256: String,
    proof_canonical_bytes: usize,
    all_proofs_identical: bool,
    all_verified: bool,
}

struct Sample {
    prove_ms: f64,
    verify_ms: f64,
    verified_request_ms: f64,
    proof_size_bytes: usize,
    commitments: usize,
    security_bits: u32,
    fri_queries: usize,
    pow_bits: u32,
    log_blowup_factor: u32,
    log_last_layer_degree_bound: u32,
    fold_step: u32,
    proof_canonical_sha256: String,
    proof_canonical_bytes: usize,
    trace_generated_on_metal: bool,
}

const fn compiled_backend() -> &'static str {
    if cfg!(feature = "metal") {
        "peer-metal"
    } else {
        "peer-cpu"
    }
}

fn compiled_features() -> Vec<&'static str> {
    let mut features = vec!["parallel", "prover"];
    if cfg!(feature = "metal") {
        features.push("metal");
    }
    features
}

fn require_backend() -> bool {
    #[cfg(all(feature = "metal", target_os = "macos"))]
    {
        let device = metal::Device::system_default().expect("peer-metal requires a Metal device");
        assert!(
            device.has_unified_memory(),
            "peer-metal requires a unified-memory Metal device"
        );
        stwo::prover::backend::metal::warmup();
        true
    }
    #[cfg(all(feature = "metal", not(target_os = "macos")))]
    panic!("peer-metal is only supported on macOS");
    #[cfg(not(feature = "metal"))]
    false
}

fn test_inputs(log_n_instances: u32) -> Vec<FibInput> {
    (0..1u32 << log_n_instances)
        .into_par_iter()
        .map(|i| FibInput {
            a: BaseField::one(),
            b: BaseField::from_u32_unchecked(i),
        })
        .collect()
}

fn generate_trace(
    inputs: &[FibInput],
) -> (
    Vec<
        stwo::prover::poly::circle::CircleEvaluation<
            CpuBackend,
            BaseField,
            stwo::prover::poly::BitReversedOrder,
        >,
    >,
    bool,
) {
    #[cfg(all(feature = "metal", target_os = "macos"))]
    {
        if let Some(trace) =
            stwo_examples::wide_fibonacci::generate_trace_cpu_metal::<N_COLUMNS>(inputs)
        {
            return (trace, true);
        }
        (generate_trace_cpu_parallel::<N_COLUMNS>(inputs), false)
    }
    #[cfg(not(all(feature = "metal", target_os = "macos")))]
    (generate_trace_cpu_parallel::<N_COLUMNS>(inputs), false)
}

fn run_sample(log_n_instances: u32) -> Sample {
    // The supremacy verified-request boundary starts before deterministic input
    // construction. Backend/Metal initialization is intentionally performed by
    // `require_backend` before warmups and is measured only by the outer cold
    // process boundary.
    let request_start = Instant::now();
    let inputs = test_inputs(log_n_instances);
    let config = PcsConfig::default();
    let prove_start = Instant::now();
    let (twiddles, (trace, trace_generated_on_metal)) = rayon::join(
        || {
            CpuBackend::precompute_twiddles(
                CanonicCoset::new(log_n_instances + 1 + config.fri_config.log_blowup_factor)
                    .circle_domain()
                    .half_coset,
            )
        },
        || generate_trace(&inputs),
    );
    let prover_channel = &mut Blake2sM31Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    commitment_scheme.set_store_polynomials_coefficients();

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(vec![]);
    tree_builder.commit(prover_channel);

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(trace);
    tree_builder.commit(prover_channel);

    let component = FrameworkComponent::new(
        &mut TraceLocationAllocator::default(),
        WideFibonacciEval::<N_COLUMNS> {
            log_n_rows: log_n_instances,
        },
        SecureField::zero(),
    );
    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(
        &[&component],
        prover_channel,
        commitment_scheme,
    )
    .expect("proof generation must succeed");
    let prove_ms = prove_start.elapsed().as_secs_f64() * 1000.0;

    let canonical_proof = serde_json::to_vec(&proof).expect("proof encoding must succeed");
    let proof_canonical_sha256 = format!("{:x}", Sha256::digest(&canonical_proof));
    let proof_canonical_bytes = canonical_proof.len();

    let verify_start = Instant::now();
    let verifier_channel = &mut Blake2sM31Channel::default();
    let commitment_scheme_verifier =
        &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(proof.config);
    let sizes = component.trace_log_degree_bounds();
    commitment_scheme_verifier.commit(proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme_verifier.commit(proof.commitments[1], &sizes[1], verifier_channel);
    verify(
        &[&component as &dyn Component],
        verifier_channel,
        commitment_scheme_verifier,
        proof.clone(),
    )
    .expect("proof verification must succeed");
    let verify_ms = verify_start.elapsed().as_secs_f64() * 1000.0;
    let verified_request_ms = request_start.elapsed().as_secs_f64() * 1000.0;

    Sample {
        prove_ms,
        verify_ms,
        verified_request_ms,
        proof_size_bytes: proof_canonical_bytes,
        commitments: proof.commitments.len(),
        security_bits: proof.config.security_bits(),
        fri_queries: proof.config.fri_config.n_queries,
        pow_bits: proof.config.pow_bits,
        log_blowup_factor: proof.config.fri_config.log_blowup_factor,
        log_last_layer_degree_bound: proof.config.fri_config.log_last_layer_degree_bound,
        fold_step: proof.config.fri_config.fold_step,
        proof_canonical_sha256,
        proof_canonical_bytes,
        trace_generated_on_metal,
    }
}

fn median(values: &[f64]) -> f64 {
    let mut ordered = values.to_vec();
    ordered.sort_by(|a, b| a.total_cmp(b));
    let middle = ordered.len() / 2;
    if ordered.len() % 2 == 0 {
        (ordered[middle - 1] + ordered[middle]) / 2.0
    } else {
        ordered[middle]
    }
}

fn parse_arg<T: std::str::FromStr>(value: Option<String>, name: &str) -> T {
    value
        .unwrap_or_else(|| panic!("missing {name}"))
        .parse()
        .unwrap_or_else(|_| panic!("invalid {name}"))
}

fn main() {
    let mut args = env::args().skip(1);
    let requested_backend = args
        .next()
        .expect("usage: BACKEND LOG WARMUPS SAMPLES OUTPUT");
    let log_n_instances: u32 = parse_arg(args.next(), "log_n_instances");
    let warmups: usize = parse_arg(args.next(), "warmups");
    let samples: usize = parse_arg(args.next(), "samples");
    let output = PathBuf::from(args.next().expect("missing output path"));
    assert!(args.next().is_none(), "unexpected arguments");
    assert_eq!(
        requested_backend,
        compiled_backend(),
        "wrong compiled backend"
    );
    assert!(samples > 0);

    let metal_device_admitted = require_backend();
    for _ in 0..warmups {
        let _ = run_sample(log_n_instances);
    }

    let measured = (0..samples)
        .map(|_| run_sample(log_n_instances))
        .collect_vec();
    let prove_samples_ms = measured.iter().map(|sample| sample.prove_ms).collect_vec();
    let verify_samples_ms = measured.iter().map(|sample| sample.verify_ms).collect_vec();
    let verified_request_samples_ms = measured
        .iter()
        .map(|sample| sample.verified_request_ms)
        .collect_vec();
    let prove_median_ms = median(&prove_samples_ms);
    let last = measured.last().expect("at least one sample");
    let all_proofs_identical = measured
        .iter()
        .all(|sample| sample.proof_canonical_sha256 == last.proof_canonical_sha256);
    assert!(all_proofs_identical, "proofs changed between samples");
    assert!(measured
        .iter()
        .all(|sample| sample.trace_generated_on_metal == last.trace_generated_on_metal));

    let report = Report {
        schema: "peer-stwo-wide-fibonacci-adapter-v2",
        peer_repository: PEER_REPOSITORY,
        peer_source_commit: PEER_COMMIT,
        backend: compiled_backend(),
        backend_type: "stwo::prover::backend::cpu::CpuBackend",
        cargo_features: compiled_features(),
        log_n_instances,
        instances: 1u64 << log_n_instances,
        n_columns: N_COLUMNS,
        warmups,
        samples,
        rayon_threads: rayon::current_num_threads(),
        timing_scope: TimingScope {
            prove: "concurrent twiddle precompute and trace generation + commitments + prove",
            verify: "independent verifier over a cloned proof",
            total: "input construction + prove + proof hashing + independent verify; primary peer verified-request metric",
            exclusions:
                "process startup, backend/Metal initialization, warmups, JSON report write",
        },
        metal_device_admitted,
        trace_generation_backend: if last.trace_generated_on_metal {
            "metal"
        } else {
            "cpu-parallel"
        },
        prove_samples_ms,
        verify_samples_ms: verify_samples_ms.clone(),
        verified_request_samples_ms: verified_request_samples_ms.clone(),
        prove_median_ms,
        verify_median_ms: median(&verify_samples_ms),
        verified_request_median_ms: median(&verified_request_samples_ms),
        row_mhz: (1u64 << log_n_instances) as f64 / prove_median_ms / 1000.0,
        proof_size_bytes: last.proof_size_bytes,
        commitments: last.commitments,
        security_bits: last.security_bits,
        fri_queries: last.fri_queries,
        pow_bits: last.pow_bits,
        log_blowup_factor: last.log_blowup_factor,
        log_last_layer_degree_bound: last.log_last_layer_degree_bound,
        fold_step: last.fold_step,
        proof_canonical_sha256: last.proof_canonical_sha256.clone(),
        proof_canonical_bytes: last.proof_canonical_bytes,
        all_proofs_identical,
        all_verified: true,
    };
    fs::write(
        output,
        serde_json::to_string_pretty(&report).unwrap() + "\n",
    )
    .unwrap();
}
