use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use serde::Serialize;

use super::*;

// Last qualified adaptive sm_90/H100 function envelope. CUDA resource
// allocation is architecture-specific; other SMs must first report facts.
const QUALIFIED_RESOURCE_SM: u32 = 90;
const QUALIFIED_MAX_REGISTERS_PER_THREAD: u32 = 82;
const QUALIFIED_MAX_LOCAL_BYTES: u64 = 32;
const QUALIFIED_MAX_STATIC_SHARED_BYTES: u64 = 4;

pub fn run(
    arena: &DeviceArena,
    prepared: &PreparedRelationGraph<'_>,
    program: &RelationKernelProgram,
    source_slots: &[Vec<ArenaSlotId>],
    current_sources: &[Vec<Vec<u32>>],
    current_alphas: &[SecureField],
    current_z: SecureField,
    adaptive_graph: &CudaGraphExec,
    expected_kernel_nodes: &[u64],
) {
    let max_tuple_words = |batch: &RelationBatchProgram| {
        batch
            .columns
            .iter()
            .flat_map(|column| &column.uses)
            .map(|relation_use| relation_use.tuple_words)
            .max()
            .unwrap_or(0)
    };
    let adaptive_lane_changes = program
        .batches
        .iter()
        .filter(|batch| {
            relation_batch_fused_eligible(batch)
                && batch.columns.len() <= 512
                && max_tuple_words(batch) <= 32
        })
        .count();
    let shared_one_read_lane = program
        .batches
        .iter()
        .filter(|batch| {
            relation_batch_fused_eligible(batch)
                && batch.columns.len() <= 512
                && max_tuple_words(batch) > 32
        })
        .count();
    assert!(
        adaptive_lane_changes > 0,
        "fixture must route one <=32-word batch differently"
    );
    assert!(
        shared_one_read_lane > 0,
        "fixture must keep one >32-word batch on one-read in both strategies"
    );

    let launch_adaptive = || {
        prepared.launch_fused_test_strategy(
            RelationFusedTestStrategy::Adaptive,
            RelationTailMode::Segmented,
        )
    };
    let launch_baseline = || {
        prepared.launch_fused_test_strategy(
            RelationFusedTestStrategy::AllOneReadBaseline,
            RelationTailMode::Segmented,
        )
    };
    let expected = reference(program, current_sources, current_alphas, current_z);

    launch_adaptive().unwrap();
    let adaptive_eager = read_snapshot(arena, prepared);
    launch_baseline().unwrap();
    let baseline_eager = read_snapshot(arena, prepared);
    assert_eq!(adaptive_eager, expected);
    assert_eq!(baseline_eager, expected);

    let capture = arena.context().capture().unwrap();
    launch_baseline().unwrap();
    let baseline_graph = capture.finish().unwrap();
    assert!(
        expected_kernel_nodes.contains(&baseline_graph.kernel_nodes()),
        "all-one-read capture node budget changed: expected one of \
         {expected_kernel_nodes:?}, got {}",
        baseline_graph.kernel_nodes()
    );
    baseline_graph.launch(arena.context()).unwrap();
    assert_eq!(read_snapshot(arena, prepared), expected);

    // Mutate both already-instantiated graphs back to the first known-good
    // fixture. The strategies must observe the exact same live pointers and
    // challenge slots rather than replay capture-time values.
    let mutated_sources = host_sources(23);
    upload_sources(arena, source_slots, &mutated_sources);
    let mutated_alphas = alpha_powers(
        SecureField::from_u32_unchecked(3, 5, 7, 11),
        program.max_alpha_powers as usize,
    );
    let mutated_z = SecureField::from_u32_unchecked(13, 17, 19, 23);
    prepared
        .upload_challenges_at_transcript_boundary(RelationChallenges {
            alpha_powers: &mutated_alphas,
            z: mutated_z,
        })
        .unwrap();
    let mutated_expected = reference(program, &mutated_sources, &mutated_alphas, mutated_z);
    adaptive_graph.launch(arena.context()).unwrap();
    let adaptive_replay = read_snapshot(arena, prepared);
    baseline_graph.launch(arena.context()).unwrap();
    let baseline_replay = read_snapshot(arena, prepared);
    assert_eq!(adaptive_replay, mutated_expected);
    assert_eq!(baseline_replay, mutated_expected);
    assert_ne!(adaptive_replay, adaptive_eager);

    let warmups = bounded_env_usize("STWO_RELATION_NATIVE_AB_WARMUPS", 5, 1, 100);
    let iterations = bounded_env_usize("STWO_RELATION_NATIVE_AB_ITERATIONS", 30, 5, 200);
    let eager = measure_alternating(
        arena.context(),
        warmups,
        iterations,
        launch_baseline,
        launch_adaptive,
    );
    let captured = measure_alternating(
        arena.context(),
        warmups,
        iterations,
        || baseline_graph.launch(arena.context()),
        || adaptive_graph.launch(arena.context()),
    );

    let adaptive_resources =
        PreparedRelationGraph::fused_test_function_resources(RelationFusedTestStrategy::Adaptive)
            .unwrap();
    let baseline_resources = PreparedRelationGraph::fused_test_function_resources(
        RelationFusedTestStrategy::AllOneReadBaseline,
    )
    .unwrap();
    let zero_denominator_batch = &program.batches[ZERO_DENOMINATOR_DIFFERENTIAL_BATCH];
    let zero_denominator_max_tuple_words = max_tuple_words(zero_denominator_batch);
    let zero_denominator_selector_differential =
        relation_batch_fused_eligible(zero_denominator_batch)
            && zero_denominator_batch.columns.len() <= 512
            && zero_denominator_max_tuple_words <= 32;
    assert!(
        zero_denominator_selector_differential,
        "zero-denominator fixture must take one-read in the baseline and \
         suffix/recompute in the adaptive selector"
    );
    let adaptive_zero_denominator_fail_closed = zero_denominator_is_fail_closed(false);
    let baseline_zero_denominator_fail_closed = zero_denominator_is_fail_closed(true);
    let invalid_input_guards = raw_guards_reject_invalid_inputs();
    let target_sms = stwo_backend_cuda_kernels::static_cuda_module_target_sms();
    let resource_abi_valid = [adaptive_resources, baseline_resources]
        .iter()
        .all(|resources| {
            resources.abi_version == 1
                && resources.reserved == 0
                && resources.max_threads_per_block >= 256
                && resources.binary_version != 0
                && resources.ptx_version != 0
                && resources.ptx_version <= resources.binary_version
                && target_sms.contains(&resources.binary_version)
        });
    let adaptive_within_qualified_envelope = adaptive_resources.registers_per_thread
        <= QUALIFIED_MAX_REGISTERS_PER_THREAD
        && adaptive_resources.local_bytes <= QUALIFIED_MAX_LOCAL_BYTES
        && adaptive_resources.static_shared_bytes <= QUALIFIED_MAX_STATIC_SHARED_BYTES;
    let adaptive_resource_ceiling_enforced =
        adaptive_resources.binary_version == QUALIFIED_RESOURCE_SM;
    let adaptive_resource_gate =
        !adaptive_resource_ceiling_enforced || adaptive_within_qualified_envelope;
    let adaptive_resource_policy = match adaptive_resources.binary_version {
        QUALIFIED_RESOURCE_SM => "qualified_sm_90_envelope",
        86 => "first_characterization_report_only",
        _ => "unqualified_architecture_report_only",
    };
    let adaptive_resource_limits = adaptive_resource_ceiling_enforced.then(|| {
        serde_json::json!({
            "registers_per_thread": QUALIFIED_MAX_REGISTERS_PER_THREAD,
            "local_bytes": QUALIFIED_MAX_LOCAL_BYTES,
            "static_shared_bytes": QUALIFIED_MAX_STATIC_SHARED_BYTES,
        })
    });
    let git_commit = std::env::var("STWO_PARITY_REF_STWO_HEAD")
        .expect("STWO_PARITY_REF_STWO_HEAD must seal the tested source");
    assert!(
        git_commit.len() == 40
            && git_commit
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "STWO_PARITY_REF_STWO_HEAD must be 40 lowercase hex digits"
    );
    let static_module_identity =
        stwo_backend_cuda_kernels::static_cuda_module_build_identity().unwrap();
    let checks = serde_json::json!({
        "same_fixture_host_bytes": true,
        "adaptive_eager_bytes": true,
        "baseline_eager_bytes": true,
        "adaptive_captured_mutation_bytes": true,
        "baseline_captured_mutation_bytes": true,
        "compact_mode_guard": true,
        "zero_denominator_selector_differential": zero_denominator_selector_differential,
        "adaptive_zero_denominator_fail_closed": adaptive_zero_denominator_fail_closed,
        "baseline_zero_denominator_fail_closed": baseline_zero_denominator_fail_closed,
        "invalid_input_guards": invalid_input_guards,
        "loaded_resource_abi": resource_abi_valid,
        "adaptive_resource_policy_admitted": adaptive_resource_gate,
        "eager_positive_median_speedup": eager.candidate_speedup > 1.0,
        "captured_positive_median_speedup": captured.candidate_speedup > 1.0,
    });
    let passed = resource_abi_valid
        && adaptive_resource_gate
        && zero_denominator_selector_differential
        && adaptive_zero_denominator_fail_closed
        && baseline_zero_denominator_fail_closed
        && invalid_input_guards
        && eager.candidate_speedup > 1.0
        && captured.candidate_speedup > 1.0;
    let receipt = serde_json::json!({
        "schema": "stwo.prepared-relation.same-binary-ab.v2",
        "passed": passed,
        "git_commit": git_commit,
        "fixture": "prepared_relation_native.cairo_program",
        "baseline": "pre_adaptive_columns_le_512_one_read",
        "baseline_source_commit": "0016f4b5",
        "candidate": "adaptive_tuple_width_gt_32_one_read",
        "selector_fixture": {
            "adaptive_lane_change_batches": adaptive_lane_changes,
            "shared_one_read_batches": shared_one_read_lane,
        },
        "zero_denominator_fixture": {
            "batch_index": ZERO_DENOMINATOR_DIFFERENTIAL_BATCH,
            "instance_index": ZERO_DENOMINATOR_DIFFERENTIAL_INSTANCE,
            "column_index": ZERO_DENOMINATOR_DIFFERENTIAL_COLUMN,
            "source_index": ZERO_DENOMINATOR_DIFFERENTIAL_SOURCE,
            "columns": zero_denominator_batch.columns.len(),
            "max_tuple_words": zero_denominator_max_tuple_words,
            "poisoned_use_tuple_words": zero_denominator_batch.columns
                [ZERO_DENOMINATOR_DIFFERENTIAL_COLUMN].uses[0].tuple_words,
            "tuple_class": "at_most_32_words",
            "baseline_lane": "one_read",
            "adaptive_lane": "suffix_recompute",
        },
        "ordering": "alternating_baseline_candidate_then_candidate_baseline",
        "percentiles": "sorted_linear_index",
        "checks": checks,
        "output_blake3": snapshot_hash(&mutated_expected),
        "static": {
            "source_identity": identity_hex(
                stwo_backend_cuda_kernels::static_cuda_source_identity()
            ),
            "module_build_identity": identity_hex(static_module_identity),
            "target_sms": target_sms,
            "block_threads": 256,
            "dynamic_shared_bytes": 24_560,
        },
        "loaded_functions": {
            "adaptive_relation_fused_kernel": resource_json(adaptive_resources),
            "all_one_read_test_kernel": resource_json(baseline_resources),
        },
        "adaptive_resource_policy": {
            "mode": adaptive_resource_policy,
            "binary_version": adaptive_resources.binary_version,
            "ceiling_enforced": adaptive_resource_ceiling_enforced,
            "limits": adaptive_resource_limits,
            "within_qualified_envelope": adaptive_resource_ceiling_enforced
                .then_some(adaptive_within_qualified_envelope),
        },
        "eager": eager,
        "captured": captured,
        "kernel_nodes": {
            "adaptive": adaptive_graph.kernel_nodes(),
            "baseline": baseline_graph.kernel_nodes(),
        },
    });
    publish(&receipt);
    assert!(
        passed,
        "same-binary adaptive relation promotion gate failed"
    );
}

fn snapshot_hash(snapshot: &[InstanceSnapshot]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"stwo.prepared-relation-native.snapshot.v1\0");
    for instance in snapshot {
        for word in [
            instance.batch_index as u64,
            instance.instance_index as u64,
            u64::from(instance.rows),
            u64::from(instance.columns),
        ] {
            hasher.update(&word.to_le_bytes());
        }
        for word in instance
            .coordinates
            .iter()
            .flatten()
            .chain(instance.claimed_sum.iter())
        {
            hasher.update(&word.to_le_bytes());
        }
    }
    hasher.finalize().to_hex().to_string()
}

fn identity_hex(identity: [u8; 32]) -> String {
    blake3::Hash::from_bytes(identity).to_hex().to_string()
}

fn resource_json(resources: RelationFusedTestFunctionResources) -> serde_json::Value {
    serde_json::json!({
        "abi_version": resources.abi_version,
        "max_threads_per_block": resources.max_threads_per_block,
        "registers_per_thread": resources.registers_per_thread,
        "binary_version": resources.binary_version,
        "ptx_version": resources.ptx_version,
        "reserved": resources.reserved,
        "local_bytes": resources.local_bytes,
        "static_shared_bytes": resources.static_shared_bytes,
    })
}

fn bounded_env_usize(name: &str, default: usize, minimum: usize, maximum: usize) -> usize {
    let value = std::env::var(name)
        .map(|value| value.parse::<usize>().unwrap())
        .unwrap_or(default);
    assert!(
        (minimum..=maximum).contains(&value),
        "{name} must be in {minimum}..={maximum}"
    );
    value
}

fn zero_denominator_is_fail_closed(all_one_read_baseline: bool) -> bool {
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .arg("--exact")
        .arg("fused_zero_denominator_child_process")
        .arg("--nocapture")
        .env("STWO_RELATION_ZERO_DENOMINATOR_CHILD", "1")
        .env_remove("STWO_RELATION_NATIVE_AB");
    if all_one_read_baseline {
        command.env("STWO_RELATION_ALL_ONE_READ_TEST", "1");
    } else {
        command.env_remove("STWO_RELATION_ALL_ONE_READ_TEST");
    }
    command.status().unwrap().success()
}

fn raw_guards_reject_invalid_inputs() -> bool {
    let launch_code = unsafe {
        stwo_backend_cuda_kernels::raw::stwo_relation_fused_all_one_read_test_on(
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::null(),
            0,
            0,
            core::ptr::null(),
            0,
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::null_mut(),
        )
    };
    let mut attributes = stwo_backend_cuda_kernels::raw::CudaFunctionAttributes::default();
    let resource_code = unsafe {
        stwo_backend_cuda_kernels::raw::stwo_relation_fused_test_function_attributes(
            u32::MAX,
            &mut attributes,
        )
    };
    launch_code != 0 && resource_code != 0 && attributes == Default::default()
}

#[derive(Clone, Debug, Serialize)]
pub struct TimingStats {
    pub samples_ms: Vec<f64>,
    pub median_ms: f64,
    pub p10_ms: f64,
    pub p90_ms: f64,
}

#[derive(Clone, Debug, Serialize)]
pub struct AlternatingTiming {
    pub warmups: usize,
    pub iterations: usize,
    pub baseline: TimingStats,
    pub candidate: TimingStats,
    pub candidate_speedup: f64,
}

pub fn measure_alternating<B, C, E>(
    context: &CudaExecContext,
    warmups: usize,
    iterations: usize,
    mut baseline: B,
    mut candidate: C,
) -> AlternatingTiming
where
    B: FnMut() -> Result<(), E>,
    C: FnMut() -> Result<(), E>,
    E: core::fmt::Debug,
{
    assert!((1..=100).contains(&warmups));
    assert!((5..=200).contains(&iterations));
    for iteration in 0..warmups {
        if iteration % 2 == 0 {
            baseline().unwrap();
            candidate().unwrap();
        } else {
            candidate().unwrap();
            baseline().unwrap();
        }
    }
    context.sync().unwrap();

    let events = CudaEvents::new();
    let mut baseline_ms = Vec::with_capacity(iterations);
    let mut candidate_ms = Vec::with_capacity(iterations);
    for iteration in 0..iterations {
        if iteration % 2 == 0 {
            baseline_ms.push(events.time(context, &mut baseline));
            candidate_ms.push(events.time(context, &mut candidate));
        } else {
            candidate_ms.push(events.time(context, &mut candidate));
            baseline_ms.push(events.time(context, &mut baseline));
        }
    }
    let baseline = stats(baseline_ms);
    let candidate = stats(candidate_ms);
    assert!(
        baseline.median_ms.is_finite()
            && baseline.median_ms > 0.0
            && candidate.median_ms.is_finite()
            && candidate.median_ms > 0.0,
        "CUDA-event medians must be finite and positive"
    );
    AlternatingTiming {
        warmups,
        iterations,
        candidate_speedup: baseline.median_ms / candidate.median_ms,
        baseline,
        candidate,
    }
}

pub fn publish(receipt: &serde_json::Value) {
    let json = serde_json::to_vec_pretty(receipt).unwrap();
    if let Some(path) = std::env::var_os("STWO_RELATION_NATIVE_AB_RECEIPT").map(PathBuf::from) {
        assert!(
            !path.exists(),
            "refusing to replace relation A/B receipt {}",
            path.display()
        );
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let temporary = path.with_extension(format!("tmp.{}", std::process::id()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .unwrap();
        file.write_all(&json).unwrap();
        file.write_all(b"\n").unwrap();
        file.sync_all().unwrap();
        fs::rename(temporary, path).unwrap();
    }
    println!(
        "STWO_RELATION_NATIVE_AB_RECEIPT_JSON={}",
        serde_json::to_string(receipt).unwrap()
    );
}

fn stats(samples_ms: Vec<f64>) -> TimingStats {
    let mut sorted = samples_ms.clone();
    sorted.sort_by(f64::total_cmp);
    TimingStats {
        median_ms: percentile(&sorted, 50),
        p10_ms: percentile(&sorted, 10),
        p90_ms: percentile(&sorted, 90),
        samples_ms,
    }
}

fn percentile(sorted: &[f64], percentile: usize) -> f64 {
    sorted[(sorted.len() - 1) * percentile / 100]
}

struct CudaEvents {
    start: *mut core::ffi::c_void,
    stop: *mut core::ffi::c_void,
}

impl CudaEvents {
    fn new() -> Self {
        let mut result = Self {
            start: core::ptr::null_mut(),
            stop: core::ptr::null_mut(),
        };
        unsafe {
            assert_eq!(cudaEventCreate(&mut result.start), 0);
            assert_eq!(cudaEventCreate(&mut result.stop), 0);
        }
        result
    }

    fn time<F, E>(&self, context: &CudaExecContext, launch: &mut F) -> f64
    where
        F: FnMut() -> Result<(), E>,
        E: core::fmt::Debug,
    {
        let mut milliseconds = 0.0f32;
        unsafe {
            assert_eq!(
                cudaEventRecord(self.start, context.stream_raw().as_ptr()),
                0
            );
        }
        launch().unwrap();
        unsafe {
            assert_eq!(cudaEventRecord(self.stop, context.stream_raw().as_ptr()), 0);
            assert_eq!(cudaEventSynchronize(self.stop), 0);
            assert_eq!(
                cudaEventElapsedTime(&mut milliseconds, self.start, self.stop),
                0
            );
        }
        f64::from(milliseconds)
    }
}

impl Drop for CudaEvents {
    fn drop(&mut self) {
        unsafe {
            assert_eq!(cudaEventDestroy(self.start), 0);
            assert_eq!(cudaEventDestroy(self.stop), 0);
        }
    }
}

extern "C" {
    fn cudaEventCreate(event: *mut *mut core::ffi::c_void) -> i32;
    fn cudaEventRecord(event: *mut core::ffi::c_void, stream: *mut core::ffi::c_void) -> i32;
    fn cudaEventSynchronize(event: *mut core::ffi::c_void) -> i32;
    fn cudaEventElapsedTime(
        milliseconds: *mut f32,
        start: *mut core::ffi::c_void,
        stop: *mut core::ffi::c_void,
    ) -> i32;
    fn cudaEventDestroy(event: *mut core::ffi::c_void) -> i32;
}
