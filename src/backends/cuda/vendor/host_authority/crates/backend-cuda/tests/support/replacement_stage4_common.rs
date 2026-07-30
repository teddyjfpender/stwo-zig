use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::Serialize;
use stwo::core::vcs::blake2_hash::Blake2sHash;
use stwo_backend_cuda::{
    ArenaLayout, ArenaSlice, ArenaSlotId, ArenaSlotSpec, CudaExecContext, DeviceArena,
};

#[derive(Clone, Copy)]
pub struct SlotRequest {
    pub id: ArenaSlotId,
    pub words: usize,
    pub alignment_words: usize,
}

#[derive(Debug, Serialize)]
pub struct FixtureReceipt {
    pub name: &'static str,
    pub production_apis: Vec<&'static str>,
    pub cases: usize,
    pub arena_bytes: usize,
    pub checks: BTreeMap<String, bool>,
    pub hashes: BTreeMap<String, String>,
}

#[derive(Debug, Serialize)]
pub struct AdmissionReceipt {
    pub schema: &'static str,
    pub fixture_filter: &'static str,
    pub run_id: String,
    pub unix_timestamp: u64,
    pub passed: bool,
    pub failure: Option<String>,
    pub git_commit: String,
    pub executable_blake3: String,
    pub source_blake3: String,
    pub cuda_device: String,
    pub requested_cuda_arch: String,
    pub nvcc_version: String,
    pub free_memory_before_bytes: usize,
    pub free_memory_after_bytes: usize,
    pub total_memory_bytes: usize,
    pub fixtures: Vec<FixtureReceipt>,
    pub performance_requested: bool,
    pub performance_failure: Option<String>,
    pub performance: Vec<PerformanceReceipt>,
}

#[derive(Debug, Serialize)]
pub struct PerformanceReceipt {
    pub name: String,
    pub parameters: BTreeMap<String, u64>,
    pub arena_bytes: BTreeMap<String, usize>,
    pub traffic_bytes: BTreeMap<String, u64>,
    pub loaded_functions: Vec<LoadedFunctionReceipt>,
    pub baseline_label: String,
    pub candidate_label: String,
    pub baseline: TimingStats,
    pub candidate: TimingStats,
    pub speedup: f64,
}

#[derive(Clone, Debug, Serialize)]
pub struct LoadedFunctionReceipt {
    pub role: &'static str,
    pub symbol: &'static str,
    pub launch_threads: u32,
    pub dynamic_shared_bytes: u64,
    pub abi_version: u32,
    pub max_threads_per_block: u32,
    pub registers_per_thread: u32,
    pub binary_version: u32,
    pub ptx_version: u32,
    pub reserved: u32,
    pub local_bytes: u64,
    pub static_shared_bytes: u64,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct TimingStats {
    pub warmups: usize,
    pub iterations: usize,
    pub median_ms: f64,
    pub p10_ms: f64,
    pub p90_ms: f64,
}

pub fn arena(requests: impl IntoIterator<Item = SlotRequest>) -> (DeviceArena, usize) {
    let mut offset = 0usize;
    let specs = requests
        .into_iter()
        .map(|request| {
            assert!(request.words != 0, "zero-sized arena slot {:?}", request.id);
            offset = offset.next_multiple_of(request.alignment_words);
            let spec = ArenaSlotSpec {
                id: request.id,
                offset_words: offset,
                len_words: request.words,
                alignment_words: request.alignment_words,
            };
            offset += request.words;
            spec
        })
        .collect::<Vec<_>>();
    let bytes = offset * core::mem::size_of::<u32>();
    let layout = ArenaLayout::new(offset, &specs).unwrap();
    (
        DeviceArena::new(CudaExecContext::new().unwrap(), layout).unwrap(),
        bytes,
    )
}

pub fn upload_words(arena: &DeviceArena, destination: ArenaSlice, words: &[u32]) {
    assert!(words.len() <= destination.len_words());
    unsafe {
        arena
            .context()
            .memcpy_h2d_async(
                destination.as_void_ptr(),
                words.as_ptr().cast(),
                core::mem::size_of_val(words),
            )
            .unwrap();
    }
}

pub fn upload_usizes(arena: &DeviceArena, destination: ArenaSlice, words: &[usize]) {
    assert!(core::mem::size_of_val(words) <= destination.len_bytes());
    unsafe {
        arena
            .context()
            .memcpy_h2d_async(
                destination.as_void_ptr(),
                words.as_ptr().cast(),
                core::mem::size_of_val(words),
            )
            .unwrap();
    }
}

pub fn fill(arena: &DeviceArena, destination: ArenaSlice, byte: u8) {
    unsafe {
        arena
            .context()
            .memset_async(destination.as_void_ptr(), byte, destination.len_bytes())
            .unwrap();
    }
}

pub fn read_words(arena: &DeviceArena, source: ArenaSlice, words: usize) -> Vec<u32> {
    assert!(words <= source.len_words());
    let mut result = vec![0u32; words];
    unsafe {
        arena
            .context()
            .memcpy_d2h_async(
                result.as_mut_ptr().cast(),
                source.as_void_ptr().cast_const(),
                core::mem::size_of_val(result.as_slice()),
            )
            .unwrap();
    }
    arena.context().sync().unwrap();
    result
}

pub fn read_hashes(arena: &DeviceArena, source: ArenaSlice, hashes: usize) -> Vec<Blake2sHash> {
    let mut result = vec![Blake2sHash::default(); hashes];
    assert!(core::mem::size_of_val(result.as_slice()) <= source.len_bytes());
    unsafe {
        arena
            .context()
            .memcpy_d2h_async(
                result.as_mut_ptr().cast(),
                source.as_void_ptr().cast_const(),
                core::mem::size_of_val(result.as_slice()),
            )
            .unwrap();
    }
    arena.context().sync().unwrap();
    result
}

pub fn hash_words(words: &[u32]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"stwo.stage4.words.v1\0");
    for word in words {
        hasher.update(&word.to_le_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

pub fn hash_hashes(hashes: &[Blake2sHash]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"stwo.stage4.blake2s.v1\0");
    for hash in hashes {
        hasher.update(&hash.0);
    }
    hasher.finalize().to_hex().to_string()
}

pub fn receipt(
    fixture_filter: &'static str,
    fixtures: Vec<FixtureReceipt>,
    performance_requested: bool,
    performance_failure: Option<String>,
    performance: Vec<PerformanceReceipt>,
    memory_before: (usize, usize),
    memory_after: (usize, usize),
) -> Result<AdmissionReceipt, String> {
    let unix_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| format!("system clock: {error}"))?
        .as_secs();
    let git_commit = std::env::var("STWO_STAGE4_GIT_COMMIT")
        .map_err(|_| "STWO_STAGE4_GIT_COMMIT must seal the synced source head".to_owned())?;
    if git_commit.len() != 40
        || !git_commit
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(format!(
            "STWO_STAGE4_GIT_COMMIT must be 40 lowercase hex digits: {git_commit}"
        ));
    }
    let executable_blake3 =
        hash_file(&std::env::current_exe().map_err(|error| error.to_string())?)?;
    let source_blake3 = source_hash()?;
    let cuda_device = command_output(
        "nvidia-smi",
        &[
            "--query-gpu=name,uuid,compute_cap,driver_version",
            "--format=csv,noheader,nounits",
        ],
    )?;
    if cuda_device.lines().count() != 1 {
        return Err(format!(
            "receipt requires exactly one visible nvidia-smi device, got {:?}",
            cuda_device.lines().collect::<Vec<_>>()
        ));
    }
    let requested_cuda_arch = std::env::var("STWO_CUDA_ARCH")
        .map_err(|_| "STWO_CUDA_ARCH must be explicit for native admission".to_owned())?;
    let fields = cuda_device.split(',').map(str::trim).collect::<Vec<_>>();
    if fields.len() != 4 {
        return Err(format!(
            "invalid nvidia-smi device identity {cuda_device:?}"
        ));
    }
    let detected_cuda_arch = format!("sm_{}", fields[2].replace('.', ""));
    if requested_cuda_arch != detected_cuda_arch {
        return Err(format!(
            "STWO_CUDA_ARCH mismatch: requested={requested_cuda_arch:?} detected={detected_cuda_arch:?}"
        ));
    }
    let nvcc_version = command_output("nvcc", &["--version"])?;
    if memory_before.1 == 0 || memory_before.1 != memory_after.1 {
        return Err(format!(
            "invalid CUDA memory identity: before={memory_before:?} after={memory_after:?}"
        ));
    }
    Ok(AdmissionReceipt {
        schema: "stwo.replacement-stage4-native.v1",
        fixture_filter,
        run_id: format!(
            "{unix_timestamp}-{}-{}",
            std::process::id(),
            &executable_blake3[..12]
        ),
        unix_timestamp,
        passed: true,
        failure: None,
        git_commit,
        executable_blake3,
        source_blake3,
        cuda_device,
        requested_cuda_arch,
        nvcc_version,
        free_memory_before_bytes: memory_before.0,
        free_memory_after_bytes: memory_after.0,
        total_memory_bytes: memory_before.1,
        fixtures,
        performance_requested,
        performance_failure,
        performance,
    })
}

#[cfg(stwo_cuda_link)]
pub fn cuda_event_timings<F, E>(
    context: &CudaExecContext,
    warmups: usize,
    iterations: usize,
    mut launch: F,
) -> TimingStats
where
    F: FnMut() -> Result<(), E>,
    E: core::fmt::Debug,
{
    assert!(iterations >= 2);
    for _ in 0..warmups {
        launch().unwrap();
    }
    context.sync().unwrap();
    let events = CudaEvents::new();
    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        events.record_start(context);
        launch().unwrap();
        samples.push(events.finish_ms(context) as f64);
    }
    timing_stats(warmups, samples)
}

/// Paired CUDA-event timings in alternating `AB, BA` order.
///
/// Both variants are deliberately bound to one context stream.
/// `*_check` runs only after the stop event has completed, so status fences
/// attest every replay without being reported as kernel time.
#[cfg(stwo_cuda_link)]
#[allow(clippy::too_many_arguments)]
pub fn cuda_event_abba_timings<FA, EA, FB, EB, CA, CB>(
    context: &CudaExecContext,
    warmups: usize,
    iterations: usize,
    mut baseline_launch: FA,
    mut candidate_launch: FB,
    mut baseline_check: CA,
    mut candidate_check: CB,
) -> (TimingStats, TimingStats)
where
    FA: FnMut() -> Result<(), EA>,
    EA: core::fmt::Debug,
    FB: FnMut() -> Result<(), EB>,
    EB: core::fmt::Debug,
    CA: FnMut(),
    CB: FnMut(),
{
    assert!(iterations >= 2);
    for iteration in 0..warmups {
        if paired_baseline_first(iteration) {
            checked_launch(&mut baseline_launch, &mut baseline_check);
            checked_launch(&mut candidate_launch, &mut candidate_check);
        } else {
            checked_launch(&mut candidate_launch, &mut candidate_check);
            checked_launch(&mut baseline_launch, &mut baseline_check);
        }
    }

    let baseline_events = CudaEvents::new();
    let candidate_events = CudaEvents::new();
    let mut baseline_samples = Vec::with_capacity(iterations);
    let mut candidate_samples = Vec::with_capacity(iterations);
    for iteration in 0..iterations {
        if paired_baseline_first(iteration) {
            baseline_samples.push(checked_sample(
                context,
                &baseline_events,
                &mut baseline_launch,
                &mut baseline_check,
            ));
            candidate_samples.push(checked_sample(
                context,
                &candidate_events,
                &mut candidate_launch,
                &mut candidate_check,
            ));
        } else {
            candidate_samples.push(checked_sample(
                context,
                &candidate_events,
                &mut candidate_launch,
                &mut candidate_check,
            ));
            baseline_samples.push(checked_sample(
                context,
                &baseline_events,
                &mut baseline_launch,
                &mut baseline_check,
            ));
        }
    }
    (
        timing_stats(warmups, baseline_samples),
        timing_stats(warmups, candidate_samples),
    )
}

#[cfg(stwo_cuda_link)]
fn checked_launch<F, E, C>(launch: &mut F, check: &mut C)
where
    F: FnMut() -> Result<(), E>,
    E: core::fmt::Debug,
    C: FnMut(),
{
    launch().unwrap();
    check();
}

#[cfg(stwo_cuda_link)]
fn checked_sample<F, E, C>(
    context: &CudaExecContext,
    events: &CudaEvents,
    launch: &mut F,
    check: &mut C,
) -> f64
where
    F: FnMut() -> Result<(), E>,
    E: core::fmt::Debug,
    C: FnMut(),
{
    events.record_start(context);
    launch().unwrap();
    let elapsed = events.finish_ms(context) as f64;
    check();
    elapsed
}

#[cfg(stwo_cuda_link)]
fn timing_stats(warmups: usize, mut samples: Vec<f64>) -> TimingStats {
    samples.sort_by(f64::total_cmp);
    TimingStats {
        warmups,
        iterations: samples.len(),
        median_ms: percentile(&samples, 50),
        p10_ms: percentile(&samples, 10),
        p90_ms: percentile(&samples, 90),
    }
}

const fn paired_baseline_first(iteration: usize) -> bool {
    iteration % 2 == 0
}

#[cfg(stwo_cuda_link)]
fn percentile(samples: &[f64], percentile: usize) -> f64 {
    samples[(samples.len() - 1) * percentile / 100]
}

#[cfg(test)]
mod timing_contract_tests {
    use super::paired_baseline_first;

    #[test]
    fn paired_order_is_ab_ba() {
        assert_eq!(
            (0..6).map(paired_baseline_first).collect::<Vec<_>>(),
            [true, false, true, false, true, false]
        );
    }

    #[test]
    fn checked_sample_observes_status_after_event_timing() {
        let source = include_str!("replacement_stage4_common.rs");
        let begin = source.find("fn checked_sample").unwrap();
        let end = source[begin..]
            .find("fn timing_stats")
            .map(|offset| begin + offset)
            .unwrap();
        let sample = &source[begin..end];
        assert!(
            sample.find("events.finish_ms(context)").unwrap() < sample.find("check();").unwrap()
        );
    }
}

#[cfg(stwo_cuda_link)]
struct CudaEvents {
    start: *mut core::ffi::c_void,
    stop: *mut core::ffi::c_void,
}

#[cfg(stwo_cuda_link)]
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

    fn record_start(&self, context: &CudaExecContext) {
        unsafe {
            assert_eq!(
                cudaEventRecord(self.start, context.stream_raw().as_ptr()),
                0
            );
        }
    }

    fn finish_ms(&self, context: &CudaExecContext) -> f32 {
        let mut elapsed = 0.0f32;
        unsafe {
            assert_eq!(cudaEventRecord(self.stop, context.stream_raw().as_ptr()), 0);
            assert_eq!(cudaEventSynchronize(self.stop), 0);
            assert_eq!(cudaEventElapsedTime(&mut elapsed, self.start, self.stop), 0);
        }
        elapsed
    }
}

#[cfg(stwo_cuda_link)]
impl Drop for CudaEvents {
    fn drop(&mut self) {
        unsafe {
            assert_eq!(cudaEventDestroy(self.start), 0);
            assert_eq!(cudaEventDestroy(self.stop), 0);
        }
    }
}

#[cfg(stwo_cuda_link)]
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

pub fn publish_receipt(receipt: &AdmissionReceipt) {
    let json = serde_json::to_vec_pretty(receipt).unwrap();
    if let Some(path) = std::env::var_os("STWO_STAGE4_NATIVE_RECEIPT").map(PathBuf::from) {
        assert!(
            !path.exists(),
            "refusing to replace existing receipt {}",
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
        fs::rename(&temporary, &path).unwrap();
    }
    println!(
        "STWO_STAGE4_NATIVE_RECEIPT_JSON={}",
        serde_json::to_string(receipt).unwrap()
    );
}

pub fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| {
            payload
                .downcast_ref::<&str>()
                .map(|value| (*value).to_owned())
        })
        .unwrap_or_else(|| "non-string panic payload".to_owned())
}

fn command_output(program: &str, arguments: &[&str]) -> Result<String, String> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let output = std::process::Command::new(program)
        .args(arguments)
        .current_dir(manifest.parent().and_then(Path::parent).unwrap_or(manifest))
        .output()
        .map_err(|error| format!("{program}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "{program} exited unsuccessfully: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let output = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if output.is_empty() {
        return Err(format!("{program} produced no identity output"));
    }
    Ok(output)
}

fn hash_file(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn source_hash() -> Result<String, String> {
    const FILES: &[(&str, &[u8])] = &[
        (
            "src/backend/prepared_progressive_commit/domain_cooperative_binding.rs",
            include_bytes!(
                "../../src/backend/prepared_progressive_commit/domain_cooperative_binding.rs"
            ),
        ),
        (
            "src/backend/prepared_progressive_commit/domain_cooperative.rs",
            include_bytes!("../../src/backend/prepared_progressive_commit/domain_cooperative.rs"),
        ),
        (
            "src/backend/prepared_progressive_commit/program.rs",
            include_bytes!("../../src/backend/prepared_progressive_commit/program.rs"),
        ),
        (
            "src/backend/prepared_progressive_commit/program_binding.rs",
            include_bytes!("../../src/backend/prepared_progressive_commit/program_binding.rs"),
        ),
        (
            "src/backend/prepared_quotient_numerator/single_write.rs",
            include_bytes!("../../src/backend/prepared_quotient_numerator/single_write.rs"),
        ),
        (
            "src/backend/prepared_quotient_numerator/launch.rs",
            include_bytes!("../../src/backend/prepared_quotient_numerator/launch.rs"),
        ),
        (
            "src/backend/prepared_quotient_numerator/prepacked.rs",
            include_bytes!("../../src/backend/prepared_quotient_numerator/prepacked.rs"),
        ),
        (
            "src/backend/quotient_numerator_staged_single_write.rs",
            include_bytes!("../../src/backend/quotient_numerator_staged_single_write.rs"),
        ),
        (
            "../backend-cuda-kernels/cuda/blake2s_quad.cu",
            include_bytes!("../../../backend-cuda-kernels/cuda/blake2s_quad.cu"),
        ),
        (
            "../backend-cuda-kernels/cuda/blake2s.cuh",
            include_bytes!("../../../backend-cuda-kernels/cuda/blake2s.cuh"),
        ),
        (
            "../backend-cuda-kernels/cuda/quotient_numerator_single_write.cu",
            include_bytes!("../../../backend-cuda-kernels/cuda/quotient_numerator_single_write.cu"),
        ),
        (
            "../backend-cuda-kernels/cuda/quotient_numerator_single_write.cuh",
            include_bytes!(
                "../../../backend-cuda-kernels/cuda/quotient_numerator_single_write.cuh"
            ),
        ),
        (
            "../backend-cuda-kernels/cuda/resource_attestation.cuh",
            include_bytes!("../../../backend-cuda-kernels/cuda/resource_attestation.cuh"),
        ),
        (
            "../backend-cuda-kernels/src/raw.rs",
            include_bytes!("../../../backend-cuda-kernels/src/raw.rs"),
        ),
        (
            "tests/replacement_stage4_native.rs",
            include_bytes!("../replacement_stage4_native.rs"),
        ),
        (
            "tests/support/replacement_stage4_common.rs",
            include_bytes!("replacement_stage4_common.rs"),
        ),
        (
            "tests/support/replacement_stage4_mode_a.rs",
            include_bytes!("replacement_stage4_mode_a.rs"),
        ),
        (
            "tests/support/replacement_stage4_bench.rs",
            include_bytes!("replacement_stage4_bench.rs"),
        ),
        (
            "tests/support/replacement_stage4_quotient.rs",
            include_bytes!("replacement_stage4_quotient.rs"),
        ),
        (
            "tests/support/replacement_stage4_quotient_prepacked.rs",
            include_bytes!("replacement_stage4_quotient_prepacked.rs"),
        ),
        (
            "tests/support/replacement_stage4_quotient_resources.rs",
            include_bytes!("replacement_stage4_quotient_resources.rs"),
        ),
    ];
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"stwo.stage4.sources.v1\0");
    for (relative, bytes) in FILES {
        hasher.update(relative.as_bytes());
        hasher.update(b"\0");
        hasher.update(bytes);
    }
    Ok(hasher.finalize().to_hex().to_string())
}
