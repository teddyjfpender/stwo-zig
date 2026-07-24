//! AOT kernel-source emission surface (GPU_RESIDENT_PROVER_DESIGN.md §4, M3).
//!
//! The recording front-ends stay the source of truth; this module exposes them
//! to the `kernel_emit` tool so kernel SOURCES are generated at build time and
//! compiled offline (nvcc -O3, per-arch cubins embedded in the fatbin) instead
//! of at prove time (NVRTC + driver ptxas — the cold-start and sm_90-cliff
//! vehicle). The emitted source text is BYTE-IDENTICAL to what the JIT lane
//! would compile: same codegen, same cache keys — a prove-time cache-key lookup
//! that misses the AOT table simply falls back to NVRTC (the drift check).
//!
//! Constraint kernels use the same instruction and compacted-live-lane split
//! policy as the runtime lowerer. The exact policy is sealed into the pack
//! identity, while per-key strict lookup proves complete source/shape coverage;
//! a matching policy tag alone never admits a partial or stale pack.

mod function_publication;
mod installed_function;

pub use function_publication::{
    loaded_aot_function_publication, LoadedAotFunctionPublication,
    LoadedAotFunctionPublicationError,
};
pub use installed_function::{
    CheckedAotArguments, InstalledAotFunction, InstalledAotFunctionError,
    InstalledAotFunctionOwnership, InstalledAotFunctionReceipt, InstalledAotFunctionResources,
    InstalledAotLaunchFacts,
};
pub use stwo_backend_cuda_kernels::aot_pack::{
    AotKernelAbiAccess, AotKernelAbiArgument, AotKernelAbiKind, AotKernelAbiSchema,
    AotKernelAuthority, AotKernelModuleGlobals, AotKernelSchemaScope,
};

/// Canonical identity the AOT pack binds to an emitted CUDA translation unit.
pub fn emitted_source_identity(source: &str) -> [u8; 32] {
    stwo_backend_cuda_kernels::aot_source_identity(source.as_bytes())
}

/// Collision-resistant identity of the exact AOT cubins and generation
/// policies embedded in this binary. All-zero means absent or policy-invalid
/// and is never source authority. Compiled proofs that require source/symbol
/// or structured ABI provenance must retain each [`loaded_kernel_authority`]
/// identity.
pub fn loaded_manifest_identity() -> [u8; 32] {
    let identity = stwo_backend_cuda_kernels::aot_pack::aot_pack_identity();
    if identity == [0; 32]
        || loaded_constraint_max_live_u32_lanes() != constraint_split_max_live_u32_lanes()
    {
        return [0; 32];
    }
    identity
}

/// Collision-resistant identity of one exact loaded `(cache_key, SM)` cubin.
/// All-zero means absent, malformed, or rejected with the containing pack.
pub fn loaded_cubin_identity(cache_key: u64, sm_major: u32, sm_minor: u32) -> [u8; 32] {
    if loaded_manifest_identity() == [0; 32] {
        return [0; 32];
    }
    stwo_backend_cuda_kernels::aot_pack::aot_cubin_identity(cache_key, sm_major, sm_minor)
}

/// Exact source/symbol/semantic/binary authority for one loaded kernel.
/// `None` means absent or rejected with the containing pack. The schema scope
/// is structured only for typed generator families which emit an exact
/// argument/access contract; unsupported families remain symbol-only.
pub fn loaded_kernel_authority(
    cache_key: u64,
    sm_major: u32,
    sm_minor: u32,
) -> Option<AotKernelAuthority> {
    if loaded_manifest_identity() == [0; 32] {
        return None;
    }
    stwo_backend_cuda_kernels::aot_pack::aot_kernel_authority(cache_key, sm_major, sm_minor)
}

/// Non-authoritative u64 compatibility/telemetry projection of
/// [`loaded_manifest_identity`]. New graph and kernel authority must use the full
/// 32-byte identity.
pub fn loaded_manifest_hash() -> u64 {
    if loaded_manifest_identity() == [0; 32] {
        return 0;
    }
    stwo_backend_cuda_kernels::aot_pack::aot_pack_manifest_hash()
}

/// Exact number of kernels embedded across every target architecture.
pub fn loaded_kernel_count() -> usize {
    stwo_backend_cuda_kernels::aot_pack::aot_pack_entries()
}

/// Exact number of kernels embedded for one target architecture.
pub fn loaded_kernel_count_for_arch(sm_major: u32, sm_minor: u32) -> usize {
    stwo_backend_cuda_kernels::aot_pack::aot_pack_entries_for_arch(sm_major, sm_minor)
}

/// Exact constraint split cap used by the loaded AOT pack. Zero means the
/// current binary has no pack and is invalid for resident composition planning.
pub fn loaded_constraint_max_instrs() -> usize {
    stwo_backend_cuda_kernels::aot_pack::aot_pack_constraint_max_instrs()
}

/// Exact compacted live-u32-lane cap used by the loaded AOT pack. Zero means no
/// pack is present. [`loaded_manifest_identity`] rejects a stale pack whose value
/// does not match the runtime lowerer's compiled policy.
pub fn loaded_constraint_max_live_u32_lanes() -> usize {
    stwo_backend_cuda_kernels::aot_pack::aot_pack_constraint_max_live_u32_lanes()
}

/// Runtime/AOT constraint splitter register-pressure policy identity.
pub const fn constraint_split_max_live_u32_lanes() -> usize {
    super::jit::CONSTRAINT_SPLIT_MAX_LIVE_U32_LANES
}

/// Cheap device-architecture admission check. Individual semantic lookups still
/// fail closed in strict GPU-native mode, so a partial pack cannot masquerade as
/// complete merely because it contains one kernel for the device.
pub fn supports_arch(sm_major: u32, sm_minor: u32) -> bool {
    loaded_manifest_identity() != [0; 32]
        && stwo_backend_cuda_kernels::aot_pack::aot_pack_supports_arch(sm_major, sm_minor)
}

/// Cheap read-only admission check for an exact embedded kernel. This searches
/// the sealed binary's static AOT index and does not initialize CUDA.
pub fn contains_loaded_kernel(cache_key: u64, sm_major: u32, sm_minor: u32) -> bool {
    loaded_cubin_identity(cache_key, sm_major, sm_minor) != [0; 32]
}

pub use stwo_backend_cuda_kernels::raw::CudaJitAotStats as RuntimeStats;

/// Permanently select the fail-closed AOT-only lane for generated kernels.
///
/// This closes runtime admission and waits for every previously admitted compile,
/// cache publication, and launch enqueue to leave its native operation scope before
/// returning. It does not synchronize completion of arbitrary GPU work that was already
/// queued, so calling it during prover construction, before proof work begins, is a
/// precondition.
pub fn require_loaded_kernels() {
    unsafe { stwo_backend_cuda_kernels::raw::stwo_cuda_jit_set_require_aot(true) }
}

pub fn runtime_stats() -> RuntimeStats {
    let mut stats = RuntimeStats::default();
    unsafe { stwo_backend_cuda_kernels::raw::stwo_cuda_jit_get_aot_stats(&mut stats) };
    stats
}

pub fn reset_runtime_stats() {
    unsafe { stwo_backend_cuda_kernels::raw::stwo_cuda_jit_reset_aot_stats() }
}

use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::FrameworkEval;

use super::jit::{
    cuda_codegen, lower_for_aot as lower_framework_eval_to_v1_split,
    lower_for_aot_with_live_cap as lower_framework_eval_to_v1_split_with_live_cap,
};

/// One emitted kernel: `name`/`cache_key` are the launch-time lookup identity
/// (identical to the JIT lane's), `source` is the self-contained CUDA TU.
pub struct EmittedKernel {
    pub kernel_name: String,
    pub cache_key: u64,
    pub semantic_hash: u64,
    pub source: String,
    /// Structured only when the typed source emitter owns an exact ABI schema.
    pub abi_schema: Option<AotKernelAbiSchema>,
    /// Collision-resistant typed-program identity; absent for unsupported families.
    pub program_identity: Option<[u8; 32]>,
}

/// One split part of a prepared constraint program. `rc_base` is the exact
/// global offset into that component's random-coefficient slice used by the
/// generated kernel ABI.
pub struct EmittedConstraintKernel {
    pub kernel: EmittedKernel,
    pub rc_base: u32,
    /// Opaque lowered program reused only when `kernel_emit` assembles an
    /// exact same-domain composition wave. Production plans keep the ordinary
    /// kernel identity and never interpret this representation.
    pub wave_fragment: ConstraintWaveFragment,
}

/// One resource-governed constraint part retained for offline wave emission.
/// Its bytecode fields stay private so callers cannot construct a source/key
/// pair which did not come from the canonical constraint lowerer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConstraintWaveFragment {
    program: super::jit::OwnedMetalEvaluationProgramV1,
}

impl ConstraintWaveFragment {
    pub fn semantic_hash(&self) -> u64 {
        self.program.header().semantic_hash
    }

    fn program_identity(&self) -> [u8; 32] {
        self.program.semantic_identity()
    }
}

/// Stable identity of one exact evaluation-domain composition wave.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompositionWaveKernelIdentity {
    pub evaluation_log_size: u32,
    pub part_count: usize,
    pub kernel_name: String,
    pub semantic_hash: u64,
    pub cache_key: u64,
}

/// Source-independent identity of one canonical part inside a wave. The
/// coefficient span is proof-global and makes a reordered or cross-domain
/// descriptor set a different AOT key even when two AIR parts share bytecode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompositionWaveKernelPartIdentity {
    pub semantic_hash: u64,
    pub coefficient_start: u32,
    pub coefficient_end: u32,
}

/// Version of the wave ABI/source emitter. Independent from the ordinary
/// per-part emitter because both kernel families coexist in the AOT pack.
///
/// V2 separates the immutable full-domain trace stride from the shard's
/// start/length and writes each result at the shard-local output index.
pub const COMPOSITION_WAVE_CODEGEN_VERSION: u64 = 2;
pub const COMPOSITION_WAVE_KERNEL_ARGUMENT_COUNT: u8 = 9;
pub const COMPOSITION_WAVE_FULL_DOMAIN_ROWS_ARGUMENT: u8 = 6;
pub const COMPOSITION_WAVE_SHARD_START_ARGUMENT: u8 = 7;
pub const COMPOSITION_WAVE_SHARD_ROWS_ARGUMENT: u8 = 8;
pub const COMPOSITION_WAVE_THREADS_PER_BLOCK: usize = 128;

fn composition_wave_semantic_hashes_match(
    identities: &[CompositionWaveKernelPartIdentity],
    fragment_semantic_hashes: &[u64],
) -> bool {
    identities.len() == fragment_semantic_hashes.len()
        && identities
            .iter()
            .zip(fragment_semantic_hashes)
            .all(|(identity, &fragment_hash)| identity.semantic_hash == fragment_hash)
}

fn composition_wave_program_identity(
    evaluation_log_size: u32,
    parts: &[(CompositionWaveKernelPartIdentity, ConstraintWaveFragment)],
) -> Option<[u8; 32]> {
    if !(2..=30).contains(&evaluation_log_size)
        || parts.is_empty()
        || parts.iter().any(|(part, fragment)| {
            part.semantic_hash == 0
                || part.coefficient_start >= part.coefficient_end
                || fragment.semantic_hash() != part.semantic_hash
                || fragment.program_identity() == [0; 32]
        })
        || parts
            .windows(2)
            .any(|pair| pair[0].0.coefficient_end > pair[1].0.coefficient_start)
    {
        return None;
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"stwo-cuda-composition-wave-program-v2\0");
    hasher.update(&super::jit::cuda_codegen::CODEGEN_VERSION.to_le_bytes());
    hasher.update(&COMPOSITION_WAVE_CODEGEN_VERSION.to_le_bytes());
    hasher.update(&AotKernelAbiSchema::CompositionWaveV2.identity());
    hasher.update(&(COMPOSITION_WAVE_THREADS_PER_BLOCK as u64).to_le_bytes());
    hasher.update(&evaluation_log_size.to_le_bytes());
    hasher.update(&(parts.len() as u64).to_le_bytes());
    for (part, fragment) in parts {
        hasher.update(&part.semantic_hash.to_le_bytes());
        hasher.update(&part.coefficient_start.to_le_bytes());
        hasher.update(&part.coefficient_end.to_le_bytes());
        hasher.update(&fragment.program_identity());
    }
    Some(*hasher.finalize().as_bytes())
}

/// Derive the runtime identity without retaining CUDA source or bytecode.
pub fn composition_wave_kernel_identity(
    evaluation_log_size: u32,
    parts: &[CompositionWaveKernelPartIdentity],
) -> Option<CompositionWaveKernelIdentity> {
    if !(2..=30).contains(&evaluation_log_size)
        || parts.is_empty()
        || parts
            .iter()
            .any(|part| part.semantic_hash == 0 || part.coefficient_start >= part.coefficient_end)
        || parts
            .windows(2)
            .any(|pair| pair[0].coefficient_end > pair[1].coefficient_start)
    {
        return None;
    }
    let mut semantic_hash = 0xcbf29ce484222325u64;
    let mut feed = |bytes: &[u8]| {
        for &byte in bytes {
            semantic_hash ^= u64::from(byte);
            semantic_hash = semantic_hash.wrapping_mul(0x100000001b3);
        }
    };
    feed(b"stwo-cuda-composition-wave-v2\0");
    feed(&[
        COMPOSITION_WAVE_KERNEL_ARGUMENT_COUNT,
        COMPOSITION_WAVE_FULL_DOMAIN_ROWS_ARGUMENT,
        COMPOSITION_WAVE_SHARD_START_ARGUMENT,
        COMPOSITION_WAVE_SHARD_ROWS_ARGUMENT,
    ]);
    feed(&(COMPOSITION_WAVE_THREADS_PER_BLOCK as u64).to_le_bytes());
    feed(&evaluation_log_size.to_le_bytes());
    feed(&(parts.len() as u64).to_le_bytes());
    for part in parts {
        feed(&part.semantic_hash.to_le_bytes());
        feed(&part.coefficient_start.to_le_bytes());
        feed(&part.coefficient_end.to_le_bytes());
    }
    let mut cache_key = 0xcbf29ce484222325u64;
    for byte in semantic_hash
        .to_le_bytes()
        .into_iter()
        .chain(super::jit::cuda_codegen::CODEGEN_VERSION.to_le_bytes())
        .chain(COMPOSITION_WAVE_CODEGEN_VERSION.to_le_bytes())
    {
        cache_key ^= u64::from(byte);
        cache_key = cache_key.wrapping_mul(0x100000001b3);
    }
    Some(CompositionWaveKernelIdentity {
        evaluation_log_size,
        part_count: parts.len(),
        kernel_name: format!("stwo_composition_wave_{semantic_hash:016x}"),
        semantic_hash,
        cache_key,
    })
}

/// Emit one self-contained AOT source for a canonical same-domain wave.
pub fn composition_wave_kernel_source(
    evaluation_log_size: u32,
    parts: &[(CompositionWaveKernelPartIdentity, ConstraintWaveFragment)],
) -> Option<EmittedKernel> {
    let part_identities = parts
        .iter()
        .map(|(identity, _)| *identity)
        .collect::<Vec<_>>();
    let fragment_semantic_hashes = parts
        .iter()
        .map(|(_, fragment)| fragment.semantic_hash())
        .collect::<Vec<_>>();
    if !composition_wave_semantic_hashes_match(&part_identities, &fragment_semantic_hashes) {
        return None;
    }
    let identity = composition_wave_kernel_identity(evaluation_log_size, &part_identities)?;
    let program_identity = composition_wave_program_identity(evaluation_log_size, parts)?;
    let programs = parts
        .iter()
        .map(|(_, fragment)| &fragment.program)
        .collect::<Vec<_>>();
    let source = super::jit::cuda_codegen::compile_composition_wave_to_cuda_source(
        &programs,
        &identity.kernel_name,
    )?;
    Some(EmittedKernel {
        kernel_name: identity.kernel_name,
        cache_key: identity.cache_key,
        semantic_hash: identity.semantic_hash,
        source,
        abi_schema: Some(AotKernelAbiSchema::CompositionWaveV2),
        program_identity: Some(program_identity),
    })
}

/// Structural constraint program plus the evaluator constants hoisted into its
/// mutable parameter tables. The kernel identities are statement independent;
/// the parameter values are the setup oracle used by higher layers to bind each
/// stable slot to its device-side statement producer.
pub struct EmittedConstraintProgram {
    pub kernels: Vec<EmittedConstraintKernel>,
    pub base_param_values: Vec<BaseField>,
    pub ext_param_values: Vec<SecureField>,
}

/// Source-free identity and proof-varying parameter values for one already
/// installed constraint program. Warm executables use this path to prove that
/// the current evaluator still lowers to the installed kernel set without
/// formatting or allocating CUDA source again.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConstraintProgramBindings {
    pub kernels: Vec<ConstraintKernelBinding>,
    pub base_param_values: Vec<BaseField>,
    pub ext_param_values: Vec<SecureField>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConstraintKernelBinding {
    pub cache_key: u64,
    pub semantic_hash: u64,
    pub rc_base: u32,
}

/// Record and lower only far enough to bind an installed AOT program. Unlike
/// [`constraint_program`], this deliberately performs no CUDA code generation.
pub fn constraint_program_bindings<F: FrameworkEval>(
    eval: &F,
    n_interactions: u32,
    claimed_sum: SecureField,
    log_size: u32,
    max_kernel_instrs: usize,
) -> Option<ConstraintProgramBindings> {
    let (parts, base_param_values, ext_param_values) = lower_framework_eval_to_v1_split(
        eval,
        n_interactions,
        0,
        0,
        claimed_sum,
        log_size,
        max_kernel_instrs,
    )
    .ok()?;
    let kernels = parts
        .iter()
        .map(|part| {
            let semantic_hash = part.program.header().semantic_hash;
            ConstraintKernelBinding {
                cache_key: cuda_codegen::jit_cache_key(semantic_hash),
                semantic_hash,
                rc_base: part.rc_base,
            }
        })
        .collect();
    Some(ConstraintProgramBindings {
        kernels,
        base_param_values,
        ext_param_values,
    })
}

/// Emit the complete prepared-program description for one concrete component.
/// This is the source of truth shared by offline AOT generation and the resident
/// composition planner; neither side may reconstruct split offsets or parameter
/// ordering from the manifest filename.
pub fn constraint_program<F: FrameworkEval>(
    eval: &F,
    n_interactions: u32,
    claimed_sum: SecureField,
    log_size: u32,
    max_kernel_instrs: usize,
) -> Option<EmittedConstraintProgram> {
    constraint_program_with_live_cap(
        eval,
        n_interactions,
        claimed_sum,
        log_size,
        max_kernel_instrs,
        constraint_split_max_live_u32_lanes(),
    )
}

/// Explicit-policy source emitter for offline ptxas/occupancy sweeps. Production
/// generation uses [`constraint_program`] and the compiled policy identity.
pub fn constraint_program_with_live_cap<F: FrameworkEval>(
    eval: &F,
    n_interactions: u32,
    claimed_sum: SecureField,
    log_size: u32,
    max_kernel_instrs: usize,
    max_live_u32_lanes: usize,
) -> Option<EmittedConstraintProgram> {
    let (parts, base_param_values, ext_param_values) =
        lower_framework_eval_to_v1_split_with_live_cap(
            eval,
            n_interactions,
            0,
            0,
            claimed_sum,
            log_size,
            max_kernel_instrs,
            max_live_u32_lanes,
        )
        .ok()?;
    let kernels = parts
        .into_iter()
        .map(|part| {
            let semantic_hash = part.program.header().semantic_hash;
            let source = cuda_codegen::compile_v1_to_cuda_source(&part.program)?;
            Some(EmittedConstraintKernel {
                kernel: EmittedKernel {
                    kernel_name: cuda_codegen::fused_kernel_name(semantic_hash),
                    cache_key: cuda_codegen::jit_cache_key(semantic_hash),
                    semantic_hash,
                    source,
                    abi_schema: Some(AotKernelAbiSchema::OrdinaryConstraintV1),
                    program_identity: Some(part.program.semantic_identity()),
                },
                rc_base: part.rc_base,
                wave_fragment: ConstraintWaveFragment {
                    program: part.program,
                },
            })
        })
        .collect::<Option<Vec<_>>>()?;
    Some(EmittedConstraintProgram {
        kernels,
        base_param_values,
        ext_param_values,
    })
}

/// Emit the fused constraint kernel(s) for a component's evaluator. The lowering
/// hoists every statement constant into parameters, so structurally identical
/// evaluator recordings emit the same sources and cache keys across statement
/// values. `max_kernel_instrs = usize::MAX` (the default) emits ONE fused
/// kernel unless a single constraint cone alone exceeds even that.
pub fn constraint_kernel_sources<F: FrameworkEval>(
    eval: &F,
    n_interactions: u32,
    claimed_sum: SecureField,
    log_size: u32,
    max_kernel_instrs: usize,
) -> Option<Vec<EmittedKernel>> {
    constraint_kernel_sources_with_live_cap(
        eval,
        n_interactions,
        claimed_sum,
        log_size,
        max_kernel_instrs,
        constraint_split_max_live_u32_lanes(),
    )
}

/// Explicit-policy source-only wrapper for offline resource sweeps.
pub fn constraint_kernel_sources_with_live_cap<F: FrameworkEval>(
    eval: &F,
    n_interactions: u32,
    claimed_sum: SecureField,
    log_size: u32,
    max_kernel_instrs: usize,
    max_live_u32_lanes: usize,
) -> Option<Vec<EmittedKernel>> {
    Some(
        constraint_program_with_live_cap(
            eval,
            n_interactions,
            claimed_sum,
            log_size,
            max_kernel_instrs,
            max_live_u32_lanes,
        )?
        .kernels
        .into_iter()
        .map(|part| part.kernel)
        .collect(),
    )
}

/// Emit a witness kernel from a recorded program (the lane's own codegen).
pub fn witness_kernel_source(
    program: &super::jit_witness::isa::WitnessProgram,
) -> Option<EmittedKernel> {
    let semantic_hash = program.semantic_hash();
    let source = super::jit_witness::codegen::compile_witness_to_cuda_source(program)?;
    Some(EmittedKernel {
        kernel_name: super::jit_witness::codegen::witness_kernel_name(semantic_hash),
        cache_key: super::jit_witness::codegen::witness_jit_cache_key(semantic_hash),
        semantic_hash,
        source,
        abi_schema: Some(AotKernelAbiSchema::RecordedWitnessV1),
        program_identity: Some(program.semantic_identity()),
    })
}

/// Source-free identity of one kernel in a canonical two-phase witness plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessPhaseKernelBinding {
    pub ordinal: u32,
    pub kernel_name: String,
    pub cache_key: u64,
}

/// Exact runtime binding for a canonical two-phase witness plan.
///
/// This deliberately carries no CUDA source: the prepared phase runtime is
/// strict-AOT-only and must resolve both cache keys from the embedded pack
/// before either phase can be launched.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessPhaseProgramBindings {
    pub parent_semantic_hash: u64,
    pub plan_hash: u64,
    pub scratch_words_per_row: u32,
    pub phases: [WitnessPhaseKernelBinding; 2],
}

/// Bind a plan only when it is the exact canonical plan for this program and
/// cut. Forged or stale hashes, boundary sources, and moved-store schedules all
/// fail before an AOT lookup or device side effect.
pub fn witness_phase_program_bindings(
    program: &super::jit_witness::isa::WitnessProgram,
    plan: &super::jit_witness::codegen::phase_plan::WitnessPhasePlan,
) -> Option<WitnessPhaseProgramBindings> {
    let canonical = super::jit_witness::codegen::phase_plan::WitnessPhasePlan::at_cut(
        program,
        plan.cut_instruction,
    )
    .ok()?;
    if canonical != *plan {
        return None;
    }
    let phases = std::array::from_fn(|ordinal| {
        let ordinal = ordinal as u32;
        WitnessPhaseKernelBinding {
            ordinal,
            kernel_name: plan.phase_kernel_name(ordinal),
            cache_key: plan.phase_cache_key(ordinal),
        }
    });
    Some(WitnessPhaseProgramBindings {
        parent_semantic_hash: plan.parent_semantic_hash,
        plan_hash: plan.plan_hash,
        scratch_words_per_row: plan.scratch_words_per_row,
        phases,
    })
}

#[cfg(test)]
mod tests {
    use stwo_constraint_framework::EvalAtRow;

    use super::super::jit_witness::codegen::phase_plan::WitnessPhasePlan;
    use super::super::jit_witness::recording::WitnessRecorder;
    use super::*;

    #[test]
    fn full_manifest_identity_is_the_only_authority() {
        let identity = loaded_manifest_identity();
        if loaded_kernel_count() == 0 {
            assert_eq!(identity, [0; 32]);
            assert_eq!(loaded_manifest_hash(), 0);
        } else {
            assert_ne!(identity, [0; 32]);
            assert_ne!(loaded_manifest_hash(), 0);
        }
        assert_eq!(loaded_cubin_identity(0, u32::MAX, u32::MAX), [0; 32]);
        assert_eq!(loaded_kernel_authority(0, u32::MAX, u32::MAX), None);
    }

    #[derive(Default)]
    struct AdmissionModel {
        active: usize,
        admitted: bool,
        closed: bool,
        runtime_resolved: bool,
        setter_returned: bool,
        side_effect_after_commit: bool,
    }

    impl AdmissionModel {
        fn enter_runtime_operation(&mut self) {
            self.admitted = !self.closed;
            self.active += usize::from(self.admitted);
        }

        fn resolve_cached_runtime_function(&mut self) {
            self.runtime_resolved = !self.closed;
        }

        fn publish_or_enqueue(&mut self) {
            if self.runtime_resolved {
                self.side_effect_after_commit |= self.setter_returned;
            }
        }

        fn leave_runtime_operation(&mut self) {
            self.active -= usize::from(self.admitted);
            self.try_commit();
        }

        fn close_strict_admission(&mut self) {
            self.closed = true;
            self.try_commit();
        }

        fn try_commit(&mut self) {
            self.setter_returned |= self.closed && self.active == 0;
        }
    }

    #[test]
    fn strict_commit_cannot_be_crossed_by_runtime_publication_or_launch() {
        // Exhaust every linearization point for closure around a cached-runtime
        // operation: enter, resolve, publish/enqueue, leave. Closing before resolve
        // rejects the runtime origin; closing later waits for the operation guard.
        for close_before_step in 0..=4 {
            let mut model = AdmissionModel::default();
            for step in 0..4 {
                if close_before_step == step {
                    model.close_strict_admission();
                }
                match step {
                    0 => model.enter_runtime_operation(),
                    1 => model.resolve_cached_runtime_function(),
                    2 => model.publish_or_enqueue(),
                    3 => model.leave_runtime_operation(),
                    _ => unreachable!(),
                }
            }
            if close_before_step == 4 {
                model.close_strict_admission();
            }
            assert!(model.setter_returned);
            assert!(
                !model.side_effect_after_commit,
                "closure step {close_before_step}"
            );
        }
    }

    #[test]
    fn composition_wave_identity_is_deterministic_and_seals_every_axis() {
        assert_eq!(COMPOSITION_WAVE_CODEGEN_VERSION, 2);
        assert_eq!(COMPOSITION_WAVE_KERNEL_ARGUMENT_COUNT, 9);
        assert_eq!(COMPOSITION_WAVE_FULL_DOMAIN_ROWS_ARGUMENT, 6);
        assert_eq!(COMPOSITION_WAVE_SHARD_START_ARGUMENT, 7);
        assert_eq!(COMPOSITION_WAVE_SHARD_ROWS_ARGUMENT, 8);
        let parts = [
            CompositionWaveKernelPartIdentity {
                semantic_hash: 11,
                coefficient_start: 3,
                coefficient_end: 5,
            },
            CompositionWaveKernelPartIdentity {
                semantic_hash: 13,
                coefficient_start: 9,
                coefficient_end: 12,
            },
        ];
        let identity = composition_wave_kernel_identity(19, &parts).unwrap();
        assert_eq!(identity.evaluation_log_size, 19);
        assert_eq!(identity.part_count, 2);
        assert_eq!(
            identity,
            composition_wave_kernel_identity(19, &parts).unwrap()
        );

        let mut different_semantic_hash = parts;
        different_semantic_hash[1].semantic_hash += 1;
        let different_semantic_hash =
            composition_wave_kernel_identity(19, &different_semantic_hash).unwrap();
        assert_ne!(identity.cache_key, different_semantic_hash.cache_key);
        assert_ne!(identity.kernel_name, different_semantic_hash.kernel_name);

        let mut different_span = parts;
        different_span[1].coefficient_start += 1;
        let different_span = composition_wave_kernel_identity(19, &different_span).unwrap();
        assert_ne!(identity.cache_key, different_span.cache_key);
        assert_ne!(identity.kernel_name, different_span.kernel_name);

        let different_log = composition_wave_kernel_identity(20, &parts).unwrap();
        assert_ne!(identity.cache_key, different_log.cache_key);
        assert_ne!(identity.kernel_name, different_log.kernel_name);
    }

    #[test]
    fn composition_wave_identity_rejects_empty_zero_reversed_and_overlap() {
        let parts = [
            CompositionWaveKernelPartIdentity {
                semantic_hash: 11,
                coefficient_start: 3,
                coefficient_end: 5,
            },
            CompositionWaveKernelPartIdentity {
                semantic_hash: 13,
                coefficient_start: 9,
                coefficient_end: 12,
            },
        ];
        assert!(composition_wave_kernel_identity(19, &[]).is_none());

        let mut zero_hash = parts;
        zero_hash[0].semantic_hash = 0;
        assert!(composition_wave_kernel_identity(19, &zero_hash).is_none());

        let mut reordered = parts;
        reordered.swap(0, 1);
        assert!(composition_wave_kernel_identity(19, &reordered).is_none());

        let mut overlapping = parts;
        overlapping[1].coefficient_start = 4;
        assert!(composition_wave_kernel_identity(19, &overlapping).is_none());

        let mut reversed = parts;
        reversed[1].coefficient_end = reversed[1].coefficient_start - 1;
        assert!(composition_wave_kernel_identity(19, &reversed).is_none());
    }

    #[test]
    fn composition_wave_source_rejects_fragment_semantic_mismatch() {
        let identities = [
            CompositionWaveKernelPartIdentity {
                semantic_hash: 11,
                coefficient_start: 3,
                coefficient_end: 5,
            },
            CompositionWaveKernelPartIdentity {
                semantic_hash: 13,
                coefficient_start: 9,
                coefficient_end: 12,
            },
        ];
        assert!(composition_wave_semantic_hashes_match(
            &identities,
            &[11, 13]
        ));
        assert!(!composition_wave_semantic_hashes_match(
            &identities,
            &[11, 17]
        ));
        assert!(!composition_wave_semantic_hashes_match(&identities, &[11]));
    }

    #[test]
    fn ordinary_witness_emitter_owns_the_recorded_witness_abi() {
        let mut recorder = WitnessRecorder::new("aot_witness_abi");
        let input = recorder.input(0);
        recorder.col_write(0, input);
        let program = recorder.finish();
        let emitted = witness_kernel_source(&program).unwrap();
        assert_eq!(emitted.program_identity, Some(program.semantic_identity()));
        let schema = emitted.abi_schema.unwrap();
        assert_eq!(schema, AotKernelAbiSchema::RecordedWitnessV1);
        assert_eq!(schema.arguments().len(), 8);
        assert_eq!(schema.arguments()[0].name, "input_cols");
        assert_eq!(schema.arguments()[4].access, AotKernelAbiAccess::ReadWrite);
        assert_eq!(schema.arguments()[7].name, "row_count");
        assert_eq!(
            schema.arguments()[7].access,
            AotKernelAbiAccess::LaunchRowCount
        );
    }

    struct OrdinaryConstraintEval;

    impl FrameworkEval for OrdinaryConstraintEval {
        fn log_size(&self) -> u32 {
            4
        }

        fn max_constraint_log_degree_bound(&self) -> u32 {
            5
        }

        fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
            let value = eval.next_trace_mask();
            eval.add_constraint(value);
            eval
        }
    }

    #[test]
    fn ordinary_constraint_emitter_owns_typed_program_and_launch_abi() {
        let program = constraint_program(
            &OrdinaryConstraintEval,
            1,
            SecureField::from_u32_unchecked(0, 0, 0, 0),
            4,
            usize::MAX,
        )
        .unwrap();
        assert_eq!(program.kernels.len(), 1);
        let part = &program.kernels[0];
        let emitted = &part.kernel;
        assert_eq!(
            emitted.program_identity,
            Some(part.wave_fragment.program.semantic_identity())
        );
        let schema = emitted.abi_schema.unwrap();
        assert_eq!(schema, AotKernelAbiSchema::OrdinaryConstraintV1);
        assert_eq!(schema.arguments().len(), 13);
        assert_eq!(schema.arguments()[0].name, "trace_cols");
        assert_eq!(schema.arguments()[6].access, AotKernelAbiAccess::ReadWrite);
        assert_eq!(
            schema.arguments()[10].access,
            AotKernelAbiAccess::LaunchRowCount
        );
        assert_eq!(
            schema.arguments()[11].access,
            AotKernelAbiAccess::TraceLogSize
        );
        assert_eq!(
            schema.arguments()[12].access,
            AotKernelAbiAccess::RandomCoefficientBase
        );
        assert!(emitted.source.contains(
            "const unsigned *const *trace_cols,\n    const unsigned *interaction_offsets,\n    \
             const unsigned *base_params,\n    const unsigned *ext_params,\n    const unsigned \
             *random_coeff_powers,\n    const unsigned *denom_inv,\n    unsigned *coord_0,\n    \
             unsigned *coord_1,\n    unsigned *coord_2,\n    unsigned *coord_3,\n    unsigned \
             row_count,\n    unsigned log_n_rows,\n    unsigned rc_base"
        ));
    }

    #[test]
    fn composition_wave_emitter_owns_typed_program_and_shard_abi() {
        let program = constraint_program(
            &OrdinaryConstraintEval,
            1,
            SecureField::from_u32_unchecked(0, 0, 0, 0),
            4,
            usize::MAX,
        )
        .unwrap();
        let fragment = program.kernels[0].wave_fragment.clone();
        let identity = CompositionWaveKernelPartIdentity {
            semantic_hash: fragment.semantic_hash(),
            coefficient_start: 0,
            coefficient_end: 1,
        };
        let emitted = composition_wave_kernel_source(5, &[(identity, fragment)]).unwrap();
        assert_eq!(
            emitted.abi_schema,
            Some(AotKernelAbiSchema::CompositionWaveV2)
        );
        assert!(emitted
            .program_identity
            .is_some_and(|identity| identity != [0; 32]));
        let schema = AotKernelAbiSchema::CompositionWaveV2;
        assert_eq!(schema.arguments().len(), 9);
        assert_eq!(schema.arguments()[0].name, "parts");
        assert_eq!(
            schema.arguments()[6].access,
            AotKernelAbiAccess::FullDomainRows
        );
        assert_eq!(schema.arguments()[7].access, AotKernelAbiAccess::ShardStart);
        assert_eq!(schema.arguments()[8].access, AotKernelAbiAccess::ShardRows);
        assert!(emitted.source.contains(
            "const StwoCudaCompositionWavePart *parts,\n    const unsigned \
             *random_coeff_powers,\n    unsigned *coord_0,\n    unsigned *coord_1,\n    unsigned \
             *coord_2,\n    unsigned *coord_3,\n    unsigned full_domain_rows,\n    unsigned \
             shard_start,\n    unsigned shard_rows"
        ));
    }

    #[test]
    fn phase_bindings_are_canonical_source_free_identities() {
        let mut recorder = WitnessRecorder::new("aot_phase_bindings");
        let input = recorder.input(0);
        let constant = recorder.constant(7);
        let crossing = recorder.m31_add(input, constant);
        let output = recorder.m31_mul(crossing, input);
        recorder.col_write(0, output);
        let program = recorder.finish();
        let plan = WitnessPhasePlan::at_cut(&program, 3).unwrap();

        let bindings = witness_phase_program_bindings(&program, &plan).unwrap();
        assert_eq!(bindings.parent_semantic_hash, program.semantic_hash());
        assert_eq!(bindings.plan_hash, plan.plan_hash);
        assert_eq!(bindings.scratch_words_per_row, plan.scratch_words_per_row);
        for (ordinal, phase) in bindings.phases.iter().enumerate() {
            let ordinal = ordinal as u32;
            assert_eq!(phase.ordinal, ordinal);
            assert_eq!(phase.kernel_name, plan.phase_kernel_name(ordinal));
            assert_eq!(phase.cache_key, plan.phase_cache_key(ordinal));
        }

        let mut forged = plan.clone();
        forged.plan_hash ^= 1;
        assert!(witness_phase_program_bindings(&program, &forged).is_none());
    }
}
