//! JIT GPU constraint-evaluation lane for CUDA (NVRTC).
//!
//! Same architecture as the Metal JIT lane: the component's constraint tree is
//! recorded once to V1 bytecode (generic `EvalAtRow` recorder, logup included),
//! compiled to a fused CUDA kernel via NVRTC (cached by the bytecode's content
//! semantic hash), and evaluated in one dispatch. Kernels generated this way are
//! consistent with THIS build's AIR by construction and use an explicit C ABI —
//! the failure mode that disqualified the precompiled NitrooZK kernel set cannot
//! occur. Falls back to `false` (caller runs the CPU lane) on any failure.

pub(crate) mod cuda_codegen;
mod program;
mod recording;

use std::ffi::CString;
use std::os::raw::c_char;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use program::lower_framework_eval_to_v1_split;
pub(crate) use program::{
    lower_framework_eval_to_v1_split as lower_for_aot,
    lower_framework_eval_to_v1_split_with_live_cap as lower_for_aot_with_live_cap,
    OwnedMetalEvaluationProgramV1, CONSTRAINT_SPLIT_MAX_LIVE_U32_LANES,
};
use stwo_constraint_framework::{FrameworkComponent, FrameworkEval};

use crate::columns::{BaseFieldVec, SecureFieldVec};

/// Default per-kernel instruction cap (base + ext bytecode instructions) for the JIT
/// size governor. Calibrated empirically on RTX 3090 / CUDA 11.8 (2026-07-02, SN-PIE
/// round 8): NVRTC is fine at 8192 instrs (~0.39 MB source, ~9 s), but **ptxas is the
/// real cliff** — the same kernel's 6.4 MB PTX ran >20 min in module load without
/// finishing. Known-good ceiling: ~3.5k instrs pass; ec_op at 2,446 instrs costs 28 s
/// (NVRTC+ptxas, one-time). At 2048 the pedersen `partial_ec_mul_generic` (20,334
/// instrs) splits into 11 kernels compiling in seconds each with only ~4% recompute
/// duplication. Sizes are logged at every compile start (`STWO_JIT_LOG`) — re-derive
/// on new CUDA versions before raising. Override with `STWO_JIT_MAX_KERNEL_INSTRS`
/// (`0` disables the governor entirely).
const DEFAULT_MAX_KERNEL_INSTRS: usize = 2048;

fn parse_max_kernel_instrs(raw: Option<&str>) -> usize {
    match raw {
        None => DEFAULT_MAX_KERNEL_INSTRS,
        Some(value) => match value.trim().parse::<usize>() {
            Ok(0) => usize::MAX, // 0 = governor disabled.
            Ok(cap) => cap,
            Err(_) => {
                eprintln!(
                    "stwo JIT: invalid STWO_JIT_MAX_KERNEL_INSTRS={value:?}; using default \
                     {DEFAULT_MAX_KERNEL_INSTRS}"
                );
                DEFAULT_MAX_KERNEL_INSTRS
            }
        },
    }
}

fn force_relax() -> bool {
    std::env::var("STWO_JIT_FORCE_RELAX").as_deref() == Ok("1")
}

fn max_kernel_instrs() -> usize {
    parse_max_kernel_instrs(std::env::var("STWO_JIT_MAX_KERNEL_INSTRS").ok().as_deref())
}

/// `STWO_JIT_DISABLE_SPLIT=1` keeps every component in one fused kernel; kernels over
/// the cap then compile with optimization disabled instead (the relief valve).
fn split_disabled() -> bool {
    std::env::var("STWO_JIT_DISABLE_SPLIT").is_ok_and(|v| !v.is_empty() && v != "0")
}

/// JIT diagnostics default ON (a production compile hang must be attributable to a
/// named kernel on the first rerun, before the process is killed); `STWO_JIT_LOG=0`
/// silences. The C++ runtime side keys off the same variable.
fn jit_log_enabled() -> bool {
    std::env::var("STWO_JIT_LOG").map_or(true, |v| v != "0")
}

fn jit_log(msg: &str) {
    if jit_log_enabled() {
        eprintln!("stwo JIT: {msg}");
    }
}

/// Wall-clock timestamp (ms since epoch) for correlating with pod logs; phase
/// durations are measured with `Instant` (monotonic).
fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// Inputs prepared by the shared constraint-eval driver (single accumulator claim).
pub(crate) struct JitInputs<'a> {
    pub trace_ptrs: &'a [Vec<*const u32>],
    pub trace_column_lens: &'a [Vec<usize>],
    pub random_coeff_powers: &'a SecureFieldVec,
    pub denom_inv: &'a BaseFieldVec,
    pub accum_coords: [*mut u32; 4],
    pub n_rows: usize,
    pub trace_log_size: u32,
}

/// Record, compile (cached), and launch the fused kernel; the kernel adds
/// `sum_i rc[i]*constraint_i(row) * denom_inv[row >> trace_log]` directly into the
/// accumulator coordinates (`inputs.accum_coords`) in place — there is no separate
/// scratch buffer or accumulate pass. Returns `false` to request the CPU lane, in
/// which case the accumulator has NOT been touched.
pub(crate) fn try_jit_constraint_quotients<E: FrameworkEval>(
    component: &FrameworkComponent<E>,
    inputs: &JitInputs<'_>,
) -> bool {
    if std::env::var_os("STWO_CUDA_DISABLE_JIT").is_some() {
        return false;
    }
    try_jit_constraint_quotients_inner(component, inputs).is_some()
}

fn try_jit_constraint_quotients_inner<E: FrameworkEval>(
    component: &FrameworkComponent<E>,
    inputs: &JitInputs<'_>,
) -> Option<()> {
    let label = std::any::type_name::<E>();
    let cap = max_kernel_instrs();
    let split_disabled = split_disabled();
    // With splitting disabled the lowering is uncapped (single fused program); the
    // configured cap still decides whether that program gets the optimization-relief
    // treatment below.
    let lowering_cap = if split_disabled { usize::MAX } else { cap };

    // Phase 1: recording + lowering (host-side codegen). Logged separately from the
    // NVRTC phase so a pegged core is attributable to the right stage.
    let codegen_start = Instant::now();
    jit_log(&format!(
        "codegen start component={label} ts_ms={}",
        now_ms()
    ));

    // Lowering hoists every base and ext constant into runtime parameters, so each
    // program — and its semantic hash — depends only on the AIR structure. The hash
    // therefore stays stable across statements and the compiled kernel is reused
    // from the in-memory or on-disk PTX cache.
    let (parts, base_param_values, ext_param_values) = lower_framework_eval_to_v1_split(
        component.evaluator(),
        inputs.trace_ptrs.len() as u32,
        0,
        0,
        component.claimed_sum(),
        component.evaluator().log_size(),
        lowering_cap,
    )
    .ok()?;

    struct JitKernel {
        source: CString,
        name: CString,
        name_str: String,
        semantic_hash: u64,
        cache_key: u64,
        rc_base: u32,
        instrs: usize,
        source_bytes: usize,
        relax_opt: bool,
    }
    let mut kernels: Vec<JitKernel> = Vec::with_capacity(parts.len());
    for part in &parts {
        let instrs = part.program.base_insts().len() + part.program.ext_insts().len();
        let semantic_hash = part.program.header().semantic_hash;
        let source = cuda_codegen::compile_v1_to_cuda_source(&part.program)?;
        let source_bytes = source.len();
        let name_str = cuda_codegen::fused_kernel_name(semantic_hash);
        kernels.push(JitKernel {
            source: CString::new(source).ok()?,
            name: CString::new(name_str.clone()).ok()?,
            name_str,
            semantic_hash,
            cache_key: cuda_codegen::jit_cache_key(semantic_hash),
            rc_base: part.rc_base,
            instrs,
            source_bytes,
            // Relief valve: a kernel still over the cap (splitting disabled, or a
            // single constraint cone bigger than the cap) compiles unoptimized.
            // STWO_JIT_FORCE_RELAX=1 relaxes EVERY kernel: on sm_90 the ptxas -O3
            // cliff made 2048-instr kernels unloadable (240s+/kernel), while -O0
            // loads in ms — force-relax keeps the big fused kernels (4x fewer
            // launches than the 512 split) at a small per-kernel efficiency cost.
            // A/B via the manifest; composition + commits are launch-bound, not
            // SASS-quality-bound, so this should net positive on sm_90.
            // rather than hanging NVRTC/ptxas for hours.
            relax_opt: instrs > cap || force_relax(),
        });
    }
    let total_instrs: usize = kernels.iter().map(|k| k.instrs).sum();
    jit_log(&format!(
        "codegen end component={label} kernels={} total_instrs={total_instrs} \
         elapsed_ms={} ts_ms={}",
        kernels.len(),
        codegen_start.elapsed().as_millis(),
        now_ms(),
    ));

    let n_rows = inputs.n_rows;
    // Pointer-table trace ABI: the kernel indexes trace_cols[global_column][row], so
    // no flattening copies are needed (and no u32 length overflow at log >= 23 sizes;
    // each column pointer addresses its own buffer). In SubDomain mode columns are
    // longer than n_rows; the first n_rows bit-reversed entries are the evaluation
    // subdomain — the same prefix the CPU lane reads.
    let mut interaction_offsets = [0u32; 3];
    let mut all_column_ptrs: Vec<*const u32> = Vec::new();
    for (interaction, tree) in inputs.trace_ptrs.iter().enumerate() {
        interaction_offsets[interaction] = all_column_ptrs.len() as u32;
        for (column_idx, &src_ptr) in tree.iter().enumerate() {
            assert!(inputs.trace_column_lens[interaction][column_idx] >= n_rows);
            all_column_ptrs.push(src_ptr);
        }
    }
    let trace_table = crate::backend::UploadedDevicePointerVec::upload(&all_column_ptrs);
    let offsets_dev = BaseFieldVec::from_vec(
        interaction_offsets
            .iter()
            .map(|&v| stwo::core::fields::m31::BaseField::from_u32_unchecked(v))
            .collect(),
    );

    let base_params = BaseFieldVec::from_vec(if base_param_values.is_empty() {
        vec![num_traits::Zero::zero()]
    } else {
        base_param_values
    });
    // Ext params = every constant the lowering hoisted out of the bytecode (lookup
    // elements, cumsum shift, structural constants), uploaded in slot order — shared
    // by every split kernel (slot numbering is global to the component). A
    // one-element zero buffer keeps the ABI pointer valid for const-free programs.
    let ext_params = SecureFieldVec::from_vec(if ext_param_values.is_empty() {
        vec![num_traits::Zero::zero()]
    } else {
        ext_param_values
    });

    crate::columns::bindings::ensure_mem_pool_init();

    // Phase 2: NVRTC compile + launch. Per-kernel forensic line BEFORE compilation so
    // a hung nvrtcCompileProgram is attributable by name/hash/size post-mortem.
    let compile_start = Instant::now();
    for kernel in &kernels {
        jit_log(&format!(
            "compile start component={label} kernel={} semantic_hash={:016x} \
             cache_key={:016x} instrs={} source_bytes={} rc_base={} relax_opt={} ts_ms={}",
            kernel.name_str,
            kernel.semantic_hash,
            kernel.cache_key,
            kernel.instrs,
            kernel.source_bytes,
            kernel.rc_base,
            kernel.relax_opt,
            now_ms(),
        ));
        if kernel.relax_opt {
            eprintln!(
                "stwo JIT WARNING: kernel {} (component {label}, {} instrs, {} source \
                 bytes) exceeds STWO_JIT_MAX_KERNEL_INSTRS={cap} and cannot be split \
                 further{}; compiling with optimization disabled (nvrtc --dopt=off, \
                 ptxas -O0). Constraint values are unaffected; kernel runtime will be \
                 slower.",
                kernel.name_str,
                kernel.instrs,
                kernel.source_bytes,
                if split_disabled {
                    " (splitting disabled via STWO_JIT_DISABLE_SPLIT)"
                } else {
                    " (single constraint dependency cone above the cap)"
                },
            );
        }
    }

    // For a split component, compile EVERYTHING before launching ANYTHING: once the
    // first kernel has accumulated, a compile failure could no longer fall back to
    // the CPU lane without double-counting. The batch precompiles the split kernels in
    // parallel (STWO_JIT_PARALLEL_COMPILE, default on) — order-independent since it only
    // populates the compile cache; the launch loop below is unchanged and sequential.
    if kernels.len() > 1 {
        let sources: Vec<*const c_char> = kernels.iter().map(|k| k.source.as_ptr()).collect();
        let names: Vec<*const c_char> = kernels.iter().map(|k| k.name.as_ptr()).collect();
        let cache_keys: Vec<u64> = kernels.iter().map(|k| k.cache_key).collect();
        let relax_opts: Vec<bool> = kernels.iter().map(|k| k.relax_opt).collect();
        // SAFETY: the four arrays live until the call returns; the CStrings they point
        // into are owned by `kernels`, which outlives this call.
        let ok = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_cuda_jit_precompile_batch(
                sources.as_ptr(),
                names.as_ptr(),
                cache_keys.as_ptr(),
                relax_opts.as_ptr(),
                kernels.len() as u32,
            )
        };
        if !ok {
            jit_log(&format!(
                "precompile batch FAILED component={label} ({} kernels) — falling back \
                 to the CPU lane",
                kernels.len()
            ));
            return None;
        }
    }

    // The kernels accumulate in place into the accumulator coordinates; no scratch
    // columns and no separate accumulate dispatch (see cuda_codegen's fused store).
    // Split kernels launch sequentially on the same (legacy default) stream, so their
    // in-place modular additions combine into exactly the fused kernel's sum.
    for (idx, kernel) in kernels.iter().enumerate() {
        let ok = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_cuda_jit_eval_fused(
                kernel.source.as_ptr(),
                kernel.name.as_ptr(),
                kernel.cache_key,
                trace_table.as_ptr().cast(),
                offsets_dev.device_ptr,
                base_params.device_ptr,
                ext_params.device_ptr,
                inputs.random_coeff_powers.device_ptr,
                inputs.denom_inv.device_ptr,
                inputs.accum_coords[0],
                inputs.accum_coords[1],
                inputs.accum_coords[2],
                inputs.accum_coords[3],
                n_rows as u32,
                inputs.trace_log_size,
                kernel.rc_base,
                kernel.relax_opt,
            )
        };
        if !ok {
            if idx == 0 {
                // Nothing launched yet — the accumulator is untouched and the CPU
                // lane is a safe fallback.
                return None;
            }
            // Later kernels were precompiled above, so this is a launch failure after
            // earlier split kernels already accumulated. Falling back to the CPU lane
            // would double-count their contribution — abort instead.
            panic!(
                "stwo JIT: kernel {}/{} ({}) of component {label} failed to launch \
                 after earlier split kernels already accumulated; the accumulator is \
                 partially updated and no safe fallback exists",
                idx + 1,
                kernels.len(),
                kernel.name_str,
            );
        }
    }
    jit_log(&format!(
        "compile+launch end component={label} kernels={} elapsed_ms={} ts_ms={}",
        kernels.len(),
        compile_start.elapsed().as_millis(),
        now_ms(),
    ));
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_kernel_instrs_default_and_parsing() {
        assert_eq!(parse_max_kernel_instrs(None), DEFAULT_MAX_KERNEL_INSTRS);
        assert_eq!(parse_max_kernel_instrs(Some("4096")), 4096);
        assert_eq!(parse_max_kernel_instrs(Some(" 12 ")), 12);
        // 0 disables the governor.
        assert_eq!(parse_max_kernel_instrs(Some("0")), usize::MAX);
        // Garbage falls back to the default.
        assert_eq!(
            parse_max_kernel_instrs(Some("banana")),
            DEFAULT_MAX_KERNEL_INSTRS
        );
    }
}
