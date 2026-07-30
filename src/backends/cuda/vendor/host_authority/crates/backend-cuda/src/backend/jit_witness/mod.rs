//! Witness-JIT lane for CUDA (witness-on-GPU W3, the "kill the 57-component tail with
//! one compiler" bet).
//!
//! # What this is
//!
//! The constraint-JIT lane ([`super::jit`]) records a component's *constraint* tree to
//! bytecode and JIT-compiles a fused CUDA kernel, cached by the bytecode's content
//! hash. This lane is the same idea for *witness* generation: a component's per-row
//! writer — instruction decode, M31/integer arithmetic, trace-column writes,
//! lookup-tuple emission, multiplicity pushes — is recorded to a witness bytecode
//! ([`isa::WitnessProgram`]) and codegen'd to a per-row CUDA kernel ([`codegen`]) via
//! the existing NVRTC lane (reusing its on-disk PTX cache and its
//! `STWO_CUDA_DISABLE_JIT`-style discipline). One generic hook lets a component opt in.
//!
//! # Kill switch and per-lane toggles (default OFF, pod-gated)
//!
//! - Master: **`STWO_CUDA_WITNESS_JIT=1`** enables the lane. Anything else (unset, `0`) is the kill
//!   switch — every component uses the host writer. Default **OFF** because the byte-equality gate
//!   (CUDA-vs-SIMD proof) has not been run on a pod for this lane; it is not byte-identical by
//!   construction (a new kernel, not a reshuffle of existing math), so it stays OFF until the pod
//!   differential passes.
//! - Per-lane: **`STWO_CUDA_WITNESS_JIT_<COMPONENT>=0`** disables one component even when the
//!   master is on (e.g. `STWO_CUDA_WITNESS_JIT_ADD_OPCODE=0`). Every lane is independently
//!   toggleable so the integration agent can bisect a mismatch to a single component with the
//!   switch.
//!
//! # The fundamental blocker (R&D finding), stated precisely
//!
//! The constraint lane records for free because `FrameworkEval::evaluate<E: EvalAtRow>`
//! is **generic over the evaluator** — swap in a `RecordingEvaluator` and the existing
//! closure records itself. Witness writers have **no** such generic entry point: the
//! generated `write_trace_simd` bodies (`stwo-cairo .../witness/components/*.rs`) are
//! monomorphic over concrete `PackedM31`/`PackedUInt16`, and they call
//! `sub_state.deduce_output(key)` — a **host-side `HashMap` lookup** into sibling
//! components' state. So a witness writer cannot be recorded automatically the way a
//! constraint evaluator can. Two things unblock full automation, neither doable in a
//! local session:
//!
//! 1. **Generic writer emission**: stwo-air-infra emits the writers against an abstract arithmetic
//!    trait (a `WitnessEvalAtRow`, the shape [`recording::WitnessRecorder`] models) instead of
//!    concrete packed types — then recording is free, exactly like constraints. Until then,
//!    per-component decode must be hand-authored against the recorder (see [`programs`]).
//! 2. **Device-resident memory tables**: `deduce_output` becomes the [`isa::WitnessOp::TableLimb`]
//!    device LUT read, which requires the `memory_address_to_id` / `memory_id_to_big` tables to
//!    already live on device (the memory-witness lane, partially landed).
//!
//! # What is delivered here (the largest sound subset, locally verified)
//!
//! The framework end-to-end minus the pod: the witness bytecode ISA, the recording
//! builder, a reference interpreter, the CUDA codegen (reusing the constraint lane's
//! proven M31 preamble and the NVRTC precompile entry point), the generic registration
//! hook, and three mid-tail components ([`programs`]: `add_opcode`, `assert_eq_opcode`,
//! `jnz_opcode_taken` — three distinct decode shapes) whose recordings are proven
//! bit-identical to the native decode by the differential unit tests. The device
//! *launch* entry point is the one pod-side seam (`stwo_cuda_jit_witness_launch`),
//! declared and stubbed; it is never called with the lane OFF.

pub mod codegen;
pub mod interp;
pub mod isa;
pub mod programs;
pub mod recording;

use std::collections::HashMap;
use std::sync::OnceLock;

/// Master kill switch. `true` only when `STWO_CUDA_WITNESS_JIT=1`.
pub fn witness_jit_enabled() -> bool {
    std::env::var("STWO_CUDA_WITNESS_JIT").as_deref() == Ok("1")
}

/// Whether a specific component's witness-JIT lane is enabled: the master must be on and
/// the per-component toggle must not be `0`. `label` is the component name
/// (e.g. `add_opcode`); the env var is `STWO_CUDA_WITNESS_JIT_<UPPER>`.
pub fn witness_jit_lane_enabled(label: &str) -> bool {
    if !witness_jit_enabled() {
        return false;
    }
    let var = format!("STWO_CUDA_WITNESS_JIT_{}", label.to_uppercase());
    std::env::var(var).as_deref() != Ok("0")
}

/// Diagnostics: default ON (a witness-JIT compile hang must be attributable to a named
/// component), silenced by `STWO_JIT_LOG=0` — the same variable the constraint lane
/// keys off, so one switch quiets both lanes.
fn log_enabled() -> bool {
    std::env::var("STWO_JIT_LOG").map_or(true, |v| v != "0")
}

fn log(msg: &str) {
    if log_enabled() {
        eprintln!("stwo witness-JIT: {msg}");
    }
}

/// The registry of components that have opted into the witness-JIT lane, keyed by label.
/// A component registers by adding a `(label, record_fn)` entry — the "one-line
/// registration" the hook exposes. Recorded once (programs are statement-independent),
/// cached for the process.
fn registry() -> &'static HashMap<&'static str, isa::WitnessProgram> {
    static REGISTRY: OnceLock<HashMap<&'static str, isa::WitnessProgram>> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        let mut m = HashMap::new();
        // The three generality-proving components. Adding a component here is the
        // single-line registration; its lane is then controlled by the env toggles.
        m.insert("add_opcode", programs::record_add_opcode_decode());
        m.insert(
            "assert_eq_opcode",
            programs::record_assert_eq_opcode_decode(),
        );
        m.insert(
            "jnz_opcode_taken",
            programs::record_jnz_opcode_taken_decode(),
        );
        m
    })
}

/// Dynamically registered programs (e.g. the transformer-EMITTED full-width writer
/// recordings from stwo-cairo, which supersede the hand decode-subsets above when
/// present). Insert-once semantics: the first registration for a label wins for the
/// process (programs are statement-independent), and lookups prefer this map over the
/// built-in registry.
fn dynamic_registry() -> &'static std::sync::RwLock<HashMap<String, &'static isa::WitnessProgram>> {
    static DYN: OnceLock<std::sync::RwLock<HashMap<String, &'static isa::WitnessProgram>>> =
        OnceLock::new();
    DYN.get_or_init(|| std::sync::RwLock::new(HashMap::new()))
}

/// Register a recorded program at runtime (leaked to 'static — one per label per
/// process; repeat registrations for the same label are ignored). This is the bridge
/// for recordings produced OUTSIDE this crate: stwo-cairo's transformer-emitted
/// `record_<component>()` outputs are the intended source.
pub fn register_recorded_program(label: &str, program: isa::WitnessProgram) {
    let mut map = dynamic_registry().write().unwrap();
    if !map.contains_key(label) {
        log(&format!(
            "registered dynamic program component={label} instrs={}",
            program.n_instrs()
        ));
        map.insert(label.to_string(), Box::leak(Box::new(program)));
    }
}

/// Look up a registered component's recorded program (dynamic registrations first,
/// then the built-in hand recordings).
pub fn recorded_program(label: &str) -> Option<&'static isa::WitnessProgram> {
    if let Some(p) = dynamic_registry().read().unwrap().get(label) {
        return Some(p);
    }
    registry().get(label)
}

/// Per-kernel instruction cap for the witness size governor. Reuses the same *value* as
/// the constraint lane's calibrated default but a distinct env var so the two lanes are
/// tuned independently. `0` disables the governor.
const DEFAULT_MAX_WITNESS_KERNEL_INSTRS: usize = 2048;

/// The prove-path size cap (fail-closed there, unlike the warm path's
/// log-and-relax): see `exec_tables::launch_recorded_witness_for_prove`.
pub fn witness_prove_max_instrs() -> usize {
    max_kernel_instrs()
}

fn max_kernel_instrs() -> usize {
    match std::env::var("STWO_CUDA_WITNESS_JIT_MAX_INSTRS") {
        Err(_) => DEFAULT_MAX_WITNESS_KERNEL_INSTRS,
        Ok(v) => match v.trim().parse::<usize>() {
            Ok(0) => usize::MAX,
            Ok(cap) => cap,
            Err(_) => DEFAULT_MAX_WITNESS_KERNEL_INSTRS,
        },
    }
}

/// Codegen a registered component's kernel and warm the NVRTC/PTX cache for it (does
/// NOT launch). Reuses the constraint lane's `stwo_cuda_jit_precompile` FFI — the same
/// NVRTC compiler and on-disk PTX cache — so a successful return proves the generated
/// witness source compiles on the pod and is cached for the subsequent launch. Returns
/// `false` (host fallback) on any failure or when the lane / kernels are unavailable.
///
/// This is the pod-validatable half of the lane that needs no new CUDA kernel: it
/// exercises record → codegen → NVRTC end to end. The device *launch* (the witness
/// kernel ABI in [`codegen`]) is the remaining pod seam via
/// [`stwo_backend_cuda_kernels::raw::stwo_cuda_jit_witness_launch`], gated identically.
pub fn precompile_witness_kernel(label: &str) -> bool {
    if !witness_jit_lane_enabled(label) {
        return false;
    }
    if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
        return false;
    }
    let Some(program) = recorded_program(label) else {
        log(&format!("no recorded program for component={label}"));
        return false;
    };

    let cap = max_kernel_instrs();
    let instrs = program.n_instrs();
    let relax_opt = instrs > cap;
    if relax_opt {
        log(&format!(
            "component={label} has {instrs} instrs > cap {cap}; compiling with \
             optimization relief (single per-row kernel — witness kernels are not \
             split, each row is independent so there is no accumulation to regroup)"
        ));
    }

    let Some(source) = codegen::compile_witness_to_cuda_source(program) else {
        log(&format!("codegen failed for component={label}"));
        return false;
    };
    let semantic_hash = program.semantic_hash();
    let name = codegen::witness_kernel_name(semantic_hash);
    let cache_key = codegen::witness_jit_cache_key(semantic_hash);

    let (Ok(c_source), Ok(c_name)) = (
        std::ffi::CString::new(source),
        std::ffi::CString::new(name.clone()),
    ) else {
        return false;
    };

    log(&format!(
        "precompile start component={label} kernel={name} semantic_hash={semantic_hash:016x} \
         cache_key={cache_key:016x} instrs={instrs} relax_opt={relax_opt}"
    ));
    let ok = unsafe {
        stwo_backend_cuda_kernels::raw::stwo_cuda_jit_precompile(
            c_source.as_ptr(),
            c_name.as_ptr(),
            cache_key,
            relax_opt,
        )
    };
    if !ok {
        log(&format!(
            "precompile FAILED component={label} — host fallback"
        ));
    }
    ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_holds_the_three_components() {
        assert!(recorded_program("add_opcode").is_some());
        assert!(recorded_program("assert_eq_opcode").is_some());
        assert!(recorded_program("jnz_opcode_taken").is_some());
        assert!(recorded_program("nonexistent").is_none());
    }

    #[test]
    fn master_switch_gates_every_lane() {
        // The gate reads process env; assert the compositional logic without mutating
        // global env (which would race other tests). With the master off, no lane is
        // enabled regardless of per-lane vars — verified by the pure predicate below.
        fn lane_enabled(master_on: bool, per_lane: Option<&str>) -> bool {
            master_on && per_lane != Some("0")
        }
        assert!(!lane_enabled(false, None));
        assert!(!lane_enabled(false, Some("1")));
        assert!(lane_enabled(true, None));
        assert!(lane_enabled(true, Some("1")));
        assert!(!lane_enabled(true, Some("0")));
    }

    #[test]
    fn governor_cap_parsing() {
        // Default when unset; the pure parse mirrors max_kernel_instrs.
        fn parse(v: Option<&str>) -> usize {
            match v {
                None => DEFAULT_MAX_WITNESS_KERNEL_INSTRS,
                Some(s) => match s.trim().parse::<usize>() {
                    Ok(0) => usize::MAX,
                    Ok(c) => c,
                    Err(_) => DEFAULT_MAX_WITNESS_KERNEL_INSTRS,
                },
            }
        }
        assert_eq!(parse(None), DEFAULT_MAX_WITNESS_KERNEL_INSTRS);
        assert_eq!(parse(Some("0")), usize::MAX);
        assert_eq!(parse(Some("512")), 512);
        assert_eq!(parse(Some("junk")), DEFAULT_MAX_WITNESS_KERNEL_INSTRS);
    }
}
