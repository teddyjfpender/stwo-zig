//! Strict-AOT two-phase overlay for an already-bound witness workspace.
//!
//! The overlay borrows [`PreparedWitnessGraph`] so input/output descriptors and
//! their physical-disjointness proof have one owner. Preparation admits both
//! exact phase cache keys before loading either module. Launch then resolves
//! both cached AOT functions before enqueueing the ordered pair on one stream.

use core::ffi::{c_char, c_void};
use std::ffi::CString;

use super::{
    bind_slot, ensure_physically_disjoint, PreparedWitnessError, PreparedWitnessGraph,
    PreparedWitnessLaunchTelemetry, PreparedWitnessMode, WitnessExecutionTables,
    WitnessKernelIdentity, WitnessLaunchContract,
};
use crate::backend::aot;
use crate::backend::exec_context::{
    cuda_device_snapshot, ArenaSlice, ArenaSlotId, CudaLaunchContext, CudaRuntimeError,
};
use crate::backend::jit_witness::codegen::phase_plan::WitnessPhasePlan;
use crate::backend::jit_witness::isa::WitnessProgram;

/// Exact optional scratch extent for a phase plan.
///
/// Zero words per row returns `None`; callers must not reserve or bind a dummy
/// device allocation for a scratch-free plan.
pub fn phase_scratch_words(
    scratch_words_per_row: u32,
    row_count: usize,
) -> Result<Option<usize>, PreparedWitnessError> {
    if row_count == 0 {
        return Err(PreparedWitnessError::ZeroRows);
    }
    u32::try_from(row_count).map_err(|_| PreparedWitnessError::RowCountOverflow)?;
    if scratch_words_per_row == 0 {
        return Ok(None);
    }
    usize::try_from(scratch_words_per_row)
        .ok()
        .and_then(|words| words.checked_mul(row_count))
        .map(Some)
        .ok_or(PreparedWitnessError::SizeOverflow)
}

fn phase_scratch_slot_requirement(
    required_words: Option<usize>,
    slot: Option<ArenaSlotId>,
) -> Result<Option<(ArenaSlotId, usize)>, PreparedWitnessError> {
    match (required_words, slot) {
        (None, None) => Ok(None),
        (None, Some(slot)) => Err(PreparedWitnessError::PhaseScratchUnexpected(slot)),
        (Some(required_words), None) => {
            Err(PreparedWitnessError::PhaseScratchMissing { required_words })
        }
        (Some(required_words), Some(slot)) => Ok(Some((slot, required_words))),
    }
}

fn admit_phase_pair_with<Contains, Precompile>(
    identities: &[WitnessKernelIdentity; 2],
    sm_major: u32,
    sm_minor: u32,
    mut contains: Contains,
    precompile: Precompile,
) -> Result<(), PreparedWitnessError>
where
    Contains: FnMut(u64, u32, u32) -> bool,
    Precompile: FnOnce() -> bool,
{
    // Check the complete pair before module loading can configure globals or
    // publish either function into the process cache.
    for identity in identities {
        if !contains(identity.cache_key, sm_major, sm_minor) {
            return Err(PreparedWitnessError::StrictAotUnavailable(identity.clone()));
        }
    }
    if !precompile() {
        return Err(PreparedWitnessError::PhaseAotPreparationFailed(
            identities.clone(),
        ));
    }
    Ok(())
}

fn validate_phase_base_identity(
    identity: &WitnessKernelIdentity,
    launch_contract: WitnessLaunchContract,
    program_label: &str,
    parent_semantic_hash: u64,
    loaded_manifest_identity: [u8; 32],
) -> Result<(), PreparedWitnessError> {
    if launch_contract != WitnessLaunchContract::Recorded
        || identity.label != program_label
        || identity.semantic_hash != parent_semantic_hash
        || identity.aot_manifest_identity == [0; 32]
        || identity.aot_manifest_identity != loaded_manifest_identity
    {
        return Err(PreparedWitnessError::PhaseProgramMismatch);
    }
    if identity.mode != PreparedWitnessMode::RequireEmbeddedAot {
        return Err(PreparedWitnessError::PhaseRequiresStrictAot);
    }
    Ok(())
}

/// Ordered, source-free phase pair over one prepared witness workspace.
pub struct PreparedWitnessPhaseProgram<'graph, 'arena> {
    graph: &'graph PreparedWitnessGraph<'arena>,
    identities: [WitnessKernelIdentity; 2],
    kernel_names: [CString; 2],
    plan_hash: u64,
    scratch: Option<ArenaSlice>,
}

impl<'graph, 'arena> PreparedWitnessPhaseProgram<'graph, 'arena> {
    /// Admit and pre-resolve a canonical phase pair.
    ///
    /// The base graph must already be strict-AOT and use the generic recorded
    /// ABI. Phase sources are never materialized at runtime. `scratch_slot`
    /// must be absent exactly when the canonical plan requests zero words.
    pub fn prepare(
        graph: &'graph PreparedWitnessGraph<'arena>,
        program: &WitnessProgram,
        plan: &WitnessPhasePlan,
        scratch_slot: Option<ArenaSlotId>,
    ) -> Result<Self, PreparedWitnessError> {
        let bindings = aot::witness_phase_program_bindings(program, plan)
            .ok_or(PreparedWitnessError::PhasePlanMismatch)?;
        validate_phase_base_identity(
            &graph.identity,
            graph.launch_contract,
            &program.label,
            bindings.parent_semantic_hash,
            aot::loaded_manifest_identity(),
        )?;

        let identities = bindings.phases.map(|phase| WitnessKernelIdentity {
            label: program.label.clone(),
            kernel_name: phase.kernel_name,
            semantic_hash: bindings.parent_semantic_hash,
            cache_key: phase.cache_key,
            aot_manifest_identity: graph.identity.aot_manifest_identity,
            aot_manifest_hash: graph.identity.aot_manifest_hash,
            mode: PreparedWitnessMode::RequireEmbeddedAot,
        });
        let kernel_names: [CString; 2] = identities
            .iter()
            .map(|identity| CString::new(identity.kernel_name.clone()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| PreparedWitnessError::InvalidKernelString)?
            .try_into()
            .expect("phase plan has exactly two identities");

        let scratch_requirement = phase_scratch_slot_requirement(
            phase_scratch_words(bindings.scratch_words_per_row, graph.row_count())?,
            scratch_slot,
        )?;
        let scratch = scratch_requirement
            .map(|(slot, words)| bind_slot(graph.arena, slot, words, 1))
            .transpose()?;
        if let Some(scratch) = scratch {
            let prepared_table_data = match graph._tables {
                WitnessExecutionTables::Legacy(_) => None,
                WitnessExecutionTables::Prepared(view) => Some(view.table_data()),
            };
            let live_ranges = graph
                .input_columns
                .iter()
                .copied()
                .chain(graph.output_columns.iter().copied())
                .chain(graph.multiplicity_columns.iter().copied())
                .chain(graph.descriptor_slices())
                .chain(graph.multiplicity_dummy)
                .chain([graph.lookup_words, graph.sub_words, scratch])
                .chain(prepared_table_data.into_iter().flatten());
            ensure_physically_disjoint(live_ranges)?;
        }

        let snapshot = cuda_device_snapshot()?;
        let source_ptrs = [core::ptr::null::<c_char>(); 2];
        let kernel_name_ptrs = kernel_names.each_ref().map(|name| name.as_ptr());
        let cache_keys = identities.each_ref().map(|identity| identity.cache_key);
        let relax_opts = [false; 2];
        admit_phase_pair_with(
            &identities,
            snapshot.sm_major,
            snapshot.sm_minor,
            aot::contains_loaded_kernel,
            || unsafe {
                stwo_backend_cuda_kernels::raw::stwo_cuda_jit_precompile_batch(
                    source_ptrs.as_ptr(),
                    kernel_name_ptrs.as_ptr(),
                    cache_keys.as_ptr(),
                    relax_opts.as_ptr(),
                    2,
                )
            },
        )?;

        Ok(Self {
            graph,
            identities,
            kernel_names,
            plan_hash: bindings.plan_hash,
            scratch,
        })
    }

    pub fn launch(&self) -> Result<PreparedWitnessLaunchTelemetry, PreparedWitnessError> {
        self.launch_on(self.graph.arena.context().launch_context())
    }

    /// Resolve both cached AOT functions, then enqueue phase 0 followed by phase
    /// 1 on this one stream. No allocation, transfer, or synchronization occurs.
    pub fn launch_on(
        &self,
        launch: CudaLaunchContext,
    ) -> Result<PreparedWitnessLaunchTelemetry, PreparedWitnessError> {
        if launch.identity_token() != self.graph.arena.context().identity_token() {
            return Err(CudaRuntimeError::ContextMismatch.into());
        }
        let kernel_name_ptrs = self.kernel_names.each_ref().map(|name| name.as_ptr());
        let cache_keys = self
            .identities
            .each_ref()
            .map(|identity| identity.cache_key);
        let scratch = self
            .scratch
            .map_or(core::ptr::null_mut::<c_void>(), ArenaSlice::as_void_ptr)
            .cast::<u32>();
        let ok = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_cuda_jit_witness_phase_pair_launch(
                kernel_name_ptrs.as_ptr(),
                cache_keys.as_ptr(),
                self.graph.input_pointers.as_u32_ptr().cast(),
                self.graph.execution_table_pointers.as_u32_ptr().cast(),
                self.graph.execution_table_strides.as_u32_ptr(),
                self.graph.output_pointers.as_u32_ptr().cast(),
                self.graph.multiplicity_pointers.as_u32_ptr().cast(),
                self.graph.lookup_words.as_u32_ptr(),
                self.graph.sub_words.as_u32_ptr(),
                scratch,
                self.graph.row_count,
                launch.stream_raw().as_ptr(),
            )
        };
        if ok {
            Ok(PreparedWitnessLaunchTelemetry::PHASE_PAIR)
        } else {
            Err(PreparedWitnessError::PhaseKernelLaunchFailed(
                self.identities.clone(),
            ))
        }
    }

    pub fn kernel_identities(&self) -> &[WitnessKernelIdentity; 2] {
        &self.identities
    }

    pub fn plan_hash(&self) -> u64 {
        self.plan_hash
    }

    pub fn scratch(&self) -> Option<ArenaSlice> {
        self.scratch
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    fn identity(phase: u32) -> WitnessKernelIdentity {
        WitnessKernelIdentity {
            label: "phase-test".to_string(),
            kernel_name: format!("phase_{phase}"),
            semantic_hash: 7,
            cache_key: 100 + u64::from(phase),
            aot_manifest_identity: [9; 32],
            aot_manifest_hash: 9,
            mode: PreparedWitnessMode::RequireEmbeddedAot,
        }
    }

    #[test]
    fn zero_scratch_has_no_slot_or_dummy_allocation() {
        assert_eq!(phase_scratch_words(0, 1 << 20).unwrap(), None);
        assert_eq!(phase_scratch_slot_requirement(None, None).unwrap(), None);
        assert_eq!(
            phase_scratch_slot_requirement(None, Some(ArenaSlotId(4))).unwrap_err(),
            PreparedWitnessError::PhaseScratchUnexpected(ArenaSlotId(4))
        );
    }

    #[test]
    fn nonzero_scratch_is_exact_and_mandatory() {
        assert_eq!(phase_scratch_words(3, 32).unwrap(), Some(96));
        assert_eq!(
            phase_scratch_slot_requirement(Some(96), None).unwrap_err(),
            PreparedWitnessError::PhaseScratchMissing { required_words: 96 }
        );
        assert_eq!(
            phase_scratch_slot_requirement(Some(96), Some(ArenaSlotId(5))).unwrap(),
            Some((ArenaSlotId(5), 96))
        );
        assert_eq!(
            phase_scratch_words(1, u32::MAX as usize + 1).unwrap_err(),
            PreparedWitnessError::RowCountOverflow
        );
    }

    #[test]
    fn phase_runtime_requires_both_independently_admitted_aot_artifacts() {
        let identities = [identity(0), identity(1)];
        let events = RefCell::new(Vec::new());
        admit_phase_pair_with(
            &identities,
            9,
            0,
            |cache_key, _, _| {
                events.borrow_mut().push(cache_key);
                true
            },
            || {
                events.borrow_mut().push(999);
                true
            },
        )
        .unwrap();
        assert_eq!(*events.borrow(), [100, 101, 999]);

        for (admitted_key, missing_phase) in [(100, 1), (101, 0)] {
            let precompiled = RefCell::new(false);
            let error = admit_phase_pair_with(
                &identities,
                9,
                0,
                |cache_key, _, _| cache_key == admitted_key,
                || {
                    *precompiled.borrow_mut() = true;
                    true
                },
            )
            .unwrap_err();
            assert_eq!(
                error,
                PreparedWitnessError::StrictAotUnavailable(identity(missing_phase))
            );
            assert!(!*precompiled.borrow());
        }
    }

    #[test]
    fn phase_overlay_requires_an_exact_strict_base_identity() {
        let mut base = identity(0);
        validate_phase_base_identity(
            &base,
            WitnessLaunchContract::Recorded,
            "phase-test",
            7,
            [9; 32],
        )
        .unwrap();

        base.mode = PreparedWitnessMode::PreResolved;
        assert_eq!(
            validate_phase_base_identity(
                &base,
                WitnessLaunchContract::Recorded,
                "phase-test",
                7,
                [9; 32],
            )
            .unwrap_err(),
            PreparedWitnessError::PhaseRequiresStrictAot
        );
        base.mode = PreparedWitnessMode::RequireEmbeddedAot;
        assert_eq!(
            validate_phase_base_identity(
                &base,
                WitnessLaunchContract::Recorded,
                "phase-test",
                8,
                [9; 32],
            )
            .unwrap_err(),
            PreparedWitnessError::PhaseProgramMismatch
        );
    }

    #[test]
    fn phase_telemetry_reports_only_two_ordered_launches() {
        assert_eq!(
            PreparedWitnessLaunchTelemetry::PHASE_PAIR,
            PreparedWitnessLaunchTelemetry {
                kernel_launches: 2,
                allocations: 0,
                h2d_bytes: 0,
                d2h_bytes: 0,
                d2d_bytes: 0,
                sync_calls: 0,
                memset_bytes: 0,
            }
        );
    }
}
