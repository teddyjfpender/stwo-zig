//! Replacement-v1 opcode ingress from canonical row-major Cairo states.
//!
//! One staged `[pc, ap, fp]` upload replaces four or five padded host-column
//! uploads. The device scatter preserves the generated witness writer's stable
//! column ABI while deriving enabler/iota and padding from row zero.

use core::ffi::c_void;
use std::collections::BTreeSet;

use super::exec_context::{ArenaError, ArenaSlice, ArenaSlotId, CudaRuntimeError, DeviceArena};
use super::prepared_witness_input::WitnessInputGatherArenaSlotRequirement;

mod authority;
mod ingress_receipt;

pub use authority::{
    WitnessCasmInputAbi, WitnessCasmInputAbiAccess, WitnessCasmInputAbiArgument,
    WitnessCasmInputAbiArgumentKind, WitnessCasmInputAuthorityError, WitnessCasmInputColumnEffect,
    WitnessCasmInputColumnValue, WitnessCasmInputContract, WitnessCasmInputEffectAbi,
    WitnessCasmInputEffectGeometry, WitnessCasmInputFixedField, WitnessCasmInputKernelLaunch,
    WitnessCasmInputLinkedContract, WitnessCasmInputRowDomain, WITNESS_CASM_INPUT_FIXED_ORDER,
};
pub use ingress_receipt::{PendingWitnessCasmInputIngressReceipt, WitnessCasmInputIngressReceipt};

const WORD_BYTES: usize = core::mem::size_of::<u32>();

pub const WITNESS_CASM_STATE_WORDS: usize = 3;
pub const WITNESS_CASM_BASE_INPUT_COLUMNS: usize = 4;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessCasmInputRequirements {
    pub n_real_rows: usize,
    pub consumer_rows: usize,
    pub include_iota: bool,
    pub staging_words: usize,
    pub consumer_input_column_words: Vec<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessCasmInputSlots {
    /// Reusable row-major `[pc, ap, fp]` staging storage.
    pub staging: ArenaSlotId,
    /// Existing stable pc/ap/fp/enabler/(optional iota) recorder inputs.
    pub consumer_input_columns: Vec<ArenaSlotId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreparedWitnessCasmInputError {
    CudaUnavailable,
    NoRows,
    SizeOverflow,
    MalformedRequirements,
    ConsumerColumnCountMismatch {
        expected: usize,
        actual: usize,
    },
    DuplicateSlot(ArenaSlotId),
    SlotSizeMismatch {
        slot: ArenaSlotId,
        expected_words: usize,
        actual_words: usize,
    },
    SlotMisaligned(ArenaSlotId),
    ContextMismatch(ArenaSlotId),
    HostWordCountMismatch {
        expected: usize,
        actual: usize,
    },
    IngressGenerationOverflow,
    InvalidIngressReceipt,
    InputNotIngested,
    KernelLaunchFailed,
    Authority(WitnessCasmInputAuthorityError),
    Arena(ArenaError),
    Cuda(CudaRuntimeError),
}

impl core::fmt::Display for PreparedWitnessCasmInputError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "prepared witness Casm input rejected: {self:?}")
    }
}

impl std::error::Error for PreparedWitnessCasmInputError {}

impl From<ArenaError> for PreparedWitnessCasmInputError {
    fn from(value: ArenaError) -> Self {
        Self::Arena(value)
    }
}

impl From<CudaRuntimeError> for PreparedWitnessCasmInputError {
    fn from(value: CudaRuntimeError) -> Self {
        Self::Cuda(value)
    }
}

impl From<WitnessCasmInputAuthorityError> for PreparedWitnessCasmInputError {
    fn from(value: WitnessCasmInputAuthorityError) -> Self {
        Self::Authority(value)
    }
}

/// Exact proof-shape geometry. Opcode consumers use scalar power-of-two rows,
/// with the generated SIMD writer's minimum packed width of sixteen.
pub fn witness_casm_input_requirements(
    n_real_rows: usize,
    include_iota: bool,
) -> Result<WitnessCasmInputRequirements, PreparedWitnessCasmInputError> {
    if n_real_rows == 0 {
        return Err(PreparedWitnessCasmInputError::NoRows);
    }
    let consumer_rows = n_real_rows
        .checked_next_power_of_two()
        .ok_or(PreparedWitnessCasmInputError::SizeOverflow)?
        .max(16);
    u32::try_from(n_real_rows).map_err(|_| PreparedWitnessCasmInputError::SizeOverflow)?;
    u32::try_from(consumer_rows).map_err(|_| PreparedWitnessCasmInputError::SizeOverflow)?;
    let staging_words = n_real_rows
        .checked_mul(WITNESS_CASM_STATE_WORDS)
        .ok_or(PreparedWitnessCasmInputError::SizeOverflow)?;
    let column_count = WITNESS_CASM_BASE_INPUT_COLUMNS + usize::from(include_iota);
    Ok(WitnessCasmInputRequirements {
        n_real_rows,
        consumer_rows,
        include_iota,
        staging_words,
        consumer_input_column_words: vec![consumer_rows; column_count],
    })
}

impl WitnessCasmInputRequirements {
    pub fn arena_slot_requirements(
        &self,
        slots: &WitnessCasmInputSlots,
    ) -> Result<Vec<WitnessInputGatherArenaSlotRequirement>, PreparedWitnessCasmInputError> {
        if slots.consumer_input_columns.len() != self.consumer_input_column_words.len() {
            return Err(PreparedWitnessCasmInputError::ConsumerColumnCountMismatch {
                expected: self.consumer_input_column_words.len(),
                actual: slots.consumer_input_columns.len(),
            });
        }
        let mut requirements = Vec::with_capacity(1 + slots.consumer_input_columns.len());
        requirements.push(WitnessInputGatherArenaSlotRequirement {
            id: slots.staging,
            len_words: self.staging_words,
            alignment_words: 1,
        });
        requirements.extend(
            slots
                .consumer_input_columns
                .iter()
                .zip(&self.consumer_input_column_words)
                .map(|(&id, &len_words)| WitnessInputGatherArenaSlotRequirement {
                    id,
                    len_words,
                    alignment_words: 1,
                }),
        );
        let mut seen = BTreeSet::new();
        for requirement in &requirements {
            if !seen.insert(requirement.id) {
                return Err(PreparedWitnessCasmInputError::DuplicateSlot(requirement.id));
            }
        }
        Ok(requirements)
    }
}

/// A same-stream staging/scatter edge. Multiple opcode lanes may reuse the
/// same staging slot by calling `ingest_and_launch` sequentially; CUDA stream
/// order prevents the next upload from overtaking the previous scatter. A new
/// attempt invalidates this stage's prior receipt; all batched host sources
/// must remain live through their shared fence.
pub struct PreparedWitnessCasmInputStage<'a> {
    arena: &'a DeviceArena,
    contract: WitnessCasmInputContract,
    staging: ArenaSlice,
    consumer_input_columns: Vec<ArenaSlice>,
    ingress_state: ingress_receipt::WitnessCasmInputIngressState,
}

impl<'a> PreparedWitnessCasmInputStage<'a> {
    pub fn prepare(
        arena: &'a DeviceArena,
        requirements: &WitnessCasmInputRequirements,
        slots: &WitnessCasmInputSlots,
    ) -> Result<Self, PreparedWitnessCasmInputError> {
        if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
            return Err(PreparedWitnessCasmInputError::CudaUnavailable);
        }
        if witness_casm_input_requirements(requirements.n_real_rows, requirements.include_iota)?
            != *requirements
        {
            return Err(PreparedWitnessCasmInputError::MalformedRequirements);
        }
        let contract = WitnessCasmInputContract::compile(requirements)?;
        requirements.arena_slot_requirements(slots)?;
        let staging = bind_min(arena, slots.staging, requirements.staging_words)?;
        let consumer_input_columns = slots
            .consumer_input_columns
            .iter()
            .zip(&requirements.consumer_input_column_words)
            .map(|(&id, &len_words)| bind_min(arena, id, len_words))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            arena,
            contract,
            staging,
            consumer_input_columns,
            ingress_state: ingress_receipt::WitnessCasmInputIngressState::new(),
        })
    }

    /// Enqueue only the real canonical rows.
    ///
    /// # Safety
    ///
    /// `words` must remain allocated at the same address and immutable until
    /// the arena context is fenced after this stage's scatter. Ingestion must
    /// run eagerly outside CUDA graph capture. Pageable memory is admitted for
    /// correctness but does not promise asynchronous DMA overlap.
    pub unsafe fn ingest_words(&self, words: &[u32]) -> Result<(), PreparedWitnessCasmInputError> {
        if words.len() != self.contract.requirements().staging_words {
            return Err(PreparedWitnessCasmInputError::HostWordCountMismatch {
                expected: self.contract.requirements().staging_words,
                actual: words.len(),
            });
        }
        let generation = self.ingress_state.next_generation()?;
        let binding = self.ingress_binding();
        let receipt = WitnessCasmInputIngressReceipt::prepare(binding, words, generation)?;

        // A valid attempt may overwrite staging, so no earlier receipt remains
        // admissible. The generation is consumed even if enqueueing fails.
        self.ingress_state.begin(receipt);
        let upload_result = unsafe {
            self.arena.context().memcpy_h2d_async(
                self.staging.as_void_ptr(),
                words.as_ptr().cast::<c_void>(),
                core::mem::size_of_val(words),
            )
        };
        if let Err(error) = upload_result {
            // An enqueue failure does not prove that no prior/partial async
            // work retained the borrowed source. Drain before returning
            // without a pending receipt.
            let sync_result = self.arena.context().sync();
            self.ingress_state.abort(receipt);
            sync_result?;
            return Err(error.into());
        }
        Ok(())
    }

    /// Enqueue the scatter and return evidence which remains pending until the
    /// caller acknowledges its existing setup fence.
    pub fn launch(
        &self,
    ) -> Result<PendingWitnessCasmInputIngressReceipt, PreparedWitnessCasmInputError> {
        let receipt = self
            .ingress_state
            .ingested()
            .ok_or(PreparedWitnessCasmInputError::InputNotIngested)?;
        let columns = &self.consumer_input_columns;
        let requirements = self.contract.requirements();
        let iota = if requirements.include_iota {
            columns[4].as_u32_ptr()
        } else {
            core::ptr::null_mut()
        };
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_witness_casm_input_scatter_on(
                self.staging.as_u32_ptr().cast_const(),
                requirements.n_real_rows as u32,
                requirements.consumer_rows as u32,
                columns[0].as_u32_ptr(),
                columns[1].as_u32_ptr(),
                columns[2].as_u32_ptr(),
                columns[3].as_u32_ptr(),
                iota,
                self.arena.context().stream_raw().as_ptr(),
            )
        };
        if code == 0 {
            match self
                .ingress_state
                .mark_scatter_enqueued(receipt, self.ingress_binding())
            {
                Ok(pending) => Ok(pending),
                Err(error) => {
                    // Fail closed if internal receipt state ever disagrees
                    // after launch: fence the enqueued work before returning
                    // without a pending token.
                    let sync_result = self.arena.context().sync();
                    self.ingress_state.abort(receipt);
                    sync_result?;
                    Err(error)
                }
            }
        } else {
            // The upload may already be in flight, but no pending receipt can
            // represent a scatter which failed to enqueue.
            let sync_result = self.arena.context().sync();
            self.ingress_state.abort(receipt);
            sync_result?;
            Err(PreparedWitnessCasmInputError::KernelLaunchFailed)
        }
    }

    /// Ingest and scatter on the arena's main stream.
    ///
    /// # Safety
    ///
    /// The source-address, immutability, lifetime, and eager-ingress contract
    /// of [`Self::ingest_words`] applies through the caller-owned fence.
    /// Starting another attempt invalidates the returned pending receipt.
    pub unsafe fn ingest_and_launch(
        &self,
        words: &[u32],
    ) -> Result<PendingWitnessCasmInputIngressReceipt, PreparedWitnessCasmInputError> {
        unsafe { self.ingest_words(words)? };
        self.launch()
    }

    /// Publish one enqueued ingress after the caller's existing setup fence.
    ///
    /// # Safety
    ///
    /// Before calling, the caller must successfully fence this stage's arena
    /// execution context after the upload and scatter represented by
    /// `pending`. The fence must also discharge the source lifetime and
    /// immutability obligation documented by [`Self::ingest_words`].
    pub unsafe fn acknowledge_ingress_fence(
        &self,
        pending: PendingWitnessCasmInputIngressReceipt,
    ) -> Result<WitnessCasmInputIngressReceipt, PreparedWitnessCasmInputError> {
        self.ingress_state.publish(pending, self.ingress_binding())
    }

    /// The only published receipt. Pending or failed work is never returned.
    pub fn ingress_receipt(&self) -> Option<WitnessCasmInputIngressReceipt> {
        self.ingress_state.receipt()
    }

    pub fn ingress_is_current(&self, receipt: &WitnessCasmInputIngressReceipt) -> bool {
        self.ingress_state
            .is_current(receipt, self.ingress_binding())
    }

    /// Consume the one exact current receipt.
    ///
    /// A mismatch fails closed by invalidating every receipt state while
    /// retaining the burned generation.
    pub fn consume_ingress_receipt(
        &self,
        receipt: WitnessCasmInputIngressReceipt,
    ) -> Result<(), PreparedWitnessCasmInputError> {
        self.ingress_state.consume(receipt, self.ingress_binding())
    }

    /// Invalidate pending and published admission evidence without rolling
    /// back the generation. This does not replace the caller-owned setup fence.
    pub fn invalidate_ingress_receipt(&self) {
        self.ingress_state.invalidate();
    }

    pub fn contract(&self) -> &WitnessCasmInputContract {
        &self.contract
    }

    pub fn requirements(&self) -> &WitnessCasmInputRequirements {
        self.contract.requirements()
    }

    pub fn staging(&self) -> ArenaSlice {
        self.staging
    }

    pub fn consumer_input_columns(&self) -> &[ArenaSlice] {
        &self.consumer_input_columns
    }

    fn ingress_binding(&self) -> ingress_receipt::WitnessCasmInputIngressBinding {
        ingress_receipt::WitnessCasmInputIngressBinding::new(
            self.arena,
            &self.contract,
            self.staging,
        )
    }
}

fn bind_min(
    arena: &DeviceArena,
    id: ArenaSlotId,
    required_words: usize,
) -> Result<ArenaSlice, PreparedWitnessCasmInputError> {
    let slice = arena.bind(id)?;
    if slice.context_token() != arena.context().identity_token() {
        return Err(PreparedWitnessCasmInputError::ContextMismatch(id));
    }
    if slice.len_words() < required_words {
        return Err(PreparedWitnessCasmInputError::SlotSizeMismatch {
            slot: id,
            expected_words: required_words,
            actual_words: slice.len_words(),
        });
    }
    if (slice.as_u32_ptr() as usize) % WORD_BYTES != 0 {
        return Err(PreparedWitnessCasmInputError::SlotMisaligned(id));
    }
    Ok(slice.truncated(required_words))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requirements_are_exact_for_plain_and_iota_lanes() {
        let plain = witness_casm_input_requirements(17, false).unwrap();
        assert_eq!(plain.consumer_rows, 32);
        assert_eq!(plain.staging_words, 51);
        assert_eq!(plain.consumer_input_column_words, [32; 4]);

        let iota = witness_casm_input_requirements(16, true).unwrap();
        assert_eq!(iota.consumer_rows, 16);
        assert_eq!(iota.staging_words, 48);
        assert_eq!(iota.consumer_input_column_words, [16; 5]);
    }

    #[test]
    fn invalid_rows_and_slot_aliases_fail_closed() {
        assert_eq!(
            witness_casm_input_requirements(0, false).unwrap_err(),
            PreparedWitnessCasmInputError::NoRows
        );
        let requirements = witness_casm_input_requirements(17, false).unwrap();
        let duplicate = ArenaSlotId(7);
        let slots = WitnessCasmInputSlots {
            staging: duplicate,
            consumer_input_columns: vec![
                duplicate,
                ArenaSlotId(8),
                ArenaSlotId(9),
                ArenaSlotId(10),
            ],
        };
        assert_eq!(
            requirements.arena_slot_requirements(&slots).unwrap_err(),
            PreparedWitnessCasmInputError::DuplicateSlot(duplicate)
        );
    }
}
