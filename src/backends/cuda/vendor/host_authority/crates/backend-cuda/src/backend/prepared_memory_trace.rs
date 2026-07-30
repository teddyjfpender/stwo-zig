//! Capture-safe materialization of the canonical Cairo memory base traces.
//!
//! The compact execution tables and Graph-A multiplicity slabs already live in
//! the proof arena. This graph only copies/slices them into the exact AIR base
//! columns; it allocates, transfers, and synchronizes nothing on launch.

use std::collections::BTreeSet;

use super::exec_context::{
    check_cuda, ArenaError, ArenaSlice, CudaLaunchContext, CudaRuntimeError, DeviceArena,
};
use super::prepared_execution_tables::{
    PreparedExecutionTablesGraph, EXECUTION_TABLE_BIG_LIMBS, EXECUTION_TABLE_SMALL_LIMBS,
};

mod authority;
mod loaded_binding;

#[cfg(test)]
mod tests;

pub use authority::{
    MemoryBaseTraceAbi, MemoryBaseTraceAbiAccess, MemoryBaseTraceAbiArgument,
    MemoryBaseTraceAbiArgumentKind, MemoryBaseTraceAuthorityError, MemoryBaseTraceContract,
    MemoryBaseTraceEffectAccess, MemoryBaseTraceEffectRole, MemoryBaseTraceKernelLaunch,
    MemoryBaseTraceLinkedContract, MemoryBaseTraceRequirements, MemoryBaseTraceStepContract,
    MemoryBaseTraceStepKind, MemoryBaseTraceValuePartRequirements,
};
use loaded_binding::PreparedMemoryBaseTraceBinding;

pub const MEMORY_ADDRESS_BASE_COLUMNS: usize = 32;
pub const MEMORY_BIG_BASE_COLUMNS: usize = EXECUTION_TABLE_BIG_LIMBS + 1;
pub const MEMORY_SMALL_BASE_COLUMNS: usize = EXECUTION_TABLE_SMALL_LIMBS + 1;

fn readable_source_words(source_words: usize, source_offset: usize, row_count: usize) -> usize {
    source_words.saturating_sub(source_offset).min(row_count)
}

#[derive(Clone, Copy, Debug)]
pub struct MemoryBaseTracePart<'a> {
    pub source_offset: usize,
    pub row_count: usize,
    pub outputs: &'a [ArenaSlice],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreparedMemoryBaseTraceError {
    CudaUnavailable,
    SizeOverflow,
    ShapeMismatch {
        role: &'static str,
        expected: usize,
        actual: usize,
    },
    SliceTooSmall {
        role: &'static str,
        required_words: usize,
        actual_words: usize,
    },
    ContextMismatch(&'static str),
    ArenaBindingMismatch(&'static str),
    InvalidContract,
    InvalidBindingGeometry(&'static str),
    InvalidBindingIdentity,
    RawBindingMismatch,
    DuplicateSlice,
    Arena(ArenaError),
    Cuda(CudaRuntimeError),
}

impl core::fmt::Display for PreparedMemoryBaseTraceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "prepared memory base trace rejected: {self:?}")
    }
}

impl std::error::Error for PreparedMemoryBaseTraceError {}

impl From<CudaRuntimeError> for PreparedMemoryBaseTraceError {
    fn from(value: CudaRuntimeError) -> Self {
        Self::Cuda(value)
    }
}

impl From<ArenaError> for PreparedMemoryBaseTraceError {
    fn from(value: ArenaError) -> Self {
        Self::Arena(value)
    }
}

struct PreparedValuePart {
    source_pointers: Vec<*const u32>,
    source_slice_words: u32,
    multiplicities: *const u32,
    multiplicity_slice_words: u32,
    row_count: u32,
    output_pointers: Vec<*mut u32>,
    rc99_limb_pointers: Vec<*const u32>,
}

pub struct PreparedMemoryBaseTraceGraph<'a> {
    arena: &'a DeviceArena,
    contract: MemoryBaseTraceContract,
    binding: PreparedMemoryBaseTraceBinding,
    address_ids: *const u32,
    address_id_words: u32,
    address_output_pointers: Vec<*mut u32>,
    big_parts: Vec<PreparedValuePart>,
    small_part: PreparedValuePart,
}

impl<'a> PreparedMemoryBaseTraceGraph<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn prepare(
        arena: &'a DeviceArena,
        execution: &PreparedExecutionTablesGraph<'a>,
        address_counts: ArenaSlice,
        address_count_words: usize,
        address_rows: usize,
        address_outputs: &[ArenaSlice],
        big_counts: ArenaSlice,
        big_count_words: usize,
        big_parts: &[MemoryBaseTracePart<'_>],
        small_counts: ArenaSlice,
        small_count_words: usize,
        small_part: MemoryBaseTracePart<'_>,
        rc99_lut: ArenaSlice,
        rc99_table_size: usize,
        rc99_counts: ArenaSlice,
    ) -> Result<Self, PreparedMemoryBaseTraceError> {
        if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
            return Err(PreparedMemoryBaseTraceError::CudaUnavailable);
        }
        check_shape(
            "address outputs",
            MEMORY_ADDRESS_BASE_COLUMNS,
            address_outputs.len(),
        )?;
        check_shape(
            "big sources",
            EXECUTION_TABLE_BIG_LIMBS,
            execution.big_limbs().len(),
        )?;
        check_shape(
            "small sources",
            EXECUTION_TABLE_SMALL_LIMBS,
            execution.small_limbs().len(),
        )?;
        if big_parts.is_empty() {
            return Err(PreparedMemoryBaseTraceError::ShapeMismatch {
                role: "big parts",
                expected: 1,
                actual: 0,
            });
        }
        for part in big_parts {
            check_shape("big outputs", MEMORY_BIG_BASE_COLUMNS, part.outputs.len())?;
        }
        check_shape(
            "small outputs",
            MEMORY_SMALL_BASE_COLUMNS,
            small_part.outputs.len(),
        )?;
        let expected_address_words = address_rows
            .checked_mul(16)
            .ok_or(PreparedMemoryBaseTraceError::SizeOverflow)?;
        if address_count_words != expected_address_words {
            return Err(PreparedMemoryBaseTraceError::ShapeMismatch {
                role: "address multiplicities",
                expected: expected_address_words,
                actual: address_count_words,
            });
        }
        let address_id_words = execution.requirements().n_addrs.saturating_sub(1);
        if address_id_words > address_count_words {
            return Err(PreparedMemoryBaseTraceError::ShapeMismatch {
                role: "address id words",
                expected: address_count_words,
                actual: address_id_words,
            });
        }
        let expected_big_words = big_parts.iter().try_fold(0usize, |end, part| {
            let next = part
                .source_offset
                .checked_add(part.row_count)
                .ok_or(PreparedMemoryBaseTraceError::SizeOverflow)?;
            Ok::<_, PreparedMemoryBaseTraceError>(end.max(next))
        })?;
        if big_count_words != expected_big_words {
            return Err(PreparedMemoryBaseTraceError::ShapeMismatch {
                role: "big multiplicities",
                expected: expected_big_words,
                actual: big_count_words,
            });
        }
        if small_part.source_offset != 0 || small_part.row_count != small_count_words {
            return Err(PreparedMemoryBaseTraceError::ShapeMismatch {
                role: "small multiplicities",
                expected: small_part.row_count,
                actual: small_count_words,
            });
        }
        check_shape("rc9_9 table size", 1usize << 18, rc99_table_size)?;
        let rc99_count_words = rc99_table_size
            .checked_mul(8)
            .ok_or(PreparedMemoryBaseTraceError::SizeOverflow)?;
        let big_part_requirements = big_parts
            .iter()
            .enumerate()
            .map(|(part_ordinal, part)| {
                Ok(MemoryBaseTraceValuePartRequirements {
                    part_ordinal: u32::try_from(part_ordinal)
                        .map_err(|_| PreparedMemoryBaseTraceError::SizeOverflow)?,
                    source_offset: part.source_offset,
                    row_count: part.row_count,
                })
            })
            .collect::<Result<Vec<_>, PreparedMemoryBaseTraceError>>()?;
        let contract = MemoryBaseTraceContract::compile(&MemoryBaseTraceRequirements {
            n_addrs: execution.requirements().n_addrs,
            raw_address_words: execution.requirements().raw_addr_to_id_words,
            address_rows,
            address_count_words,
            big_source_words: execution.requirements().big_column_words,
            big_count_words,
            big_parts: big_part_requirements,
            small_source_words: execution.requirements().small_column_words,
            small_count_words,
            small_part: MemoryBaseTraceValuePartRequirements {
                part_ordinal: 0,
                source_offset: small_part.source_offset,
                row_count: small_part.row_count,
            },
            rc99_lut_words: rc99_table_size,
            rc99_count_words,
        })
        .map_err(|_| PreparedMemoryBaseTraceError::InvalidContract)?;
        contract
            .validate()
            .map_err(|_| PreparedMemoryBaseTraceError::InvalidContract)?;

        let token = arena.context().identity_token();
        let mut all = Vec::new();
        for (role, slice, words) in [
            (
                "raw address table",
                execution.raw_addr_to_id(),
                execution.requirements().raw_addr_to_id_words,
            ),
            (
                "address multiplicities",
                address_counts,
                address_count_words,
            ),
            ("big multiplicities", big_counts, big_count_words),
            ("small multiplicities", small_counts, small_count_words),
            ("rc9_9 LUT", rc99_lut, 1usize << 18),
            ("rc9_9 multiplicities", rc99_counts, rc99_count_words),
        ] {
            validate_slice(role, slice, words, token)?;
            all.push(slice.id());
        }
        for (&source, words) in execution
            .big_limbs()
            .iter()
            .zip(std::iter::repeat(execution.requirements().big_column_words))
            .chain(execution.small_limbs().iter().zip(std::iter::repeat(
                execution.requirements().small_column_words,
            )))
        {
            validate_slice("memory limb source", source, words, token)?;
            all.push(source.id());
        }
        for (output, words) in address_outputs
            .iter()
            .copied()
            .zip(std::iter::repeat(address_rows))
            .chain(big_parts.iter().flat_map(|part| {
                part.outputs
                    .iter()
                    .copied()
                    .zip(std::iter::repeat(part.row_count))
            }))
            .chain(
                small_part
                    .outputs
                    .iter()
                    .copied()
                    .zip(std::iter::repeat(small_part.row_count)),
            )
        {
            validate_slice("memory base output", output, words, token)?;
            all.push(output.id());
        }
        let mut distinct = BTreeSet::new();
        if all.into_iter().any(|id| !distinct.insert(id)) {
            return Err(PreparedMemoryBaseTraceError::DuplicateSlice);
        }
        let binding = PreparedMemoryBaseTraceBinding::prepare(
            arena,
            &contract,
            execution,
            address_counts,
            address_outputs,
            big_counts,
            big_parts,
            small_counts,
            small_part,
            rc99_lut,
            rc99_counts,
        )?;

        let address_ids = if address_id_words == 0 {
            checked_subslice("address ids from one", execution.raw_addr_to_id(), 0, 0)?
        } else {
            checked_subslice(
                "address ids from one",
                execution.raw_addr_to_id(),
                1,
                address_id_words,
            )?
        };
        let prepared_part = |part: &MemoryBaseTracePart<'_>,
                             sources: &[ArenaSlice],
                             source_words: usize,
                             counts: ArenaSlice| {
            let source_slice_words =
                readable_source_words(source_words, part.source_offset, part.row_count);
            let source_pointers = sources
                .iter()
                .copied()
                .map(|source| source_pointer(source, part.source_offset, source_slice_words))
                .collect::<Result<Vec<_>, _>>()?;
            let multiplicities = checked_subslice(
                "memory value multiplicity slice",
                counts,
                part.source_offset,
                part.row_count,
            )?;
            Ok::<_, PreparedMemoryBaseTraceError>(PreparedValuePart {
                source_pointers,
                source_slice_words: u32::try_from(source_slice_words)
                    .map_err(|_| PreparedMemoryBaseTraceError::SizeOverflow)?,
                multiplicities: multiplicities.as_u32_ptr().cast_const(),
                multiplicity_slice_words: u32::try_from(part.row_count)
                    .map_err(|_| PreparedMemoryBaseTraceError::SizeOverflow)?,
                row_count: u32::try_from(part.row_count)
                    .map_err(|_| PreparedMemoryBaseTraceError::SizeOverflow)?,
                output_pointers: part
                    .outputs
                    .iter()
                    .map(|slice| slice.as_u32_ptr())
                    .collect(),
                rc99_limb_pointers: part
                    .outputs
                    .iter()
                    .take(part.outputs.len() - 1)
                    .map(|slice| slice.as_u32_ptr().cast_const())
                    .collect(),
            })
        };
        let big_parts = big_parts
            .iter()
            .map(|part| {
                prepared_part(
                    part,
                    execution.big_limbs(),
                    execution.requirements().big_column_words,
                    big_counts,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let small_part = prepared_part(
            &small_part,
            execution.small_limbs(),
            execution.requirements().small_column_words,
            small_counts,
        )?;
        let graph = Self {
            arena,
            contract,
            binding,
            address_ids: address_ids.as_u32_ptr().cast_const(),
            address_id_words: u32::try_from(address_id_words)
                .map_err(|_| PreparedMemoryBaseTraceError::SizeOverflow)?,
            address_output_pointers: address_outputs
                .iter()
                .map(|slice| slice.as_u32_ptr())
                .collect(),
            big_parts,
            small_part,
        };
        graph.validate_loaded_binding(arena)?;
        Ok(graph)
    }

    pub fn launch(&self) -> Result<(), PreparedMemoryBaseTraceError> {
        self.launch_on(self.arena.context().launch_context())
    }

    /// Seed the plan-owned canonical rc9_9 lookup table before capture.
    pub fn upload_rc99_lut(&self, words: &[u32]) -> Result<(), PreparedMemoryBaseTraceError> {
        let rc99_lut = self.binding.rc99_lut();
        check_shape("rc9_9 LUT upload", rc99_lut.len_words(), words.len())?;
        unsafe {
            self.arena.context().memcpy_h2d_async(
                rc99_lut.as_void_ptr(),
                words.as_ptr().cast(),
                core::mem::size_of_val(words),
            )?;
        }
        self.arena.context().sync()?;
        Ok(())
    }

    pub fn launch_on(&self, launch: CudaLaunchContext) -> Result<(), PreparedMemoryBaseTraceError> {
        if launch.identity_token() != self.arena.context().identity_token() {
            return Err(CudaRuntimeError::ContextMismatch.into());
        }
        let stream = launch.stream_raw().as_ptr();
        let requirements = self.contract.requirements();
        let address = unsafe {
            stwo_backend_cuda_kernels::raw::memory_address_base_trace_sliced_on(
                self.address_ids,
                self.address_id_words,
                self.binding.address_counts().as_u32_ptr().cast_const(),
                requirements.address_count_words as u32,
                requirements.address_rows as u32,
                self.address_output_pointers.as_ptr(),
                stream,
            )
        };
        check_cuda("memory_address_base_trace_sliced_on", address)?;
        for part in &self.big_parts {
            self.launch_value_part(EXECUTION_TABLE_BIG_LIMBS, part, stream)?;
            self.launch_rc99(part, EXECUTION_TABLE_BIG_LIMBS / 2, stream)?;
        }
        self.launch_value_part(EXECUTION_TABLE_SMALL_LIMBS, &self.small_part, stream)?;
        self.launch_rc99(&self.small_part, EXECUTION_TABLE_SMALL_LIMBS / 2, stream)
    }

    fn launch_value_part(
        &self,
        n_limbs: usize,
        part: &PreparedValuePart,
        stream: *mut core::ffi::c_void,
    ) -> Result<(), PreparedMemoryBaseTraceError> {
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::memory_value_base_trace_sliced_on(
                part.source_pointers.as_ptr(),
                n_limbs as u32,
                part.source_slice_words,
                part.multiplicities,
                part.multiplicity_slice_words,
                part.row_count,
                part.output_pointers.as_ptr(),
                stream,
            )
        };
        check_cuda("memory_value_base_trace_sliced_on", code)?;
        Ok(())
    }

    fn launch_rc99(
        &self,
        part: &PreparedValuePart,
        n_pairs: usize,
        stream: *mut core::ffi::c_void,
    ) -> Result<(), PreparedMemoryBaseTraceError> {
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::memory_rc99_count_on(
                part.rc99_limb_pointers.as_ptr(),
                n_pairs as u32,
                part.row_count,
                self.binding.rc99_lut().as_u32_ptr().cast_const(),
                self.contract.requirements().rc99_lut_words as u32,
                self.binding.rc99_counts().as_u32_ptr(),
                stream,
            )
        };
        check_cuda("memory_rc99_count_on", code)?;
        Ok(())
    }

    pub fn kernel_launches(&self) -> usize {
        3 + 2 * self.big_parts.len()
    }

    pub fn rc99_lut(&self) -> ArenaSlice {
        self.binding.rc99_lut()
    }

    pub fn rc99_counts(&self) -> ArenaSlice {
        self.binding.rc99_counts()
    }

    pub fn rc99_table_size(&self) -> usize {
        self.contract.requirements().rc99_lut_words
    }

    /// Exact address-free semantic authority compiled for this prepared graph.
    pub fn contract(&self) -> &MemoryBaseTraceContract {
        &self.contract
    }

    /// Address-free identity of the ordered logical arena binding.
    pub fn binding_identity(&self) -> [u8; 32] {
        self.binding.identity()
    }

    /// Revalidate arena ownership, exact dimensions, and every private launch
    /// pointer before admitting a loaded graph.
    pub fn validate_loaded_binding(
        &self,
        arena: &DeviceArena,
    ) -> Result<(), PreparedMemoryBaseTraceError> {
        if !core::ptr::eq(self.arena, arena) {
            return Err(PreparedMemoryBaseTraceError::ArenaBindingMismatch(
                "prepared graph",
            ));
        }
        self.binding.validate(arena, &self.contract)?;
        if !self.binding.raw_matches(
            &self.contract,
            self.address_ids,
            self.address_id_words,
            &self.address_output_pointers,
            &self.big_parts,
            &self.small_part,
        ) {
            return Err(PreparedMemoryBaseTraceError::RawBindingMismatch);
        }
        Ok(())
    }

    pub fn belongs_to(&self, arena: &DeviceArena) -> bool {
        self.validate_loaded_binding(arena).is_ok()
    }

    pub fn address_source(&self) -> ArenaSlice {
        self.binding.address_source()
    }

    pub fn address_counts(&self) -> ArenaSlice {
        self.binding.address_counts()
    }

    pub fn address_outputs(&self) -> &[ArenaSlice] {
        self.binding.address_outputs()
    }

    pub fn big_sources(&self) -> &[ArenaSlice] {
        self.binding.big_sources()
    }

    pub fn big_counts(&self) -> ArenaSlice {
        self.binding.big_counts()
    }

    pub fn big_outputs(&self, part_ordinal: usize) -> Option<&[ArenaSlice]> {
        self.binding.big_outputs(part_ordinal)
    }

    pub fn small_sources(&self) -> &[ArenaSlice] {
        self.binding.small_sources()
    }

    pub fn small_counts(&self) -> ArenaSlice {
        self.binding.small_counts()
    }

    pub fn small_outputs(&self) -> &[ArenaSlice] {
        self.binding.small_outputs()
    }
}

fn check_shape(
    role: &'static str,
    expected: usize,
    actual: usize,
) -> Result<(), PreparedMemoryBaseTraceError> {
    if expected == actual {
        Ok(())
    } else {
        Err(PreparedMemoryBaseTraceError::ShapeMismatch {
            role,
            expected,
            actual,
        })
    }
}

fn validate_slice(
    role: &'static str,
    slice: ArenaSlice,
    required_words: usize,
    token: core::ptr::NonNull<core::ffi::c_void>,
) -> Result<(), PreparedMemoryBaseTraceError> {
    if slice.context_token() != token {
        return Err(PreparedMemoryBaseTraceError::ContextMismatch(role));
    }
    if slice.len_words() < required_words {
        return Err(PreparedMemoryBaseTraceError::SliceTooSmall {
            role,
            required_words,
            actual_words: slice.len_words(),
        });
    }
    Ok(())
}

fn checked_subslice(
    role: &'static str,
    slice: ArenaSlice,
    offset_words: usize,
    len_words: usize,
) -> Result<ArenaSlice, PreparedMemoryBaseTraceError> {
    let required_words = offset_words
        .checked_add(len_words)
        .ok_or(PreparedMemoryBaseTraceError::SizeOverflow)?;
    if required_words > slice.len_words() {
        return Err(PreparedMemoryBaseTraceError::SliceTooSmall {
            role,
            required_words,
            actual_words: slice.len_words(),
        });
    }
    slice
        .checked_subslice(offset_words, len_words)
        .map_err(Into::into)
}

fn source_pointer(
    source: ArenaSlice,
    source_offset: usize,
    source_slice_words: usize,
) -> Result<*const u32, PreparedMemoryBaseTraceError> {
    if source_slice_words == 0 {
        return Ok(core::ptr::null());
    }
    checked_subslice(
        "memory value source slice",
        source,
        source_offset,
        source_slice_words,
    )
    .map(|slice| slice.as_u32_ptr().cast_const())
}
