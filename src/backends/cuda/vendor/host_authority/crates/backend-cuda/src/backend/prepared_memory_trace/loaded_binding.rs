//! Immutable, address-free admission for one prepared memory Base graph.
//!
//! The receipt owns only checked arena views and logical geometry. Device
//! addresses remain private launch details and are deliberately excluded from
//! its identity.

use std::collections::BTreeSet;

use super::{
    readable_source_words, MemoryBaseTraceContract, MemoryBaseTracePart,
    PreparedMemoryBaseTraceError, PreparedValuePart, MEMORY_ADDRESS_BASE_COLUMNS,
    MEMORY_BIG_BASE_COLUMNS, MEMORY_SMALL_BASE_COLUMNS,
};
use crate::backend::exec_context::{ArenaSlice, DeviceArena};
use crate::backend::prepared_execution_tables::{
    ExecutionTablesContract, PreparedExecutionTablesGraph, EXECUTION_TABLE_BIG_LIMBS,
    EXECUTION_TABLE_SMALL_LIMBS,
};

const BINDING_DOMAIN: &[u8] = b"stwo-cuda-memory-base-loaded-binding-v1\0";
const BINDING_SOURCE: &[u8] = include_bytes!("loaded_binding.rs");

struct ValuePartBinding {
    source_offset: usize,
    row_count: usize,
    outputs: Vec<ArenaSlice>,
}

/// Canonical logical storage inventory behind a prepared launch graph.
pub(super) struct PreparedMemoryBaseTraceBinding {
    identity: [u8; 32],
    address_source: ArenaSlice,
    address_counts: ArenaSlice,
    address_outputs: Vec<ArenaSlice>,
    big_sources: Vec<ArenaSlice>,
    big_counts: ArenaSlice,
    big_parts: Vec<ValuePartBinding>,
    small_sources: Vec<ArenaSlice>,
    small_counts: ArenaSlice,
    small_part: ValuePartBinding,
    rc99_lut: ArenaSlice,
    rc99_counts: ArenaSlice,
    execution_contract: ExecutionTablesContract,
}

impl PreparedMemoryBaseTraceBinding {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn prepare(
        arena: &DeviceArena,
        contract: &MemoryBaseTraceContract,
        execution: &PreparedExecutionTablesGraph<'_>,
        address_counts: ArenaSlice,
        address_outputs: &[ArenaSlice],
        big_counts: ArenaSlice,
        big_parts: &[MemoryBaseTracePart<'_>],
        small_counts: ArenaSlice,
        small_part: MemoryBaseTracePart<'_>,
        rc99_lut: ArenaSlice,
        rc99_counts: ArenaSlice,
    ) -> Result<Self, PreparedMemoryBaseTraceError> {
        if !execution.belongs_to(arena) {
            return Err(PreparedMemoryBaseTraceError::ArenaBindingMismatch(
                "execution tables",
            ));
        }
        let mut binding = Self {
            identity: [0; 32],
            address_source: execution.raw_addr_to_id(),
            address_counts,
            address_outputs: address_outputs.to_vec(),
            big_sources: execution.big_limbs().to_vec(),
            big_counts,
            big_parts: big_parts
                .iter()
                .map(|part| ValuePartBinding {
                    source_offset: part.source_offset,
                    row_count: part.row_count,
                    outputs: part.outputs.to_vec(),
                })
                .collect(),
            small_sources: execution.small_limbs().to_vec(),
            small_counts,
            small_part: ValuePartBinding {
                source_offset: small_part.source_offset,
                row_count: small_part.row_count,
                outputs: small_part.outputs.to_vec(),
            },
            rc99_lut,
            rc99_counts,
            execution_contract: execution.contract().clone(),
        };
        binding.validate_geometry(contract)?;
        binding.identity = binding.canonical_identity(contract)?;
        binding.validate(arena, contract)?;
        Ok(binding)
    }

    pub(super) fn validate(
        &self,
        arena: &DeviceArena,
        contract: &MemoryBaseTraceContract,
    ) -> Result<(), PreparedMemoryBaseTraceError> {
        contract
            .validate()
            .map_err(|_| PreparedMemoryBaseTraceError::InvalidContract)?;
        self.execution_contract
            .validate()
            .map_err(|_| PreparedMemoryBaseTraceError::InvalidContract)?;
        self.validate_geometry(contract)?;
        if self.canonical_identity(contract)? != self.identity {
            return Err(PreparedMemoryBaseTraceError::InvalidBindingIdentity);
        }
        for (role, slice) in self.slices() {
            validate_arena_slice(arena, role, slice)?;
        }
        Ok(())
    }

    pub(super) fn raw_matches(
        &self,
        contract: &MemoryBaseTraceContract,
        address_ids: *const u32,
        address_id_words: u32,
        address_outputs: &[*mut u32],
        big_parts: &[PreparedValuePart],
        small_part: &PreparedValuePart,
    ) -> bool {
        // These wrappers copy process-local pointer vectors into by-value
        // kernel arguments; there is no device pointer-table workspace.
        let requirements = contract.requirements();
        let expected_address_words = requirements.n_addrs.saturating_sub(1);
        let expected_address_ids = if expected_address_words == 0 {
            self.address_source.as_u32_ptr().cast_const()
        } else {
            self.address_source
                .as_u32_ptr()
                .wrapping_add(1)
                .cast_const()
        };
        address_ids == expected_address_ids
            && address_id_words as usize == expected_address_words
            && pointer_list_matches(address_outputs, &self.address_outputs)
            && big_parts.len() == self.big_parts.len()
            && big_parts
                .iter()
                .zip(&self.big_parts)
                .all(|(prepared, binding)| {
                    value_part_raw_matches(prepared, binding, &self.big_sources, self.big_counts)
                })
            && value_part_raw_matches(
                small_part,
                &self.small_part,
                &self.small_sources,
                self.small_counts,
            )
    }

    pub(super) const fn identity(&self) -> [u8; 32] {
        self.identity
    }

    pub(super) const fn address_source(&self) -> ArenaSlice {
        self.address_source
    }

    pub(super) const fn address_counts(&self) -> ArenaSlice {
        self.address_counts
    }

    pub(super) fn address_outputs(&self) -> &[ArenaSlice] {
        &self.address_outputs
    }

    pub(super) fn big_sources(&self) -> &[ArenaSlice] {
        &self.big_sources
    }

    pub(super) const fn big_counts(&self) -> ArenaSlice {
        self.big_counts
    }

    pub(super) fn big_outputs(&self, ordinal: usize) -> Option<&[ArenaSlice]> {
        self.big_parts
            .get(ordinal)
            .map(|part| part.outputs.as_slice())
    }

    pub(super) fn small_sources(&self) -> &[ArenaSlice] {
        &self.small_sources
    }

    pub(super) const fn small_counts(&self) -> ArenaSlice {
        self.small_counts
    }

    pub(super) fn small_outputs(&self) -> &[ArenaSlice] {
        &self.small_part.outputs
    }

    pub(super) const fn rc99_lut(&self) -> ArenaSlice {
        self.rc99_lut
    }

    pub(super) const fn rc99_counts(&self) -> ArenaSlice {
        self.rc99_counts
    }

    fn validate_geometry(
        &self,
        contract: &MemoryBaseTraceContract,
    ) -> Result<(), PreparedMemoryBaseTraceError> {
        let requirements = contract.requirements();
        let execution = self.execution_contract.requirements();
        if execution.n_addrs != requirements.n_addrs
            || execution.raw_addr_to_id_words != requirements.raw_address_words
            || execution.big_column_words != requirements.big_source_words
            || execution.small_column_words != requirements.small_source_words
        {
            return Err(PreparedMemoryBaseTraceError::InvalidBindingGeometry(
                "execution contract",
            ));
        }
        exact_slice(
            "raw address table",
            self.address_source,
            requirements.raw_address_words,
        )?;
        exact_slice(
            "address multiplicities",
            self.address_counts,
            requirements.address_count_words,
        )?;
        exact_columns(
            "address outputs",
            &self.address_outputs,
            MEMORY_ADDRESS_BASE_COLUMNS,
            requirements.address_rows,
        )?;
        exact_columns(
            "big sources",
            &self.big_sources,
            EXECUTION_TABLE_BIG_LIMBS,
            requirements.big_source_words,
        )?;
        exact_slice(
            "big multiplicities",
            self.big_counts,
            requirements.big_count_words,
        )?;
        if self.big_parts.len() != requirements.big_parts.len() {
            return Err(shape(
                "big parts",
                requirements.big_parts.len(),
                self.big_parts.len(),
            ));
        }
        for (actual, expected) in self.big_parts.iter().zip(&requirements.big_parts) {
            if actual.source_offset != expected.source_offset
                || actual.row_count != expected.row_count
            {
                return Err(PreparedMemoryBaseTraceError::InvalidBindingGeometry(
                    "big part",
                ));
            }
            exact_columns(
                "big outputs",
                &actual.outputs,
                MEMORY_BIG_BASE_COLUMNS,
                actual.row_count,
            )?;
        }
        exact_columns(
            "small sources",
            &self.small_sources,
            EXECUTION_TABLE_SMALL_LIMBS,
            requirements.small_source_words,
        )?;
        exact_slice(
            "small multiplicities",
            self.small_counts,
            requirements.small_count_words,
        )?;
        if self.small_part.source_offset != requirements.small_part.source_offset
            || self.small_part.row_count != requirements.small_part.row_count
        {
            return Err(PreparedMemoryBaseTraceError::InvalidBindingGeometry(
                "small part",
            ));
        }
        exact_columns(
            "small outputs",
            &self.small_part.outputs,
            MEMORY_SMALL_BASE_COLUMNS,
            self.small_part.row_count,
        )?;
        exact_slice("rc9_9 LUT", self.rc99_lut, requirements.rc99_lut_words)?;
        exact_slice(
            "rc9_9 multiplicities",
            self.rc99_counts,
            requirements.rc99_count_words,
        )?;
        ensure_distinct(self.slices().map(|(_, slice)| slice.id()))?;
        Ok(())
    }

    fn canonical_identity(
        &self,
        contract: &MemoryBaseTraceContract,
    ) -> Result<[u8; 32], PreparedMemoryBaseTraceError> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(BINDING_DOMAIN);
        hasher.update(&(BINDING_SOURCE.len() as u64).to_le_bytes());
        hasher.update(BINDING_SOURCE);
        hasher.update(&contract.identity());
        hasher.update(&self.execution_contract.identity());
        for (role, slice) in self.slices() {
            hasher.update(&(role.len() as u64).to_le_bytes());
            hasher.update(role.as_bytes());
            hasher.update(&slice.id().0.to_le_bytes());
            hasher.update(
                &u64::try_from(slice.len_words())
                    .map_err(|_| PreparedMemoryBaseTraceError::SizeOverflow)?
                    .to_le_bytes(),
            );
        }
        for part in self.big_parts.iter().chain([&self.small_part]) {
            hasher.update(
                &u64::try_from(part.source_offset)
                    .map_err(|_| PreparedMemoryBaseTraceError::SizeOverflow)?
                    .to_le_bytes(),
            );
            hasher.update(
                &u64::try_from(part.row_count)
                    .map_err(|_| PreparedMemoryBaseTraceError::SizeOverflow)?
                    .to_le_bytes(),
            );
        }
        Ok(*hasher.finalize().as_bytes())
    }

    fn slices(&self) -> impl Iterator<Item = (&'static str, ArenaSlice)> + '_ {
        [
            ("raw address table", self.address_source),
            ("address multiplicities", self.address_counts),
            ("big multiplicities", self.big_counts),
            ("small multiplicities", self.small_counts),
            ("rc9_9 LUT", self.rc99_lut),
            ("rc9_9 multiplicities", self.rc99_counts),
        ]
        .into_iter()
        .chain(
            self.address_outputs
                .iter()
                .copied()
                .map(|slice| ("address output", slice)),
        )
        .chain(
            self.big_sources
                .iter()
                .copied()
                .map(|slice| ("big source", slice)),
        )
        .chain(
            self.big_parts
                .iter()
                .flat_map(|part| part.outputs.iter().copied())
                .map(|slice| ("big output", slice)),
        )
        .chain(
            self.small_sources
                .iter()
                .copied()
                .map(|slice| ("small source", slice)),
        )
        .chain(
            self.small_part
                .outputs
                .iter()
                .copied()
                .map(|slice| ("small output", slice)),
        )
    }
}

fn value_part_raw_matches(
    prepared: &PreparedValuePart,
    binding: &ValuePartBinding,
    sources: &[ArenaSlice],
    counts: ArenaSlice,
) -> bool {
    let readable = readable_source_words(
        sources.first().map_or(0, |source| source.len_words()),
        binding.source_offset,
        binding.row_count,
    );
    prepared.source_slice_words as usize == readable
        && prepared.row_count as usize == binding.row_count
        && prepared.multiplicity_slice_words as usize == binding.row_count
        && prepared.source_pointers.len() == sources.len()
        && prepared
            .source_pointers
            .iter()
            .zip(sources)
            .all(|(&actual, source)| {
                let expected = if readable == 0 {
                    core::ptr::null()
                } else {
                    source
                        .as_u32_ptr()
                        .wrapping_add(binding.source_offset)
                        .cast_const()
                };
                actual == expected
            })
        && prepared.multiplicities
            == counts
                .as_u32_ptr()
                .wrapping_add(binding.source_offset)
                .cast_const()
        && pointer_list_matches(&prepared.output_pointers, &binding.outputs)
        && prepared.rc99_limb_pointers.len() + 1 == binding.outputs.len()
        && prepared
            .rc99_limb_pointers
            .iter()
            .zip(&binding.outputs)
            .all(|(&actual, output)| actual == output.as_u32_ptr().cast_const())
}

fn pointer_list_matches(actual: &[*mut u32], expected: &[ArenaSlice]) -> bool {
    actual.len() == expected.len()
        && actual
            .iter()
            .zip(expected)
            .all(|(&actual, expected)| actual == expected.as_u32_ptr())
}

fn exact_columns(
    role: &'static str,
    actual: &[ArenaSlice],
    expected_columns: usize,
    expected_words: usize,
) -> Result<(), PreparedMemoryBaseTraceError> {
    if actual.len() != expected_columns {
        return Err(shape(role, expected_columns, actual.len()));
    }
    for &slice in actual {
        exact_slice(role, slice, expected_words)?;
    }
    Ok(())
}

fn exact_slice(
    role: &'static str,
    slice: ArenaSlice,
    expected_words: usize,
) -> Result<(), PreparedMemoryBaseTraceError> {
    if slice.len_words() == expected_words {
        Ok(())
    } else {
        Err(shape(role, expected_words, slice.len_words()))
    }
}

fn validate_arena_slice(
    arena: &DeviceArena,
    role: &'static str,
    slice: ArenaSlice,
) -> Result<(), PreparedMemoryBaseTraceError> {
    let owner = arena.bind(slice.id())?;
    if slice.belongs_to(arena.context())
        && owner.as_u32_ptr() == slice.as_u32_ptr()
        && owner.len_words() >= slice.len_words()
    {
        Ok(())
    } else {
        Err(PreparedMemoryBaseTraceError::ArenaBindingMismatch(role))
    }
}

fn ensure_distinct(
    ids: impl Iterator<Item = crate::backend::exec_context::ArenaSlotId>,
) -> Result<(), PreparedMemoryBaseTraceError> {
    let mut distinct = BTreeSet::new();
    if ids.into_iter().all(|id| distinct.insert(id)) {
        Ok(())
    } else {
        Err(PreparedMemoryBaseTraceError::DuplicateSlice)
    }
}

fn shape(role: &'static str, expected: usize, actual: usize) -> PreparedMemoryBaseTraceError {
    PreparedMemoryBaseTraceError::ShapeMismatch {
        role,
        expected,
        actual,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::prepared_execution_tables::{
        execution_tables_workspace_requirements, ExecutionTablesContract,
    };
    use crate::backend::prepared_memory_trace::{
        MemoryBaseTraceRequirements, MemoryBaseTraceValuePartRequirements,
    };

    fn binding(pointer_bias: usize) -> (MemoryBaseTraceContract, PreparedMemoryBaseTraceBinding) {
        let execution_requirements = execution_tables_workspace_requirements(4, 3, 2).unwrap();
        let execution_contract = ExecutionTablesContract::compile(&execution_requirements).unwrap();
        let contract = MemoryBaseTraceContract::compile(&MemoryBaseTraceRequirements {
            n_addrs: 4,
            raw_address_words: execution_requirements.raw_addr_to_id_words,
            address_rows: 2,
            address_count_words: 32,
            big_source_words: execution_requirements.big_column_words,
            big_count_words: 3,
            big_parts: vec![MemoryBaseTraceValuePartRequirements {
                part_ordinal: 0,
                source_offset: 0,
                row_count: 3,
            }],
            small_source_words: execution_requirements.small_column_words,
            small_count_words: 2,
            small_part: MemoryBaseTraceValuePartRequirements {
                part_ordinal: 0,
                source_offset: 0,
                row_count: 2,
            },
            rc99_lut_words: 1 << 18,
            rc99_count_words: 8 << 18,
        })
        .unwrap();
        let mut next_id = 1u32;
        let mut next = |words| {
            let id = next_id;
            next_id += 1;
            ArenaSlice::dangling_at_for_test(id, pointer_bias + id as usize * (1 << 20), words)
        };
        let mut prepared = PreparedMemoryBaseTraceBinding {
            identity: [0; 32],
            address_source: next(execution_requirements.raw_addr_to_id_words),
            address_counts: next(32),
            address_outputs: (0..MEMORY_ADDRESS_BASE_COLUMNS).map(|_| next(2)).collect(),
            big_sources: (0..EXECUTION_TABLE_BIG_LIMBS)
                .map(|_| next(execution_requirements.big_column_words))
                .collect(),
            big_counts: next(3),
            big_parts: vec![ValuePartBinding {
                source_offset: 0,
                row_count: 3,
                outputs: (0..MEMORY_BIG_BASE_COLUMNS).map(|_| next(3)).collect(),
            }],
            small_sources: (0..EXECUTION_TABLE_SMALL_LIMBS)
                .map(|_| next(execution_requirements.small_column_words))
                .collect(),
            small_counts: next(2),
            small_part: ValuePartBinding {
                source_offset: 0,
                row_count: 2,
                outputs: (0..MEMORY_SMALL_BASE_COLUMNS).map(|_| next(2)).collect(),
            },
            rc99_lut: next(1 << 18),
            rc99_counts: next(8 << 18),
            execution_contract,
        };
        prepared.validate_geometry(&contract).unwrap();
        prepared.identity = prepared.canonical_identity(&contract).unwrap();
        (contract, prepared)
    }

    fn raw_part(
        sources: &[ArenaSlice],
        counts: ArenaSlice,
        part: &ValuePartBinding,
    ) -> PreparedValuePart {
        let source_words =
            readable_source_words(sources[0].len_words(), part.source_offset, part.row_count);
        PreparedValuePart {
            source_pointers: sources
                .iter()
                .map(|source| {
                    source
                        .as_u32_ptr()
                        .wrapping_add(part.source_offset)
                        .cast_const()
                })
                .collect(),
            source_slice_words: source_words as u32,
            multiplicities: counts
                .as_u32_ptr()
                .wrapping_add(part.source_offset)
                .cast_const(),
            multiplicity_slice_words: part.row_count as u32,
            row_count: part.row_count as u32,
            output_pointers: part
                .outputs
                .iter()
                .map(|output| output.as_u32_ptr())
                .collect(),
            rc99_limb_pointers: part
                .outputs
                .iter()
                .take(part.outputs.len() - 1)
                .map(|output| output.as_u32_ptr().cast_const())
                .collect(),
        }
    }

    #[test]
    fn binding_identity_is_address_free_but_order_sensitive() {
        let (contract, first) = binding(0);
        let (_, mut relocated) = binding(1 << 28);
        assert_eq!(first.identity, relocated.identity);

        relocated.address_outputs.swap(0, 1);
        assert_ne!(
            first.identity,
            relocated.canonical_identity(&contract).unwrap()
        );
    }

    #[test]
    fn geometry_and_private_pointer_tables_fail_closed_on_drift() {
        let (contract, mut binding) = binding(0);
        let big = raw_part(
            &binding.big_sources,
            binding.big_counts,
            &binding.big_parts[0],
        );
        let small = raw_part(
            &binding.small_sources,
            binding.small_counts,
            &binding.small_part,
        );
        let mut address_pointers = binding
            .address_outputs
            .iter()
            .map(|output| output.as_u32_ptr())
            .collect::<Vec<_>>();
        assert!(binding.raw_matches(
            &contract,
            binding.address_source.as_u32_ptr().wrapping_add(1),
            3,
            &address_pointers,
            &[big],
            &small,
        ));
        address_pointers.swap(0, 1);
        assert!(!binding.raw_matches(
            &contract,
            binding.address_source.as_u32_ptr().wrapping_add(1),
            3,
            &address_pointers,
            &[raw_part(
                &binding.big_sources,
                binding.big_counts,
                &binding.big_parts[0],
            )],
            &small,
        ));

        let first = binding.address_outputs[0];
        binding.address_outputs[0] =
            ArenaSlice::dangling_at_for_test(first.id().0, 64, first.len_words() + 1);
        assert!(matches!(
            binding.validate_geometry(&contract),
            Err(PreparedMemoryBaseTraceError::ShapeMismatch {
                role: "address outputs",
                ..
            })
        ));
    }
}
