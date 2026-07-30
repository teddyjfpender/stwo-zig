//! Runtime receipt for one statement-varying execution-table ingest.
//!
//! Process-local arena and pointer tokens are admission evidence only. They
//! must never enter a semantic, artifact, program, or proof identity.

use core::cell::Cell;

use super::{
    ArenaSlice, ArenaSlotId, DeviceArena, ExecutionTablesContract, ExecutionTablesHostData,
    PreparedExecutionTablesError, F252_WORDS, SMALL_WORDS,
};

const INGEST_DOMAIN: &[u8] = b"stwo-cuda-execution-tables-ingest-v1\0";
const U32_CHUNK_WORDS: usize = 1024;
const U128_CHUNK_WORDS: usize = 256;

/// Process-local proof that one exact host table set was copied and fenced.
///
/// The receipt is unforgeable outside this module. Writer exclusivity for the
/// three raw slots remains a proof-plan obligation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionTablesIngestReceipt {
    contract_identity: [u8; 32],
    arena_identity: usize,
    exec_context_token: u64,
    raw_addr_to_id_slot: ArenaSlotId,
    raw_addr_to_id_address: usize,
    raw_addr_to_id_words: usize,
    raw_f252_slot: ArenaSlotId,
    raw_f252_address: usize,
    raw_f252_words: usize,
    raw_small_slot: ArenaSlotId,
    raw_small_address: usize,
    raw_small_words: usize,
    content_identity: [u8; 32],
    generation: u64,
}

impl ExecutionTablesIngestReceipt {
    pub(super) fn prepare(
        binding: ExecutionTablesIngestBinding,
        contract: &ExecutionTablesContract,
        host: ExecutionTablesHostData<'_>,
        generation: u64,
    ) -> Result<Self, PreparedExecutionTablesError> {
        check_host_shape(
            "addr_to_id",
            contract.requirements().n_addrs,
            host.addr_to_id.len(),
        )?;
        check_host_shape(
            "f252_values",
            contract.requirements().n_big,
            host.f252_values.len(),
        )?;
        check_host_shape(
            "small_values",
            contract.requirements().n_small,
            host.small_values.len(),
        )?;
        if generation == 0 {
            return Err(PreparedExecutionTablesError::IngestGenerationOverflow);
        }
        Ok(Self {
            contract_identity: contract.identity(),
            arena_identity: binding.arena_identity,
            exec_context_token: binding.exec_context_token,
            raw_addr_to_id_slot: binding.raw_addr_to_id.slot,
            raw_addr_to_id_address: binding.raw_addr_to_id.address,
            raw_addr_to_id_words: binding.raw_addr_to_id.words,
            raw_f252_slot: binding.raw_f252.slot,
            raw_f252_address: binding.raw_f252.address,
            raw_f252_words: binding.raw_f252.words,
            raw_small_slot: binding.raw_small.slot,
            raw_small_address: binding.raw_small.address,
            raw_small_words: binding.raw_small.words,
            content_identity: ingest_content_identity(host)?,
            generation,
        })
    }

    pub(super) fn matches(
        self,
        binding: ExecutionTablesIngestBinding,
        current_generation: u64,
    ) -> bool {
        self.generation != 0
            && self.generation == current_generation
            && self.contract_identity == binding.contract_identity
            && self.arena_identity == binding.arena_identity
            && self.exec_context_token == binding.exec_context_token
            && self.raw_addr_to_id_slot == binding.raw_addr_to_id.slot
            && self.raw_addr_to_id_address == binding.raw_addr_to_id.address
            && self.raw_addr_to_id_words == binding.raw_addr_to_id.words
            && self.raw_f252_slot == binding.raw_f252.slot
            && self.raw_f252_address == binding.raw_f252.address
            && self.raw_f252_words == binding.raw_f252.words
            && self.raw_small_slot == binding.raw_small.slot
            && self.raw_small_address == binding.raw_small.address
            && self.raw_small_words == binding.raw_small.words
    }

    pub const fn contract_identity(self) -> [u8; 32] {
        self.contract_identity
    }
    pub const fn arena_identity(self) -> usize {
        self.arena_identity
    }
    pub const fn exec_context_token(self) -> u64 {
        self.exec_context_token
    }
    pub const fn raw_addr_to_id_slot(self) -> ArenaSlotId {
        self.raw_addr_to_id_slot
    }
    pub const fn raw_addr_to_id_address(self) -> usize {
        self.raw_addr_to_id_address
    }
    pub const fn raw_addr_to_id_words(self) -> usize {
        self.raw_addr_to_id_words
    }
    pub const fn raw_f252_slot(self) -> ArenaSlotId {
        self.raw_f252_slot
    }
    pub const fn raw_f252_address(self) -> usize {
        self.raw_f252_address
    }
    pub const fn raw_f252_words(self) -> usize {
        self.raw_f252_words
    }
    pub const fn raw_small_slot(self) -> ArenaSlotId {
        self.raw_small_slot
    }
    pub const fn raw_small_address(self) -> usize {
        self.raw_small_address
    }
    pub const fn raw_small_words(self) -> usize {
        self.raw_small_words
    }
    pub const fn content_identity(self) -> [u8; 32] {
        self.content_identity
    }
    pub const fn generation(self) -> u64 {
        self.generation
    }
}

pub(super) struct ExecutionTablesIngestState {
    generation: Cell<u64>,
    receipt: Cell<Option<ExecutionTablesIngestReceipt>>,
}

impl ExecutionTablesIngestState {
    pub(super) const fn new() -> Self {
        Self {
            generation: Cell::new(0),
            receipt: Cell::new(None),
        }
    }

    pub(super) fn next_generation(&self) -> Result<u64, PreparedExecutionTablesError> {
        next_ingest_generation(self.generation.get())
    }

    pub(super) fn begin(&self, receipt: ExecutionTablesIngestReceipt) {
        debug_assert_eq!(
            receipt.generation(),
            self.generation.get().checked_add(1).unwrap()
        );
        self.generation.set(receipt.generation());
        self.receipt.set(None);
    }

    pub(super) fn publish(&self, receipt: ExecutionTablesIngestReceipt) {
        debug_assert_eq!(receipt.generation(), self.generation.get());
        self.receipt.set(Some(receipt));
    }

    pub(super) fn receipt(&self) -> Option<ExecutionTablesIngestReceipt> {
        self.receipt.get()
    }

    pub(super) fn is_current(
        &self,
        receipt: &ExecutionTablesIngestReceipt,
        binding: ExecutionTablesIngestBinding,
    ) -> bool {
        self.receipt.get() == Some(*receipt) && receipt.matches(binding, self.generation.get())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IngestRangeBinding {
    slot: ArenaSlotId,
    address: usize,
    words: usize,
}

impl From<ArenaSlice> for IngestRangeBinding {
    fn from(slice: ArenaSlice) -> Self {
        Self {
            slot: slice.id(),
            address: slice.as_u32_ptr() as usize,
            words: slice.len_words(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ExecutionTablesIngestBinding {
    contract_identity: [u8; 32],
    arena_identity: usize,
    exec_context_token: u64,
    raw_addr_to_id: IngestRangeBinding,
    raw_f252: IngestRangeBinding,
    raw_small: IngestRangeBinding,
}

impl ExecutionTablesIngestBinding {
    pub(super) fn new(
        arena: &DeviceArena,
        contract: &ExecutionTablesContract,
        raw_addr_to_id: ArenaSlice,
        raw_f252: ArenaSlice,
        raw_small: ArenaSlice,
    ) -> Self {
        Self {
            contract_identity: contract.identity(),
            arena_identity: arena.base_ptr().as_ptr() as usize,
            exec_context_token: arena.exec_context_token(),
            raw_addr_to_id: raw_addr_to_id.into(),
            raw_f252: raw_f252.into(),
            raw_small: raw_small.into(),
        }
    }
}

pub(super) fn next_ingest_generation(current: u64) -> Result<u64, PreparedExecutionTablesError> {
    current
        .checked_add(1)
        .ok_or(PreparedExecutionTablesError::IngestGenerationOverflow)
}

fn ingest_content_identity(
    host: ExecutionTablesHostData<'_>,
) -> Result<[u8; 32], PreparedExecutionTablesError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(INGEST_DOMAIN);

    hash_field_header(&mut hasher, 1, host.addr_to_id.len(), 1)?;
    hash_u32_words(&mut hasher, host.addr_to_id.iter().copied());

    hash_field_header(&mut hasher, 2, host.f252_values.len(), F252_WORDS)?;
    hash_u32_words(
        &mut hasher,
        host.f252_values.iter().flat_map(|row| row.iter().copied()),
    );

    hash_field_header(&mut hasher, 3, host.small_values.len(), SMALL_WORDS)?;
    hash_u128_words(&mut hasher, host.small_values.iter().copied());
    Ok(*hasher.finalize().as_bytes())
}

fn hash_field_header(
    hasher: &mut blake3::Hasher,
    role: u8,
    rows: usize,
    words_per_row: usize,
) -> Result<(), PreparedExecutionTablesError> {
    hasher.update(&[role]);
    hasher.update(
        &u64::try_from(rows)
            .map_err(|_| PreparedExecutionTablesError::SizeOverflow)?
            .to_le_bytes(),
    );
    hasher.update(
        &u64::try_from(words_per_row)
            .map_err(|_| PreparedExecutionTablesError::SizeOverflow)?
            .to_le_bytes(),
    );
    Ok(())
}

fn check_host_shape(
    role: &'static str,
    expected: usize,
    actual: usize,
) -> Result<(), PreparedExecutionTablesError> {
    if expected == actual {
        Ok(())
    } else {
        Err(PreparedExecutionTablesError::HostShapeMismatch {
            role,
            expected,
            actual,
        })
    }
}

fn hash_u32_words(hasher: &mut blake3::Hasher, mut words: impl Iterator<Item = u32>) {
    let mut bytes = [0u8; U32_CHUNK_WORDS * 4];
    loop {
        let mut count = 0;
        for destination in bytes.chunks_exact_mut(4) {
            let Some(word) = words.next() else { break };
            destination.copy_from_slice(&word.to_le_bytes());
            count += 1;
        }
        if count == 0 {
            return;
        }
        hasher.update(&bytes[..count * 4]);
    }
}

fn hash_u128_words(hasher: &mut blake3::Hasher, mut words: impl Iterator<Item = u128>) {
    let mut bytes = [0u8; U128_CHUNK_WORDS * 16];
    loop {
        let mut count = 0;
        for destination in bytes.chunks_exact_mut(16) {
            let Some(word) = words.next() else { break };
            destination.copy_from_slice(&word.to_le_bytes());
            count += 1;
        }
        if count == 0 {
            return;
        }
        hasher.update(&bytes[..count * 16]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host<'a>(
        addr_to_id: &'a [u32],
        f252_values: &'a [[u32; F252_WORDS]],
        small_values: &'a [u128],
    ) -> ExecutionTablesHostData<'a> {
        ExecutionTablesHostData {
            addr_to_id,
            f252_values,
            small_values,
        }
    }

    #[test]
    fn content_identity_binds_every_canonical_little_endian_field() {
        let addr = [0x0102_0304, 5];
        let f252 = [[6, 7, 8, 9, 10, 11, 12, 0xa1b2_c3d4]];
        let small = [0x0102_0304_0506_0708_1112_1314_1516_1718u128];
        let actual = ingest_content_identity(host(&addr, &f252, &small)).unwrap();

        let mut reference = blake3::Hasher::new();
        reference.update(INGEST_DOMAIN);
        for (role, rows, width) in [(1u8, 2u64, 1u64), (2, 1, 8), (3, 1, 4)] {
            reference.update(&[role]);
            reference.update(&rows.to_le_bytes());
            reference.update(&width.to_le_bytes());
            match role {
                1 => addr.iter().for_each(|word| {
                    reference.update(&word.to_le_bytes());
                }),
                2 => f252[0].iter().for_each(|word| {
                    reference.update(&word.to_le_bytes());
                }),
                3 => small.iter().for_each(|word| {
                    reference.update(&word.to_le_bytes());
                }),
                _ => unreachable!(),
            }
        }
        assert_eq!(actual, *reference.finalize().as_bytes());

        let mut changed_addr = addr;
        changed_addr.swap(0, 1);
        assert_ne!(
            actual,
            ingest_content_identity(host(&changed_addr, &f252, &small)).unwrap()
        );
        let mut changed_f252 = f252;
        changed_f252[0][7] ^= 1;
        assert_ne!(
            actual,
            ingest_content_identity(host(&addr, &changed_f252, &small)).unwrap()
        );
        let changed_small = [small[0].swap_bytes()];
        assert_ne!(
            actual,
            ingest_content_identity(host(&addr, &f252, &changed_small)).unwrap()
        );
        assert_ne!(
            actual,
            ingest_content_identity(host(&addr[..1], &f252, &small)).unwrap()
        );
    }

    #[test]
    fn receipt_matches_exact_binding_and_nonzero_generation() {
        let contract = ExecutionTablesContract::compile(
            &super::super::execution_tables_workspace_requirements(2, 1, 1).unwrap(),
        )
        .unwrap();
        let binding = ExecutionTablesIngestBinding {
            contract_identity: contract.identity(),
            arena_identity: 11,
            exec_context_token: 13,
            raw_addr_to_id: IngestRangeBinding {
                slot: ArenaSlotId(17),
                address: 19,
                words: 2,
            },
            raw_f252: IngestRangeBinding {
                slot: ArenaSlotId(23),
                address: 29,
                words: 8,
            },
            raw_small: IngestRangeBinding {
                slot: ArenaSlotId(31),
                address: 37,
                words: 4,
            },
        };
        let addr = [1, 2];
        let f252 = [[3; F252_WORDS]];
        let small = [4u128];
        let receipt = ExecutionTablesIngestReceipt::prepare(
            binding,
            &contract,
            host(&addr, &f252, &small),
            1,
        )
        .unwrap();
        assert!(receipt.matches(binding, 1));
        assert!(!receipt.matches(binding, 2));
        for mutation in [
            ExecutionTablesIngestBinding {
                contract_identity: [8; 32],
                ..binding
            },
            ExecutionTablesIngestBinding {
                arena_identity: 12,
                ..binding
            },
            ExecutionTablesIngestBinding {
                exec_context_token: 14,
                ..binding
            },
            ExecutionTablesIngestBinding {
                raw_addr_to_id: IngestRangeBinding {
                    slot: ArenaSlotId(18),
                    ..binding.raw_addr_to_id
                },
                ..binding
            },
            ExecutionTablesIngestBinding {
                raw_addr_to_id: IngestRangeBinding {
                    address: 20,
                    ..binding.raw_addr_to_id
                },
                ..binding
            },
            ExecutionTablesIngestBinding {
                raw_addr_to_id: IngestRangeBinding {
                    words: 3,
                    ..binding.raw_addr_to_id
                },
                ..binding
            },
            ExecutionTablesIngestBinding {
                raw_f252: IngestRangeBinding {
                    slot: ArenaSlotId(24),
                    ..binding.raw_f252
                },
                ..binding
            },
            ExecutionTablesIngestBinding {
                raw_f252: IngestRangeBinding {
                    address: 30,
                    ..binding.raw_f252
                },
                ..binding
            },
            ExecutionTablesIngestBinding {
                raw_f252: IngestRangeBinding {
                    words: 9,
                    ..binding.raw_f252
                },
                ..binding
            },
            ExecutionTablesIngestBinding {
                raw_small: IngestRangeBinding {
                    slot: ArenaSlotId(32),
                    ..binding.raw_small
                },
                ..binding
            },
            ExecutionTablesIngestBinding {
                raw_small: IngestRangeBinding {
                    address: 38,
                    ..binding.raw_small
                },
                ..binding
            },
            ExecutionTablesIngestBinding {
                raw_small: IngestRangeBinding {
                    words: 5,
                    ..binding.raw_small
                },
                ..binding
            },
        ] {
            assert!(!receipt.matches(mutation, 1));
        }
        assert_eq!(
            ExecutionTablesIngestReceipt::prepare(
                binding,
                &contract,
                host(&addr, &f252, &small),
                0,
            ),
            Err(PreparedExecutionTablesError::IngestGenerationOverflow)
        );
        assert_eq!(
            next_ingest_generation(u64::MAX),
            Err(PreparedExecutionTablesError::IngestGenerationOverflow)
        );
    }

    #[test]
    fn state_preserves_current_on_rejection_and_invalidates_before_publish() {
        let requirements = super::super::execution_tables_workspace_requirements(2, 1, 1).unwrap();
        let contract = ExecutionTablesContract::compile(&requirements).unwrap();
        let binding = ExecutionTablesIngestBinding {
            contract_identity: contract.identity(),
            arena_identity: 11,
            exec_context_token: 13,
            raw_addr_to_id: IngestRangeBinding {
                slot: ArenaSlotId(17),
                address: 19,
                words: requirements.raw_addr_to_id_words,
            },
            raw_f252: IngestRangeBinding {
                slot: ArenaSlotId(23),
                address: 29,
                words: requirements.raw_f252_words,
            },
            raw_small: IngestRangeBinding {
                slot: ArenaSlotId(31),
                address: 37,
                words: requirements.raw_small_words,
            },
        };
        let addr = [1, 2];
        let f252 = [[3; F252_WORDS]];
        let small = [4u128];
        let state = ExecutionTablesIngestState::new();
        let first = ExecutionTablesIngestReceipt::prepare(
            binding,
            &contract,
            host(&addr, &f252, &small),
            state.next_generation().unwrap(),
        )
        .unwrap();
        state.begin(first);
        assert!(state.receipt().is_none());
        state.publish(first);
        assert!(state.is_current(&first, binding));

        assert_eq!(
            ExecutionTablesIngestReceipt::prepare(
                binding,
                &contract,
                host(&addr[..1], &f252, &small),
                state.next_generation().unwrap(),
            ),
            Err(PreparedExecutionTablesError::HostShapeMismatch {
                role: "addr_to_id",
                expected: 2,
                actual: 1,
            })
        );
        assert!(state.is_current(&first, binding));

        let second = ExecutionTablesIngestReceipt::prepare(
            binding,
            &contract,
            host(&addr, &f252, &small),
            state.next_generation().unwrap(),
        )
        .unwrap();
        state.begin(second);
        assert!(state.receipt().is_none());
        assert!(!state.is_current(&first, binding));

        let third = ExecutionTablesIngestReceipt::prepare(
            binding,
            &contract,
            host(&addr, &f252, &small),
            state.next_generation().unwrap(),
        )
        .unwrap();
        assert_eq!(third.generation(), 3);
    }
}
