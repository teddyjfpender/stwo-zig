//! Process-local authority for one statement's EC-op segment start.

use core::cell::Cell;

use super::{ArenaSlice, ArenaSlotId, DeviceArena, EcOpCompositeContract, PreparedEcOpError};

/// Proof that one fill was successfully enqueued on the arena's main stream.
///
/// This is not a device-completion fence. A lane launch must inherit the main
/// stream's ordering through the arena fork/join contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EcOpSegmentStartReceipt {
    contract_identity: [u8; 32],
    arena_identity: usize,
    exec_context_token: u64,
    source_slot: ArenaSlotId,
    source_address: usize,
    source_words: usize,
    segment_start: u32,
    generation: u64,
}

impl EcOpSegmentStartReceipt {
    pub(super) fn prepare(
        binding: EcOpSegmentStartBinding,
        segment_start: u32,
        generation: u64,
    ) -> Result<Self, PreparedEcOpError> {
        if generation == 0 {
            return Err(PreparedEcOpError::SegmentStartGenerationOverflow);
        }
        Ok(Self {
            contract_identity: binding.contract_identity,
            arena_identity: binding.arena_identity,
            exec_context_token: binding.exec_context_token,
            source_slot: binding.source_slot,
            source_address: binding.source_address,
            source_words: binding.source_words,
            segment_start,
            generation,
        })
    }

    pub(super) fn matches(self, binding: EcOpSegmentStartBinding, generation: u64) -> bool {
        self.generation != 0
            && self.generation == generation
            && self.contract_identity == binding.contract_identity
            && self.arena_identity == binding.arena_identity
            && self.exec_context_token == binding.exec_context_token
            && self.source_slot == binding.source_slot
            && self.source_address == binding.source_address
            && self.source_words == binding.source_words
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

    pub const fn source_slot(self) -> ArenaSlotId {
        self.source_slot
    }

    pub const fn source_address(self) -> usize {
        self.source_address
    }

    pub const fn source_words(self) -> usize {
        self.source_words
    }

    pub const fn segment_start(self) -> u32 {
        self.segment_start
    }

    pub const fn generation(self) -> u64 {
        self.generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct EcOpSegmentStartBinding {
    contract_identity: [u8; 32],
    arena_identity: usize,
    exec_context_token: u64,
    source_slot: ArenaSlotId,
    source_address: usize,
    source_words: usize,
}

impl EcOpSegmentStartBinding {
    pub(super) fn new(
        arena: &DeviceArena,
        contract: &EcOpCompositeContract,
        source: ArenaSlice,
    ) -> Self {
        Self {
            contract_identity: contract.identity(),
            arena_identity: arena.base_ptr().as_ptr() as usize,
            exec_context_token: arena.exec_context_token(),
            source_slot: source.id(),
            source_address: source.as_u32_ptr() as usize,
            source_words: source.len_words(),
        }
    }
}

pub(super) struct EcOpSegmentStartState {
    generation: Cell<u64>,
    receipt: Cell<Option<EcOpSegmentStartReceipt>>,
}

impl EcOpSegmentStartState {
    pub(super) const fn new() -> Self {
        Self {
            generation: Cell::new(0),
            receipt: Cell::new(None),
        }
    }

    pub(super) fn next_generation(&self) -> Result<u64, PreparedEcOpError> {
        self.generation
            .get()
            .checked_add(1)
            .ok_or(PreparedEcOpError::SegmentStartGenerationOverflow)
    }

    pub(super) fn begin(&self, receipt: EcOpSegmentStartReceipt) {
        debug_assert_eq!(
            receipt.generation(),
            self.generation.get().checked_add(1).unwrap()
        );
        self.generation.set(receipt.generation());
        self.receipt.set(None);
    }

    pub(super) fn publish(&self, receipt: EcOpSegmentStartReceipt) {
        debug_assert_eq!(receipt.generation(), self.generation.get());
        self.receipt.set(Some(receipt));
    }

    pub(super) fn receipt(&self) -> Option<EcOpSegmentStartReceipt> {
        self.receipt.get()
    }

    pub(super) fn is_current(
        &self,
        receipt: &EcOpSegmentStartReceipt,
        binding: EcOpSegmentStartBinding,
    ) -> bool {
        self.receipt.get() == Some(*receipt) && receipt.matches(binding, self.generation.get())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> EcOpSegmentStartBinding {
        EcOpSegmentStartBinding {
            contract_identity: [7; 32],
            arena_identity: 11,
            exec_context_token: 13,
            source_slot: ArenaSlotId(17),
            source_address: 19,
            source_words: 1,
        }
    }

    #[test]
    fn receipt_binds_value_runtime_source_and_generation() {
        let first = EcOpSegmentStartReceipt::prepare(binding(), 23, 1).unwrap();
        let changed_value = EcOpSegmentStartReceipt::prepare(binding(), 29, 1).unwrap();
        let second = EcOpSegmentStartReceipt::prepare(binding(), 29, 2).unwrap();
        assert!(first.matches(binding(), 1));
        assert!(!first.matches(binding(), 2));
        assert_eq!(first.segment_start(), 23);
        assert_ne!(first, changed_value);
        assert_eq!(second.segment_start(), 29);
        assert_ne!(first, second);

        let mutations: [fn(&mut EcOpSegmentStartBinding); 6] = [
            |binding| binding.contract_identity[0] ^= 1,
            |binding| binding.arena_identity += 1,
            |binding| binding.exec_context_token += 1,
            |binding| binding.source_slot = ArenaSlotId(binding.source_slot.0 + 1),
            |binding| binding.source_address += 4,
            |binding| binding.source_words += 1,
        ];
        for mutate in mutations {
            let mut wrong = binding();
            mutate(&mut wrong);
            assert!(!second.matches(wrong, 2));
        }
        assert_eq!(
            EcOpSegmentStartReceipt::prepare(binding(), 23, 0),
            Err(PreparedEcOpError::SegmentStartGenerationOverflow)
        );
    }

    #[test]
    fn state_invalidates_before_publish_and_rejects_old_generation() {
        let state = EcOpSegmentStartState::new();
        let first = EcOpSegmentStartReceipt::prepare(binding(), 23, 1).unwrap();
        state.begin(first);
        assert_eq!(state.receipt(), None);
        state.publish(first);
        assert!(state.is_current(&first, binding()));

        let second = EcOpSegmentStartReceipt::prepare(binding(), 29, 2).unwrap();
        state.begin(second);
        assert_eq!(state.receipt(), None);
        assert!(!state.is_current(&first, binding()));
        state.publish(second);
        assert!(state.is_current(&second, binding()));
    }

    #[test]
    fn generation_overflow_fails_closed() {
        let state = EcOpSegmentStartState {
            generation: Cell::new(u64::MAX),
            receipt: Cell::new(None),
        };
        assert_eq!(
            state.next_generation(),
            Err(PreparedEcOpError::SegmentStartGenerationOverflow)
        );
    }
}
