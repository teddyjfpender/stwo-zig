//! Runtime receipt for one row-major CASM ingest and scatter.
//!
//! Process-local arena and pointer tokens are admission evidence only. They
//! must never enter a semantic, artifact, program, or proof identity.

use core::cell::Cell;

use super::{
    ArenaSlice, ArenaSlotId, DeviceArena, PreparedWitnessCasmInputError, WitnessCasmInputAbi,
    WitnessCasmInputContract, WitnessCasmInputRowDomain, WITNESS_CASM_STATE_WORDS,
};

const INGRESS_DOMAIN: &[u8] = b"stwo-cuda-witness-casm-input-ingress-v1\0";
const HASH_CHUNK_WORDS: usize = 1024;

/// Enqueued CASM ingress which is not admission evidence until its setup fence
/// has completed.
///
/// The value is deliberately neither `Clone` nor `Copy`: one enqueue grants
/// one acknowledgement attempt. Its fields are private so it cannot be
/// converted into a published receipt outside this module.
#[must_use = "CASM ingress is not admissible until its setup fence is acknowledged"]
#[derive(Debug, Eq, PartialEq)]
pub struct PendingWitnessCasmInputIngressReceipt {
    receipt: WitnessCasmInputIngressReceipt,
}

impl PendingWitnessCasmInputIngressReceipt {
    pub const fn contract_identity(&self) -> [u8; 32] {
        self.receipt.contract_identity()
    }

    pub const fn content_identity(&self) -> [u8; 32] {
        self.receipt.content_identity()
    }

    pub const fn generation(&self) -> u64 {
        self.receipt.generation()
    }
}

/// Process-local proof that one exact row-major source was ingested, scattered,
/// and covered by the caller-owned setup fence.
///
/// Writer exclusivity for staging and consumer columns remains a proof-plan
/// obligation. This receipt only tracks work submitted through its prepared
/// CASM stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessCasmInputIngressReceipt {
    contract_identity: [u8; 32],
    arena_identity: usize,
    exec_context_token: u64,
    staging_slot: ArenaSlotId,
    staging_address: usize,
    staging_words: usize,
    abi: WitnessCasmInputAbi,
    row_domain: WitnessCasmInputRowDomain,
    state_words_per_row: usize,
    real_rows: usize,
    consumer_rows: usize,
    include_iota: bool,
    content_identity: [u8; 32],
    generation: u64,
}

impl WitnessCasmInputIngressReceipt {
    pub(super) fn prepare(
        binding: WitnessCasmInputIngressBinding,
        words: &[u32],
        generation: u64,
    ) -> Result<Self, PreparedWitnessCasmInputError> {
        if generation == 0 {
            return Err(PreparedWitnessCasmInputError::IngressGenerationOverflow);
        }
        if words.len() != binding.staging_words {
            return Err(PreparedWitnessCasmInputError::HostWordCountMismatch {
                expected: binding.staging_words,
                actual: words.len(),
            });
        }
        Ok(Self {
            contract_identity: binding.contract_identity,
            arena_identity: binding.arena_identity,
            exec_context_token: binding.exec_context_token,
            staging_slot: binding.staging_slot,
            staging_address: binding.staging_address,
            staging_words: binding.staging_words,
            abi: binding.abi,
            row_domain: binding.row_domain,
            state_words_per_row: binding.state_words_per_row,
            real_rows: binding.real_rows,
            consumer_rows: binding.consumer_rows,
            include_iota: binding.include_iota,
            content_identity: ingress_content_identity(binding, words)?,
            generation,
        })
    }

    pub(super) fn matches(
        self,
        binding: WitnessCasmInputIngressBinding,
        current_generation: u64,
    ) -> bool {
        self.generation != 0
            && self.generation == current_generation
            && self.contract_identity == binding.contract_identity
            && self.arena_identity == binding.arena_identity
            && self.exec_context_token == binding.exec_context_token
            && self.staging_slot == binding.staging_slot
            && self.staging_address == binding.staging_address
            && self.staging_words == binding.staging_words
            && self.abi == binding.abi
            && self.row_domain == binding.row_domain
            && self.state_words_per_row == binding.state_words_per_row
            && self.real_rows == binding.real_rows
            && self.consumer_rows == binding.consumer_rows
            && self.include_iota == binding.include_iota
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

    pub const fn staging_slot(self) -> ArenaSlotId {
        self.staging_slot
    }

    pub const fn staging_address(self) -> usize {
        self.staging_address
    }

    pub const fn staging_words(self) -> usize {
        self.staging_words
    }

    pub const fn abi(self) -> WitnessCasmInputAbi {
        self.abi
    }

    pub const fn row_domain(self) -> WitnessCasmInputRowDomain {
        self.row_domain
    }

    pub const fn state_words_per_row(self) -> usize {
        self.state_words_per_row
    }

    pub const fn real_rows(self) -> usize {
        self.real_rows
    }

    pub const fn consumer_rows(self) -> usize {
        self.consumer_rows
    }

    pub const fn include_iota(self) -> bool {
        self.include_iota
    }

    pub const fn content_identity(self) -> [u8; 32] {
        self.content_identity
    }

    pub const fn generation(self) -> u64 {
        self.generation
    }
}

pub(super) struct WitnessCasmInputIngressState {
    generation: Cell<u64>,
    candidate: Cell<Option<WitnessCasmInputIngressReceipt>>,
    scatter_enqueued: Cell<bool>,
    receipt: Cell<Option<WitnessCasmInputIngressReceipt>>,
}

impl WitnessCasmInputIngressState {
    pub(super) const fn new() -> Self {
        Self {
            generation: Cell::new(0),
            candidate: Cell::new(None),
            scatter_enqueued: Cell::new(false),
            receipt: Cell::new(None),
        }
    }

    pub(super) fn next_generation(&self) -> Result<u64, PreparedWitnessCasmInputError> {
        self.generation
            .get()
            .checked_add(1)
            .ok_or(PreparedWitnessCasmInputError::IngressGenerationOverflow)
    }

    /// Begin only after host shape and content have been validated. From this
    /// point, no earlier receipt may attest potentially changed device bytes.
    pub(super) fn begin(&self, receipt: WitnessCasmInputIngressReceipt) {
        debug_assert_eq!(
            receipt.generation(),
            self.generation.get().checked_add(1).unwrap()
        );
        self.generation.set(receipt.generation());
        self.candidate.set(Some(receipt));
        self.scatter_enqueued.set(false);
        self.receipt.set(None);
    }

    pub(super) fn ingested(&self) -> Option<WitnessCasmInputIngressReceipt> {
        (!self.scatter_enqueued.get())
            .then(|| self.candidate.get())
            .flatten()
    }

    pub(super) fn abort(&self, receipt: WitnessCasmInputIngressReceipt) {
        if self.candidate.get() == Some(receipt) {
            self.candidate.set(None);
            self.scatter_enqueued.set(false);
        }
        self.receipt.set(None);
    }

    pub(super) fn mark_scatter_enqueued(
        &self,
        receipt: WitnessCasmInputIngressReceipt,
        binding: WitnessCasmInputIngressBinding,
    ) -> Result<PendingWitnessCasmInputIngressReceipt, PreparedWitnessCasmInputError> {
        if self.candidate.get() != Some(receipt)
            || self.scatter_enqueued.get()
            || !receipt.matches(binding, self.generation.get())
        {
            return Err(PreparedWitnessCasmInputError::InvalidIngressReceipt);
        }
        self.scatter_enqueued.set(true);
        Ok(PendingWitnessCasmInputIngressReceipt { receipt })
    }

    pub(super) fn publish(
        &self,
        pending: PendingWitnessCasmInputIngressReceipt,
        binding: WitnessCasmInputIngressBinding,
    ) -> Result<WitnessCasmInputIngressReceipt, PreparedWitnessCasmInputError> {
        let receipt = pending.receipt;
        if self.candidate.get() != Some(receipt)
            || !self.scatter_enqueued.get()
            || !receipt.matches(binding, self.generation.get())
        {
            return Err(PreparedWitnessCasmInputError::InvalidIngressReceipt);
        }
        self.candidate.set(None);
        self.scatter_enqueued.set(false);
        self.receipt.set(Some(receipt));
        Ok(receipt)
    }

    pub(super) fn receipt(&self) -> Option<WitnessCasmInputIngressReceipt> {
        self.receipt.get()
    }

    pub(super) fn is_current(
        &self,
        receipt: &WitnessCasmInputIngressReceipt,
        binding: WitnessCasmInputIngressBinding,
    ) -> bool {
        self.receipt.get() == Some(*receipt) && receipt.matches(binding, self.generation.get())
    }

    pub(super) fn consume(
        &self,
        receipt: WitnessCasmInputIngressReceipt,
        binding: WitnessCasmInputIngressBinding,
    ) -> Result<(), PreparedWitnessCasmInputError> {
        let current = self.is_current(&receipt, binding);
        self.invalidate();
        current
            .then_some(())
            .ok_or(PreparedWitnessCasmInputError::InvalidIngressReceipt)
    }

    pub(super) fn invalidate(&self) {
        self.candidate.set(None);
        self.scatter_enqueued.set(false);
        self.receipt.set(None);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct WitnessCasmInputIngressBinding {
    contract_identity: [u8; 32],
    arena_identity: usize,
    exec_context_token: u64,
    staging_slot: ArenaSlotId,
    staging_address: usize,
    staging_words: usize,
    abi: WitnessCasmInputAbi,
    row_domain: WitnessCasmInputRowDomain,
    state_words_per_row: usize,
    real_rows: usize,
    consumer_rows: usize,
    include_iota: bool,
}

impl WitnessCasmInputIngressBinding {
    pub(super) fn new(
        arena: &DeviceArena,
        contract: &WitnessCasmInputContract,
        staging: ArenaSlice,
    ) -> Self {
        Self {
            contract_identity: contract.identity(),
            arena_identity: arena.base_ptr().as_ptr() as usize,
            exec_context_token: arena.exec_context_token(),
            staging_slot: staging.id(),
            staging_address: staging.as_u32_ptr() as usize,
            staging_words: staging.len_words(),
            abi: contract.abi(),
            row_domain: contract.row_domain(),
            state_words_per_row: WITNESS_CASM_STATE_WORDS,
            real_rows: contract.requirements().n_real_rows,
            consumer_rows: contract.requirements().consumer_rows,
            include_iota: contract.requirements().include_iota,
        }
    }
}

fn ingress_content_identity(
    binding: WitnessCasmInputIngressBinding,
    words: &[u32],
) -> Result<[u8; 32], PreparedWitnessCasmInputError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(INGRESS_DOMAIN);
    hasher.update(&[binding.abi as u8, binding.row_domain as u8]);
    hash_usize(&mut hasher, binding.state_words_per_row)?;
    hash_usize(&mut hasher, binding.real_rows)?;
    hash_usize(&mut hasher, binding.consumer_rows)?;
    hasher.update(&[u8::from(binding.include_iota)]);
    hash_usize(&mut hasher, words.len())?;

    let mut bytes = [0u8; HASH_CHUNK_WORDS * core::mem::size_of::<u32>()];
    for chunk in words.chunks(HASH_CHUNK_WORDS) {
        for (word, destination) in chunk.iter().zip(bytes.chunks_exact_mut(4)) {
            destination.copy_from_slice(&word.to_le_bytes());
        }
        hasher.update(&bytes[..chunk.len() * core::mem::size_of::<u32>()]);
    }
    Ok(*hasher.finalize().as_bytes())
}

fn hash_usize(
    hasher: &mut blake3::Hasher,
    value: usize,
) -> Result<(), PreparedWitnessCasmInputError> {
    hasher.update(
        &u64::try_from(value)
            .map_err(|_| PreparedWitnessCasmInputError::SizeOverflow)?
            .to_le_bytes(),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> WitnessCasmInputIngressBinding {
        WitnessCasmInputIngressBinding {
            contract_identity: [7; 32],
            arena_identity: 11,
            exec_context_token: 13,
            staging_slot: ArenaSlotId(17),
            staging_address: 19,
            staging_words: 6,
            abi: WitnessCasmInputAbi::RowMajorStateScatterV1,
            row_domain: WitnessCasmInputRowDomain::RealPrefixWithRowZeroPaddingV1,
            state_words_per_row: 3,
            real_rows: 2,
            consumer_rows: 16,
            include_iota: false,
        }
    }

    fn receipt(
        binding: WitnessCasmInputIngressBinding,
        words: &[u32],
        generation: u64,
    ) -> WitnessCasmInputIngressReceipt {
        WitnessCasmInputIngressReceipt::prepare(binding, words, generation).unwrap()
    }

    fn pending_for_test(
        receipt: WitnessCasmInputIngressReceipt,
    ) -> PendingWitnessCasmInputIngressReceipt {
        PendingWitnessCasmInputIngressReceipt { receipt }
    }

    #[test]
    fn content_identity_binds_order_extent_and_typed_geometry() {
        let binding = binding();
        let words = [1, 2, 3, 4, 5, 6];
        let identity = ingress_content_identity(binding, &words).unwrap();
        assert_eq!(identity, ingress_content_identity(binding, &words).unwrap());
        assert_ne!(
            identity,
            ingress_content_identity(binding, &[1, 2, 3, 4, 6, 5]).unwrap()
        );
        assert_ne!(
            identity,
            ingress_content_identity(binding, &[1, 2, 3, 4, 5]).unwrap()
        );

        let mut geometry = binding;
        geometry.real_rows = 1;
        assert_ne!(
            identity,
            ingress_content_identity(geometry, &words).unwrap()
        );
        assert_ne!(identity, [0; 32]);
    }

    #[test]
    fn chunked_content_hash_is_canonical_at_the_chunk_boundary() {
        let mut binding = binding();
        binding.real_rows = 342;
        binding.consumer_rows = 512;
        binding.staging_words = 1026;
        let words = (0..binding.staging_words)
            .map(|word| word as u32)
            .collect::<Vec<_>>();

        let mut reference = blake3::Hasher::new();
        reference.update(INGRESS_DOMAIN);
        reference.update(&[binding.abi as u8, binding.row_domain as u8]);
        for value in [
            binding.state_words_per_row,
            binding.real_rows,
            binding.consumer_rows,
        ] {
            reference.update(&u64::try_from(value).unwrap().to_le_bytes());
        }
        reference.update(&[u8::from(binding.include_iota)]);
        reference.update(&u64::try_from(words.len()).unwrap().to_le_bytes());
        for word in &words {
            reference.update(&word.to_le_bytes());
        }
        assert_eq!(
            ingress_content_identity(binding, &words).unwrap(),
            *reference.finalize().as_bytes()
        );
    }

    #[test]
    fn receipt_binds_slot_context_content_and_row_major_geometry() {
        let binding = binding();
        let words = [1, 2, 3, 4, 5, 6];
        let receipt = receipt(binding, &words, 1);
        assert!(receipt.matches(binding, 1));

        let mut mutations = Vec::new();
        let mut changed = binding;
        changed.contract_identity[0] ^= 1;
        mutations.push(changed);
        changed = binding;
        changed.arena_identity += 1;
        mutations.push(changed);
        changed = binding;
        changed.exec_context_token += 1;
        mutations.push(changed);
        changed = binding;
        changed.staging_slot = ArenaSlotId(18);
        mutations.push(changed);
        changed = binding;
        changed.staging_address += 4;
        mutations.push(changed);
        changed = binding;
        changed.staging_words += 1;
        mutations.push(changed);
        changed = binding;
        changed.state_words_per_row += 1;
        mutations.push(changed);
        changed = binding;
        changed.real_rows += 1;
        mutations.push(changed);
        changed = binding;
        changed.consumer_rows *= 2;
        mutations.push(changed);
        changed = binding;
        changed.include_iota = true;
        mutations.push(changed);

        for mutation in mutations {
            assert!(!receipt.matches(mutation, 1));
        }
        assert!(!receipt.matches(binding, 2));
        assert_ne!(
            receipt.content_identity(),
            self::receipt(binding, &[6, 5, 4, 3, 2, 1], 1).content_identity()
        );
        assert_eq!(receipt.contract_identity(), [7; 32]);
        assert_eq!(receipt.arena_identity(), 11);
        assert_eq!(receipt.exec_context_token(), 13);
        assert_eq!(receipt.staging_slot(), ArenaSlotId(17));
        assert_eq!(receipt.staging_address(), 19);
        assert_eq!(receipt.staging_words(), 6);
        assert_eq!(receipt.abi(), WitnessCasmInputAbi::RowMajorStateScatterV1);
        assert_eq!(
            receipt.row_domain(),
            WitnessCasmInputRowDomain::RealPrefixWithRowZeroPaddingV1
        );
        assert_eq!(receipt.state_words_per_row(), 3);
        assert_eq!(receipt.real_rows(), 2);
        assert_eq!(receipt.consumer_rows(), 16);
        assert!(!receipt.include_iota());
        assert_eq!(receipt.generation(), 1);
    }

    #[test]
    fn publication_requires_pending_current_generation_after_scatter() {
        let binding = binding();
        let state = WitnessCasmInputIngressState::new();
        let first = receipt(binding, &[1, 2, 3, 4, 5, 6], 1);
        assert_eq!(state.next_generation().unwrap(), 1);
        state.begin(first);
        assert_eq!(state.next_generation().unwrap(), 2);

        assert_eq!(state.receipt(), None);
        assert!(!state.is_current(&first, binding));
        assert_eq!(
            state.publish(pending_for_test(first), binding),
            Err(PreparedWitnessCasmInputError::InvalidIngressReceipt)
        );

        let pending = state.mark_scatter_enqueued(first, binding).unwrap();
        assert_eq!(pending.contract_identity(), [7; 32]);
        assert_eq!(pending.content_identity(), first.content_identity());
        assert_eq!(pending.generation(), 1);
        assert_eq!(state.receipt(), None);
        assert!(!state.is_current(&first, binding));
        let published = state.publish(pending, binding).unwrap();
        assert_eq!(state.receipt(), Some(first));
        assert!(state.is_current(&published, binding));
    }

    #[test]
    fn stale_and_replayed_generations_fail_closed() {
        let binding = binding();
        let state = WitnessCasmInputIngressState::new();
        let first = receipt(binding, &[1, 2, 3, 4, 5, 6], 1);
        state.begin(first);
        let stale = state.mark_scatter_enqueued(first, binding).unwrap();

        let second = receipt(binding, &[6, 5, 4, 3, 2, 1], 2);
        state.begin(second);
        assert_eq!(
            state.publish(stale, binding),
            Err(PreparedWitnessCasmInputError::InvalidIngressReceipt)
        );
        let pending = state.mark_scatter_enqueued(second, binding).unwrap();
        let replay = pending_for_test(second);
        state.publish(pending, binding).unwrap();
        assert_eq!(
            state.publish(replay, binding),
            Err(PreparedWitnessCasmInputError::InvalidIngressReceipt)
        );
        assert!(state.is_current(&second, binding));

        let mut changed_content = second;
        changed_content.content_identity[0] ^= 1;
        assert_eq!(
            state.publish(pending_for_test(changed_content), binding),
            Err(PreparedWitnessCasmInputError::InvalidIngressReceipt)
        );
        assert!(state.is_current(&second, binding));
    }

    #[test]
    fn consume_is_exact_single_use_and_stale_mismatch_fails_closed() {
        let binding = binding();
        let state = WitnessCasmInputIngressState::new();
        let first = receipt(binding, &[1, 2, 3, 4, 5, 6], 1);
        state.begin(first);
        let pending = state.mark_scatter_enqueued(first, binding).unwrap();
        state.publish(pending, binding).unwrap();

        state.consume(first, binding).unwrap();
        assert_eq!(state.receipt(), None);
        assert_eq!(
            state.consume(first, binding),
            Err(PreparedWitnessCasmInputError::InvalidIngressReceipt)
        );
        assert_eq!(state.next_generation().unwrap(), 2);

        let second = receipt(binding, &[6, 5, 4, 3, 2, 1], 2);
        state.begin(second);
        let pending = state.mark_scatter_enqueued(second, binding).unwrap();
        state.publish(pending, binding).unwrap();
        assert_eq!(
            state.consume(first, binding),
            Err(PreparedWitnessCasmInputError::InvalidIngressReceipt)
        );
        assert_eq!(state.receipt(), None);
        assert!(!state.is_current(&second, binding));
        assert_eq!(state.next_generation().unwrap(), 3);

        let third = receipt(binding, &[2, 3, 4, 5, 6, 7], 3);
        state.begin(third);
        let pending = state.mark_scatter_enqueued(third, binding).unwrap();
        state.publish(pending, binding).unwrap();
        assert!(state.is_current(&third, binding));
    }

    #[test]
    fn invalidate_clears_partial_and_published_state_without_reusing_generations() {
        let binding = binding();
        let state = WitnessCasmInputIngressState::new();

        let before_scatter = receipt(binding, &[1, 2, 3, 4, 5, 6], 1);
        state.begin(before_scatter);
        state.invalidate();
        assert_eq!(state.ingested(), None);
        assert_eq!(state.receipt(), None);
        assert_eq!(
            state.mark_scatter_enqueued(before_scatter, binding),
            Err(PreparedWitnessCasmInputError::InvalidIngressReceipt)
        );
        assert_eq!(state.next_generation().unwrap(), 2);

        let after_scatter = receipt(binding, &[6, 5, 4, 3, 2, 1], 2);
        state.begin(after_scatter);
        let pending = state.mark_scatter_enqueued(after_scatter, binding).unwrap();
        state.invalidate();
        assert_eq!(
            state.publish(pending, binding),
            Err(PreparedWitnessCasmInputError::InvalidIngressReceipt)
        );
        assert_eq!(state.next_generation().unwrap(), 3);

        let published = receipt(binding, &[2, 3, 4, 5, 6, 7], 3);
        state.begin(published);
        let pending = state.mark_scatter_enqueued(published, binding).unwrap();
        state.publish(pending, binding).unwrap();
        state.invalidate();
        assert_eq!(state.receipt(), None);
        assert!(!state.is_current(&published, binding));
        assert_eq!(state.next_generation().unwrap(), 4);

        let fresh = receipt(binding, &[7, 6, 5, 4, 3, 2], 4);
        state.begin(fresh);
        let pending = state.mark_scatter_enqueued(fresh, binding).unwrap();
        state.publish(pending, binding).unwrap();
        assert!(state.is_current(&fresh, binding));
    }

    #[test]
    fn generation_overflow_and_invalid_host_extent_preserve_current() {
        let binding = binding();
        let state = WitnessCasmInputIngressState::new();
        let current = receipt(binding, &[1, 2, 3, 4, 5, 6], 1);
        state.begin(current);
        let pending = state.mark_scatter_enqueued(current, binding).unwrap();
        state.publish(pending, binding).unwrap();

        assert_eq!(
            WitnessCasmInputIngressReceipt::prepare(binding, &[1, 2], 2),
            Err(PreparedWitnessCasmInputError::HostWordCountMismatch {
                expected: 6,
                actual: 2,
            })
        );
        assert!(state.is_current(&current, binding));

        state.generation.set(u64::MAX);
        assert_eq!(
            state.next_generation(),
            Err(PreparedWitnessCasmInputError::IngressGenerationOverflow)
        );
    }
}
