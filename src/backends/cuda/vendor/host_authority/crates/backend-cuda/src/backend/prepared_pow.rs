//! Prepared resident Blake2s proof-of-work.
//!
//! The persistent search kernel reads the current device transcript digest and
//! publishes the numerically smallest nonce on the SIMD grind lattice
//! `{(hi << 32) | low : 0 <= low < 2^POW_GRIND_LOW_BITS}` satisfying the
//! ordinary Blake2s channel check. The SIMD reference
//! (`stwo::prover::backend::simd::grind`) scans hi ascending, then low
//! ascending within each hi; because `low < 2^20 < 2^32`, that scan order IS
//! numeric order on the lattice, so the kernel's numeric minimum over mapped
//! lattice nonces is byte-identical to `SimdBackend::grind`. Replay contains
//! only stream memsets, one prefix-hash kernel, and the persistent search.

use std::collections::BTreeSet;

use super::device_transcript::BLAKE2S_TRANSCRIPT_STATE_WORDS;
use super::exec_context::{
    check_cuda, ArenaError, ArenaSlice, ArenaSlotId, CudaRuntimeError, DeviceArena,
};

const WORD_BYTES: usize = core::mem::size_of::<u32>();
pub const POW_NONCE_WORDS: usize = 2;
pub const POW_PREFIX_DIGEST_WORDS: usize = 8;
pub const POW_U64_ALIGNMENT_WORDS: usize = core::mem::align_of::<u64>() / WORD_BYTES;
/// Low-bit width of the SIMD grind lattice (GRIND_LOW_BITS in
/// `stwo::prover::backend::simd::grind`).
pub const POW_GRIND_LOW_BITS: u32 = 20;
/// Exclusive end of the SIMD grind index lattice. This mirrors the CUDA and
/// SIMD requirement that the high limb remains below the M31 modulus.
pub const POW_INDEX_LIMIT: u64 = (0x7fff_ffff_u64) << POW_GRIND_LOW_BITS;
pub const POW_THREADS_PER_BLOCK: u32 = 256;
/// Compiled search contract. The source-level unroll sweep selected u2 as the
/// primary and u5 as the identical fallback. `__launch_bounds__(256, 6)` caps
/// the compiler at the 75%-occupancy register envelope on SM90; the release
/// resource gate additionally rejects any ptxas spill.
#[cfg(test)]
const POW_PRIMARY_ROUND_UNROLL: u32 = 2;
#[cfg(test)]
const POW_FALLBACK_ROUND_UNROLL: u32 = 5;
#[cfg(test)]
const POW_MIN_BLOCKS_PER_SM: u32 = 6;

/// Host mirror of the kernel's monotone index -> nonce map
/// (`pow_index_to_nonce` in `cuda/resident_pow.cu`): linear search index `i`
/// covers exactly the SIMD lattice nonce `(hi << 32) | low` with
/// `hi = i >> 20` and `low = i & 0xFFFFF`. Strictly increasing in `i` (nonce
/// bits 20..31 are always zero), so numeric order on mapped nonces equals
/// index order equals the SIMD (hi ascending, low ascending) scan order.
pub const fn pow_index_to_nonce(index: u64) -> u64 {
    ((index >> POW_GRIND_LOW_BITS) << 32) | (index & ((1 << POW_GRIND_LOW_BITS) - 1))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Blake2sPowWorkspaceRequirements {
    pub state_words: usize,
    pub nonce_words: usize,
    pub best_nonce_words: usize,
    pub completed_blocks_words: usize,
    pub prefix_digest_words: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Blake2sPowWorkspaceSlots {
    pub best_nonce: ArenaSlotId,
    pub completed_blocks: ArenaSlotId,
    pub prefix_digest: ArenaSlotId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Blake2sPowArenaSlotRequirement {
    pub id: ArenaSlotId,
    pub len_words: usize,
    pub alignment_words: usize,
}

/// Shared geometry for one wait-all fleet PoW attempt. Every rank tile must be
/// derived from this value; independently chosen launch widths are not a valid
/// fleet partition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Blake2sPowFleetAttempt {
    rank_count: u32,
    start_index: u64,
    end_index: u64,
    grid_blocks: u32,
}

impl Blake2sPowFleetAttempt {
    pub fn new(
        rank_count: u32,
        start_index: u64,
        end_index: u64,
        grid_blocks: u32,
    ) -> Result<Self, PreparedBlake2sPowError> {
        let workers_per_rank = u64::from(grid_blocks)
            .checked_mul(u64::from(POW_THREADS_PER_BLOCK))
            .ok_or(PreparedBlake2sPowError::InvalidRankTile)?;
        workers_per_rank
            .checked_mul(u64::from(rank_count))
            .ok_or(PreparedBlake2sPowError::InvalidRankTile)?;
        if rank_count == 0
            || start_index >= end_index
            || end_index > POW_INDEX_LIMIT
            || grid_blocks == 0
            || grid_blocks > i32::MAX as u32
        {
            return Err(PreparedBlake2sPowError::InvalidRankTile);
        }
        Ok(Self {
            rank_count,
            start_index,
            end_index,
            grid_blocks,
        })
    }

    pub fn rank_tile(self, rank: u32) -> Result<Blake2sPowRankTile, PreparedBlake2sPowError> {
        if rank >= self.rank_count {
            return Err(PreparedBlake2sPowError::InvalidRankTile);
        }
        Ok(Blake2sPowRankTile {
            attempt: self,
            rank,
        })
    }

    pub const fn rank_count(self) -> u32 {
        self.rank_count
    }

    pub const fn start_index(self) -> u64 {
        self.start_index
    }

    pub const fn end_index(self) -> u64 {
        self.end_index
    }

    pub const fn grid_blocks(self) -> u32 {
        self.grid_blocks
    }
}

/// One rank's exact share of a shared [`Blake2sPowFleetAttempt`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Blake2sPowRankTile {
    attempt: Blake2sPowFleetAttempt,
    rank: u32,
}

impl Blake2sPowRankTile {
    pub const fn attempt(self) -> Blake2sPowFleetAttempt {
        self.attempt
    }

    pub const fn rank_count(self) -> u32 {
        self.attempt.rank_count
    }

    pub const fn rank(self) -> u32 {
        self.rank
    }

    pub const fn start_index(self) -> u64 {
        self.attempt.start_index
    }

    pub const fn end_index(self) -> u64 {
        self.attempt.end_index
    }

    pub const fn grid_blocks(self) -> u32 {
        self.attempt.grid_blocks
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreparedBlake2sPowError {
    InvalidPowBits(u32),
    InvalidRankTile,
    ContextMismatch(ArenaSlotId),
    AliasedSlot(ArenaSlotId),
    StateTooSmall {
        required: usize,
        actual: usize,
    },
    NonceTooSmall {
        required: usize,
        actual: usize,
    },
    SlotTooSmall {
        slot: ArenaSlotId,
        required: usize,
        actual: usize,
    },
    MisalignedBestNonce(ArenaSlotId),
    Arena(ArenaError),
    Cuda(CudaRuntimeError),
}

impl core::fmt::Display for PreparedBlake2sPowError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid prepared CUDA Blake2s PoW graph: {self:?}")
    }
}

impl std::error::Error for PreparedBlake2sPowError {}

impl From<ArenaError> for PreparedBlake2sPowError {
    fn from(value: ArenaError) -> Self {
        Self::Arena(value)
    }
}

impl From<CudaRuntimeError> for PreparedBlake2sPowError {
    fn from(value: CudaRuntimeError) -> Self {
        Self::Cuda(value)
    }
}

pub const fn blake2s_pow_workspace_requirements() -> Blake2sPowWorkspaceRequirements {
    Blake2sPowWorkspaceRequirements {
        state_words: BLAKE2S_TRANSCRIPT_STATE_WORDS,
        nonce_words: POW_NONCE_WORDS,
        best_nonce_words: POW_NONCE_WORDS,
        completed_blocks_words: 1,
        prefix_digest_words: POW_PREFIX_DIGEST_WORDS,
    }
}

impl Blake2sPowWorkspaceRequirements {
    pub fn arena_slot_requirements(
        self,
        slots: Blake2sPowWorkspaceSlots,
    ) -> Result<[Blake2sPowArenaSlotRequirement; 3], PreparedBlake2sPowError> {
        let mut distinct = BTreeSet::new();
        for slot in [
            slots.best_nonce,
            slots.completed_blocks,
            slots.prefix_digest,
        ] {
            if !distinct.insert(slot) {
                return Err(PreparedBlake2sPowError::AliasedSlot(slot));
            }
        }
        Ok([
            Blake2sPowArenaSlotRequirement {
                id: slots.best_nonce,
                len_words: self.best_nonce_words,
                alignment_words: POW_U64_ALIGNMENT_WORDS,
            },
            Blake2sPowArenaSlotRequirement {
                id: slots.completed_blocks,
                len_words: self.completed_blocks_words,
                alignment_words: 1,
            },
            Blake2sPowArenaSlotRequirement {
                id: slots.prefix_digest,
                len_words: self.prefix_digest_words,
                alignment_words: 1,
            },
        ])
    }
}

pub struct PreparedBlake2sPowGraph<'a> {
    arena: &'a DeviceArena,
    pow_bits: u32,
    transcript_state: ArenaSlice,
    best_nonce: ArenaSlice,
    completed_blocks: ArenaSlice,
    prefix_digest: ArenaSlice,
    transcript_nonce: ArenaSlice,
}

impl<'a> PreparedBlake2sPowGraph<'a> {
    pub fn prepare(
        arena: &'a DeviceArena,
        transcript_state: ArenaSlice,
        pow_bits: u32,
        transcript_nonce: ArenaSlice,
        slots: Blake2sPowWorkspaceSlots,
    ) -> Result<Self, PreparedBlake2sPowError> {
        validate_pow_bits(pow_bits)?;
        let requirements = blake2s_pow_workspace_requirements();
        if transcript_state.len_words() < requirements.state_words {
            return Err(PreparedBlake2sPowError::StateTooSmall {
                required: requirements.state_words,
                actual: transcript_state.len_words(),
            });
        }
        if transcript_nonce.len_words() < requirements.nonce_words {
            return Err(PreparedBlake2sPowError::NonceTooSmall {
                required: requirements.nonce_words,
                actual: transcript_nonce.len_words(),
            });
        }
        let slot_requirements = requirements.arena_slot_requirements(slots)?;
        let best_nonce = bind_slot(arena, slot_requirements[0])?;
        let completed_blocks = bind_slot(arena, slot_requirements[1])?;
        let prefix_digest = bind_slot(arena, slot_requirements[2])?;
        if (best_nonce.as_u32_ptr() as usize) % core::mem::align_of::<u64>() != 0 {
            return Err(PreparedBlake2sPowError::MisalignedBestNonce(
                best_nonce.id(),
            ));
        }

        let bindings = [
            transcript_state,
            transcript_nonce,
            best_nonce,
            completed_blocks,
            prefix_digest,
        ];
        let context = arena.context().identity_token();
        let mut identities = BTreeSet::new();
        for binding in bindings {
            if binding.context_token() != context {
                return Err(PreparedBlake2sPowError::ContextMismatch(binding.id()));
            }
            if !identities.insert(binding.id()) {
                return Err(PreparedBlake2sPowError::AliasedSlot(binding.id()));
            }
        }

        Ok(Self {
            arena,
            pow_bits,
            transcript_state,
            best_nonce,
            completed_blocks,
            prefix_digest,
            transcript_nonce,
        })
    }

    pub fn state_source(&self) -> ArenaSlice {
        self.transcript_state
    }

    pub const fn pow_bits(&self) -> u32 {
        self.pow_bits
    }

    pub fn nonce_destination(&self) -> ArenaSlice {
        self.transcript_nonce
    }

    /// Read the exact device transcript state at a fleet hand-off boundary.
    pub fn read_state(
        &self,
    ) -> Result<[u32; BLAKE2S_TRANSCRIPT_STATE_WORDS], PreparedBlake2sPowError> {
        let mut state = [0u32; BLAKE2S_TRANSCRIPT_STATE_WORDS];
        unsafe {
            self.arena.context().memcpy_d2h_async(
                state.as_mut_ptr().cast(),
                self.transcript_state.as_void_ptr().cast_const(),
                core::mem::size_of_val(&state),
            )?;
        }
        self.arena.context().sync()?;
        Ok(state)
    }

    /// Install a coordinator-owned transcript state on a persistent PoW worker.
    pub fn upload_state(
        &self,
        state: &[u32; BLAKE2S_TRANSCRIPT_STATE_WORDS],
    ) -> Result<(), PreparedBlake2sPowError> {
        unsafe {
            self.arena.context().memcpy_h2d_async(
                self.transcript_state.as_void_ptr(),
                state.as_ptr().cast(),
                core::mem::size_of_val(state),
            )?;
        }
        self.arena.context().sync()?;
        Ok(())
    }

    /// Read the rank-local minimum after [`Self::launch_rank_tile`]. This is a
    /// worker result, not a transcript nonce; only a wait-all reducer may
    /// publish the global minimum through [`Self::upload_nonce`].
    pub fn read_rank_result(&self) -> Result<u64, PreparedBlake2sPowError> {
        let mut words = [0u32; POW_NONCE_WORDS];
        unsafe {
            self.arena.context().memcpy_d2h_async(
                words.as_mut_ptr().cast(),
                self.best_nonce.as_void_ptr().cast_const(),
                core::mem::size_of_val(&words),
            )?;
        }
        self.arena.context().sync()?;
        Ok(u64::from(words[0]) | (u64::from(words[1]) << 32))
    }

    /// Install the canonical wait-all minimum before the transcript absorbs it.
    pub fn upload_nonce(&self, nonce: u64) -> Result<(), PreparedBlake2sPowError> {
        let words = [nonce as u32, (nonce >> 32) as u32];
        unsafe {
            self.arena.context().memcpy_h2d_async(
                self.transcript_nonce.as_void_ptr(),
                words.as_ptr().cast(),
                core::mem::size_of_val(&words),
            )?;
        }
        self.arena.context().sync()?;
        Ok(())
    }

    /// Initialize caller-owned scratch, hash the transcript prefix once, and
    /// enqueue the persistent search. No digest or nonce crosses the host.
    pub fn launch(&self) -> Result<(), PreparedBlake2sPowError> {
        self.initialize_monolithic_scratch()?;
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_blake2s_pow_persistent_on(
                self.transcript_state.as_u32_ptr().cast_const(),
                self.pow_bits,
                self.prefix_digest.as_u32_ptr(),
                self.best_nonce.as_u32_ptr().cast::<u64>(),
                self.completed_blocks.as_u32_ptr(),
                self.transcript_nonce.as_u32_ptr(),
                self.arena.context().stream_raw().as_ptr(),
            )
        };
        check_cuda("prepared_blake2s_pow", code)?;
        Ok(())
    }

    /// Search one fleet rank's exact share of one attempt tile. The tile is a
    /// launch parameter so a persistent worker can retry without rebuilding
    /// its prepared arena bindings.
    pub fn launch_rank_tile(
        &self,
        tile: Blake2sPowRankTile,
    ) -> Result<(), PreparedBlake2sPowError> {
        self.reset_best_nonce()?;
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_blake2s_pow_rank_tile_on(
                self.transcript_state.as_u32_ptr().cast_const(),
                self.pow_bits,
                tile.rank_count(),
                tile.rank(),
                tile.start_index(),
                tile.end_index(),
                tile.grid_blocks(),
                self.prefix_digest.as_u32_ptr(),
                self.best_nonce.as_u32_ptr().cast::<u64>(),
                self.arena.context().stream_raw().as_ptr(),
            )
        };
        check_cuda("prepared_blake2s_pow_rank_tile", code)?;
        Ok(())
    }

    /// Execute one worker request with a single required completion fence.
    pub fn execute_rank_tile(
        &self,
        state: &[u32; BLAKE2S_TRANSCRIPT_STATE_WORDS],
        tile: Blake2sPowRankTile,
    ) -> Result<u64, PreparedBlake2sPowError> {
        unsafe {
            self.arena.context().memcpy_h2d_async(
                self.transcript_state.as_void_ptr(),
                state.as_ptr().cast(),
                core::mem::size_of_val(state),
            )?;
        }
        self.launch_rank_tile(tile)?;
        self.read_rank_result()
    }

    fn reset_best_nonce(&self) -> Result<(), PreparedBlake2sPowError> {
        unsafe {
            self.arena.context().memset_async(
                self.best_nonce.as_void_ptr(),
                0xff,
                POW_NONCE_WORDS * WORD_BYTES,
            )?;
        }
        Ok(())
    }

    fn initialize_monolithic_scratch(&self) -> Result<(), PreparedBlake2sPowError> {
        self.reset_best_nonce()?;
        unsafe {
            self.arena.context().memset_async(
                self.completed_blocks.as_void_ptr(),
                0,
                WORD_BYTES,
            )?;
            self.arena.context().memset_async(
                self.transcript_nonce.as_void_ptr(),
                0xff,
                POW_NONCE_WORDS * WORD_BYTES,
            )?;
        }
        Ok(())
    }
}

/// Mirrors the SIMD reference's `pow_bits <= 32` assertion. The lattice
/// enumeration keeps this bound sound: `pow_bits = 32` needs ~2^32 attempts in
/// expectation, i.e. ~2^12 hi blocks of 2^20 lows each, far below the kernel's
/// `hi < 2^31 - 1` give-up limit (which itself mirrors the SIMD post-grind
/// assertion that the found hi is reduced modulo the M31 prime).
fn validate_pow_bits(pow_bits: u32) -> Result<(), PreparedBlake2sPowError> {
    if pow_bits > 32 {
        return Err(PreparedBlake2sPowError::InvalidPowBits(pow_bits));
    }
    Ok(())
}

fn bind_slot(
    arena: &DeviceArena,
    requirement: Blake2sPowArenaSlotRequirement,
) -> Result<ArenaSlice, PreparedBlake2sPowError> {
    let slice = arena.bind(requirement.id)?;
    if slice.len_words() < requirement.len_words {
        return Err(PreparedBlake2sPowError::SlotTooSmall {
            slot: requirement.id,
            required: requirement.len_words,
            actual: slice.len_words(),
        });
    }
    // Pooled slots may be larger than any single logical buffer; expose only
    // the logical extent so no consumer derives sizes from the pooled surplus.
    Ok(slice.truncated(requirement.len_words))
}

#[cfg(test)]
mod tests {
    use stwo::core::channel::{Blake2sChannelGeneric, Channel};
    use stwo::core::proof_of_work::GrindOps;
    use stwo::core::vcs::blake2_hash::Blake2sHasherGeneric;
    use stwo::prover::backend::simd::SimdBackend;

    use super::*;

    const TEST_POW_IV: [u32; 8] = [
        0x6A09_E667,
        0xBB67_AE85,
        0x3C6E_F372,
        0xA54F_F53A,
        0x510E_527F,
        0x9B05_688C,
        0x1F83_D9AB,
        0x5BE0_CD19,
    ];
    const TEST_POW_SIGMA: [[usize; 16]; 10] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    ];

    fn reference_pow_prefix(channel: &Blake2sChannelGeneric<false>, pow_bits: u32) -> [u8; 32] {
        let mut prefix = Blake2sHasherGeneric::<false>::default();
        prefix.update(&Blake2sChannelGeneric::<false>::POW_PREFIX.to_le_bytes());
        prefix.update(&[0u8; 12]);
        prefix.update(&channel.digest().0);
        prefix.update(&pow_bits.to_le_bytes());
        prefix.finalize().0
    }

    fn reference_candidate_hash_word(prefix: &[u8; 32], nonce: u64) -> u32 {
        let mut candidate = Blake2sHasherGeneric::<false>::default();
        candidate.update(prefix);
        candidate.update(&nonce.to_le_bytes());
        let hash = candidate.finalize();
        u32::from_le_bytes(hash.0[..4].try_into().unwrap())
    }

    fn test_pow_g(
        state: &mut [u32; 16],
        indices: [usize; 4],
        first_message: u32,
        second_message: u32,
    ) {
        let [a, b, c, d] = indices;
        let (mut va, mut vb, mut vc, mut vd) = (state[a], state[b], state[c], state[d]);
        va = va.wrapping_add(vb).wrapping_add(first_message);
        vd = (vd ^ va).rotate_right(16);
        vc = vc.wrapping_add(vd);
        vb = (vb ^ vc).rotate_right(12);
        va = va.wrapping_add(vb).wrapping_add(second_message);
        vd = (vd ^ va).rotate_right(8);
        vc = vc.wrapping_add(vd);
        vb = (vb ^ vc).rotate_right(7);
        state[a] = va;
        state[b] = vb;
        state[c] = vc;
        state[d] = vd;
    }

    fn decoded_candidate_hash_word(prefix: &[u8; 32], nonce: u64) -> u32 {
        let prefix_words = core::array::from_fn::<_, 8, _>(|word| {
            u32::from_le_bytes(prefix[4 * word..4 * word + 4].try_into().unwrap())
        });
        let message = |index: usize| match index {
            0..=7 => prefix_words[index],
            8 => nonce as u32,
            9 => (nonce >> 32) as u32,
            _ => 0,
        };
        let parameterized_iv = TEST_POW_IV[0] ^ 0x0101_0020;
        let mut state = [0u32; 16];
        state[0] = parameterized_iv;
        state[1..8].copy_from_slice(&TEST_POW_IV[1..]);
        state[8..].copy_from_slice(&TEST_POW_IV);
        state[12] ^= 40;
        state[14] ^= u32::MAX;

        for sigma in TEST_POW_SIGMA {
            for lane in 0..4 {
                test_pow_g(
                    &mut state,
                    [lane, lane + 4, lane + 8, lane + 12],
                    message(sigma[2 * lane]),
                    message(sigma[2 * lane + 1]),
                );
            }
            for lane in 0..4 {
                test_pow_g(
                    &mut state,
                    [
                        lane,
                        4 + (lane + 1) % 4,
                        8 + (lane + 2) % 4,
                        12 + (lane + 3) % 4,
                    ],
                    message(sigma[8 + 2 * lane]),
                    message(sigma[8 + 2 * lane + 1]),
                );
            }
        }
        parameterized_iv ^ state[0] ^ state[8]
    }

    fn reference_valid_pow(
        channel: &Blake2sChannelGeneric<false>,
        pow_bits: u32,
        nonce: u64,
    ) -> bool {
        reference_candidate_hash_word(&reference_pow_prefix(channel, pow_bits), nonce)
            .trailing_zeros()
            >= pow_bits
    }

    #[test]
    fn exact_scratch_layout() {
        let requirements = blake2s_pow_workspace_requirements();
        assert_eq!(requirements.state_words, 16);
        assert_eq!(requirements.nonce_words, 2);
        assert_eq!(requirements.best_nonce_words, 2);
        assert_eq!(requirements.completed_blocks_words, 1);
        assert_eq!(requirements.prefix_digest_words, 8);
        assert_eq!(POW_U64_ALIGNMENT_WORDS, 2);
        assert_eq!(
            requirements
                .arena_slot_requirements(Blake2sPowWorkspaceSlots {
                    best_nonce: ArenaSlotId(7),
                    completed_blocks: ArenaSlotId(8),
                    prefix_digest: ArenaSlotId(9),
                })
                .unwrap(),
            [
                Blake2sPowArenaSlotRequirement {
                    id: ArenaSlotId(7),
                    len_words: 2,
                    alignment_words: 2,
                },
                Blake2sPowArenaSlotRequirement {
                    id: ArenaSlotId(8),
                    len_words: 1,
                    alignment_words: 1,
                },
                Blake2sPowArenaSlotRequirement {
                    id: ArenaSlotId(9),
                    len_words: 8,
                    alignment_words: 1,
                },
            ]
        );
    }

    #[test]
    fn pow_prefix_and_validity_match_blake2s_channel() {
        let mut channel = Blake2sChannelGeneric::<false>::default();
        channel.mix_u32s(&[1, 0x1122_3344, 0xaabb_ccdd, 9]);
        for pow_bits in [0, 1, 7, 16, 26, 31, 32] {
            for nonce in [0, 1, 17, 0x1122_3344_5566_7788] {
                assert_eq!(
                    reference_valid_pow(&channel, pow_bits, nonce),
                    channel.verify_pow_nonce(pow_bits, nonce),
                    "pow_bits={pow_bits}, nonce={nonce}"
                );
            }
        }
    }

    #[test]
    fn decoded_candidate_block_matches_independent_hash_on_boundaries_and_mutations() {
        let mut channel = Blake2sChannelGeneric::<false>::default();
        channel.mix_u32s(&[0, 1, u32::MAX, 0x1122_3344, 0xaabb_ccdd]);
        let baseline = reference_pow_prefix(&channel, 19);
        let mut prefixes = vec![baseline, [0u8; 32], [u8::MAX; 32]];
        for byte in 0..32 {
            let mut mutated = baseline;
            mutated[byte] ^= if byte & 1 == 0 { 1 } else { 0x80 };
            prefixes.push(mutated);
        }
        let last_lattice_index =
            ((0x7fff_fffeu64) << POW_GRIND_LOW_BITS) | ((1 << POW_GRIND_LOW_BITS) - 1);
        let mut nonces = vec![
            0,
            1,
            (1 << POW_GRIND_LOW_BITS) - 1,
            1 << POW_GRIND_LOW_BITS,
            1 << 32,
            (1 << 32) | ((1 << POW_GRIND_LOW_BITS) - 1),
            pow_index_to_nonce(last_lattice_index),
            u64::MAX,
        ];
        nonces.extend((0..64).map(|bit| 1u64 << bit));

        for prefix in &prefixes {
            for &nonce in &nonces {
                assert_eq!(
                    decoded_candidate_hash_word(prefix, nonce),
                    reference_candidate_hash_word(prefix, nonce),
                    "prefix={prefix:02x?} nonce={nonce:#018x}"
                );
            }
        }

        let baseline_word = decoded_candidate_hash_word(&baseline, 0x0000_0001_000f_ffff);
        for byte in 0..32 {
            assert_ne!(
                decoded_candidate_hash_word(&prefixes[3 + byte], 0x0000_0001_000f_ffff),
                baseline_word,
                "prefix byte {byte} must affect the candidate hash"
            );
        }
    }

    #[test]
    fn index_to_nonce_mapping_pins_the_simd_lattice() {
        // Identity below the first hi block.
        assert_eq!(pow_index_to_nonce(0), 0);
        assert_eq!(pow_index_to_nonce(1), 1);
        assert_eq!(pow_index_to_nonce((1 << 20) - 1), (1 << 20) - 1);
        // Crossing a low-block boundary increments hi and resets low.
        assert_eq!(pow_index_to_nonce(1 << 20), 1 << 32);
        assert_eq!(pow_index_to_nonce((1 << 20) + 1), (1 << 32) | 1);

        // Equivalence with the lattice documented in grind_blake2s.cu and
        // implemented by the SIMD grind: index (hi << 20) | low covers
        // exactly the nonce (hi << 32) | low, 0 <= low < 2^20.
        for hi in [0u64, 1, 2, 41, (1 << 31) - 2] {
            for low in [0u64, 1, 0x12345, (1 << 20) - 1] {
                assert_eq!(pow_index_to_nonce((hi << 20) | low), (hi << 32) | low);
            }
        }

        // Strict monotonicity across block boundaries: numeric order on
        // mapped nonces equals index order, which is the SIMD scan order.
        let samples = [
            0u64,
            1,
            (1 << 20) - 1,
            1 << 20,
            (1 << 20) + 1,
            (5 << 20) + 7,
            u64::from(u32::MAX),
        ];
        for pair in samples.windows(2) {
            assert!(pow_index_to_nonce(pair[0]) < pow_index_to_nonce(pair[1]));
        }
    }

    #[test]
    fn mapped_strided_minimum_matches_simd_grind() {
        let mut channel = Blake2sChannelGeneric::<false>::default();
        channel.mix_u32s(&[42, 77, 99]);
        let expected = SimdBackend::grind(&channel, 10);
        // Invert the monotone map to bound the walk at the known answer.
        let expected_index =
            ((expected >> 32) << POW_GRIND_LOW_BITS) | (expected & ((1 << POW_GRIND_LOW_BITS) - 1));
        assert_eq!(pow_index_to_nonce(expected_index), expected);
        let workers = 37u64;
        let strided = (0..workers)
            .filter_map(|worker| {
                (worker..=expected_index)
                    .step_by(workers as usize)
                    .map(pow_index_to_nonce)
                    .find(|&nonce| reference_valid_pow(&channel, 10, nonce))
            })
            .min()
            .unwrap();
        assert_eq!(strided, expected);
    }

    #[test]
    fn varied_salts_pin_exact_lowest_nonce_and_attempt_count() {
        let cases: &[(&[u32], u64, u64)] = &[
            (&[], 0x154f, 5_456),
            (&[0], 0x01c8, 457),
            (&[1], 0x0726, 1_831),
            (&[42, 77, 99], 0x19fc, 6_653),
            (&[0x1122_3344, 0xaabb_ccdd, 9], 0x0c7f, 3_200),
            (&[u32::MAX, 0, 0xdead_beef], 0x0197, 408),
        ];
        for &(salt, expected_nonce, expected_attempts) in cases {
            let mut channel = Blake2sChannelGeneric::<false>::default();
            if !salt.is_empty() {
                channel.mix_u32s(salt);
            }
            assert_eq!(SimdBackend::grind(&channel, 12), expected_nonce);
            let expected_index = ((expected_nonce >> 32) << POW_GRIND_LOW_BITS)
                | (expected_nonce & ((1 << POW_GRIND_LOW_BITS) - 1));
            assert_eq!(expected_index + 1, expected_attempts);
            assert!((0..expected_index)
                .map(pow_index_to_nonce)
                .all(|nonce| !reference_valid_pow(&channel, 12, nonce)));
            assert!(reference_valid_pow(&channel, 12, expected_nonce));
        }
    }

    #[test]
    fn lattice_enumeration_skips_dense_nonces_outside_the_simd_search_space() {
        // Synthetic qualifying set reproducing the divergence scenario: the
        // dense-u64 minimum 0x30_0000 has low-32 bits >= 2^20, so the SIMD
        // grind NEVER tests it; the reference answer is the lattice point.
        let lattice_hit = (3u64 << 32) | 7;
        let dense_only_hit = 0x30_0000u64;
        let qualifies = |nonce: u64| nonce == dense_only_hit || nonce == lattice_hit;
        assert!(dense_only_hit < lattice_hit, "dense minimum must differ");

        // SIMD scan-order reference (hi ascending, low ascending) == index
        // order under the monotone map.
        let simd_answer = (0u64..)
            .map(pow_index_to_nonce)
            .find(|&nonce| qualifies(nonce))
            .unwrap();
        assert_eq!(simd_answer, lattice_hit);

        // Kernel model: workers stride the index space, atomicMin over MAPPED
        // nonces. Each worker's minimum is its first hit (map is monotone per
        // residue class); the global minimum is the SIMD answer, and the
        // dense-only nonce is never enumerated.
        let workers = 5u64;
        let limit = (3u64 << POW_GRIND_LOW_BITS) + 8;
        let strided = (0..workers)
            .filter_map(|worker| {
                (worker..limit)
                    .step_by(workers as usize)
                    .map(pow_index_to_nonce)
                    .inspect(|&nonce| assert_ne!(nonce, dense_only_hit))
                    .find(|&nonce| qualifies(nonce))
            })
            .min()
            .unwrap();
        assert_eq!(strided, simd_answer);
    }

    #[test]
    fn pow_bits_above_supported_reference_range_fail_closed() {
        assert_eq!(
            validate_pow_bits(33),
            Err(PreparedBlake2sPowError::InvalidPowBits(33))
        );
        assert_eq!(validate_pow_bits(32), Ok(()));
        assert_eq!(validate_pow_bits(26), Ok(()));
    }

    #[test]
    fn fleet_rank_tiles_cover_non_aligned_attempt_exactly_once() {
        let rank_count = 4;
        let grid_blocks = 1;
        let start = 17;
        let end = 3_019;
        let workers_per_rank = u64::from(grid_blocks) * u64::from(POW_THREADS_PER_BLOCK);
        let stride = workers_per_rank * u64::from(rank_count);
        let mut visits = vec![0u8; usize::try_from(end - start).unwrap()];
        let attempt = Blake2sPowFleetAttempt::new(rank_count, start, end, grid_blocks).unwrap();

        for rank in 0..rank_count {
            let tile = attempt.rank_tile(rank).unwrap();
            assert_eq!(tile.rank_count(), rank_count);
            assert_eq!(tile.rank(), rank);
            assert_eq!(tile.start_index(), start);
            assert_eq!(tile.end_index(), end);
            assert_eq!(tile.grid_blocks(), grid_blocks);
            for local_worker in 0..workers_per_rank {
                let residue = u64::from(rank) * workers_per_rank + local_worker;
                let tile_residue = start % stride;
                let delta = if residue >= tile_residue {
                    residue - tile_residue
                } else {
                    stride - (tile_residue - residue)
                };
                let mut index = start + delta;
                while index < end {
                    visits[usize::try_from(index - start).unwrap()] += 1;
                    index += stride;
                }
            }
        }
        assert!(visits.iter().all(|&count| count == 1));
    }

    #[test]
    fn invalid_fleet_rank_tiles_fail_closed() {
        for geometry in [
            (0, 0, 1, 1),
            (2, 1, 1, 1),
            (2, 2, 1, 1),
            (2, 0, POW_INDEX_LIMIT + 1, 1),
            (2, 0, 1, 0),
        ] {
            assert_eq!(
                Blake2sPowFleetAttempt::new(geometry.0, geometry.1, geometry.2, geometry.3),
                Err(PreparedBlake2sPowError::InvalidRankTile)
            );
        }
        let attempt = Blake2sPowFleetAttempt::new(2, 0, 1, 1).unwrap();
        assert_eq!(
            attempt.rank_tile(2),
            Err(PreparedBlake2sPowError::InvalidRankTile)
        );
    }

    #[test]
    fn extreme_valid_geometry_cannot_wrap_into_another_rank() {
        let attempt =
            Blake2sPowFleetAttempt::new(u32::MAX, 17, POW_INDEX_LIMIT, 8_388_609).unwrap();
        let tile = attempt.rank_tile(u32::MAX - 1).unwrap();
        let workers_per_rank = u64::from(tile.grid_blocks()) * u64::from(POW_THREADS_PER_BLOCK);
        let stride = workers_per_rank * u64::from(tile.rank_count());
        let residue = u64::from(tile.rank()) * workers_per_rank;
        let tile_residue = tile.start_index() % stride;
        let delta = if residue >= tile_residue {
            residue - tile_residue
        } else {
            stride - (tile_residue - residue)
        };
        assert!(delta >= tile.end_index() - tile.start_index());
    }

    #[test]
    fn compiled_pow_variant_contract_is_pinned() {
        assert_eq!(POW_PRIMARY_ROUND_UNROLL, 2);
        assert_eq!(POW_FALLBACK_ROUND_UNROLL, 5);
        assert_eq!(POW_MIN_BLOCKS_PER_SM, 6);

        let source = include_str!("../../../backend-cuda-kernels/cuda/resident_pow.cu");
        assert!(source.contains("constexpr int POW_PRIMARY_ROUND_UNROLL = 2;"));
        assert!(source.contains("constexpr int POW_FALLBACK_ROUND_UNROLL = 5;"));
        assert!(source.contains("__launch_bounds__(POW_BLOCK_SIZE, POW_MIN_BLOCKS_PER_SM)"));
        assert_eq!(source.matches("pow_prefix_digest<<<").count(), 2);
        assert_eq!(source.matches("persistent_pow_search<").count(), 2);
        assert_eq!(
            source.matches("persistent_pow_rank_tile_search<").count(),
            2
        );
        assert!(source.contains("residue >= tile_residue"));
        assert!(source.contains("stride - (tile_residue - residue)"));
        assert!(source.contains("delta < tile_length ? tile_start + delta : tile_end"));
        assert!(source.contains("stride >= tile_end - index"));
        assert_eq!(source.matches("stwo_blake2s_hash2_device(").count(), 1);
        assert!(source.contains("pow_message_word("));
        assert!(source.contains("fixed_candidate_hash_word(prefix, candidate)"));
        assert!(!source.contains("uint32_t m[16]"));

        let fixed_schedule = source
            .split("fixed_candidate_hash_word")
            .nth(1)
            .expect("fixed candidate definition")
            .split("template <int ROUND_UNROLL>")
            .next()
            .expect("fixed candidate body")
            .split("POW_FIXED_ROUND(")
            .skip(1)
            .map(|tail| {
                tail.split(')')
                    .next()
                    .expect("fixed round arguments")
                    .split(',')
                    .map(|word| word.trim().parse::<usize>().expect("numeric word index"))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        assert_eq!(fixed_schedule.len(), TEST_POW_SIGMA.len());
        for (actual, expected) in fixed_schedule.iter().zip(TEST_POW_SIGMA) {
            assert_eq!(actual, &expected);
        }
    }
}
