//! RV32 word-granular Keccak-256 sponge wrapper over the already-authenticated
//! `stwo.keccakf.1600.v1` permutation.
//!
//! This changes no proof relation and introduces no new host oracle.  Aligned
//! inputs are absorbed four bytes per RV32 load; unaligned inputs retain the
//! exact byte path.  Keccak padding, permutation ordering, and the 32-byte
//! squeeze are byte-for-byte identical to the baseline guest wrapper.

use core::ptr;

const RATE_BYTES: usize = 136;
const RATE_WORDS: usize = RATE_BYTES / 4;

#[inline(always)]
unsafe fn xor_word(state: *mut u32, input: *const u32, index: usize) {
    let left = unsafe { ptr::read(state.add(index)) };
    let right = unsafe { ptr::read(input.add(index)) };
    unsafe { ptr::write(state.add(index), left ^ right) };
}

#[inline(always)]
unsafe fn xor_words(state: *mut u32, input: *const u32, count: usize) {
    let mut index = 0usize;
    while index + 4 <= count {
        unsafe {
            xor_word(state, input, index);
            xor_word(state, input, index + 1);
            xor_word(state, input, index + 2);
            xor_word(state, input, index + 3);
        }
        index += 4;
    }
    while index < count {
        unsafe { xor_word(state, input, index) };
        index += 1;
    }
}

/// Hash `len` bytes and write the canonical 32-byte Keccak-256 digest.
///
/// # Safety
///
/// `input` must be readable for `len` bytes and `output` writable for 32
/// bytes. The caller retains the baseline null checks.
#[inline]
pub unsafe fn hash(input: *const u8, len: usize, output: *mut u8) {
    let mut state = [0u64; 25];
    let state_bytes = state.as_mut_ptr().cast::<u8>();
    let state_words = state.as_mut_ptr().cast::<u32>();
    let aligned_input = (input as usize) & 3 == 0;
    let mut consumed = 0usize;

    if aligned_input {
        while len - consumed >= RATE_BYTES {
            unsafe {
                xor_words(state_words, input.add(consumed).cast::<u32>(), RATE_WORDS);
                super::stwo_keccakf(state.as_mut_ptr());
            }
            consumed += RATE_BYTES;
        }
    } else {
        while len - consumed >= RATE_BYTES {
            let mut index = 0usize;
            while index < RATE_BYTES {
                unsafe {
                    *state_bytes.add(index) ^= *input.add(consumed + index);
                }
                index += 1;
            }
            unsafe { super::stwo_keccakf(state.as_mut_ptr()) };
            consumed += RATE_BYTES;
        }
    }

    const WORD_BYTES: usize = core::mem::size_of::<u32>();
    let tail_start = consumed;
    if aligned_input {
        let tail_words = (len - tail_start) / WORD_BYTES;
        unsafe {
            xor_words(state_words, input.add(tail_start).cast::<u32>(), tail_words);
        }
        consumed += tail_words * WORD_BYTES;
    }
    while consumed < len {
        unsafe {
            *state_bytes.add(consumed - tail_start) ^= *input.add(consumed);
        }
        consumed += 1;
    }
    let tail_len = len - tail_start;
    unsafe {
        // Keccak-256 domain separation and multi-rate padding: 0x01 ... 0x80.
        *state_bytes.add(tail_len) ^= 0x01;
        *state_bytes.add(RATE_BYTES - 1) ^= 0x80;
        super::stwo_keccakf(state.as_mut_ptr());
        ptr::copy_nonoverlapping(state_bytes, output, 32);
    }
}
