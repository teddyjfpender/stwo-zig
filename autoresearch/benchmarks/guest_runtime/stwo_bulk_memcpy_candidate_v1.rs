//! Guest-side transport candidate for `stwo.bulk_memcpy.word.v1`.
//!
//! This is deliberately not a global `memcpy` override. Callers may select the
//! custom instruction only when the measured fast-path contract holds; all
//! other calls retain Rust's ordinary `copy_nonoverlapping` implementation.
//! Production activation stays false until the caller and memory-interaction
//! STARK components freshly verify.

#[cfg(all(feature = "bulk-memcpy-candidate", target_arch = "riscv32"))]
use core::arch::asm;

pub const PRODUCTION_ACTIVATION: bool = false;
pub const CARGO_FEATURE: &str = "bulk-memcpy-candidate";
pub const CUSTOM_0_MAJOR_OPCODE: u32 = 0x0b;
pub const FUNCT7: u32 = 4;
pub const PROOF_OPCODE_ID: u32 = 48;
pub const FIXED_INSTRUCTION_WORD: u32 = 0x08c5_850b;
pub const MINIMUM_ADMITTED_LENGTH: usize = 32;
pub const DATA_ADDRESS_LIMIT: usize = 1 << 30;

#[inline(always)]
fn disjoint(destination: usize, source: usize, length: usize) -> bool {
    let Some(destination_end) = destination.checked_add(length) else {
        return false;
    };
    let Some(source_end) = source.checked_add(length) else {
        return false;
    };
    destination_end <= DATA_ADDRESS_LIMIT
        && source_end <= DATA_ADDRESS_LIMIT
        && (source_end <= destination || destination_end <= source)
}

#[inline(always)]
fn aligned_words_disjoint(destination: usize, source: usize, length: usize) -> bool {
    let start_offset = destination & 3;
    let Some(word_count) = length
        .checked_add(start_offset)
        .and_then(|value| value.checked_add(3))
        .map(|value| value / 4)
    else {
        return false;
    };
    let source_first = source / 4;
    let destination_first = destination / 4;
    let Some(source_end) = source_first.checked_add(word_count) else {
        return false;
    };
    let Some(destination_end) = destination_first.checked_add(word_count) else {
        return false;
    };
    source_end <= destination_first || destination_end <= source_first
}

#[inline(always)]
fn admitted(destination: *mut u8, source: *const u8, length: usize) -> bool {
    length >= MINIMUM_ADMITTED_LENGTH
        && ((destination as usize) ^ (source as usize)) & 3 == 0
        && disjoint(destination as usize, source as usize, length)
        && aligned_words_disjoint(destination as usize, source as usize, length)
}

/// Copy `length` non-overlapping bytes and return `destination` like C memcpy.
///
/// # Safety
///
/// The source and destination spans must be valid for `length` bytes. They
/// must not overlap, matching `copy_nonoverlapping`/`memcpy` semantics.
#[inline]
pub unsafe fn copy_candidate(destination: *mut u8, source: *const u8, length: usize) -> *mut u8 {
    #[cfg(all(feature = "bulk-memcpy-candidate", target_arch = "riscv32"))]
    if !PRODUCTION_ACTIVATION && admitted(destination, source, length) {
        unsafe {
            asm!(
                ".word 0x08c5850b",
                in("a0") destination,
                in("a1") source,
                in("a2") length,
                options(nostack),
            );
        }
        return destination;
    }

    // This exact path is retained when the Cargo feature is absent, on host
    // builds, and for every call outside the proof-backed admission contract.
    unsafe { core::ptr::copy_nonoverlapping(source, destination, length) };
    destination
}

const _: () = assert!(!PRODUCTION_ACTIVATION);
const _: () = assert!(FUNCT7 == 4);
const _: () = assert!(PROOF_OPCODE_ID == 48);
const _: () = assert!(FIXED_INSTRUCTION_WORD >> 25 == FUNCT7);
const _: () = assert!(FIXED_INSTRUCTION_WORD & 0x7f == CUSTOM_0_MAJOR_OPCODE);
