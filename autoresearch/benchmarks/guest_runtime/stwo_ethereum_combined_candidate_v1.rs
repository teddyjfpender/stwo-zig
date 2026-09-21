//! Source-closure entrypoint for the final nonproduction Ethereum candidate.
//!
//! The candidate guest must enable `bulk-memcpy-candidate`, route memcpy call
//! sites through `bulk_memcpy::copy_candidate`, and construct its EVM through
//! `CandidateEvmFactory`. Merely compiling this module changes neither route.

#[path = "stwo_bulk_memcpy_candidate_v1.rs"]
pub mod bulk_memcpy;
#[path = "stwo_revm_stack_swap_candidate_v1.rs"]
pub mod stack_swap;

pub const PRODUCTION_ACTIVATION: bool = false;
pub const REQUIRED_CARGO_FEATURE: &str = bulk_memcpy::CARGO_FEATURE;
pub const BULK_MEMCPY_FIXED_WORD: u32 = bulk_memcpy::FIXED_INSTRUCTION_WORD;
pub const BULK_MEMCPY_PROOF_OPCODE_ID: u32 = bulk_memcpy::PROOF_OPCODE_ID;
pub const STACK_SWAP_FIXED_WORD: u32 = 0x0ab5_000b;
pub const STACK_SWAP_PROOF_OPCODE_ID: u32 = 49;

pub type CandidateEvmFactory = stack_swap::StwoStackSwapEvmFactory<STACK_SWAP_FIXED_WORD>;

/// Exact opt-in memcpy route used by the final candidate guest.
///
/// # Safety
///
/// The caller must satisfy ordinary `copy_nonoverlapping` requirements. The
/// bulk wrapper additionally checks the proof-backed aligned/disjoint contract
/// and falls back to software for every unsupported call.
#[inline]
pub unsafe fn copy_candidate(destination: *mut u8, source: *const u8, length: usize) -> *mut u8 {
    unsafe { bulk_memcpy::copy_candidate(destination, source, length) }
}

const _: () = assert!(!PRODUCTION_ACTIVATION);
const _: () = assert!(BULK_MEMCPY_FIXED_WORD == 0x08c5_850b);
const _: () = assert!(BULK_MEMCPY_PROOF_OPCODE_ID == 48);
const _: () = assert!(STACK_SWAP_FIXED_WORD == 0x0ab5_000b);
const _: () = assert!(STACK_SWAP_PROOF_OPCODE_ID == 49);
