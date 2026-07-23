//! Raw FFI declarations for the staged CUDA kernel entry points.
//!
//! Link-gated: with `stwo_cuda_link` (set by the build script when nvcc compiled the
//! kernels) these resolve to the static archive; otherwise `stubs.rs` provides
//! panicking `no_mangle` definitions so the crate links everywhere.

use core::ffi::c_void;

/// Attributes reported by CUDA for a function loaded on the current device.
/// Keep in sync with `StwoCudaFunctionAttributes` in
/// `cuda/resource_attestation.cuh`.
#[repr(C, align(8))]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct CudaFunctionAttributes {
    pub abi_version: u32,
    pub max_threads_per_block: u32,
    pub registers_per_thread: u32,
    pub binary_version: u32,
    pub ptx_version: u32,
    pub reserved: u32,
    pub local_bytes: u64,
    pub static_shared_bytes: u64,
}

const _: () = assert!(core::mem::size_of::<CudaFunctionAttributes>() == 40);
const _: () = assert!(core::mem::align_of::<CudaFunctionAttributes>() == 8);
const _: () = assert!(core::mem::offset_of!(CudaFunctionAttributes, local_bytes) == 24);
const _: () = assert!(core::mem::offset_of!(CudaFunctionAttributes, static_shared_bytes) == 32);

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct CudaSecureField {
    pub a: u32,
    pub b: u32,
    pub c: u32,
    pub d: u32,
}

impl CudaSecureField {
    pub fn zero() -> Self {
        Self {
            a: 0,
            b: 0,
            c: 0,
            d: 0,
        }
    }
}

pub const STWO_QUOTIENT_NATIVE_RUN_MAX_RUNS: usize = 24;

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct CudaQuotientNativeRunEntry {
    pub term_begin: u32,
    pub term_end: u32,
    pub source_log_size: u32,
    pub scratch_offset_words: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct CudaQuotientNativeRunManifest {
    pub run_count: u32,
    pub direct_term_begin: u32,
    pub direct_term_end: u32,
    pub target_log_size: u32,
    pub runs: [CudaQuotientNativeRunEntry; STWO_QUOTIENT_NATIVE_RUN_MAX_RUNS],
}

const _: () = assert!(core::mem::size_of::<CudaQuotientNativeRunEntry>() == 16);
const _: () = assert!(core::mem::align_of::<CudaQuotientNativeRunEntry>() == 4);
const _: () = assert!(core::mem::size_of::<CudaQuotientNativeRunManifest>() == 400);
const _: () = assert!(core::mem::align_of::<CudaQuotientNativeRunManifest>() == 4);
const _: () = assert!(core::mem::offset_of!(CudaQuotientNativeRunManifest, runs) == 16);

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct CirclePointBaseField {
    pub x: u32,
    pub y: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct LayerIndexPair {
    pub layer_idx: u32,
    pub hash_idx: u32,
}

#[repr(C, align(32))]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Blake2sHash(pub [u8; 32]);

/// Exact device ABI for a clonable domain-progressive Blake2s leaf state.
/// Counter and pending length are launch-global canonical-prefix scalars.
/// Keep in sync with `ProgressiveBlake2sState` in `cuda/blake2s.cuh`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ProgressiveBlake2sState {
    pub h: [u32; 8],
    pub pending: [u32; 16],
}

const _: () = assert!(core::mem::size_of::<ProgressiveBlake2sState>() == 96);
const _: () = assert!(core::mem::offset_of!(ProgressiveBlake2sState, pending) == 32);

/// Host-owned recipe for reconstructing the lazy final Blake2s block from
/// retained device columns. Keep in sync with `CompactBlake2sTailDescriptor`
/// in `cuda/blake2s.cuh`.
#[repr(C, align(8))]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct CompactBlake2sTailDescriptor {
    pub column_addresses: [u64; 16],
    pub log_ratios: [u32; 16],
}

const _: () = assert!(core::mem::size_of::<CompactBlake2sTailDescriptor>() == 192);
const _: () = assert!(core::mem::align_of::<CompactBlake2sTailDescriptor>() == 8);
const _: () = assert!(core::mem::offset_of!(CompactBlake2sTailDescriptor, column_addresses) == 0);
const _: () = assert!(core::mem::offset_of!(CompactBlake2sTailDescriptor, log_ratios) == 128);

/// Largest canonical word prefix whose byte counter fits the low 32-bit
/// counter implemented by the four-lane compressor.
pub const BLAKE2S_PROGRESSIVE_QUAD_MAX_COUNTER_COLUMNS: u32 = 0x3fff_ffff;

/// Address-free half of the native ABI admission. Pointer and stream checks
/// remain in the C wrapper; keeping the counter predicate here makes boundary
/// behavior executable in no-CUDA builds and available to prepared binders.
pub const fn blake2s_progressive_absorb_quad_counts_valid(
    number_of_columns: u32,
    absorbed_columns_before: u32,
    initializes_state: bool,
) -> bool {
    number_of_columns != 0
        && (!initializes_state || absorbed_columns_before == 0)
        && number_of_columns <= BLAKE2S_PROGRESSIVE_QUAD_MAX_COUNTER_COLUMNS
        && absorbed_columns_before
            <= BLAKE2S_PROGRESSIVE_QUAD_MAX_COUNTER_COLUMNS - number_of_columns
}

/// Number of words retained lazily after a canonical prefix. A complete
/// 16-word block stays lazy until more input arrives or the hash is finalized.
pub const fn blake2s_compact_tail_words(absorbed_columns: u32) -> u32 {
    if absorbed_columns == 0 {
        0
    } else {
        (absorbed_columns - 1) % 16 + 1
    }
}

/// Address-free compact absorb admission. Initialization is exact: only an
/// empty prefix initializes, and an empty prefix must initialize.
pub const fn blake2s_compact_absorb_counts_valid(
    number_of_columns: u32,
    absorbed_columns_before: u32,
    initializes_state: bool,
) -> bool {
    number_of_columns != 0
        && initializes_state == (absorbed_columns_before == 0)
        && number_of_columns <= BLAKE2S_PROGRESSIVE_QUAD_MAX_COUNTER_COLUMNS
        && absorbed_columns_before
            <= BLAKE2S_PROGRESSIVE_QUAD_MAX_COUNTER_COLUMNS - number_of_columns
}

/// Fail-closed descriptor admission mirrored by the native wrapper. Unused
/// entries must be canonical zeroes so captured launch parameters are stable.
pub const fn blake2s_compact_tail_descriptor_valid(
    descriptor: &CompactBlake2sTailDescriptor,
    target_log_size: u32,
    absorbed_columns: u32,
) -> bool {
    if target_log_size >= 31 || absorbed_columns > BLAKE2S_PROGRESSIVE_QUAD_MAX_COUNTER_COLUMNS {
        return false;
    }
    let pending_words = blake2s_compact_tail_words(absorbed_columns) as usize;
    let mut word = 0;
    while word < 16 {
        let address = descriptor.column_addresses[word];
        let log_ratio = descriptor.log_ratios[word];
        if word < pending_words {
            if address == 0 || address & 3 != 0 || log_ratio > target_log_size {
                return false;
            }
        } else if address != 0 || log_ratio != 0 {
            return false;
        }
        word += 1;
    }
    true
}

#[cfg(test)]
mod progressive_blake2s_state_tests {
    use super::{
        blake2s_compact_absorb_counts_valid, blake2s_compact_tail_descriptor_valid,
        blake2s_compact_tail_words, blake2s_progressive_absorb_quad_counts_valid, Blake2sHash,
        CompactBlake2sTailDescriptor, ProgressiveBlake2sState,
        BLAKE2S_PROGRESSIVE_QUAD_MAX_COUNTER_COLUMNS,
    };

    #[test]
    fn compact_layout_preserves_legacy_hash_and_pending_words_little_endian() {
        assert!(cfg!(target_endian = "little"));
        let h = core::array::from_fn(|index| 0x1020_3040u32.wrapping_add(index as u32));
        let pending = core::array::from_fn(|index| 0x8090_a0b0u32.wrapping_add(index as u32));
        let state = ProgressiveBlake2sState { h, pending };

        let mut legacy = [0x5au8; 128];
        for (index, word) in h.into_iter().enumerate() {
            legacy[4 * index..4 * index + 4].copy_from_slice(&word.to_le_bytes());
        }
        for (index, word) in pending.into_iter().enumerate() {
            legacy[48 + 4 * index..52 + 4 * index].copy_from_slice(&word.to_le_bytes());
        }

        assert_eq!(core::mem::size_of_val(&state), 96);
        assert_eq!(core::mem::offset_of!(ProgressiveBlake2sState, pending), 32);
        for (index, word) in state.h.into_iter().enumerate() {
            assert_eq!(word.to_ne_bytes(), legacy[4 * index..4 * index + 4]);
        }
        for (index, word) in state.pending.into_iter().enumerate() {
            assert_eq!(word.to_ne_bytes(), legacy[48 + 4 * index..52 + 4 * index]);
        }
        assert_eq!(128 - core::mem::size_of_val(&state), 32);
    }

    #[test]
    fn progressive_quad_counter_admission_rejects_max_plus_one_and_sum_overflow() {
        let max = BLAKE2S_PROGRESSIVE_QUAD_MAX_COUNTER_COLUMNS;
        assert!(blake2s_progressive_absorb_quad_counts_valid(max, 0, true));
        assert!(blake2s_progressive_absorb_quad_counts_valid(
            1,
            max - 1,
            false
        ));
        assert!(!blake2s_progressive_absorb_quad_counts_valid(0, 0, true));
        assert!(!blake2s_progressive_absorb_quad_counts_valid(
            max + 1,
            0,
            true
        ));
        assert!(!blake2s_progressive_absorb_quad_counts_valid(1, max, false));
        assert!(!blake2s_progressive_absorb_quad_counts_valid(1, 1, true));

        type AbsorbQuadFn = unsafe extern "C" fn(
            u32,
            u32,
            u32,
            *const *mut u32,
            u32,
            *mut ProgressiveBlake2sState,
            *mut core::ffi::c_void,
        ) -> i32;
        let _: AbsorbQuadFn = super::stwo_blake2s_progressive_absorb_quad_on;

        let native = include_str!("../cuda/blake2s_quad.cu");
        assert!(native.contains("constexpr uint32_t kMaxQuadRows = 1u << 30;"));
        assert!(native.contains("size > kMaxQuadRows"));
        assert!(native.contains("number_of_columns > kMaxCounterColumns"));
    }

    #[test]
    fn compact_descriptor_layout_and_lazy_boundaries_are_exact() {
        assert_eq!(core::mem::size_of::<CompactBlake2sTailDescriptor>(), 192);
        assert_eq!(core::mem::align_of::<CompactBlake2sTailDescriptor>(), 8);
        assert_eq!(
            core::mem::offset_of!(CompactBlake2sTailDescriptor, column_addresses),
            0
        );
        assert_eq!(
            core::mem::offset_of!(CompactBlake2sTailDescriptor, log_ratios),
            128
        );
        assert_eq!(blake2s_compact_tail_words(0), 0);
        assert_eq!(blake2s_compact_tail_words(1), 1);
        assert_eq!(blake2s_compact_tail_words(15), 15);
        assert_eq!(blake2s_compact_tail_words(16), 16);
        assert_eq!(blake2s_compact_tail_words(17), 1);
        assert_eq!(blake2s_compact_tail_words(32), 16);

        let header = include_str!("../cuda/blake2s.cuh");
        assert!(header.contains("sizeof(CompactBlake2sTailDescriptor) == 192"));
        assert!(header.contains("alignof(CompactBlake2sTailDescriptor) == 8"));
        assert!(header.contains("offsetof(CompactBlake2sTailDescriptor, log_ratios) == 128"));
    }

    #[test]
    fn compact_admission_is_canonical_and_fail_closed() {
        let max = BLAKE2S_PROGRESSIVE_QUAD_MAX_COUNTER_COLUMNS;
        assert!(blake2s_compact_absorb_counts_valid(1, 0, true));
        assert!(blake2s_compact_absorb_counts_valid(1, max - 1, false));
        assert!(!blake2s_compact_absorb_counts_valid(1, 0, false));
        assert!(!blake2s_compact_absorb_counts_valid(1, 1, true));
        assert!(!blake2s_compact_absorb_counts_valid(0, 0, true));
        assert!(!blake2s_compact_absorb_counts_valid(1, max, false));

        let empty = CompactBlake2sTailDescriptor::default();
        assert!(blake2s_compact_tail_descriptor_valid(&empty, 5, 0));

        let mut full = CompactBlake2sTailDescriptor::default();
        for word in 0..16 {
            full.column_addresses[word] = 4 * (word as u64 + 1);
            full.log_ratios[word] = word as u32 % 6;
        }
        assert!(blake2s_compact_tail_descriptor_valid(&full, 5, 16));

        let mut noncanonical = full;
        noncanonical.column_addresses[15] = 0;
        assert!(!blake2s_compact_tail_descriptor_valid(&noncanonical, 5, 16));
        let mut noncanonical = empty;
        noncanonical.log_ratios[1] = 1;
        assert!(!blake2s_compact_tail_descriptor_valid(&noncanonical, 5, 0));
        let mut misaligned = empty;
        misaligned.column_addresses[0] = 5;
        assert!(!blake2s_compact_tail_descriptor_valid(&misaligned, 5, 1));
        let mut excessive_lift = empty;
        excessive_lift.column_addresses[0] = 4;
        excessive_lift.log_ratios[0] = 6;
        assert!(!blake2s_compact_tail_descriptor_valid(
            &excessive_lift,
            5,
            1
        ));
        assert!(!blake2s_compact_tail_descriptor_valid(&empty, 31, 0));
    }

    #[test]
    fn compact_ffi_uses_the_pinned_descriptor_by_pointer_and_hash_state() {
        type AbsorbFn = unsafe extern "C" fn(
            u32,
            u32,
            u32,
            *const *mut u32,
            u32,
            *const CompactBlake2sTailDescriptor,
            *mut Blake2sHash,
            *mut core::ffi::c_void,
        ) -> i32;
        type ExpandFn = unsafe extern "C" fn(
            u32,
            u32,
            *mut Blake2sHash,
            *mut Blake2sHash,
            *mut core::ffi::c_void,
        ) -> i32;
        type ExpandAbsorbFn = unsafe extern "C" fn(
            u32,
            u32,
            u32,
            u32,
            *const *mut u32,
            *const CompactBlake2sTailDescriptor,
            *const Blake2sHash,
            *mut Blake2sHash,
            *mut core::ffi::c_void,
        ) -> i32;
        type FinalizeFn = unsafe extern "C" fn(
            u32,
            u32,
            *const CompactBlake2sTailDescriptor,
            *mut Blake2sHash,
            *mut core::ffi::c_void,
        ) -> i32;
        type TerminalPairFn = unsafe extern "C" fn(
            u32,
            u32,
            u32,
            *const *mut u32,
            u32,
            *const CompactBlake2sTailDescriptor,
            *mut u32,
            u32,
            *mut Blake2sHash,
            *mut core::ffi::c_void,
        ) -> i32;
        let _: AbsorbFn = super::stwo_blake2s_compact_absorb_quad_on;
        let _: ExpandAbsorbFn = super::stwo_blake2s_compact_expand_absorb_quad_on;
        let _: TerminalPairFn = super::stwo_blake2s_compact_absorb_n2b_terminal_pair_on;
        let _: ExpandFn = super::stwo_blake2s_compact_expand_in_place_on;
        let _: FinalizeFn = super::stwo_blake2s_compact_finalize_quad_in_place_on;

        let native = include_str!("../cuda/blake2s_quad.cu");
        assert!(native.contains("const CompactBlake2sTailDescriptor descriptor = *tail;"));
        assert!(native.contains("CompactBlake2sTailDescriptor tail,"));
        assert!(native.contains("void compact_leaf_expand_absorb_quad("));
        assert!(native.contains("2u * (expansion * source_pair + child) + parity"));
        assert!(native.contains("__syncwarp(pair_mask);"));
        assert!(native.contains("prefinal_columns[consumed + local][row]"));
        assert!(native.contains("stwo_n2b_final_pair("));
        let terminal = include_str!("../cuda/n2b_terminal.cuh");
        assert!(terminal.contains("const m31 left = prefinal[2 * pair]"));
        assert!(terminal.contains("const m31 right = prefinal[2 * pair + 1]"));
        let expansion = include_str!("../cuda/progressive_commit_in_place.cu");
        assert!(expansion.contains("2 * sizeof(Blake2sHash)"));
    }
}

/// Process-local provenance counters for generated CUDA kernels. Strict
/// GPU-native admission requires `aot_misses == runtime_loads ==
/// strict_rejections == 0`; cache hits retain their original provenance.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct CudaJitAotStats {
    pub aot_loads: u64,
    pub aot_cache_hits: u64,
    pub aot_misses: u64,
    pub runtime_loads: u64,
    pub runtime_cache_hits: u64,
    pub strict_rejections: u64,
}

pub const CUDA_PEDERSEN_PUBLICATION_ABI_VERSION: u32 = 2;
pub const CUDA_PEDERSEN_GLOBALS_ABSENT: u32 = 0;
pub const CUDA_PEDERSEN_GLOBALS_PRESENT: u32 = 1;
pub const CUDA_PEDERSEN_PUBLICATION_AOT: u32 = 1 << 0;
pub const CUDA_PEDERSEN_PUBLICATION_READBACK_VERIFIED: u32 = 1 << 1;
pub const CUDA_PEDERSEN_PUBLICATION_EVENT_COMPLETE: u32 = 1 << 2;
pub const CUDA_PEDERSEN_PUBLICATION_REQUIRED_FLAGS: u32 = CUDA_PEDERSEN_PUBLICATION_AOT
    | CUDA_PEDERSEN_PUBLICATION_READBACK_VERIFIED
    | CUDA_PEDERSEN_PUBLICATION_EVENT_COMPLETE;

/// Live process-local receipt for one loaded AOT module's Pedersen globals.
///
/// Tokens and pointers are deliberately not semantic identities. The safe
/// backend layer composes this with the registered table and AOT-pack authority.
#[repr(C, align(8))]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CudaPedersenModulePublication {
    pub abi_version: u32,
    pub flags: u32,
    pub device_ordinal: u32,
    pub sm_major: u32,
    pub sm_minor: u32,
    pub pointer_count: u32,
    pub columns_symbol_bytes: u32,
    pub rows_symbol_bytes: u32,
    pub n_rows: u32,
    pub globals_state: u32,
    pub cache_key: u64,
    pub module_token: u64,
    pub function_token: u64,
    pub context_token: u64,
    pub columns_symbol_token: u64,
    pub rows_symbol_token: u64,
    pub completion_event_token: u64,
    pub column_pointers: [u64; 56],
}

impl Default for CudaPedersenModulePublication {
    fn default() -> Self {
        Self {
            abi_version: 0,
            flags: 0,
            device_ordinal: 0,
            sm_major: 0,
            sm_minor: 0,
            pointer_count: 0,
            columns_symbol_bytes: 0,
            rows_symbol_bytes: 0,
            n_rows: 0,
            globals_state: 0,
            cache_key: 0,
            module_token: 0,
            function_token: 0,
            context_token: 0,
            columns_symbol_token: 0,
            rows_symbol_token: 0,
            completion_event_token: 0,
            column_pointers: [0; 56],
        }
    }
}

const _: () = assert!(core::mem::size_of::<CudaPedersenModulePublication>() == 544);
const _: () = assert!(core::mem::align_of::<CudaPedersenModulePublication>() == 8);
const _: () = assert!(core::mem::offset_of!(CudaPedersenModulePublication, cache_key) == 40);
const _: () = assert!(core::mem::offset_of!(CudaPedersenModulePublication, column_pointers) == 96);

pub const CUDA_AOT_FUNCTION_PUBLICATION_ABI_VERSION: u32 = 1;
pub const CUDA_AOT_FUNCTION_PUBLICATION_AOT: u32 = 1;

/// Read-only publication of the exact function the legacy JIT/AOT cache will
/// resolve for `(cache_key, current CUDA context, kernel_name)`.
#[repr(C, align(8))]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct CudaAotFunctionPublication {
    pub abi_version: u32,
    pub flags: u32,
    pub device_ordinal: u32,
    pub sm_major: u32,
    pub sm_minor: u32,
    pub reserved: u32,
    pub cache_key: u64,
    pub context_token: u64,
    pub module_token: u64,
    pub function_token: u64,
}

const _: () = assert!(core::mem::size_of::<CudaAotFunctionPublication>() == 56);
const _: () = assert!(core::mem::align_of::<CudaAotFunctionPublication>() == 8);
const _: () = assert!(core::mem::offset_of!(CudaAotFunctionPublication, cache_key) == 24);

pub const CUDA_INSTALLED_AOT_FUNCTION_ABI_VERSION: u32 = 2;
pub const CUDA_INSTALLED_AOT_BORROWED_PUBLISHED: u32 = 2;

/// Native receipt for one context-bound installed AOT function.
///
/// Address tokens are process-local equality facts, never semantic identities.
#[repr(C, align(8))]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct CudaInstalledAotFunctionReceipt {
    pub abi_version: u32,
    pub ownership: u32,
    pub device_ordinal: u32,
    pub sm_major: u32,
    pub sm_minor: u32,
    pub argument_count: u32,
    pub grid_x: u32,
    pub grid_y: u32,
    pub grid_z: u32,
    pub block_x: u32,
    pub block_y: u32,
    pub block_z: u32,
    pub dynamic_shared_bytes: u32,
    pub reserved: u32,
    pub context_token: u64,
    pub module_token: u64,
    pub function_token: u64,
    pub stream_token: u64,
    pub function: CudaFunctionAttributes,
}

const _: () = assert!(core::mem::size_of::<CudaInstalledAotFunctionReceipt>() == 128);
const _: () = assert!(core::mem::align_of::<CudaInstalledAotFunctionReceipt>() == 8);
const _: () = assert!(core::mem::offset_of!(CudaInstalledAotFunctionReceipt, context_token) == 56);
const _: () = assert!(core::mem::offset_of!(CudaInstalledAotFunctionReceipt, function) == 88);

#[cfg(test)]
mod pedersen_publication_abi_tests {
    use super::{
        CudaAotFunctionPublication, CudaInstalledAotFunctionReceipt, CudaPedersenModulePublication,
    };

    #[test]
    fn pedersen_columns_require_current_device_accessible_ranges() {
        let native = include_str!("../cuda/runtime_jit.cu");
        assert!(native.contains("static bool is_current_device_u32_allocation("));
        assert!(native.contains("attributes.type != cudaMemoryTypeDevice"));
        assert!(native.contains("attributes.device != static_cast<int>(device)"));
        assert!(
            native.contains("reinterpret_cast<CUdeviceptr>(attributes.devicePointer) != pointer")
        );
        assert!(native.contains("CU_POINTER_ATTRIBUTE_RANGE_START_ADDR"));
        assert!(native.contains("CU_POINTER_ATTRIBUTE_RANGE_SIZE"));
        assert!(native.contains("range_start == pointer && range_bytes >= required_bytes"));
        assert!(!native.contains("CU_POINTER_ATTRIBUTE_CONTEXT, pointer"));
    }

    #[test]
    fn publication_layout_and_native_contract_are_exact() {
        assert_eq!(core::mem::size_of::<CudaPedersenModulePublication>(), 544);
        assert_eq!(core::mem::align_of::<CudaPedersenModulePublication>(), 8);
        assert_eq!(
            core::mem::offset_of!(CudaPedersenModulePublication, cache_key),
            40
        );
        assert_eq!(
            core::mem::offset_of!(CudaPedersenModulePublication, column_pointers),
            96
        );
        type Query = unsafe extern "C" fn(
            *const core::ffi::c_char,
            u64,
            *mut CudaPedersenModulePublication,
        ) -> bool;
        let _: Query = super::stwo_cuda_jit_get_pedersen_module_publication;
        type FunctionQuery = unsafe extern "C" fn(
            *const core::ffi::c_char,
            u64,
            *mut CudaAotFunctionPublication,
        ) -> bool;
        let _: FunctionQuery = super::stwo_cuda_jit_get_aot_function_publication;
        assert_eq!(core::mem::size_of::<CudaAotFunctionPublication>(), 56);
        assert_eq!(
            core::mem::offset_of!(CudaAotFunctionPublication, cache_key),
            24
        );
        assert_eq!(core::mem::size_of::<CudaInstalledAotFunctionReceipt>(), 128);
        assert_eq!(
            core::mem::offset_of!(CudaInstalledAotFunctionReceipt, function),
            88
        );

        let native = include_str!("../cuda/runtime_jit.cu");
        assert!(native.contains("cols_size != kColumnsBytes"));
        assert!(native.contains("rows_size != kRowsBytes"));
        assert!(native.contains("cuMemcpyDtoH(readback_ptrs"));
        assert!(native.contains("memcmp(readback_ptrs, ptrs, sizeof(ptrs))"));
        assert!(native.contains("cuEventSynchronize(completion_event)"));
        assert!(native.contains("\"g_stwo_wit_pedersen_n_rows\") != CUDA_ERROR_NOT_FOUND"));
        assert!(native.contains("JitCacheKey{cache_key, context}"));
        assert!(native.contains("cached.origin != KernelOrigin::Aot"));
        assert!(native.contains("receipt.function_token !="));
        assert!(native.contains("cached.pedersen_publication.function_token !="));
        assert!(native.contains("get_live_aot_function_publication"));
        assert!(native.contains("cached.module != installed->module"));
        assert!(native.contains("cuStreamGetCtx"));
        assert!(native.contains("query_driver_function_attributes"));
        assert!(native.contains("cuFuncGetAttribute"));
        assert!(!native.contains("create_owned_installed_function"));
        assert!(native.contains("if (!is_borrowed_pedersen_table_registered())"));
        let table_runtime = include_str!("../cuda/pedersen_table_init.cu");
        assert!(table_runtime.contains(
            "!pedersen_table_mode_can_publish_witness_globals(\n    PEDERSEN_TABLE_MODE_OWNED_GENERATED_COLUMNS)"
        ));

        if !crate::CUDA_KERNELS_BUILT {
            let kernel = std::ffi::CString::new("witness").unwrap();
            let mut receipt = CudaPedersenModulePublication {
                abi_version: 99,
                ..CudaPedersenModulePublication::default()
            };
            assert!(!unsafe {
                super::stwo_cuda_jit_get_pedersen_module_publication(
                    kernel.as_ptr(),
                    7,
                    &mut receipt,
                )
            });
            assert_eq!(receipt, CudaPedersenModulePublication::default());
            let mut function = CudaAotFunctionPublication {
                abi_version: 99,
                ..CudaAotFunctionPublication::default()
            };
            assert!(!unsafe {
                super::stwo_cuda_jit_get_aot_function_publication(kernel.as_ptr(), 7, &mut function)
            });
            assert_eq!(function, CudaAotFunctionPublication::default());
        }
    }
}

/// Exact host/device ABI for one already-bound constraint part inside a
/// same-domain composition wave. Keep in sync with
/// `StwoCudaCompositionWavePart` emitted by `cuda_codegen.rs`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CudaCompositionWavePart {
    pub trace_cols: *const *const u32,
    pub interaction_offsets: *const u32,
    pub base_params: *const u32,
    pub ext_params: *const u32,
    pub denom_inv: *const u32,
    pub log_n_rows: u32,
    /// Proof-global start of this part's descending coefficient span.
    pub rc_base: u32,
}

const _: () = assert!(core::mem::size_of::<CudaCompositionWavePart>() == 48);
const _: () = assert!(core::mem::align_of::<CudaCompositionWavePart>() == 8);
const _: () = assert!(core::mem::offset_of!(CudaCompositionWavePart, trace_cols) == 0);
const _: () = assert!(core::mem::offset_of!(CudaCompositionWavePart, interaction_offsets) == 8);
const _: () = assert!(core::mem::offset_of!(CudaCompositionWavePart, base_params) == 16);
const _: () = assert!(core::mem::offset_of!(CudaCompositionWavePart, ext_params) == 24);
const _: () = assert!(core::mem::offset_of!(CudaCompositionWavePart, denom_inv) == 32);
const _: () = assert!(core::mem::offset_of!(CudaCompositionWavePart, log_n_rows) == 40);
const _: () = assert!(core::mem::offset_of!(CudaCompositionWavePart, rc_base) == 44);

#[cfg(test)]
mod composition_wave_abi_tests {
    use super::CudaCompositionWavePart;

    #[test]
    fn composition_wave_descriptor_and_launch_abi_are_exact() {
        assert_eq!(core::mem::size_of::<CudaCompositionWavePart>(), 48);
        assert_eq!(core::mem::align_of::<CudaCompositionWavePart>(), 8);
        assert_eq!(
            core::mem::offset_of!(CudaCompositionWavePart, trace_cols),
            0
        );
        assert_eq!(
            core::mem::offset_of!(CudaCompositionWavePart, interaction_offsets),
            8
        );
        assert_eq!(
            core::mem::offset_of!(CudaCompositionWavePart, base_params),
            16
        );
        assert_eq!(
            core::mem::offset_of!(CudaCompositionWavePart, ext_params),
            24
        );
        assert_eq!(
            core::mem::offset_of!(CudaCompositionWavePart, denom_inv),
            32
        );
        assert_eq!(
            core::mem::offset_of!(CudaCompositionWavePart, log_n_rows),
            40
        );
        assert_eq!(core::mem::offset_of!(CudaCompositionWavePart, rc_base), 44);

        type LaunchFn = unsafe extern "C" fn(
            *const core::ffi::c_char,
            *const core::ffi::c_char,
            u64,
            *const CudaCompositionWavePart,
            *const u32,
            *mut u32,
            *mut u32,
            *mut u32,
            *mut u32,
            u32,
            u32,
            u32,
            *mut core::ffi::c_void,
        ) -> bool;
        let _: LaunchFn = super::stwo_cuda_jit_eval_composition_wave_on;

        let native = include_str!("../cuda/runtime_jit.cu");
        assert!(native.contains("sizeof(StwoCudaCompositionWavePart) == 48"));
        assert!(native.contains("alignof(StwoCudaCompositionWavePart) == 8"));
        assert!(native.contains("uint32_t full_domain_rows"));
        assert!(native.contains("uint32_t shard_start"));
        assert!(native.contains("uint32_t shard_rows"));
        assert!(native.contains("shard_rows > full_domain_rows - shard_start"));
        assert!(native.contains(
            "(void *)&full_domain_rows,     (void *)&shard_start,\n        (void *)&shard_rows,"
        ));
        assert!(native.contains("ceil_div_nonzero_u32(shard_rows, block)"));
        assert!(!native.contains("composition_wave_on(\n    const char *source,\n    const char *kernel_name,\n    uint64_t cache_key,\n    uint32_t part_count"));
    }
}

#[cfg_attr(stwo_cuda_link, link(name = "stwo_cuda_kernels", kind = "static"))]
extern "C" {
    /// Returns the collision-resistant build identity carried by the linked
    /// ordinary static CUDA archive. This does not attest loaded SASS.
    pub fn stwo_static_cuda_module_build_identity(out: *mut u8) -> i32;

    /// Returns a CUDA error code (0 = success). Sets the default mem pool's release
    /// threshold to never-release so warm proves reuse allocations.
    pub fn cuda_mem_pool_init() -> i32;
    /// Default-pool-only checked allocation/copy/free. These validate the
    /// admitted current device and never use the legacy cudaMalloc fallback.
    pub fn cuda_default_pool_alloc_checked(
        byte_count: usize,
        output: *mut *mut core::ffi::c_void,
    ) -> i32;
    pub fn cuda_default_pool_copy_h2d_checked(
        host: *const core::ffi::c_void,
        device: *mut core::ffi::c_void,
        byte_count: usize,
    ) -> i32;
    pub fn cuda_default_pool_free_checked(device: *mut core::ffi::c_void) -> i32;
    pub fn cuda_default_pool_stream_sync_checked() -> i32;
    /// Checked current used/reserved bytes for the process-wide default pool.
    pub fn cuda_default_pool_current(used_current: *mut usize, reserved_current: *mut usize)
        -> i32;
    /// Fence stream 0, trim unused default-pool backing memory, and return its
    /// checked post-trim current used/reserved bytes.
    pub fn cuda_default_pool_trim(
        min_bytes_to_keep: usize,
        used_current: *mut usize,
        reserved_current: *mut usize,
    ) -> i32;
    /// Chunked atomicMin nonce search; returns the LOWEST valid nonce, matching the
    /// SIMD grind's search order byte-exactly (non-M31 Blake2s channel only).
    pub fn grind_blake2s(host_prefixed_digest: *const u32, pow_bits: u32) -> u64;
    /// GPU generation of preprocessed columns (values identical to the CPU
    /// constructors; commitment roots must be byte-equal).
    pub fn gen_seq_column_on_gpu(output: *mut u32, log_size: u32);
    pub fn gen_range_check_columns_on_gpu(
        output_columns: *const *mut u32,
        n_columns: u32,
        bits_per_segment: *const u32,
        n_segments: u32,
    );
    pub fn gen_bitwise_xor_columns_on_gpu(output_columns: *const *mut u32, n_bits: u32);
    /// Fail-closed resident preprocessed-column lane. Every function returns a
    /// CUDA status (zero is success). Allocation requires the admitted default
    /// pool and never falls back to an untracked `cudaMalloc`; the legacy void
    /// entry points above retain their abort-on-error contract.
    pub fn stwo_preprocessed_alloc_u32_checked(count: usize, output: *mut *mut u32) -> i32;
    pub fn stwo_preprocessed_copy_h2d_checked(
        host: *const u32,
        device: *mut u32,
        count: usize,
    ) -> i32;
    pub fn stwo_preprocessed_gen_seq_checked(output: *mut u32, log_size: u32) -> i32;
    pub fn stwo_preprocessed_gen_range_checked(
        output_columns: *const *mut u32,
        n_columns: u32,
        bits_per_segment: *const u32,
        n_segments: u32,
    ) -> i32;
    pub fn stwo_preprocessed_gen_xor_checked(output_columns: *const *mut u32, n_bits: u32) -> i32;
    pub fn stwo_preprocessed_stream_sync_checked() -> i32;
    /// JIT-compile (NVRTC; cached by the CONTENT semantic hash, never pointers) and
    /// launch a generated fused constraint kernel. `rc_base` is the kernel's first
    /// constraint's global index into `random_coeff_powers` (non-zero only for split
    /// kernels); `relax_opt` compiles with optimization disabled (nvrtc --dopt=off,
    /// ptxas -O0) for kernels too large to optimize in reasonable time. Returns false
    /// on any compile or launch failure; the caller falls back to the CPU lane.
    #[allow(clippy::too_many_arguments)]
    pub fn stwo_cuda_jit_eval_fused(
        source: *const core::ffi::c_char,
        kernel_name: *const core::ffi::c_char,
        semantic_hash: u64,
        trace_values: *const u32,
        interaction_offsets: *const u32,
        base_params: *const u32,
        ext_params: *const u32,
        random_coeff_powers: *const u32,
        denom_inv: *const u32,
        coord_0: *mut u32,
        coord_1: *mut u32,
        coord_2: *mut u32,
        coord_3: *mut u32,
        row_count: u32,
        log_n_rows: u32,
        rc_base: u32,
        relax_opt: bool,
    ) -> bool;
    /// Allocation-free explicit-stream form used by resident composition graphs.
    #[allow(clippy::too_many_arguments)]
    pub fn stwo_cuda_jit_eval_fused_on(
        source: *const core::ffi::c_char,
        kernel_name: *const core::ffi::c_char,
        semantic_hash: u64,
        trace_values: *const u32,
        interaction_offsets: *const u32,
        base_params: *const u32,
        ext_params: *const u32,
        random_coeff_powers: *const u32,
        denom_inv: *const u32,
        coord_0: *mut u32,
        coord_1: *mut u32,
        coord_2: *mut u32,
        coord_3: *mut u32,
        row_count: u32,
        log_n_rows: u32,
        rc_base: u32,
        relax_opt: bool,
        stream: *mut c_void,
    ) -> bool;
    /// Launch one precompiled same-domain composition wave over an exact row
    /// shard. The generated kernel fixes descriptor order in its source,
    /// retains `full_domain_rows` as the read stride, and writes `shard_rows`
    /// elements through each already-sliced coordinate pointer.
    #[allow(clippy::too_many_arguments)]
    pub fn stwo_cuda_jit_eval_composition_wave_on(
        source: *const core::ffi::c_char,
        kernel_name: *const core::ffi::c_char,
        cache_key: u64,
        parts: *const CudaCompositionWavePart,
        random_coeff_powers: *const u32,
        coord_0: *mut u32,
        coord_1: *mut u32,
        coord_2: *mut u32,
        coord_3: *mut u32,
        full_domain_rows: u32,
        shard_start: u32,
        shard_rows: u32,
        stream: *mut c_void,
    ) -> bool;
    /// Generate `[alpha^(count-1), ..., alpha, 1]` from a device-resident
    /// transcript parameter on the caller's stream.
    pub fn stwo_composition_generate_descending_powers_on(
        random_coefficient: *const CudaSecureField,
        powers: *mut CudaSecureField,
        count: u32,
        stream: *mut c_void,
    ) -> i32;
    /// Lift the smaller coordinate-major secure evaluation into the larger
    /// bit-reversed circle domain and add it in place, on `stream`.
    pub fn stwo_composition_lift_accumulate_on(
        previous_coordinates: *const u32,
        previous_log_size: u32,
        current_coordinates: *mut u32,
        current_log_size: u32,
        stream: *mut c_void,
    ) -> i32;
    /// Materialize statement-dependent extension parameters into stable
    /// per-component destinations. Source kinds are 0 = z, 1 = alpha power,
    /// and 2 = claimed sum; every result is multiplied by its M31 scale.
    /// `claimed_sums` may be null exactly when `claimed_sum_count` is zero.
    #[allow(clippy::too_many_arguments)]
    pub fn stwo_composition_materialize_ext_params_on(
        destinations: *const *mut CudaSecureField,
        source_kinds: *const u32,
        source_indices: *const u32,
        scales: *const u32,
        count: u32,
        z: *const CudaSecureField,
        alpha_powers: *const CudaSecureField,
        alpha_power_count: u32,
        claimed_sums: *const *const CudaSecureField,
        claimed_sum_count: u32,
        stream: *mut c_void,
    ) -> i32;
    /// Compile a generated kernel into the JIT cache WITHOUT launching it. Used to
    /// compile every kernel of a split component before the first launch, so a
    /// compile failure can still fall back to the CPU lane with an untouched
    /// accumulator. Returns false on compile failure.
    pub fn stwo_cuda_jit_precompile(
        source: *const core::ffi::c_char,
        kernel_name: *const core::ffi::c_char,
        semantic_hash: u64,
        relax_opt: bool,
    ) -> bool;
    /// Precompile a batch of kernels into the JIT cache without launching, compiling
    /// across a worker pool when `STWO_JIT_PARALLEL_COMPILE` is enabled (default; set to
    /// `0` to force sequential, or to a positive integer to cap workers). The arrays are
    /// parallel (length `count`): `sources[i]`/`kernel_names[i]` are NUL-terminated,
    /// `cache_keys[i]` is the content semantic hash, `relax_opts[i]` the optimization
    /// relief flag. Returns false if ANY kernel fails to compile (caller falls back to
    /// the CPU lane). The populated cache is identical to a sequential precompile.
    pub fn stwo_cuda_jit_precompile_batch(
        sources: *const *const core::ffi::c_char,
        kernel_names: *const *const core::ffi::c_char,
        cache_keys: *const u64,
        relax_opts: *const bool,
        count: u32,
    ) -> bool;
    /// Process-wide fail-closed policy for generated kernels. Set before any
    /// proof work; when true, an absent/unloadable embedded AOT entry is an
    /// error and NVRTC/disk-PTX paths are not entered.
    pub fn stwo_cuda_jit_set_require_aot(required: bool);
    pub fn stwo_cuda_jit_get_aot_stats(out: *mut CudaJitAotStats);
    /// Query the exact live `(cache_key, current CUDA context, kernel_name)`
    /// cache entry. Returns false for a miss, runtime-origin module, absent
    /// globals, failed readback, or incomplete publication event.
    pub fn stwo_cuda_jit_get_pedersen_module_publication(
        kernel_name: *const core::ffi::c_char,
        cache_key: u64,
        out: *mut CudaPedersenModulePublication,
    ) -> bool;
    pub fn stwo_cuda_jit_get_aot_function_publication(
        kernel_name: *const core::ffi::c_char,
        cache_key: u64,
        out: *mut CudaAotFunctionPublication,
    ) -> bool;
    #[allow(clippy::too_many_arguments)]
    pub fn stwo_installed_aot_function_borrow_published_create(
        exec_context: *mut c_void,
        kernel_name: *const core::ffi::c_char,
        cache_key: u64,
        expected_sm: u32,
        expected_module_token: u64,
        expected_function_token: u64,
        expected_context_token: u64,
        argument_count: u32,
        grid_x: u32,
        grid_y: u32,
        grid_z: u32,
        block_x: u32,
        block_y: u32,
        block_z: u32,
        dynamic_shared_bytes: u32,
        out_handle: *mut *mut c_void,
        out_receipt: *mut CudaInstalledAotFunctionReceipt,
    ) -> i32;
    pub fn stwo_installed_aot_function_launch(
        handle: *mut c_void,
        exec_context: *mut c_void,
        arguments: *mut *mut c_void,
        argument_count: u32,
    ) -> i32;
    pub fn stwo_installed_aot_function_destroy(handle: *mut c_void) -> i32;
    /// Reset counters only. Cached functions and their AOT/runtime provenance
    /// remain intact, so subsequent cache-hit accounting stays truthful.
    pub fn stwo_cuda_jit_reset_aot_stats();
    /// Per-component constraint-quotient kernel dispatch (NitrooZK lineage). The first
    /// 4 bytes behind `eval` are an FNV1a hash of the component name selecting the
    /// kernel; the rest is the raw `FrameworkEval` struct the kernel's generated code
    /// reads. Returns false when no kernel matches (caller falls back to CPU).
    #[allow(clippy::too_many_arguments)]
    pub fn copy_uint32_t_vec_from_device_to_host(
        device_ptr: *const u32,
        host_ptr: *const u32,
        size: u32,
    );

    pub fn copy_uint32_t_vec_from_host_to_device(host_ptr: *const u32, size: u32) -> *const u32;

    pub fn copy_uint32_t_vec_from_device_to_device(
        from: *const u32,
        dst: *const u32,
        size: u32,
    ) -> *const u32;

    pub fn copy_uint32_t_vec_from_device_to_device_offset(
        from: *const u32,
        dst: *const u32,
        size: u32,
        offset: u32,
    );

    pub fn cuda_zero_device_region(ptr: *const u32, offset_words: u64, n_words: u64);

    pub fn cuda_alloc_pinned_host_u32(n_words: u64) -> *mut u32;

    pub fn cuda_free_pinned_host_u32(ptr: *mut u32);

    pub fn copy_uint32_t_vec_from_host_to_device_into(
        host_ptr: *const u32,
        device_ptr: *const u32,
        n_words: u64,
    );

    pub fn copy_uint32_t_vec_from_host_to_device_into_async(
        host_ptr: *const u32,
        device_ptr: *const u32,
        n_words: u64,
    );

    pub fn stwo_legacy_stream_sync();

    pub fn cuda_gather_uint32_t(
        device_src: *const u32,
        host_indices: *const u32,
        n_indices: u32,
        host_out: *mut u32,
    );

    /// Allocation-free, explicit-stream multi-column gather. All descriptor
    /// arrays and the output are device-resident; returns a CUDA status.
    pub fn stwo_batch_gather_column_rows_launch(
        columns_device: *const *const u32,
        row_offsets_device: *const u32,
        row_indices_device: *const u32,
        n_columns: u32,
        total_rows: u32,
        output_device: *mut u32,
        stream: *mut c_void,
    ) -> i32;

    /// Host compatibility wrapper: uploads explicit descriptor arrays, performs
    /// one gather launch, and copies the flattened output D2H once.
    pub fn stwo_batch_gather_column_rows_host(
        columns_host: *const *const u32,
        column_lengths_host: *const u32,
        row_offsets_host: *const u32,
        row_indices_host: *const u32,
        n_columns: u32,
        total_rows: u32,
        output_host: *mut u32,
    ) -> i32;

    pub fn cuda_malloc_uint32_t(size: u32) -> *const u32;

    pub fn cuda_set_uint32_t(device_ptr: *const c_void, index: usize, val: u32);

    pub fn cuda_get_uint32_t(device_ptr: *const c_void, index: usize) -> u32;

    pub fn cuda_increase_at(device_ptr: *const c_void, addr: u32);

    pub fn cuda_get_secure_field(device_ptr: *const c_void, index: usize) -> CudaSecureField;

    pub fn cuda_malloc_blake_2s_hash(size: usize) -> *const Blake2sHash;

    pub fn cuda_alloc_zeroes_uint32_t(size: u32) -> *const u32;

    pub fn cuda_alloc_zeroes_blake_2s_hash(size: usize) -> *const Blake2sHash;

    pub fn cuda_free_memory(device_ptr: *const c_void);

    pub fn cuda_get_memory_info(free_mem: *mut usize, total_mem: *mut usize);
    pub fn cuda_pool_highwater(used_high: *mut usize, reserved_high: *mut usize);
    pub fn cuda_pool_highwater_reset();

    pub fn bit_reverse_base_field(array: *const u32, size: usize);

    pub fn bit_reverse_secure_field(array: *const u32, size: usize);

    pub fn batch_inverse_base_field(from: *const u32, dst: *const u32, size: usize);

    // pub fn batch_inverse_secure_field(from: *const u32, dst: *const u32, size: usize);

    pub fn sort_values_and_permute_with_bit_reverse_order(
        from: *const u32,
        size: usize,
    ) -> *const u32;

    pub fn precompute_twiddles(
        initial: CirclePointBaseField,
        step: CirclePointBaseField,
        total_size: usize,
    ) -> *const u32;

    pub fn evaluate_columns(
        eval_domain_sizes: *const u32,
        values: *const *const u32,
        twiddles_tree: *const u32,
        twiddle_tree_size: u32,
        number_of_columns: u32,
        column_sizes: *const u32,
    );

    pub fn eval_at_point(
        coeffs: *const u32,
        coeffs_size: u32,
        point_x: CudaSecureField,
        point_y: CudaSecureField,
    ) -> CudaSecureField;

    pub fn batch_eval_at_points(
        coeffs_ptrs: *const *const u32,
        coeffs_size: i32,
        num_polys: i32,
        point_x: CudaSecureField,
        point_y: CudaSecureField,
        results: *mut CudaSecureField,
    );

    pub fn barycentric_point_vanishings(
        half_coset_initial_index: u32,
        half_coset_step_size: u32,
        size: u32,
        log_size: u32,
        point_x: CudaSecureField,
        point_y: CudaSecureField,
        result: *const u32,
    );

    pub fn barycentric_weights_from_point_vanishings(
        point_vanishings: *const u32,
        size: u32,
        even_scale: CudaSecureField,
        odd_scale: CudaSecureField,
        result_weights: *const u32,
    );

    pub fn barycentric_eval_base_field(
        eval_values: *const u32,
        weights: *const u32,
        size: u32,
    ) -> CudaSecureField;

    pub fn barycentric_eval_base_field_many(
        columns_dev: *const *const u32,
        n_cols: u32,
        weights: *const u32,
        size: u32,
        out_host: *mut CudaSecureField,
    );

    pub fn fold_line(
        gpu_domain: *const u32,
        twiddle_offset: usize,
        n: usize,
        eval_values: *const *const u32,
        alpha: CudaSecureField,
        folded_values: *const *const u32,
    );

    pub fn fold_circle_into_line(
        gpu_domain: *const u32,
        twiddle_offset: usize,
        n: usize,
        eval_values: *const *const u32,
        alpha: CudaSecureField,
        folded_values: *const *const u32,
    );

    /// Allocation-free explicit-stream FRI folds. Pointer tables are device
    /// buffers and remain caller-owned for the full capture/replay lifetime.
    pub fn stwo_fold_line_on(
        gpu_domain: *const u32,
        twiddle_offset: u32,
        n: u32,
        eval_values: *const *mut u32,
        alpha: *const CudaSecureField,
        alpha_squarings: u32,
        folded_values: *const *mut u32,
        stream: *mut c_void,
    ) -> i32;
    pub fn stwo_fold_circle_into_line_on(
        gpu_domain: *const u32,
        twiddle_offset: u32,
        n: u32,
        eval_values: *const *mut u32,
        alpha: *const CudaSecureField,
        alpha_squarings: u32,
        folded_values: *const *mut u32,
        stream: *mut c_void,
    ) -> i32;

    pub fn accumulate(size: u32, left_columns: *const *const u32, right_columns: *const *const u32);

    pub fn lift_accumulate_secure_columns(
        size: u32,
        log_ratio: u32,
        previous_columns: *const *const u32,
        current_columns: *const *const u32,
    );

    pub fn commit_on_first_layer(
        size: usize,
        amount_of_columns: usize,
        columns: *const *const u32,
        result: *mut Blake2sHash,
    );

    pub fn commit_on_first_layer_lifted(
        size: usize,
        amount_of_columns: usize,
        columns: *const *const u32,
        column_log_sizes: *const u32,
        lifting_log_size: u32,
        result: *mut Blake2sHash,
    );

    pub fn commit_on_layer_with_previous(
        size: usize,
        amount_of_columns: usize,
        columns: *const *const u32,
        previous_layer: *const Blake2sHash,
        result: *mut Blake2sHash,
    );

    /// Workstream D layer-pair fusion: hash two internal (column-free) tree levels
    /// per launch. `size` = grandparent hash count; `previous_layer` holds 4*size.
    pub fn commit_on_two_layers_with_previous(
        size: usize,
        previous_layer: *const Blake2sHash,
        result: *mut Blake2sHash,
    );

    /// Streaming leaf commit (VRAM diet): the lifted first layer split so the
    /// caller LDEs base columns one group at a time. init -> update per group
    /// -> finalize; `state` holds h[8] per leaf. Byte-identical to
    /// `commit_on_first_layer_lifted`.
    pub fn stream_leaf_init(size: u32, state: *mut Blake2sHash);
    pub fn stream_leaf_update(
        size: u32,
        group_n_cols: u32,
        columns: *const *const u32,
        column_log_sizes: *const u32,
        lifting_log_size: u32,
        cols_done: u32,
        state: *mut Blake2sHash,
    );
    /// ILP2 leaf-update lane (Step 3.2, opt-in `STWO_CUDA_BLAKE2S_LEAF_ILP=1`):
    /// one thread hashes TWO adjacent rows with interleaved G-function streams,
    /// halving the grid. Byte-identical to `stream_leaf_update`; odd row counts
    /// hash the final unpaired row through the scalar stream.
    pub fn stream_leaf_update_ilp2(
        size: u32,
        group_n_cols: u32,
        columns: *const *const u32,
        column_log_sizes: *const u32,
        lifting_log_size: u32,
        cols_done: u32,
        state: *mut Blake2sHash,
    );
    pub fn stream_leaf_finalize(
        size: u32,
        rem_cols: u32,
        columns: *const *const u32,
        column_log_sizes: *const u32,
        lifting_log_size: u32,
        cols_done: u32,
        result: *mut Blake2sHash,
    );

    /// Allocation-free explicit-stream commit-island kernels. Pointer tables,
    /// state, scratch, and outputs are caller-owned device buffers.
    pub fn stwo_blake2s_leaf_init_on(
        size: u32,
        state: *mut Blake2sHash,
        stream: *mut core::ffi::c_void,
    ) -> i32;
    pub fn stwo_blake2s_progressive_init_on(
        size: u32,
        states: *mut ProgressiveBlake2sState,
        stream: *mut core::ffi::c_void,
    ) -> i32;
    pub fn stwo_blake2s_progressive_absorb_on(
        size: u32,
        number_of_columns: u32,
        absorbed_columns_before: u32,
        columns: *const *mut u32,
        states: *mut ProgressiveBlake2sState,
        stream: *mut core::ffi::c_void,
    ) -> i32;
    /// Four-lane retained-domain absorb with exact lazy-pending semantics.
    pub fn stwo_blake2s_progressive_absorb_quad_on(
        size: u32,
        number_of_columns: u32,
        absorbed_columns_before: u32,
        columns: *const *mut u32,
        initializes_state: u32,
        states: *mut ProgressiveBlake2sState,
        stream: *mut core::ffi::c_void,
    ) -> i32;
    /// Compact four-lane absorb. The wrapper copies `tail` into the captured
    /// kernel parameters; only the addressed device columns must outlive it.
    pub fn stwo_blake2s_compact_absorb_quad_on(
        size: u32,
        number_of_columns: u32,
        absorbed_columns_before: u32,
        columns: *const *mut u32,
        initializes_state: u32,
        tail: *const CompactBlake2sTailDescriptor,
        states: *mut Blake2sHash,
        stream: *mut core::ffi::c_void,
    ) -> i32;
    /// Source-major compact state expansion plus absorb. Source and
    /// destination state spans must be disjoint.
    pub fn stwo_blake2s_compact_expand_absorb_quad_on(
        from_log_size: u32,
        to_log_size: u32,
        number_of_columns: u32,
        absorbed_columns_before: u32,
        columns: *const *mut u32,
        tail: *const CompactBlake2sTailDescriptor,
        source_states: *const Blake2sHash,
        destination_states: *mut Blake2sHash,
        stream: *mut core::ffi::c_void,
    ) -> i32;
    /// Final-circle producer plus compact absorb. The native eight-lane owner
    /// loads a complete sibling pair before writing either retained word.
    pub fn stwo_blake2s_compact_absorb_n2b_terminal_pair_on(
        size: u32,
        number_of_columns: u32,
        absorbed_columns_before: u32,
        prefinal_columns: *const *mut u32,
        initializes_state: u32,
        tail: *const CompactBlake2sTailDescriptor,
        twiddles: *mut u32,
        twiddle_words: u32,
        states: *mut Blake2sHash,
        stream: *mut core::ffi::c_void,
    ) -> i32;
    pub fn stwo_blake2s_progressive_expand_on(
        from_log_size: u32,
        to_log_size: u32,
        states_in: *const ProgressiveBlake2sState,
        states_out: *mut ProgressiveBlake2sState,
        stream: *mut core::ffi::c_void,
    ) -> i32;
    pub fn stwo_blake2s_progressive_expand_in_place_on(
        from_log_size: u32,
        to_log_size: u32,
        states: *mut ProgressiveBlake2sState,
        scratch_pair: *mut ProgressiveBlake2sState,
        stream: *mut core::ffi::c_void,
    ) -> i32;
    pub fn stwo_blake2s_compact_expand_in_place_on(
        from_log_size: u32,
        to_log_size: u32,
        states: *mut Blake2sHash,
        scratch_pair: *mut Blake2sHash,
        stream: *mut core::ffi::c_void,
    ) -> i32;
    pub fn stwo_blake2s_progressive_finalize_on(
        size: u32,
        absorbed_columns: u32,
        states: *const ProgressiveBlake2sState,
        result: *mut Blake2sHash,
        stream: *mut core::ffi::c_void,
    ) -> i32;
    pub fn stwo_blake2s_progressive_finalize_in_place_on(
        size: u32,
        absorbed_columns: u32,
        states_and_hashes: *mut ProgressiveBlake2sState,
        scratch_pair: *mut ProgressiveBlake2sState,
        stream: *mut core::ffi::c_void,
    ) -> i32;
    pub fn stwo_blake2s_compact_finalize_quad_in_place_on(
        size: u32,
        absorbed_columns: u32,
        tail: *const CompactBlake2sTailDescriptor,
        states_and_hashes: *mut Blake2sHash,
        stream: *mut core::ffi::c_void,
    ) -> i32;
    pub fn stwo_blake2s_leaf_update_on(
        size: u32,
        group_n_cols: u32,
        columns: *const *mut u32,
        column_log_sizes: *const u32,
        lifting_log_size: u32,
        cols_done: u32,
        state: *mut Blake2sHash,
        stream: *mut core::ffi::c_void,
    ) -> i32;
    /// ILP2 explicit-stream twin of `stwo_blake2s_leaf_update_on` (same
    /// contract; two rows per thread, halved grid, byte-identical digests).
    pub fn stwo_blake2s_leaf_update_ilp2_on(
        size: u32,
        group_n_cols: u32,
        columns: *const *mut u32,
        column_log_sizes: *const u32,
        lifting_log_size: u32,
        cols_done: u32,
        state: *mut Blake2sHash,
        stream: *mut core::ffi::c_void,
    ) -> i32;
    /// Four-lane cooperative twin of `stwo_blake2s_leaf_update_on`. One quad
    /// owns one leaf and distributes the Blake2s G functions across lanes.
    pub fn stwo_blake2s_leaf_update_quad_on(
        size: u32,
        group_n_cols: u32,
        columns: *const *mut u32,
        column_log_sizes: *const u32,
        lifting_log_size: u32,
        cols_done: u32,
        state: *mut Blake2sHash,
        stream: *mut core::ffi::c_void,
    ) -> i32;
    pub fn stwo_blake2s_leaf_finalize_on(
        size: u32,
        rem_cols: u32,
        columns: *const *mut u32,
        column_log_sizes: *const u32,
        lifting_log_size: u32,
        cols_done: u32,
        result: *mut Blake2sHash,
        stream: *mut core::ffi::c_void,
    ) -> i32;
    /// Complete each column's final circle butterfly inside the leaf-hash
    /// kernel instead of materializing and rereading the completed LDE.
    #[allow(clippy::too_many_arguments)]
    pub fn stwo_blake2s_leaf_group_from_lde_on(
        size: u32,
        group_n_cols: u32,
        prefinal_columns: *const *mut u32,
        column_log_sizes: *const u32,
        lifting_log_size: u32,
        cols_done: u32,
        is_final: u32,
        twiddles: *mut u32,
        twiddle_words: u32,
        state: *mut Blake2sHash,
        stream: *mut core::ffi::c_void,
    ) -> i32;
    pub fn stwo_blake2s_layer_on(
        previous_layer: *const Blake2sHash,
        output_size: u32,
        result: *mut Blake2sHash,
        stream: *mut core::ffi::c_void,
    ) -> i32;
    pub fn stwo_blake2s_layer_in_place_on(
        output_size: u32,
        hashes: *mut Blake2sHash,
        scratch_pair: *mut ProgressiveBlake2sState,
        stream: *mut core::ffi::c_void,
    ) -> i32;
    /// Four column-free interior Merkle levels in ONE launch (Step 3.2 fused
    /// interior lane, opt-in via `STWO_CUDA_BLAKE2S_INTERIOR_FUSED=1`).
    /// `previous_layer` holds `16 * output_size` child digests; `result[i]` is
    /// the level-4 ancestor of children `16i..16i+16`. Intermediate levels stay
    /// in shared memory and are never written to global. Byte-identical to four
    /// sequential `stwo_blake2s_layer_on` launches; buffers must not alias.
    pub fn stwo_blake2s_interior4_on(
        previous_layer: *const Blake2sHash,
        output_size: u32,
        result: *mut Blake2sHash,
        stream: *mut core::ffi::c_void,
    ) -> i32;
    /// Hash four QM31 coordinate columns in the exact unpacked/packed FRI leaf
    /// byte order without materializing packed columns.
    pub fn stwo_blake2s_fri_leaf_on(
        evaluation_size: u32,
        coordinate_columns: *const *mut u32,
        log_rows_per_leaf: u32,
        result: *mut Blake2sHash,
        stream: *mut core::ffi::c_void,
    ) -> i32;

    pub fn copy_blake_2s_hash_vec_from_host_to_device(
        from: *const Blake2sHash,
        size: usize,
    ) -> *mut Blake2sHash;

    pub fn copy_blake_2s_hash_vec_from_device_to_host(
        from: *const Blake2sHash,
        to: *mut Blake2sHash,
        size: usize,
    );

    pub fn copy_blake_2s_hash_vec_from_device_to_device(
        from: *const Blake2sHash,
        dst: *const Blake2sHash,
        size: usize,
    );

    pub fn cuda_get_blake_2s_hash(
        device_ptr: *const Blake2sHash,
        host_ptr: *mut Blake2sHash,
        index: usize,
    );

    pub fn cuda_set_blake_2s_hash(
        device_ptr: *mut Blake2sHash,
        index: usize,
        host_ptr: *const Blake2sHash,
    );

    pub fn cuda_batch_get_blake_2s_hash(
        device_ptr: *const Blake2sHash,
        host_ptr: *mut Blake2sHash,
        indices: *const u32,
        n_indices: u32,
    );

    pub fn cuda_multi_layer_batch_get_blake_2s_hash(
        layer_device_ptrs: *const *const Blake2sHash,
        host_ptr: *mut Blake2sHash,
        pairs: *const LayerIndexPair,
        n_pairs: u32,
    );

    pub fn copy_device_pointer_vec_from_host_to_device(
        from: *const *const u32,
        size: usize,
    ) -> *const *const u32;

    pub fn cuda_release_uploaded_pointer_vec(device_ptr: *const *const u32);

    pub fn accumulate_quotients(
        half_coset_initial_index: u32,
        half_coset_step_size: u32,
        domain_size: u32,
        columns: *const *const u32,
        number_of_columns: usize,
        random_coeff: CudaSecureField,
        sample_points: *const u32,
        sample_columns_indexes: *const u32,
        sample_columns_indexes_size: u32,
        sample_column_values: *const CudaSecureField,
        sample_column_and_values_sizes: *const u32,
        sample_size: u32,
        result_column_0: *const u32,
        result_column_1: *const u32,
        result_column_2: *const u32,
        result_column_3: *const u32,
        flattened_line_coeffs_size: u32,
    );

    pub fn accumulate_partial_quotient_numerators(
        domain_size: u32,
        columns: *const *const u32,
        sample_column_indexes: *const u32,
        sample_column_indexes_size: u32,
        line_coeffs_b: *const CudaSecureField,
        line_coeffs_c: *const CudaSecureField,
        result_column_0: *const u32,
        result_column_1: *const u32,
        result_column_2: *const u32,
        result_column_3: *const u32,
    );

    pub fn combine_quotients_from_numerators(
        half_coset_initial_index: u32,
        half_coset_step_size: u32,
        domain_size: u32,
        domain_log_size: u32,
        sample_points: *const CudaSecureField,
        sample_size: u32,
        first_linear_term_accs: *const CudaSecureField,
        partial_numerator_log_sizes: *const u32,
        partial_numerators_0: *const *const u32,
        partial_numerators_1: *const *const u32,
        partial_numerators_2: *const *const u32,
        partial_numerators_3: *const *const u32,
        result_column_0: *const u32,
        result_column_1: *const u32,
        result_column_2: *const u32,
        result_column_3: *const u32,
    );

    /// Allocation-free quotient combination on an explicit proof stream.
    pub fn stwo_combine_quotients_from_numerators_on(
        half_coset_initial_index: u32,
        half_coset_step_size: u32,
        domain_size: u32,
        domain_log_size: u32,
        sample_points: *const u32,
        sample_size: u32,
        first_linear_term_accs: *const CudaSecureField,
        partial_numerator_log_sizes: *const u32,
        partial_numerators_0: *const *const u32,
        partial_numerators_1: *const *const u32,
        partial_numerators_2: *const *const u32,
        partial_numerators_3: *const *const u32,
        result_column_0: *mut u32,
        result_column_1: *mut u32,
        result_column_2: *mut u32,
        result_column_3: *mut u32,
        stream: *mut c_void,
    ) -> i32;

    /// Exact SN2 quotient producer fused through B2N stages 1..7.
    #[allow(clippy::too_many_arguments)]
    pub fn stwo_combine_quotients_b2n_init7_on(
        half_coset_initial_index: u32,
        half_coset_step_size: u32,
        domain_size: u32,
        domain_log_size: u32,
        sample_points: *const u32,
        sample_size: u32,
        first_linear_term_accs: *const CudaSecureField,
        partial_numerator_log_sizes: *const u32,
        partial_numerators_0: *const *const u32,
        partial_numerators_1: *const *const u32,
        partial_numerators_2: *const *const u32,
        partial_numerators_3: *const *const u32,
        result_column_0: *mut u32,
        result_column_1: *mut u32,
        result_column_2: *mut u32,
        result_column_3: *mut u32,
        inverse_twiddles: *const u32,
        inverse_twiddle_words: u32,
        eval_domain_size: u32,
        stream: *mut c_void,
    ) -> i32;

    pub fn stwo_combine_quotients_b2n_init7_function_attributes(
        out: *mut CudaFunctionAttributes,
    ) -> i32;

    pub fn stwo_prepare_quotient_numerator_terms_on(
        term_descriptors: *const u32,
        term_count: u32,
        sample_points: *const u32,
        sample_values: *const CudaSecureField,
        random_coefficient: *const CudaSecureField,
        term_points: *mut u32,
        line_coefficients: *mut CudaSecureField,
        stream: *mut c_void,
    ) -> i32;

    pub fn stwo_finalize_quotient_numerator_groups_on(
        group_offsets: *const u32,
        group_term_indices: *const u32,
        group_count: u32,
        term_points: *const u32,
        line_coefficients: *mut CudaSecureField,
        sample_points: *mut u32,
        first_linear_terms: *mut CudaSecureField,
        stream: *mut c_void,
    ) -> i32;

    pub fn stwo_zero_quotient_numerator_outputs_on(
        group_log_sizes: *const u32,
        group_count: u32,
        max_output_size: u32,
        outputs_0: *const *mut u32,
        outputs_1: *const *mut u32,
        outputs_2: *const *mut u32,
        outputs_3: *const *mut u32,
        stream: *mut c_void,
    ) -> i32;

    pub fn stwo_accumulate_quotient_numerator_batch_on(
        group_offsets: *const u32,
        term_descriptors: *const u32,
        group_count: u32,
        max_output_size: u32,
        source_evaluations: *const *const u32,
        line_coefficients: *const CudaSecureField,
        group_log_sizes: *const u32,
        outputs_0: *const *mut u32,
        outputs_1: *const *mut u32,
        outputs_2: *const *mut u32,
        outputs_3: *const *mut u32,
        stream: *mut c_void,
    ) -> i32;

    pub fn stwo_accumulate_quotient_numerator_single_write_on(
        group_offsets: *const u32,
        term_descriptors: *const u32,
        group_count: u32,
        max_output_size: u32,
        source_evaluations: *const *const u32,
        line_coefficients: *const CudaSecureField,
        group_log_sizes: *const u32,
        outputs_0: *const *mut u32,
        outputs_1: *const *mut u32,
        outputs_2: *const *mut u32,
        outputs_3: *const *mut u32,
        stream: *mut c_void,
    ) -> i32;

    pub fn stwo_accumulate_quotient_numerator_packed_single_write_on(
        group_row_offsets: *const u64,
        group_term_offsets: *const u32,
        term_descriptors: *const u32,
        group_count: u32,
        packed_output_rows: u64,
        source_evaluations: *const *const u32,
        line_coefficients: *const CudaSecureField,
        group_log_sizes: *const u32,
        outputs_0: *const *mut u32,
        outputs_1: *const *mut u32,
        outputs_2: *const *mut u32,
        outputs_3: *const *mut u32,
        stream: *mut c_void,
    ) -> i32;

    pub fn stwo_accumulate_quotient_numerator_group_direct_on(
        term_descriptors: *const u32,
        term_begin: u32,
        term_end: u32,
        group_log_size: u32,
        source_evaluations: *const *const u32,
        line_coefficients: *const CudaSecureField,
        group_b: *const CudaSecureField,
        output_0: *mut u32,
        output_1: *mut u32,
        output_2: *mut u32,
        output_3: *mut u32,
        stream: *mut c_void,
    ) -> i32;

    pub fn stwo_accumulate_quotient_numerator_group_direct_tiled_on(
        term_descriptors: *const u32,
        term_begin: u32,
        term_end: u32,
        group_log_size: u32,
        source_evaluations: *const *const u32,
        line_coefficients: *const CudaSecureField,
        group_b: *const CudaSecureField,
        output_0: *mut u32,
        output_1: *mut u32,
        output_2: *mut u32,
        output_3: *mut u32,
        tile_words: u32,
        stream: *mut c_void,
    ) -> i32;

    pub fn stwo_accumulate_quotient_numerator_group_direct_contribution_tiled_on(
        term_descriptors: *const u32,
        term_begin: u32,
        term_end: u32,
        group_log_size: u32,
        source_evaluations: *const *const u32,
        line_coefficients: *const CudaSecureField,
        group_b: *const CudaSecureField,
        output_0: *mut u32,
        output_1: *mut u32,
        output_2: *mut u32,
        output_3: *mut u32,
        stream: *mut c_void,
    ) -> i32;

    pub fn stwo_quotient_numerator_group_direct_tiled_function_attributes(
        tile_words: u32,
        out: *mut CudaFunctionAttributes,
    ) -> i32;

    pub fn stwo_quotient_numerator_group_direct_contribution_tiled_function_attributes(
        out: *mut CudaFunctionAttributes,
    ) -> i32;

    pub fn stwo_precompute_quotient_numerator_native_run_on(
        term_descriptors: *const u32,
        term_begin: u32,
        term_end: u32,
        source_log_size: u32,
        source_evaluations: *const *const u32,
        line_coefficients: *const CudaSecureField,
        scratch_0: *mut u32,
        scratch_1: *mut u32,
        scratch_2: *mut u32,
        scratch_3: *mut u32,
        scratch_offset_words: u32,
        stream: *mut c_void,
    ) -> i32;

    pub fn stwo_expand_quotient_numerator_native_run_sums_on(
        manifest: *const CudaQuotientNativeRunManifest,
        term_descriptors: *const u32,
        source_evaluations: *const *const u32,
        line_coefficients: *const CudaSecureField,
        group_b: *const CudaSecureField,
        scratch_0: *const u32,
        scratch_1: *const u32,
        scratch_2: *const u32,
        scratch_3: *const u32,
        output_0: *mut u32,
        output_1: *mut u32,
        output_2: *mut u32,
        output_3: *mut u32,
        stream: *mut c_void,
    ) -> i32;

    pub fn stwo_quotient_numerator_native_run_precompute_function_attributes(
        out: *mut CudaFunctionAttributes,
    ) -> i32;

    pub fn stwo_quotient_numerator_native_run_sum_expand_function_attributes(
        out: *mut CudaFunctionAttributes,
    ) -> i32;

    pub fn stwo_prepare_quotient_numerator_prepacked_terms_on(
        group_term_offsets: *const u32,
        term_descriptors: *const u32,
        group_count: u32,
        term_count: u32,
        source_evaluations: *const *const u32,
        source_count: u32,
        line_coefficients: *const CudaSecureField,
        prepacked_storage: *mut u32,
        prepacked_storage_words: u64,
        stream: *mut c_void,
    ) -> i32;

    pub fn stwo_accumulate_quotient_numerator_prepacked_single_write_on(
        group_row_offsets: *const u64,
        group_term_offsets: *const u32,
        group_count: u32,
        term_count: u32,
        packed_output_rows: u64,
        prepacked_storage: *mut u32,
        prepacked_storage_words: u64,
        group_log_sizes: *const u32,
        outputs_0: *const *mut u32,
        outputs_1: *const *mut u32,
        outputs_2: *const *mut u32,
        outputs_3: *const *mut u32,
        stream: *mut c_void,
    ) -> i32;

    /// Allocation-free coefficient-form OODS evaluation on an explicit proof stream.
    pub fn stwo_oods_derive_points_on(
        oods_parameter: *const CudaSecureField,
        offset_points: *const CirclePointBaseField,
        fold_counts: *const u32,
        output_indices: *const u32,
        sample_count: u32,
        coefficient_log_size: u32,
        sample_points: *mut u32,
        evaluation_points: *mut u32,
        folding_factors: *mut CudaSecureField,
        stream: *mut c_void,
    ) -> i32;

    pub fn stwo_oods_eval_first_on(
        coefficients: *const *const u32,
        coefficient_size: u32,
        sample_count: u32,
        folding_factors: *const CudaSecureField,
        scratch: *mut CudaSecureField,
        stream: *mut c_void,
    ) -> i32;

    pub fn stwo_oods_eval_reduce_on(
        input: *const CudaSecureField,
        input_size: u32,
        input_stride: u32,
        factor_index: u32,
        coefficient_log_size: u32,
        sample_count: u32,
        folding_factors: *const CudaSecureField,
        output: *mut CudaSecureField,
        output_stride: u32,
        stream: *mut c_void,
    ) -> i32;

    pub fn stwo_oods_store_results_on(
        reduced: *const CudaSecureField,
        reduced_stride: u32,
        output_indices: *const u32,
        sample_count: u32,
        sampled_values: *mut CudaSecureField,
        stream: *mut c_void,
    ) -> i32;

    pub fn stwo_oods_barycentric_weights_on(
        half_coset_initial_index: u32,
        half_coset_step_size: u32,
        size: u32,
        log_size: u32,
        evaluation_point: *const u32,
        si0: CudaSecureField,
        vanishing_rotation: CirclePointBaseField,
        numerator_inverses: *mut CudaSecureField,
        weights: *mut CudaSecureField,
        scales: *mut CudaSecureField,
        stream: *mut c_void,
    ) -> i32;

    pub fn stwo_oods_barycentric_weights_collapsed_cohort_on(
        half_coset_initial_index: u32,
        half_coset_step_size: u32,
        size: u32,
        log_size: u32,
        evaluation_points: *const u32,
        descriptor_offsets: *const u32,
        group_count: u32,
        si0: CudaSecureField,
        vanishing_rotation: CirclePointBaseField,
        weights: *mut CudaSecureField,
        stream: *mut c_void,
    ) -> i32;

    pub fn stwo_oods_barycentric_eval_many_on(
        columns: *const *const u32,
        column_count: u32,
        weights: *const CudaSecureField,
        size: u32,
        partial_sums: *mut CudaSecureField,
        reduction_blocks: u32,
        output_indices: *const u32,
        sampled_values: *mut CudaSecureField,
        stream: *mut c_void,
    ) -> i32;

    pub fn gen_eq_evals(
        v: CudaSecureField,
        y: *const CudaSecureField,
        y_size: u32,
        evals: *const CudaSecureField,
        evals_size: u32,
    );

    pub fn gkr_next_grand_product_layer(
        input_layer: *const CudaSecureField,
        input_size: u32,
        output_layer: *const CudaSecureField,
    );

    pub fn gkr_next_logup_generic_layer(
        numerators: *const CudaSecureField,
        denominators: *const CudaSecureField,
        input_size: u32,
        next_numerators: *const CudaSecureField,
        next_denominators: *const CudaSecureField,
    );

    pub fn gkr_next_logup_multiplicities_layer(
        numerators: *const u32,
        denominators: *const CudaSecureField,
        input_size: u32,
        next_numerators: *const CudaSecureField,
        next_denominators: *const CudaSecureField,
    );

    pub fn gkr_next_logup_singles_layer(
        denominators: *const CudaSecureField,
        input_size: u32,
        next_numerators: *const CudaSecureField,
        next_denominators: *const CudaSecureField,
    );

    pub fn gkr_sum_grand_product(
        eq_evals: *const CudaSecureField,
        input_layer: *const CudaSecureField,
        n_terms: u32,
        eval_at_0: *mut CudaSecureField,
        eval_at_2: *mut CudaSecureField,
    );

    pub fn gkr_sum_logup_generic(
        eq_evals: *const CudaSecureField,
        numerators: *const CudaSecureField,
        denominators: *const CudaSecureField,
        n_terms: u32,
        lambda: CudaSecureField,
        eval_at_0: *mut CudaSecureField,
        eval_at_2: *mut CudaSecureField,
    );

    pub fn gkr_sum_logup_multiplicities(
        eq_evals: *const CudaSecureField,
        numerators: *const u32,
        denominators: *const CudaSecureField,
        n_terms: u32,
        lambda: CudaSecureField,
        eval_at_0: *mut CudaSecureField,
        eval_at_2: *mut CudaSecureField,
    );

    pub fn gkr_sum_logup_singles(
        eq_evals: *const CudaSecureField,
        denominators: *const CudaSecureField,
        n_terms: u32,
        lambda: CudaSecureField,
        eval_at_0: *mut CudaSecureField,
        eval_at_2: *mut CudaSecureField,
    );

    pub fn fix_first_variable_base_field(
        evals: *const u32,
        evals_size: usize,
        assignment: CudaSecureField,
        output_evals: *const u32,
    );

    pub fn fix_first_variable_secure_field(
        evals: *const u32,
        evals_size: usize,
        assignment: CudaSecureField,
        output_evals: *const u32,
    );

    // Assert EQ FP IMM trace generation
    pub fn ntt_n2b_native_batch(
        value: *mut *mut u32,
        log_n: u32,
        num_poly: u32,
        start_stage: u32,
        end_stage: u32,
        g_twiddles: *const u32,
        twiddles_size: u32,
        eval_domain_size: u32,
    );

    pub fn ntt_b2n_column(
        values_columns: *mut *mut u32,
        log_n: u32,
        num_poly: u32,
        g_twiddles: *const u32,
        twiddles_size: u32,
        eval_domain_size: u32,
    );

    /// Allocation-free B2N transform for logs 3 through 30 using a device
    /// pointer table and explicit stream.
    pub fn stwo_ntt_b2n_columns_on(
        device_values: *const *mut u32,
        log_n: u32,
        num_poly: u32,
        g_twiddles: *mut u32,
        twiddles_size: u32,
        eval_domain_size: u32,
        stream: *mut c_void,
    ) -> i32;

    /// Exact log-23 continuation after producer-owned B2N stages 1..7.
    pub fn stwo_ntt_b2n_columns_after_first_seven_on(
        device_values: *const *mut u32,
        log_n: u32,
        num_poly: u32,
        g_twiddles: *const u32,
        twiddles_size: u32,
        eval_domain_size: u32,
        stream: *mut c_void,
    ) -> i32;

    pub fn stwo_ntt_b2n_after_first_seven_function_attributes(
        start_stage: u32,
        stages: u32,
        out: *mut CudaFunctionAttributes,
    ) -> i32;

    /// Allocation-free B2N transform for logs 3 through 30 using separate
    /// input/output pointer tables on an explicit stream. Each input may
    /// exactly alias its paired output.
    pub fn stwo_ntt_b2n_columns_out_of_place_on(
        inputs: *const *const u32,
        outputs: *const *mut u32,
        log_n: u32,
        num_poly: u32,
        g_twiddles: *const u32,
        twiddles_size: u32,
        eval_domain_size: u32,
        stream: *mut c_void,
    ) -> i32;

    /// Allocation-free B2N transform that writes the normalized result to
    /// both halves of each paired `2^(log_n + 1)`-word retained output. This
    /// is byte-identical to the first N2B layer after coefficient zero-extension.
    pub fn stwo_ntt_b2n_columns_to_retained_on(
        inputs: *const *const u32,
        retained_outputs: *const *mut u32,
        log_n: u32,
        num_poly: u32,
        g_twiddles: *const u32,
        twiddles_size: u32,
        eval_domain_size: u32,
        stream: *mut c_void,
    ) -> i32;

    /// Exact four-coordinate Composition fallback to eight duplicated
    /// stage-two retained columns.
    pub fn stwo_ntt_b2n_composition_to_retained_on(
        source_values: *const *mut u32,
        retained_outputs: *const *mut u32,
        log_n: u32,
        inverse_twiddles: *const u32,
        inverse_twiddle_words: u32,
        eval_domain_size: u32,
        stream: *mut c_void,
    ) -> i32;

    /// Log-25 Composition boundary that also executes the first forward
    /// interval before its only retained global write. Log 24 fails closed;
    /// its 512-thread fused specialization exceeds SM90's register budget.
    #[allow(clippy::too_many_arguments)]
    pub fn stwo_ntt_b2n_composition_fused_first_forward_on(
        source_values: *const *mut u32,
        retained_outputs: *const *mut u32,
        log_n: u32,
        inverse_twiddles: *const u32,
        inverse_twiddle_words: u32,
        forward_twiddles: *const u32,
        forward_twiddle_words: u32,
        eval_domain_size: u32,
        stream: *mut c_void,
    ) -> i32;

    pub fn ntt_n2b_columns(
        values_columns: *mut *mut u32,
        log_n: u32,
        num_poly: u32,
        g_twiddles: *const u32,
        twiddles_size: u32,
        eval_domain_size: u32,
    );

    /// Allocation-free N2B transform. `device_values` is already a
    /// device-resident pointer table and every launch uses `stream`.
    pub fn stwo_ntt_n2b_columns_on(
        device_values: *const *mut u32,
        log_n: u32,
        num_poly: u32,
        g_twiddles: *mut u32,
        twiddles_size: u32,
        eval_domain_size: u32,
        stream: *mut core::ffi::c_void,
    ) -> i32;

    /// Continue N2B in place from the exact stage-one image `[c, c]` through
    /// stages 2..=`log_n`, using the device pointer table and `stream`.
    pub fn stwo_ntt_n2b_columns_from_stage_two_on(
        device_values: *const *mut u32,
        log_n: u32,
        num_poly: u32,
        g_twiddles: *mut u32,
        twiddles_size: u32,
        eval_domain_size: u32,
        stream: *mut core::ffi::c_void,
    ) -> i32;

    /// Stage-two direct-retained successor ending immediately before the
    /// terminal circle butterfly owned by the paired compact consumer.
    pub fn stwo_ntt_n2b_columns_from_stage_two_before_circle_on(
        device_values: *const *mut u32,
        log_n: u32,
        num_poly: u32,
        g_twiddles: *mut u32,
        twiddles_size: u32,
        eval_domain_size: u32,
        stream: *mut core::ffi::c_void,
    ) -> i32;

    /// Continue from stage two through every complete N2B interval before the
    /// configured terminal interval consumed by the fixed16 compact sink.
    pub fn stwo_ntt_n2b_columns_from_stage_two_before_final_interval_on(
        device_values: *const *mut u32,
        log_n: u32,
        num_poly: u32,
        g_twiddles: *mut u32,
        twiddles_size: u32,
        eval_domain_size: u32,
        stream: *mut core::ffi::c_void,
    ) -> i32;

    /// Complete only the configured final interval while leaving the circle
    /// butterfly for the paired compact remainder sink.
    pub fn stwo_ntt_n2b_columns_final_interval_before_circle_on(
        device_values: *const *mut u32,
        log_n: u32,
        num_poly: u32,
        g_twiddles: *mut u32,
        twiddles_size: u32,
        eval_domain_size: u32,
        stream: *mut core::ffi::c_void,
    ) -> i32;

    /// Exact eight-column Composition continuation after the fused first
    /// forward interval. Only log24 and log25 are admitted.
    pub fn stwo_ntt_n2b_columns_after_first_stage_two_interval_on(
        device_values: *const *mut u32,
        log_n: u32,
        num_poly: u32,
        g_twiddles: *mut u32,
        twiddles_size: u32,
        eval_domain_size: u32,
        stream: *mut core::ffi::c_void,
    ) -> i32;

    /// Allocation-free LDE. Pointer and exact coefficient-size tables are
    /// device-resident; staging and N2B use `stream`.
    pub fn stwo_lde_n2b_columns_on(
        coefficient_values: *const *const u32,
        coefficient_sizes: *const u32,
        device_values: *const *mut u32,
        log_n: u32,
        num_poly: u32,
        g_twiddles: *mut u32,
        twiddles_size: u32,
        eval_domain_size: u32,
        stream: *mut core::ffi::c_void,
    ) -> i32;

    /// Allocation-free LDE prefix ending immediately before the final circle
    /// butterfly; consumed by `stwo_blake2s_leaf_group_from_lde_on`.
    pub fn stwo_lde_n2b_columns_before_circle_on(
        coefficient_values: *const *const u32,
        coefficient_sizes: *const u32,
        device_values: *const *mut u32,
        log_n: u32,
        num_poly: u32,
        g_twiddles: *mut u32,
        twiddles_size: u32,
        eval_domain_size: u32,
        stream: *mut core::ffi::c_void,
    ) -> i32;

    /// Setup-time dynamic-shared-memory admission for the producer-fused
    /// 16-column N2B→Blake kernel selected by `log_n`.
    pub fn stwo_lde_n2b_hash16_configure(log_n: u32) -> i32;

    /// Stage and transform 16 same-log full-lifting columns, feeding final N2B
    /// values directly from registers/shared memory into leaf states.
    #[allow(clippy::too_many_arguments)]
    pub fn stwo_lde_n2b_hash16_on(
        coefficient_values: *const *const u32,
        coefficient_sizes: *const u32,
        device_values: *const *mut u32,
        log_n: u32,
        g_twiddles: *mut u32,
        twiddles_size: u32,
        eval_domain_size: u32,
        cols_done: u32,
        is_final: u32,
        states: *mut Blake2sHash,
        stream: *mut core::ffi::c_void,
    ) -> i32;

    pub fn inclusive_prefix_sum(device_bit_rev_circle_domain_evals: *const u32, len: u32);

    pub fn inclusive_prefix_sum_x4(
        c0: *const u32,
        c1: *const u32,
        c2: *const u32,
        c3: *const u32,
        len: u32,
    );

    pub fn logup_fraction_chain(
        num0: *const u32,
        num1: *const u32,
        num2: *const u32,
        num3: *const u32,
        denom_packed: *const u32,
        prev0: *const u32,
        prev1: *const u32,
        prev2: *const u32,
        prev3: *const u32,
        size: u32,
    );

    /// Device logup pair generation from word-major witness-lane lookup flats
    /// (ENDGAME 6a). See cuda/logup_pairs.cu for the descriptor layout.
    pub fn stwo_logup_pairs_from_flats(
        flats: *const u32,
        n_rows: u32,
        n_real: u32,
        descs_host: *const u32,
        n_cols: u32,
        alphas_host: *const u32,
        n_alphas: u32,
        z_host: *const u32,
        num_cols_device_table: *const *mut u32,
        den_dense_device_table: *const *mut u32,
    ) -> bool;

    /// Exact CUB storage query used during prepared relation setup.
    pub fn stwo_relation_scan_temp_bytes(len: u32) -> usize;

    /// Expand the transcript draw `[z, alpha]` into z plus alpha powers on the
    /// explicit proof stream.
    pub fn stwo_relation_expand_challenges_on(
        drawn_z_alpha: *const u32,
        alpha_powers: *mut u32,
        n_alpha_powers: u32,
        z: *mut u32,
        stream: *mut core::ffi::c_void,
    ) -> i32;

    /// Allocation-free, stream-explicit generated relation pair engine.
    pub fn stwo_relation_pairs_on(
        sources: *const *const u32,
        n_sources: u32,
        n_rows: u32,
        n_real: u32,
        source_offset_rows: u32,
        descriptors: *const u32,
        n_columns: u32,
        alpha_powers: *const u32,
        n_alpha_powers: u32,
        z: *const u32,
        outputs: *const *mut u32,
        denominators: *mut u32,
        stream: *mut core::ffi::c_void,
    ) -> i32;

    pub fn stwo_relation_pairs_global_on(
        source_tables: *const *const *const u32,
        descriptors: *const *const u32,
        output_tables: *const *const *mut u32,
        denominator_slabs: *const *mut u32,
        geometry: *const u32,
        n_instances: u32,
        total_pair_blocks: u32,
        alpha_powers: *const u32,
        n_alpha_powers: u32,
        z: *const u32,
        stream: *mut core::ffi::c_void,
    ) -> i32;

    /// Fused pairs -> single-inversion -> fraction-chain lane: one proof-wide
    /// launch over the shared 11-word geometry records. `eligible_mask` is a
    /// HOST pointer to 8 words (256 instance bits) copied into the by-value
    /// kernel parameter before launch; ineligible instances are skipped and
    /// must be executed by the caller on the 3-stage path.
    pub fn stwo_relation_fused_on(
        source_tables: *const *const *const u32,
        descriptors: *const *const u32,
        output_tables: *const *const *mut u32,
        geometry: *const u32,
        n_instances: u32,
        total_row_blocks: u32,
        alpha_powers: *const u32,
        n_alpha_powers: u32,
        z: *const u32,
        eligible_mask: *const u32,
        stream: *mut core::ffi::c_void,
    ) -> i32;

    /// Test-only launch of the exact pre-adaptive `columns <= 512` selector.
    /// It is compiled beside, but does not modify or replace, the production
    /// fused kernel.
    #[cfg(feature = "test-only-relation-ab")]
    pub fn stwo_relation_fused_all_one_read_test_on(
        source_tables: *const *const *const u32,
        descriptors: *const *const u32,
        output_tables: *const *const *mut u32,
        geometry: *const u32,
        n_instances: u32,
        total_row_blocks: u32,
        alpha_powers: *const u32,
        n_alpha_powers: u32,
        z: *const u32,
        eligible_mask: *const u32,
        stream: *mut core::ffi::c_void,
    ) -> i32;

    /// Loaded-function facts for the production adaptive kernel (`0`) or the
    /// dormant pre-adaptive test baseline (`1`).
    #[cfg(feature = "test-only-relation-ab")]
    pub fn stwo_relation_fused_test_function_attributes(
        strategy: u32,
        out: *mut CudaFunctionAttributes,
    ) -> i32;

    /// Isolated exact Blake-G relation body. Six raw input columns produce all
    /// 36 interaction coordinates without a flattened lookup slab.
    pub fn stwo_relation_blake_g_inputs_on(
        sources: *const *const u32,
        n_sources: u32,
        n_rows: u32,
        n_real: u32,
        alpha_powers: *const u32,
        n_alpha_powers: u32,
        z: *const u32,
        outputs: *const *mut u32,
        n_outputs: u32,
        stream: *mut core::ffi::c_void,
    ) -> i32;

    pub fn stwo_relation_fraction_chain_on(
        outputs: *const *mut u32,
        denominators: *mut u32,
        inverse_scratch: *mut u32,
        n_rows: u32,
        n_columns: u32,
        stream: *mut core::ffi::c_void,
    ) -> i32;

    pub fn stwo_relation_reduce_shift_on(
        output_0: *mut u32,
        output_1: *mut u32,
        output_2: *mut u32,
        output_3: *mut u32,
        n_rows: u32,
        reduction_a: *mut u32,
        reduction_b: *mut u32,
        reduction_capacity: u32,
        claimed_sum: *mut u32,
        inverse_rows: u32,
        stream: *mut core::ffi::c_void,
    ) -> i32;

    pub fn stwo_relation_prefix_scan_on(
        output: *mut u32,
        n_rows: u32,
        eval_scratch: *mut u32,
        scan_temp: *mut core::ffi::c_void,
        scan_temp_bytes: usize,
        stream: *mut core::ffi::c_void,
    ) -> i32;

    pub fn stwo_relation_tail_global_on(
        output_tables: *const *const *mut u32,
        claimed_sums: *const *mut u32,
        geometry: *const u32,
        n_instances: u32,
        total_row_blocks: u32,
        reduction_partials: *mut u32,
        reduction_capacity: u32,
        scan_block_sums: *mut u32,
        scan_capacity: u32,
        stream: *mut core::ffi::c_void,
    ) -> i32;

    pub fn logup_fraction_chain_dense(
        num0: *const u32,
        num1: *const u32,
        num2: *const u32,
        num3: *const u32,
        denoms_dense: *const u32,
        prev0: *const u32,
        prev1: *const u32,
        prev2: *const u32,
        prev3: *const u32,
        size: u32,
    );

    pub fn logup_sum_secure_coords(
        c0: *const u32,
        c1: *const u32,
        c2: *const u32,
        c3: *const u32,
        size: u32,
    ) -> CudaSecureField;

    pub fn memory_limb_split_big(
        values: *const u32,
        n_values: u32,
        column_length: u32,
        limb_cols: *const *const u32,
    );

    pub fn memory_limb_split_small(
        values: *const u32,
        n_values: u32,
        column_length: u32,
        limb_cols: *const *const u32,
    );

    pub fn memory_limb_split_big_into_on(
        values: *const u32,
        n_values: u32,
        column_length: u32,
        limb_cols_host: *const *mut u32,
        mults_host: *const u32,
        mults: *mut u32,
        stream: *mut c_void,
    ) -> i32;
    pub fn stwo_relation_fraction_chain_global_on(
        output_tables: *const *const *mut u32,
        denominator_slabs: *const *mut u32,
        geometry: *const u32,
        n_instances: u32,
        total_inverse_blocks: u32,
        total_chain_blocks: u32,
        stream: *mut c_void,
    ) -> i32;

    pub fn memory_limb_split_small_into_on(
        values: *const u32,
        n_values: u32,
        column_length: u32,
        limb_cols_host: *const *mut u32,
        mults_host: *const u32,
        mults: *mut u32,
        stream: *mut c_void,
    ) -> i32;

    pub fn memory_limb_split_big_columns_on(
        values: *const u32,
        n_values: u32,
        column_length: u32,
        limb_cols_host: *const *mut u32,
        stream: *mut c_void,
    ) -> i32;

    pub fn memory_limb_split_small_columns_on(
        values: *const u32,
        n_values: u32,
        column_length: u32,
        limb_cols_host: *const *mut u32,
        stream: *mut c_void,
    ) -> i32;
    pub fn memory_address_base_trace_on(
        raw_addr_to_id: *const u32,
        n_addrs: u32,
        multiplicities: *const u32,
        count_words: u32,
        column_length: u32,
        outputs_host: *const *mut u32,
        stream: *mut c_void,
    ) -> i32;
    pub fn memory_value_base_trace_on(
        sources_host: *const *const u32,
        n_limbs: u32,
        source_words: u32,
        source_offset: u32,
        multiplicities: *const u32,
        count_words: u32,
        column_length: u32,
        outputs_host: *const *mut u32,
        stream: *mut c_void,
    ) -> i32;
    pub fn memory_address_base_trace_sliced_on(
        address_ids: *const u32,
        address_id_words: u32,
        multiplicities: *const u32,
        multiplicity_words: u32,
        column_length: u32,
        outputs_host: *const *mut u32,
        stream: *mut c_void,
    ) -> i32;
    pub fn memory_value_base_trace_sliced_on(
        sources_host: *const *const u32,
        n_limbs: u32,
        source_slice_words: u32,
        multiplicities: *const u32,
        multiplicity_slice_words: u32,
        column_length: u32,
        outputs_host: *const *mut u32,
        stream: *mut c_void,
    ) -> i32;

    /// Capture-safe native Cairo `ec_op_builtin` writer. The execution-table
    /// pointer table is device-resident; every destination points into the
    /// proof arena.
    #[allow(clippy::too_many_arguments)]
    pub fn ec_op_builtin_witness_on(
        execution_tables: *const *const u32,
        n_addresses: u32,
        n_big: u32,
        n_small: u32,
        segment_start_source: *const u32,
        row_count: u32,
        trace_columns_host: *const *mut u32,
        lookup_words: *mut u32,
        partial_input_columns_host: *const *mut u32,
        partial_row_count: u32,
        address_counts: *mut u32,
        address_count_words: u32,
        big_counts: *mut u32,
        big_count_words: u32,
        small_counts: *mut u32,
        small_count_words: u32,
        range_check_8_counts: *mut u32,
        range_check_8_count_words: u32,
        stream: *mut c_void,
    ) -> i32;

    pub fn memory_rc99_count(
        limb_cols: *const *const u32,
        n_pairs: u32,
        column_length: u32,
        input_to_row_lut: *const u32,
        rc_table_size: u32,
        counts: *mut u32,
    );

    pub fn memory_rc99_count_on(
        limb_cols_host: *const *const u32,
        n_pairs: u32,
        column_length: u32,
        input_to_row_lut: *const u32,
        rc_table_size: u32,
        counts: *mut u32,
        stream: *mut c_void,
    ) -> i32;

    pub fn memory_logup_inputs(
        limb_cols: *const *const u32,
        n_limbs: u32,
        mults: *const u32,
        relation_id: u32,
        id_offset: u32,
        id_tag: u32,
        column_length: u32,
        alpha_powers: *const u32,
        z: CudaSecureField,
        denoms: *const u32,
        num0: *const u32,
        num1: *const u32,
        num2: *const u32,
        num3: *const u32,
    );

    pub fn memory_rc_pair_logup(
        limb_a: *const u32,
        limb_b: *const u32,
        limb_c: *const u32,
        limb_d: *const u32,
        rel_id0: u32,
        rel_id1: u32,
        column_length: u32,
        alpha_powers: *const u32,
        z: CudaSecureField,
        denoms: *const u32,
        num0: *const u32,
        num1: *const u32,
        num2: *const u32,
        num3: *const u32,
    );

    /// Composed device `deduce_output` (ENDGAME §2 keystone): for each queried address,
    /// read the raw encoded id from `addr_to_id`, decode the tag, and gather the 28
    /// 9-bit value limbs from the device-resident big/small split tables — the device
    /// equivalent of the host `memory_address_to_id` + `memory_id_to_big` deduction.
    /// `big_limbs`/`small_limbs`/`out_limbs` are device-resident arrays of device
    /// column pointers (28 / 8 / 28). Addresses must be non-empty cells.
    pub fn exec_deduce_output(
        addr_to_id: *const u32,
        big_limbs: *const *const u32,
        small_limbs: *const *const u32,
        addresses: *const u32,
        n_queries: u32,
        out_ids: *mut u32,
        out_limbs: *const *mut u32,
    );

    pub fn logup_shift_secure_coords(
        c0: *const u32,
        c1: *const u32,
        c2: *const u32,
        c3: *const u32,
        shift: CudaSecureField,
        size: u32,
    );

    pub fn blake_g_write_trace(
        inputs: *const u32,
        n_rows: u32,
        column_length: u32,
        cols: *const *const u32,
    );

    /// Allocation-free arena-native blake_g writer. Exactly one of `inputs`
    /// (row-major) and `producer_sub` (blake_round word-major edge) is non-null.
    /// `trace_cols_host` is a host array of 53 device addresses copied into the
    /// kernel argument; lookup/sub are canonical word-major flat outputs.
    pub fn blake_g_write_trace_into_on(
        inputs: *const u32,
        producer_sub: *const u32,
        producer_rows: u32,
        producer_word_base: u32,
        producer_instances: u32,
        n_rows: u32,
        column_length: u32,
        trace_cols_host: *const *mut u32,
        lookup: *mut u32,
        sub: *mut u32,
        stream: *mut c_void,
    ) -> i32;

    /// Replacement-only form of `blake_g_write_trace_into_on`. The 20-word
    /// `aux` slab replaces the 87-word flattened lookup output.
    pub fn blake_g_write_trace_projected_into_on(
        inputs: *const u32,
        producer_sub: *const u32,
        producer_rows: u32,
        producer_word_base: u32,
        producer_instances: u32,
        n_rows: u32,
        column_length: u32,
        trace_cols_host: *const *mut u32,
        aux: *mut u32,
        sub: *mut u32,
        stream: *mut c_void,
    ) -> i32;

    /// Resident producer/feed fusion. Inputs and trace outputs are host
    /// arrays of 6/53 arena device addresses. LUTs are ordered xor8/4/7/9 and
    /// count slabs xor8/12/4/7/9. The kernel writes no sub-input slab.
    pub fn blake_g_write_trace_fused_into_on(
        input_cols_host: *const *const u32,
        n_rows: u32,
        column_length: u32,
        trace_cols_host: *const *mut u32,
        lookup: *mut u32,
        luts_host: *const *const u32,
        counts_host: *const *mut u32,
        stream: *mut c_void,
    ) -> i32;

    /// Replacement-only producer/feed fusion with a 20-word auxiliary source
    /// instead of the flattened 87-word lookup output.
    pub fn blake_g_write_trace_fused_projected_into_on(
        input_cols_host: *const *const u32,
        n_rows: u32,
        column_length: u32,
        trace_cols_host: *const *mut u32,
        aux: *mut u32,
        luts_host: *const *const u32,
        counts_host: *const *mut u32,
        stream: *mut c_void,
    ) -> i32;

    /// Replacement producer/feed fusion. The enabler is synthesized and no
    /// flattened lookup or auxiliary relation slab is written.
    pub fn blake_g_write_trace_fused_direct_into_on(
        input_cols_host: *const *const u32,
        n_rows: u32,
        column_length: u32,
        trace_cols_host: *const *mut u32,
        luts_host: *const *const u32,
        counts_host: *const *mut u32,
        stream: *mut c_void,
    ) -> i32;

    pub fn blake_g_xor_count(
        a_cols: *const *const u32,
        b_cols: *const *const u32,
        rel_idx: *const u32,
        n_pairs: u32,
        column_length: u32,
        shift: u32,
        lut: *const u32,
        table_size: u32,
        counts: *mut u32,
    );

    pub fn blake_g_xor12_count(
        a_cols: *const *const u32,
        b_cols: *const *const u32,
        n_pairs: u32,
        column_length: u32,
        limb_bits: u32,
        expand_bits: u32,
        table_size: u32,
        counts: *mut u32,
    );

    pub fn blake_g_pair_logup(
        a0: *const u32,
        b0: *const u32,
        x0: *const u32,
        a1: *const u32,
        b1: *const u32,
        x1: *const u32,
        rel0: u32,
        rel1: u32,
        column_length: u32,
        alpha: *const u32,
        z: CudaSecureField,
        denoms: *const u32,
        num0: *const u32,
        num1: *const u32,
        num2: *const u32,
        num3: *const u32,
    );

    pub fn blake_g_final_logup(
        val_cols: *const *const u32,
        enabler: *const u32,
        rel: u32,
        column_length: u32,
        alpha: *const u32,
        z: CudaSecureField,
        denoms: *const u32,
        num0: *const u32,
        num1: *const u32,
        num2: *const u32,
        num3: *const u32,
    );

    // Pedersen family witness-on-GPU (partial_ec_mul / pedersen_aggregator).
    // See `cuda/pedersen_witness.cu` for the scope contract; these are the
    // reusable interaction/logup kernels (base-trace gadget kernels land per
    // component on hardware behind the STWO_CUDA_WITNESS_VERIFY differential).
    #[allow(clippy::too_many_arguments)]
    pub fn pedersen_pair_logup(
        vals0: *const *const u32,
        rel0: u32,
        vals1: *const *const u32,
        rel1: u32,
        n_vals: u32,
        m0: *const u32,
        m1: *const u32,
        sign0: i32,
        sign1: i32,
        column_length: u32,
        alpha: *const u32,
        z: CudaSecureField,
        denoms: *const u32,
        num0: *const u32,
        num1: *const u32,
        num2: *const u32,
        num3: *const u32,
    );

    #[allow(clippy::too_many_arguments)]
    pub fn pedersen_multi_logup(
        vals: *const *const u32,
        n_vals: u32,
        rel: u32,
        mult: *const u32,
        neg_num: i32,
        column_length: u32,
        alpha: *const u32,
        z: CudaSecureField,
        denoms: *const u32,
        num0: *const u32,
        num1: *const u32,
        num2: *const u32,
        num3: *const u32,
    );

    // Poseidon252 CUDA acceleration functions
    // Note: FieldElement252 is represented as 32 bytes (8 x u32)
    // Note: Poseidon252Hash is 32-byte struct, equivalent to [u8; 32]
    pub fn cuda_malloc_poseidon252_hash(size: usize) -> *mut [u8; 32];

    pub fn cuda_alloc_zeroes_poseidon252_hash(size: usize) -> *mut [u8; 32];

    pub fn copy_poseidon252_hash_vec_from_host_to_device(
        from: *const [u8; 32],
        size: usize,
    ) -> *mut [u8; 32];

    pub fn copy_poseidon252_hash_vec_from_device_to_host(
        from: *const [u8; 32],
        to: *mut [u8; 32],
        size: usize,
    );

    pub fn copy_poseidon252_hash_vec_from_device_to_device(
        from: *const [u8; 32],
        dst: *mut [u8; 32],
        size: usize,
    );

    pub fn cuda_get_poseidon252_hash(
        device_ptr: *const [u8; 32],
        host_ptr: *mut [u8; 32],
        index: usize,
    );

    pub fn cuda_set_poseidon252_hash(
        device_ptr: *mut [u8; 32],
        index: usize,
        value: *const [u8; 32],
    );

    // Hybrid Poseidon252 Merkle functions that use GPU for data processing
    // and CPU for verified hashing
    // GPU-only aliases matching Blake2s interface
    pub fn poseidon252_commit_on_first_layer(
        size: usize,
        amount_of_columns: usize,
        columns: *const *const u32,
        result: *mut [u8; 32],
    );

    pub fn poseidon252_commit_on_layer_with_previous(
        size: usize,
        amount_of_columns: usize,
        columns: *const *const u32,
        previous_layer: *const [u8; 32],
        result: *mut [u8; 32],
    );

    // Test function to compute offset_bit_reversed_circle_domain_index on GPU
    pub fn test_offset_bit_reversed_indices(
        result_host: *mut u32,
        domain_log_size: u32,
        eval_log_size: u32,
        offset: i32,
        n: u32,
    );

    /// Witness-JIT lane: NVRTC-compile (cached by `cache_key`, the CONTENT hash — never
    /// pointers) and launch a generated per-row witness kernel. The ABI matches
    /// `stwo-backend-cuda::backend::jit_witness::codegen`: one thread per row reads the
    /// packed input columns, replays the recorded decode in registers, writes committed
    /// trace columns, atomic-adds multiplicities, and stores lookup words.
    ///
    /// Pointer tables are device-resident arrays of device pointers (the pointer-table
    /// trace ABI — no flatten copies, no u32 length overflow at log >= 23). `relax_opt`
    /// compiles with optimization disabled for oversized kernels. Returns false on any
    /// compile or launch failure; the caller falls back to the host writer with an
    /// untouched output (this lane is default OFF and pod-gated — see
    /// `STWO_CUDA_WITNESS_JIT`).
    #[allow(clippy::too_many_arguments)]
    pub fn stwo_cuda_jit_witness_launch(
        source: *const core::ffi::c_char,
        kernel_name: *const core::ffi::c_char,
        cache_key: u64,
        input_cols: *const *const u32,
        table_bases: *const *const u32,
        table_strides: *const u32,
        out_cols: *const *mut u32,
        mult_counts: *const *mut u32,
        lookup_words: *mut u32,
        sub_words: *mut u32,
        row_count: u32,
        relax_opt: bool,
        // Stage B′: stream to launch on. Null = legacy default stream (pre-B′).
        stream: *mut core::ffi::c_void,
    ) -> bool;

    /// Strict-AOT two-phase witness launch. Resolves both cached phase functions
    /// before enqueueing phase 0 then phase 1 on the same stream. `phase_scratch`
    /// may be null only for a plan whose generated kernels never dereference it.
    #[allow(clippy::too_many_arguments)]
    pub fn stwo_cuda_jit_witness_phase_pair_launch(
        kernel_names: *const *const core::ffi::c_char,
        cache_keys: *const u64,
        input_cols: *const *const u32,
        table_bases: *const *const u32,
        table_strides: *const u32,
        out_cols: *const *mut u32,
        mult_counts: *const *mut u32,
        lookup_words: *mut u32,
        sub_words: *mut u32,
        phase_scratch: *mut u32,
        row_count: u32,
        stream: *mut core::ffi::c_void,
    ) -> bool;

    // Stage B′ fan-out primitives (see cuda_mem_pool.cu). `stwo_fanout_stream`
    // returns pool stream `i` (round-robin) as an opaque handle; `fork`/`join`
    // are the thread-safe (fresh-event) bridges around a lane's stream work.
    pub fn stwo_fanout_stream(i: i32) -> *mut core::ffi::c_void;
    pub fn stwo_fanout_fork(stream: *mut core::ffi::c_void);
    pub fn stwo_fanout_join(stream: *mut core::ffi::c_void);

    // Resource-owning execution context for one resident proof (design §19,
    // cuda_exec_context.cu): an owned non-blocking stream + its own never-release
    // memory pool. Every function returns a CUDA status (0 = success); context
    // creation fails closed when an isolated pool cannot be created.
    pub fn stwo_cuda_device_snapshot(
        out_count: *mut u32,
        out_current: *mut u32,
        out_sm_major: *mut u32,
        out_sm_minor: *mut u32,
    ) -> i32;
    pub fn stwo_exec_context_create(out_handle: *mut *mut core::ffi::c_void) -> i32;
    pub fn stwo_exec_context_destroy(handle: *mut core::ffi::c_void) -> i32;
    pub fn stwo_exec_context_sync(handle: *mut core::ffi::c_void) -> i32;
    pub fn stwo_exec_context_pool_current(
        handle: *mut core::ffi::c_void,
        used_current: *mut usize,
        reserved_current: *mut usize,
    ) -> i32;
    pub fn stwo_exec_context_stream_sync(
        handle: *mut core::ffi::c_void,
        stream: *mut core::ffi::c_void,
    ) -> i32;
    pub fn stwo_exec_context_stream(
        handle: *mut core::ffi::c_void,
        out_stream: *mut *mut core::ffi::c_void,
    ) -> i32;
    pub fn stwo_exec_context_device(handle: *mut core::ffi::c_void, out_device: *mut i32) -> i32;
    pub fn stwo_exec_context_timing_begin(
        handle: *mut core::ffi::c_void,
        out_interval_capacity: *mut u32,
    ) -> i32;
    pub fn stwo_exec_context_timing_mark(handle: *mut core::ffi::c_void) -> i32;
    pub fn stwo_exec_context_timing_elapsed(
        handle: *mut core::ffi::c_void,
        out_elapsed_ms: *mut f32,
        capacity: u32,
        out_count: *mut u32,
    ) -> i32;
    pub fn stwo_exec_context_lane_count(handle: *mut core::ffi::c_void, out_count: *mut u32)
        -> i32;
    pub fn stwo_exec_context_lane_stream(
        handle: *mut core::ffi::c_void,
        lane: u32,
        out_stream: *mut *mut core::ffi::c_void,
    ) -> i32;
    pub fn stwo_exec_context_lane_fork(handle: *mut core::ffi::c_void, lane: u32) -> i32;
    pub fn stwo_exec_context_lane_join(handle: *mut core::ffi::c_void, lane: u32) -> i32;
    pub fn stwo_exec_context_join_all_lanes(handle: *mut core::ffi::c_void) -> i32;
    pub fn stwo_exec_context_alloc_u32(
        handle: *mut core::ffi::c_void,
        count: usize,
        out_ptr: *mut *mut u32,
    ) -> i32;
    pub fn stwo_exec_context_free_u32(handle: *mut core::ffi::c_void, ptr: *mut u32) -> i32;
    pub fn stwo_exec_context_memset_async(
        handle: *mut core::ffi::c_void,
        dst: *mut core::ffi::c_void,
        value: i32,
        bytes: usize,
    ) -> i32;
    pub fn stwo_exec_context_fill_u32_async(
        handle: *mut core::ffi::c_void,
        dst: *mut u32,
        value: u32,
        count: usize,
    ) -> i32;
    pub fn stwo_exec_context_memcpy_d2d_async(
        handle: *mut core::ffi::c_void,
        dst: *mut core::ffi::c_void,
        src: *const core::ffi::c_void,
        bytes: usize,
    ) -> i32;
    pub fn stwo_exec_context_memcpy_h2d_async(
        handle: *mut core::ffi::c_void,
        dst: *mut core::ffi::c_void,
        src: *const core::ffi::c_void,
        bytes: usize,
    ) -> i32;
    pub fn stwo_exec_context_memcpy_d2h_async(
        handle: *mut core::ffi::c_void,
        dst: *mut core::ffi::c_void,
        src: *const core::ffi::c_void,
        bytes: usize,
    ) -> i32;

    // Whole-allocation VMM storage. One handle owns a stable virtual address and
    // admits only consecutive reclaim/remap generations.
    pub fn stwo_vmm_allocation_create(
        context_handle: *mut core::ffi::c_void,
        requested_bytes: usize,
        out_handle: *mut *mut core::ffi::c_void,
        out_ptr: *mut *mut core::ffi::c_void,
        out_mapped_bytes: *mut usize,
        out_granularity: *mut usize,
    ) -> i32;
    pub fn stwo_vmm_allocation_unmap_release(
        handle: *mut core::ffi::c_void,
        context_handle: *mut core::ffi::c_void,
        expected_generation: u32,
    ) -> i32;
    pub fn stwo_vmm_allocation_remap_next(
        handle: *mut core::ffi::c_void,
        context_handle: *mut core::ffi::c_void,
        current_generation: u32,
        next_generation: u32,
    ) -> i32;
    pub fn stwo_vmm_allocation_destroy(handle: *mut core::ffi::c_void) -> i32;

    // Dedicated one-owner/one-peer CUDA IPC exchange storage. The memory and
    // event handles are exactly CUDA_IPC_HANDLE_SIZE (64) opaque bytes.
    pub fn stwo_ipc_exchange_context_uuid(
        context_handle: *mut core::ffi::c_void,
        out_uuid: *mut u8,
    ) -> i32;
    #[allow(clippy::too_many_arguments)]
    pub fn stwo_ipc_exchange_owner_create(
        context_handle: *mut core::ffi::c_void,
        logical_bytes: usize,
        initial_generation: u64,
        expected_owner_uuid: *const u8,
        out_handle: *mut *mut core::ffi::c_void,
        out_pointer: *mut *mut core::ffi::c_void,
        out_allocation_bytes: *mut usize,
        out_memory_handle: *mut u8,
        out_ready_event_handle: *mut u8,
        out_consumed_event_handle: *mut u8,
    ) -> i32;
    pub fn stwo_ipc_exchange_owner_publish(
        handle: *mut core::ffi::c_void,
        context_handle: *mut core::ffi::c_void,
        source: *const core::ffi::c_void,
        bytes: usize,
        generation: u64,
    ) -> i32;
    pub fn stwo_ipc_exchange_owner_reclaim(
        handle: *mut core::ffi::c_void,
        context_handle: *mut core::ffi::c_void,
        generation: u64,
    ) -> i32;
    pub fn stwo_ipc_exchange_owner_mark_peer_closed(
        handle: *mut core::ffi::c_void,
        context_handle: *mut core::ffi::c_void,
        generation: u64,
    ) -> i32;
    pub fn stwo_ipc_exchange_owner_close(
        handle: *mut core::ffi::c_void,
        context_handle: *mut core::ffi::c_void,
    ) -> i32;
    #[allow(clippy::too_many_arguments)]
    pub fn stwo_ipc_exchange_import_open(
        context_handle: *mut core::ffi::c_void,
        logical_bytes: usize,
        allocation_bytes: usize,
        initial_generation: u64,
        expected_peer_uuid: *const u8,
        memory_handle: *const u8,
        ready_event_handle: *const u8,
        consumed_event_handle: *const u8,
        out_handle: *mut *mut core::ffi::c_void,
        out_remote_pointer: *mut *mut core::ffi::c_void,
    ) -> i32;
    pub fn stwo_ipc_exchange_import_consume(
        handle: *mut core::ffi::c_void,
        context_handle: *mut core::ffi::c_void,
        destination: *mut core::ffi::c_void,
        bytes: usize,
        generation: u64,
    ) -> i32;
    pub fn stwo_ipc_exchange_import_arm_next(
        handle: *mut core::ffi::c_void,
        context_handle: *mut core::ffi::c_void,
        next_generation: u64,
    ) -> i32;
    pub fn stwo_ipc_exchange_import_close(
        handle: *mut core::ffi::c_void,
        context_handle: *mut core::ffi::c_void,
        generation: u64,
    ) -> i32;
    pub fn stwo_ipc_exchange_import_destroy(handle: *mut core::ffi::c_void) -> i32;

    // Opaque CUDA graph lifecycle rooted on the context main stream. Explicit
    // proof-owned lane fork/join edges admit auxiliary streams into the same
    // captured segment; host transcript work remains outside.
    pub fn stwo_graph_capture_begin(handle: *mut core::ffi::c_void) -> i32;
    pub fn stwo_graph_capture_end(
        handle: *mut core::ffi::c_void,
        out_exec: *mut *mut core::ffi::c_void,
        out_kernel_nodes: *mut u64,
    ) -> i32;
    pub fn stwo_graph_capture_abort(handle: *mut core::ffi::c_void) -> i32;
    pub fn stwo_graph_launch(
        exec_handle: *mut core::ffi::c_void,
        context_handle: *mut core::ffi::c_void,
    ) -> i32;
    pub fn stwo_graph_destroy(exec_handle: *mut core::ffi::c_void) -> i32;

    // Ordinary-Blake2s Fiat-Shamir transcript kernels. The 16-word state,
    // mirror snapshots, all sources, and all outputs are caller-owned device
    // arena ranges. Every operation is enqueued on the explicit proof stream.
    pub fn stwo_blake2s_transcript_init_on(
        state: *mut u32,
        seed: *const u32,
        seed_snapshot: *mut u32,
        initial_chain: u64,
        stream: *mut core::ffi::c_void,
    ) -> i32;
    pub fn stwo_blake2s_transcript_mix_words_on(
        state: *mut u32,
        expected_step: u32,
        expected_chain: u64,
        next_chain: u64,
        source: *const u32,
        n_words: u32,
        validate_m31: u32,
        input_snapshot: *mut u32,
        boundary_snapshot: *mut u32,
        stream: *mut core::ffi::c_void,
    ) -> i32;
    pub fn stwo_blake2s_transcript_absorb_pow_on(
        state: *mut u32,
        expected_step: u32,
        expected_chain: u64,
        next_chain: u64,
        nonce_words: *const u32,
        pow_bits: u32,
        input_snapshot: *mut u32,
        boundary_snapshot: *mut u32,
        stream: *mut core::ffi::c_void,
    ) -> i32;
    pub fn stwo_blake2s_transcript_draw_u32s_on(
        state: *mut u32,
        expected_step: u32,
        expected_chain: u64,
        next_chain: u64,
        output: *mut u32,
        output_snapshot: *mut u32,
        boundary_snapshot: *mut u32,
        stream: *mut core::ffi::c_void,
    ) -> i32;
    pub fn stwo_blake2s_transcript_draw_secure_on(
        state: *mut u32,
        expected_step: u32,
        expected_chain: u64,
        next_chain: u64,
        n_felts: u32,
        max_rejection_rounds: u32,
        output: *mut u32,
        output_snapshot: *mut u32,
        boundary_snapshot: *mut u32,
        stream: *mut core::ffi::c_void,
    ) -> i32;
    pub fn stwo_blake2s_transcript_draw_queries_on(
        state: *mut u32,
        expected_step: u32,
        expected_chain: u64,
        next_chain: u64,
        log_domain_size: u32,
        n_queries: u32,
        output: *mut u32,
        output_snapshot: *mut u32,
        boundary_snapshot: *mut u32,
        stream: *mut core::ffi::c_void,
    ) -> i32;

    // Truth oracle for the witness-JIT computed deduces (ISA-V3 kinds 2-11):
    // runs the exact `stwo_wit_deduce_*` device functions the JIT kernels embed
    // from a precompiled kernel (see `stwo_wit_deduce_oracle.cu`), so the pod
    // ladder can compare against the host `fast_deduction` before trusting any
    // JIT kernel. Buffers are flat per the recorder shapes (kind 2: 72->72;
    // kind 3: 1->56; kinds 4-7: 56->28; kind 8: 1->30; kind 9: 10->10;
    // kind 10: 32->32; kind 11: 42->42 words per item). Returns 0 on success;
    // nonzero means "no data" (unknown kind, table init failure, CUDA error) —
    // never zeros.
    pub fn stwo_wit_deduce_oracle_run(
        kind: u32,
        h_in: *const u32,
        h_out: *mut u32,
        n_items: u32,
    ) -> i32;

    // Checked borrowed registration validates all 56 host pointers and rows,
    // returns success for the exact already-active table, rejects any different
    // active table, and commits host runtime state only after device publication
    // completes successfully.
    pub fn stwo_pedersen_table_init_borrowed_checked(columns: *const *mut u32, n_rows: u32) -> i32;
    // Legacy ASSERT wrapper retained for non-formal callers.
    pub fn pedersen_table_init(columns: *const *mut u32, n_rows: u32);

    // Device DAG (B2): generalized multiplicity count feed over a witness
    // kernel's word-major sub buffer (see witness_feed_counts.cu). All pointer
    // args are DEVICE pointers; descs is the flat 14-u32-stride descriptor
    // array. Returns 0 on success.
    // Commit fusion (C2): the top K Merkle levels in one launch (see the tail
    // kernel in blake2s.cu). out_levels is a DEVICE array of per-level output
    // pointers; level l holds first_size >> (l+1) hashes.
    pub fn stwo_blake2s_tail(
        first_dev: *const Blake2sHash,
        first_size: u32,
        out_levels_dev: *const *mut Blake2sHash,
        n_levels: u32,
    ) -> i32;
    pub fn stwo_blake2s_tail_on(
        first_dev: *const Blake2sHash,
        first_size: u32,
        out_levels_dev: *const *mut Blake2sHash,
        n_levels: u32,
        stream: *mut core::ffi::c_void,
    ) -> i32;

    // Device edge (B3): blake_round's sub buffer -> blake_g's row-major input
    // buffer (the certified hand lane's ABI). See blake_witness.cu.
    pub fn stwo_blake_g_inputs_from_sub(
        producer_sub_dev: *const u32,
        producer_rows: u32,
        word_base: u32,
        n_instances: u32,
        consumer_rows: u32,
        out_row_major_dev: *mut u32,
    ) -> i32;

    // Device DAG (B3): gather a consumer's input columns from a producer's
    // word-major sub buffer (see witness_edge_gather.cu). Padding rows
    // replicate the first packed row, matching the host resize rule.
    pub fn stwo_witness_edge_gather(
        producer_sub_dev: *const u32,
        producer_rows: u32,
        word_base: u32,
        words_per_instance: u32,
        n_instances: u32,
        consumer_rows: u32,
        consumer_cols_dev: *const *mut u32,
    ) -> i32;
    #[allow(clippy::too_many_arguments)]
    pub fn stwo_witness_input_gather_on(
        producer_subs_dev: *const *const u32,
        edge_descs_dev: *const u32,
        n_edges: u32,
        input_width: u32,
        total_real_rows: u32,
        consumer_rows: u32,
        consumer_cols_dev: *const *mut u32,
        include_enabler: u32,
        include_iota: u32,
        stream: *mut c_void,
    ) -> i32;
    #[allow(clippy::too_many_arguments)]
    pub fn stwo_witness_input_seed_on(
        scalars_dev: *const u32,
        n_scalars: u32,
        n_real_rows: u32,
        consumer_rows: u32,
        consumer_cols_dev: *const *mut u32,
        include_enabler: u32,
        include_iota: u32,
        stream: *mut c_void,
    ) -> i32;
    #[allow(clippy::too_many_arguments)]
    pub fn stwo_witness_casm_input_scatter_on(
        rows_dev: *const u32,
        n_real: u32,
        consumer_rows: u32,
        pc_dev: *mut u32,
        ap_dev: *mut u32,
        fp_dev: *mut u32,
        enabler_dev: *mut u32,
        iota_dev: *mut u32,
        stream: *mut c_void,
    ) -> i32;
    pub fn stwo_witness_input_compact_sort_temp_bytes(rows: u32, out_bytes: *mut usize) -> i32;
    pub fn stwo_witness_input_compact_scan_temp_bytes(rows: u32, out_bytes: *mut usize) -> i32;
    #[allow(clippy::too_many_arguments)]
    pub fn stwo_witness_input_compact_on(
        producer_subs_dev: *const *const u32,
        edge_descs_dev: *const u32,
        n_edges: u32,
        tuple_words: u32,
        key_words: u32,
        total_rows: u32,
        sort_rows: u32,
        consumer_rows: u32,
        n_inputs: u32,
        consumer_cols_dev: *const *mut u32,
        enabler_slot: u32,
        iota_slot: u32,
        multiplicity_slot: u32,
        tuples_dev: *mut u32,
        keys_a_dev: *mut u32,
        keys_b_dev: *mut u32,
        indices_a_dev: *mut u32,
        indices_b_dev: *mut u32,
        heads_dev: *mut u32,
        positions_dev: *mut u32,
        n_unique_dev: *mut u32,
        sort_temp_dev: *mut c_void,
        sort_temp_bytes: usize,
        scan_temp_dev: *mut c_void,
        scan_temp_bytes: usize,
        stream: *mut c_void,
    ) -> i32;

    /// Capture-safe fixed-table BaseTrace/LookupInputs materialization from
    /// stable device descriptor and pointer tables.
    #[allow(clippy::too_many_arguments)]
    pub fn stwo_fixed_table_materialize_on(
        source_columns_dev: *const *const u32,
        multiplicity_columns_dev: *const *const u32,
        trace_multiplicity_columns_dev: *const u32,
        trace_outputs_dev: *const *mut u32,
        n_trace_outputs: u32,
        lookup_descriptors_dev: *const u32,
        lookup_outputs_dev: *const *mut u32,
        n_lookup_outputs: u32,
        row_count: u32,
        stream: *mut c_void,
    ) -> i32;

    pub fn stwo_witness_feed_counts(
        sub_words_dev: *const u32,
        column_length: u32,
        descs_dev: *const u32,
        n_descs: u32,
        luts_dev: *const *const u32,
        counts_dev: *const *mut u32,
    ) -> i32;
    pub fn stwo_witness_feed_counts_on(
        sub_words_dev: *const u32,
        column_length: u32,
        descs_dev: *const u32,
        n_descs: u32,
        luts_dev: *const *const u32,
        counts_dev: *const *mut u32,
        stream: *mut c_void,
    ) -> i32;
    // Step 4.3 privatized variant of the count feed: per-block shared-memory
    // histograms for descriptors whose touched table footprint fits 48KB
    // static shared, block-local atomics, unconditional global merge;
    // oversized families keep the global-atomic path inside the same launch.
    // Byte-identical count slabs (wrapping u32 adds are commutative and
    // associative). Same ABI as stwo_witness_feed_counts[_on].
    pub fn stwo_witness_feed_counts_privatized(
        sub_words_dev: *const u32,
        column_length: u32,
        descs_dev: *const u32,
        n_descs: u32,
        luts_dev: *const *const u32,
        counts_dev: *const *mut u32,
    ) -> i32;
    pub fn stwo_witness_feed_counts_privatized_on(
        sub_words_dev: *const u32,
        column_length: u32,
        descs_dev: *const u32,
        n_descs: u32,
        luts_dev: *const *const u32,
        counts_dev: *const *mut u32,
        stream: *mut c_void,
    ) -> i32;
    pub fn stwo_witness_feed_clear_on(
        destinations_dev: *const *mut u32,
        lengths_dev: *const u32,
        n_destinations: u32,
        max_words: u32,
        stream: *mut c_void,
    ) -> i32;

    /// Allocation-free final line interpolation, degree validation, and direct
    /// row-major transcript-input emission.
    pub fn stwo_fri_last_layer_on(
        evaluation: *const u32,
        evaluation_stride: u32,
        log_size: u32,
        inverse_twiddles: *const u32,
        inverse_twiddle_words: u32,
        log_degree_bound: u32,
        coefficients: *mut u32,
        degree_error: *mut u32,
        transcript_coefficients: *mut u32,
        stream: *mut c_void,
    ) -> i32;

    /// Persistent Blake2s nonce search over the SIMD grind lattice
    /// `{(hi << 32) | low : 0 <= low < 2^20}` from the current device
    /// transcript state. Publishes the numerically smallest qualifying
    /// lattice nonce, which is byte-identical to the SIMD reference grind
    /// (its hi-ascending, low-ascending scan order equals numeric order on
    /// the lattice).
    pub fn stwo_blake2s_pow_persistent_on(
        transcript_state: *const u32,
        pow_bits: u32,
        prefix_digest: *mut u32,
        best_nonce: *mut u64,
        completed_blocks: *mut u32,
        transcript_nonce: *mut u32,
        stream: *mut c_void,
    ) -> i32;

    /// Search one global SIMD-lattice tile on one fleet rank. Rank residues
    /// are disjoint and exhaustive; the output is the rank-local minimum or
    /// `u64::MAX` when the tile contains no qualifying nonce for this rank.
    #[allow(clippy::too_many_arguments)]
    pub fn stwo_blake2s_pow_rank_tile_on(
        transcript_state: *const u32,
        pow_bits: u32,
        rank_count: u32,
        rank: u32,
        tile_start: u64,
        tile_end: u64,
        grid_blocks: u32,
        prefix_digest: *mut u32,
        best_nonce: *mut u64,
        stream: *mut c_void,
    ) -> i32;

    pub fn stwo_blake2s_sparse_leaf_group_on(
        leaf_indices: *const u32,
        leaf_count: *const u32,
        max_leaf_count: u32,
        group_n_cols: u32,
        columns: *const *mut u32,
        column_log_sizes: *const u32,
        lifting_log_size: u32,
        cols_done: u32,
        is_final: u32,
        states: *mut Blake2sHash,
        stream: *mut c_void,
    ) -> i32;

    pub fn stwo_decommit_normalize_queries_on(
        raw_queries: *const u32,
        raw_query_count: u32,
        query_log_size: u32,
        tree_count: u32,
        unique_queries: *mut u32,
        unique_count: *mut u32,
        assembly: *mut u32,
        assembly_capacity_words: u32,
        stream: *mut c_void,
    ) -> i32;
    pub fn stwo_decommit_prepare_trace_queries_on(
        unique_queries: *const u32,
        unique_count: *const u32,
        max_queries: u32,
        source_log_size: u32,
        tree_log_size: u32,
        leaf_log_size: u32,
        unretained_bottom_layers: u32,
        mapped_queries: *mut u32,
        mapped_count: *mut u32,
        walk_queries: *mut u32,
        walk_count: *mut u32,
        leaf_indices: *mut u32,
        leaf_count: *mut u32,
        stream: *mut c_void,
    ) -> i32;
    pub fn stwo_decommit_pack_trace_group_on(
        tree_index: u32,
        total_column_count: u32,
        first_column: u32,
        group_column_count: u32,
        columns: *const *const u32,
        column_log_sizes: *const u32,
        lifting_log_size: u32,
        mapped_queries: *const u32,
        mapped_count: *const u32,
        max_queries: u32,
        assembly: *mut u32,
        assembly_capacity_words: u32,
        stream: *mut c_void,
    ) -> i32;
    pub fn stwo_decommit_sparse_parent_on(
        child_indices: *const u32,
        child_hashes: *const Blake2sHash,
        child_count: *const u32,
        max_child_count: u32,
        parent_indices: *mut u32,
        parent_hashes: *mut Blake2sHash,
        parent_count: *mut u32,
        stream: *mut c_void,
    ) -> i32;
    pub fn stwo_decommit_assemble_trace_on(
        tree_index: u32,
        tree_role: u32,
        leaf_log_size: u32,
        first_retained_log_size: u32,
        column_count: u32,
        mapped_count: *const u32,
        max_queries: u32,
        walk_queries: *mut u32,
        walk_scratch: *mut u32,
        walk_count: *const u32,
        retained_layers_by_log: *const *const Blake2sHash,
        sparse_indices: *const u32,
        sparse_hashes: *const Blake2sHash,
        sparse_level_offsets: *const u32,
        sparse_level_counts: *const u32,
        sparse_level_count: u32,
        assembly: *mut u32,
        assembly_capacity_words: u32,
        stream: *mut c_void,
    ) -> i32;
    pub fn stwo_decommit_prepare_fri_queries_on(
        unique_queries: *const u32,
        unique_count: *const u32,
        max_queries: u32,
        cumulative_fold: u32,
        fold_step: u32,
        log_rows_per_leaf: u32,
        tree_queries: *mut u32,
        tree_query_count: *mut u32,
        expanded_positions: *mut u32,
        expanded_count: *mut u32,
        walk_queries: *mut u32,
        walk_count: *mut u32,
        stream: *mut c_void,
    ) -> i32;
    pub fn stwo_decommit_assemble_fri_on(
        tree_index: u32,
        leaf_log_size: u32,
        tree_queries: *const u32,
        tree_query_count: *const u32,
        expanded_positions: *const u32,
        expanded_count: *const u32,
        coordinate_columns: *const *const u32,
        walk_queries: *mut u32,
        walk_scratch: *mut u32,
        walk_count: *const u32,
        retained_layers_by_log: *const *const Blake2sHash,
        assembly: *mut u32,
        assembly_capacity_words: u32,
        stream: *mut c_void,
    ) -> i32;
    pub fn stwo_relation_scan_tail_on(
        output_tables: *const *const *mut u32,
        claimed_sums: *const *mut u32,
        geometry: *const u32,
        n_instances: u32,
        total_row_blocks: u32,
        partition_descriptors: *mut u32,
        descriptor_capacity_words: u32,
        stream: *mut c_void,
    ) -> i32;
    // Fused FRI triple fold (Step 3.4, `fri_fold_fused.cu`): one 8-to-1 kernel
    // replacing the three per-fold launches of a full `fold_step == 3` round.
    // Byte-identical to that sequence; see the kernel-file comment.
    pub fn stwo_fri_fold_fused3_on(
        gpu_domain: *const u32,
        twiddle_offset_0: u32,
        twiddle_offset_1: u32,
        twiddle_offset_2: u32,
        n: u32,
        first_fold_is_circle: u32,
        eval_values: *const *mut u32,
        alpha: *const CudaSecureField,
        folded_values: *const *mut u32,
        stream: *mut c_void,
    ) -> i32;
}

// --- ntt_leaf_fused ---
#[cfg_attr(stwo_cuda_link, link(name = "stwo_cuda_kernels", kind = "static"))]
extern "C" {
    /// Setup-time dynamic-shared-memory admission for the retained
    /// write+hash final N2B kernel selected by `log_n` (`ntt_leaf_fused.cu`).
    pub fn stwo_ntt_leaf_fused_configure(log_n: u32) -> i32;

    /// Retained twin of [`stwo_lde_n2b_hash16_on`]: stage and transform 16
    /// same-log full-lifting columns, WRITE the completed evaluations into
    /// `device_values` (kept resident for decommitment) AND absorb the same
    /// final tile into the leaf states — zero evaluation re-read for hashing.
    #[allow(clippy::too_many_arguments)]
    pub fn stwo_ntt_leaf_fused_on(
        coefficient_values: *const *const u32,
        coefficient_sizes: *const u32,
        device_values: *const *mut u32,
        log_n: u32,
        g_twiddles: *mut u32,
        twiddles_size: u32,
        eval_domain_size: u32,
        cols_done: u32,
        is_final: u32,
        states: *mut Blake2sHash,
        stream: *mut c_void,
    ) -> i32;

    /// Setup-time shared-memory admission for the domain-progressive final NTT
    /// tile sink. This is distinct from the retained streaming-leaf entry point
    /// so enabling one topology cannot mutate the other's admission contract.
    pub fn stwo_ntt_progressive_leaf_fused_configure(log_n: u32) -> i32;

    /// Transform one canonical 16-column same-log tile and place its final
    /// values directly into the progressive BLAKE2s pending block. Retained
    /// outputs selected by `retained_write_mask` are materialized byte-exactly;
    /// zero bits omit a dead completed-LDE write.
    #[allow(clippy::too_many_arguments)]
    pub fn stwo_ntt_progressive_leaf_fused_on(
        coefficient_values: *const *const u32,
        coefficient_sizes: *const u32,
        device_values: *const *mut u32,
        log_n: u32,
        g_twiddles: *mut u32,
        twiddles_size: u32,
        eval_domain_size: u32,
        cols_done: u32,
        retained_write_mask: u32,
        states: *mut ProgressiveBlake2sState,
        stream: *mut c_void,
    ) -> i32;

    /// Setup-time shared-memory admission for the candidate fixed16 compact
    /// terminal interval. Hardware qualification is required before selection.
    pub fn stwo_ntt_direct_compact_final16_configure(log_n: u32) -> i32;

    /// Complete `16 * tiles` prefinal columns in place and advance compact
    /// leaf states without a separate full-evaluation absorb pass.
    #[allow(clippy::too_many_arguments)]
    pub fn stwo_ntt_direct_compact_final16_on(
        device_values: *const *mut u32,
        log_n: u32,
        tiles: u32,
        g_twiddles: *mut u32,
        twiddles_size: u32,
        eval_domain_size: u32,
        cols_done: u32,
        initial_tail: *const CompactBlake2sTailDescriptor,
        states: *mut Blake2sHash,
        stream: *mut c_void,
    ) -> i32;

    /// Validate the additive eight-warp column-parallel terminal successor.
    /// Only final seven/eight-stage interval shapes are admitted.
    pub fn stwo_ntt_direct_compact_final16_col8_configure(log_n: u32) -> i32;

    /// Complete `16 * tiles` prefinal columns with eight producer warps over
    /// one shared row tile, then advance the compact leaf state in place.
    #[allow(clippy::too_many_arguments)]
    pub fn stwo_ntt_direct_compact_final16_col8_on(
        device_values: *const *mut u32,
        log_n: u32,
        tiles: u32,
        g_twiddles: *mut u32,
        twiddles_size: u32,
        eval_domain_size: u32,
        cols_done: u32,
        initial_tail: *const CompactBlake2sTailDescriptor,
        states: *mut Blake2sHash,
        stream: *mut c_void,
    ) -> i32;
}

#[cfg(test)]
mod direct_retained_b2n_contract_tests {
    use super::*;

    type DirectRetainedB2nFn = unsafe extern "C" fn(
        *const *const u32,
        *const *mut u32,
        u32,
        u32,
        *const u32,
        u32,
        u32,
        *mut c_void,
    ) -> i32;

    type StageTwoN2bFn =
        unsafe extern "C" fn(*const *mut u32, u32, u32, *mut u32, u32, u32, *mut c_void) -> i32;

    #[test]
    fn direct_retained_b2n_abi_is_linked() {
        let _: DirectRetainedB2nFn = stwo_ntt_b2n_columns_to_retained_on;
        let _: StageTwoN2bFn = stwo_ntt_n2b_columns_from_stage_two_on;
        let _: StageTwoN2bFn = stwo_ntt_n2b_columns_from_stage_two_before_circle_on;
        let _: StageTwoN2bFn = stwo_ntt_n2b_columns_from_stage_two_before_final_interval_on;
        let _: StageTwoN2bFn = stwo_ntt_n2b_columns_final_interval_before_circle_on;
    }

    fn optimized_partition(log_n: u32) -> Vec<u32> {
        match log_n {
            3..=12 => vec![log_n],
            13..=19 => [[6, 7], [6, 8], [8, 7], [8, 8], [6, 11], [8, 10], [8, 11]]
                [usize::try_from(log_n - 13).unwrap()]
            .to_vec(),
            20..=27 => [
                [6, 6, 8],
                [6, 8, 7],
                [6, 8, 8],
                [8, 8, 7],
                [8, 8, 8],
                [6, 8, 11],
                [8, 8, 10],
                [8, 8, 11],
            ][usize::try_from(log_n - 20).unwrap()]
            .to_vec(),
            28..=30 => [[6, 6, 6, 10], [6, 6, 6, 11], [6, 6, 8, 10]]
                [usize::try_from(log_n - 28).unwrap()]
            .to_vec(),
            _ => panic!("unsupported test log {log_n}"),
        }
    }

    #[test]
    fn stage_two_partition_covers_every_stage_once_and_keeps_later_boundaries() {
        for log_n in 3..=30 {
            let full = optimized_partition(log_n);
            assert_eq!(full.iter().sum::<u32>(), log_n);

            let mut direct = full.clone();
            direct[0] -= 1;
            assert_eq!(direct.iter().sum::<u32>(), log_n - 1);
            assert!(log_n < 13 || matches!(direct[0], 5 | 7));

            let mut stage = 2;
            for (index, stages) in direct.into_iter().enumerate() {
                let end = stage + stages - 1;
                if index > 0 {
                    assert_eq!(stage, 1 + full[..index].iter().sum::<u32>());
                }
                assert!(end <= log_n);
                stage = end + 1;
            }
            assert_eq!(stage, log_n + 1);
        }
    }

    #[test]
    fn rectangular_first_interval_transpose_is_a_total_address_permutation() {
        for (log_values_per_thread, log_warps_per_block) in [(3, 2), (4, 3)] {
            let values_per_thread = 1usize << log_values_per_thread;
            let warps = 1usize << log_warps_per_block;
            let groups = values_per_thread * warps;
            let mut loaded = vec![false; groups];

            for new_warp in 0..warps {
                for register in 0..values_per_thread {
                    let flat = new_warp * values_per_thread + register;
                    let old_i = flat >> log_warps_per_block;
                    let old_warp = flat & (warps - 1);
                    let stored = old_i * warps + old_warp;
                    let output = new_warp * values_per_thread + register;

                    assert_eq!(stored, flat);
                    assert_eq!(output, flat);
                    assert!(!loaded[stored]);
                    loaded[stored] = true;
                }
            }
            assert!(loaded.into_iter().all(|seen| seen));

            for log_stride in (0..log_warps_per_block).rev() {
                let stride = 1usize << log_stride;
                let mut touched = vec![false; values_per_thread];
                for gid in 0..values_per_thread / 2 {
                    let inner_group = gid & (stride - 1);
                    let inner_pair = gid >> log_stride;
                    let left = inner_group + (inner_pair << (log_stride + 1));
                    let right = left + stride;
                    assert!(!touched[left] && !touched[right]);
                    touched[left] = true;
                    touched[right] = true;
                }
                assert!(touched.into_iter().all(|seen| seen));
            }
        }
    }

    #[test]
    fn duplicate_image_is_byte_exact_first_zero_extended_n2b_layer() {
        const P: u64 = (1u64 << 31) - 1;
        for log_n in 3..=12 {
            let n = 1usize << log_n;
            for index in 0..n {
                let coefficient = (((index as u64 * 0x45d9_f3b) + log_n as u64) % P) as u32;
                for twiddle in [0, 1, P / 2, P - 1] {
                    let zero_times_twiddle = (0u64 * twiddle) % P;
                    let left = ((u64::from(coefficient) + zero_times_twiddle) % P) as u32;
                    let right = ((u64::from(coefficient) + P - zero_times_twiddle) % P) as u32;
                    assert_eq!(left.to_le_bytes(), coefficient.to_le_bytes());
                    assert_eq!(right.to_le_bytes(), coefficient.to_le_bytes());
                }
            }
        }
    }

    #[test]
    fn cuda_terminal_writer_is_fused_and_fail_closed() {
        let source = include_str!("../cuda/ifft.cu");
        for required in [
            "output_ntt_start[output_index + (1u << log_n)] = vals[i]",
            "output_start[left_index + (1u << log_n)] = left_r",
            "output_start[right_index + (1u << log_n)] = right_r",
            "DUPLICATE_TO_RETAINED && start_stage + stages - 1 != log_n",
            "DUPLICATE_TO_RETAINED && i + 1 == count",
            "b2n_columns_out_of_place_entry<false>",
            "b2n_columns_out_of_place_entry<true>",
        ] {
            assert!(
                source.contains(required),
                "missing CUDA contract: {required}"
            );
        }
    }

    #[test]
    fn cuda_stage_two_successor_is_rectangular_exact_and_fail_closed() {
        let source = include_str!("../cuda/rfft.cu");
        for required in [
            "ntt_n2b_nofinal_stage_batch_on<3, 2>",
            "ntt_n2b_nofinal_stage_batch_on<4, 3>",
            "config[0] - skipped_stages",
            "first_stage > 2",
            "eval_domain_size != (1u << (log_n - 1))",
            "stwo_ntt_n2b_columns_from_stage_two_on",
            "stwo_ntt_n2b_columns_from_stage_two_before_circle_on",
            "stwo_ntt_n2b_columns_from_stage_two_before_final_interval_on",
            "stwo_ntt_n2b_columns_final_interval_before_circle_on",
            "eval_domain_size, 2, cuda_stream",
            "false, false",
        ] {
            assert!(
                source.contains(required),
                "missing CUDA stage-two contract: {required}"
            );
        }
    }
}
