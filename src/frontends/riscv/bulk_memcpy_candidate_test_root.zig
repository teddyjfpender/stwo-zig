//! Fast nonproduction edit loop for the word-granular memcpy candidate.

test {
    _ = @import("air/guest_precompile/bulk_memcpy_caller_candidate_v1_test.zig");
    _ = @import("air/guest_precompile/bulk_memcpy_trace_v1_test.zig");
    _ = @import("air/guest_precompile/bulk_memcpy_word_candidate_v1_test.zig");
    _ = @import("air/guest_precompile/bulk_memcpy_vm_profile_v1.zig");
    _ = @import("isa/bulk_memcpy_candidate_v1.zig");
    _ = @import("isa/bulk_memcpy_private_registry_v1.zig");
    _ = @import("isa/ethereum_bulk_memcpy_candidate_v1.zig");
    _ = @import("prover/guest_precompile/ethereum_bulk_memcpy_candidate_decode_v1.zig");
    _ = @import("runner/ethereum_bulk_memcpy_candidate_result_v1.zig");
    _ = @import("runner/ethereum_candidate_combined_result_v1.zig");
    _ = @import("runner/guest_precompile/bulk_memcpy_candidate_dispatch_v1.zig");
    _ = @import("runner/guest_precompile/ethereum_bulk_memcpy_candidate_v1.zig");
    _ = @import("runner/guest_precompile/ethereum_bulk_memcpy_candidate_test.zig");
    _ = @import("runner/guest_precompile/ethereum_candidate_combined_dispatch_v1.zig");
    _ = @import("runner/guest_precompile/ethereum_candidate_combined_elf_receipt_v1.zig");
    _ = @import("runner/guest_precompile/ethereum_candidate_combined_test.zig");
    _ = @import("runner/guest_precompile/ethereum_candidate_combined_v1.zig");
    _ = @import("runner/guest_precompile/bulk_memcpy_v1_test.zig");
}
