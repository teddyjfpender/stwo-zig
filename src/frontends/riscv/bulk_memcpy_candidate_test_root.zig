//! Fast nonproduction edit loop for the word-granular memcpy candidate.

test {
    _ = @import("air/guest_precompile/tests/bulk_memcpy_caller_candidate_test.zig");
    _ = @import("isa/bulk_memcpy_candidate.zig");
    _ = @import("isa/bulk_memcpy_private_registry.zig");
    _ = @import("isa/ethereum_bulk_memcpy_candidate.zig");
    _ = @import("runner/ethereum_bulk_memcpy_candidate_result.zig");
    _ = @import("runner/ethereum_candidate_combined_result.zig");
    _ = @import("runner/guest_precompile/bulk_memcpy_candidate_dispatch.zig");
    _ = @import("runner/guest_precompile/ethereum_bulk_memcpy_candidate.zig");
    _ = @import("runner/guest_precompile/tests/ethereum_bulk_memcpy_candidate_test.zig");
    _ = @import("runner/guest_precompile/ethereum_candidate_combined_dispatch.zig");
    _ = @import("runner/guest_precompile/ethereum_candidate_combined_elf_receipt.zig");
    _ = @import("runner/guest_precompile/tests/ethereum_candidate_combined_test.zig");
    _ = @import("runner/guest_precompile/ethereum_candidate_combined.zig");
    _ = @import("runner/guest_precompile/tests/bulk_memcpy_test.zig");
}
