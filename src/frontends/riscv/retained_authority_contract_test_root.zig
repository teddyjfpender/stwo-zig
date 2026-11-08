//! Focused retained live regression owner.
test {
    _ = @import("air/lang/tests/function_activation_logup_test.zig");
    _ = @import("air/guest_precompile/tests/sha256_memory_caller_test.zig");
    _ = @import("recursion/air/tests/blake3_draw_witness_test.zig");
    _ = @import("air/guest_precompile/tests/relation_test.zig");
    _ = @import("recursion/tests/segment_range_authority_test.zig");
}
