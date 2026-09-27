comptime {
    _ = @import("prover/block_v5_blake3_words_tail_test_v1.zig");
}
test "original words tail body: real shared Builder and routed AIR source retention" {
    @import("block_v5_blake3_words_tail_codegen_v1.zig").stwo_original_words_tail_body_gate();
}
