comptime {
    _ = @import("runner/balanced_schedule.zig");
    _ = @import("recursion/air/blake3_public_subtrees.zig");
    _ = @import("recursion/blake3_stream_frontier.zig");
    _ = @import("recursion/blake3_exact_forest_transport.zig");
    _ = @import("recursion/blake3_exact_root_aggregate_test.zig");
}
