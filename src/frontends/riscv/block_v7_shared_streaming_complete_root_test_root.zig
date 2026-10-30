//! Explicit production complete CPU path with one authenticated epoch prefix.
test "v7 shared production execution reaches one detached complete root" {
    try @import("prover/tests/block_v7_streaming_complete_root_test.zig").qualify(true);
}
