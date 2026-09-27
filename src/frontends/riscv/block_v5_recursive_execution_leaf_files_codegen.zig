//! Retain all three actual typed fresh-load/publication routes without calling.
const std = @import("std");
const Files = @import("prover/block_v5_recursive_execution_leaf_files_v1.zig");
pub export fn stwo_recursive_execution_leaf_files_body_gate() void {
    inline for (.{ Files.Family.caller_arithmetic, .caller_fused, .native_capacity_fused }) |family| {
        const T = Files.ForFamily(family);
        inline for (.{ &T.encode, &T.decodeMetadata, &T.View.verify, &T.loadFresh, &T.publish }) |body| std.mem.doNotOptimizeAway(body);
    }
}
