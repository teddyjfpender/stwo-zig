//! Retain every genuine provider/execution store body without invocation.
const std = @import("std");
const Execution = @import("prover/block_v5_recursive_execution_leaf_store_v1.zig");
const Providers = @import("prover/block_v5_recursive_provider_store_v1.zig");
fn retain(comptime T: type) void {
    inline for (.{ &T.Store.initWriter, &T.Store.initReader, &T.Store.put, &T.Store.takeFresh, &T.Store.proofBytes, &T.Store.deinit, &T.Store.filePins, &T.Store.requireVerified, &T.Store.sink, &T.Store.loader }) |body| std.mem.doNotOptimizeAway(body);
}
export fn stwo_recursive_leaf_store_body_gate() void {
    inline for (comptime std.meta.tags(Execution.Family)) |family| retain(Execution.ForFamily(family));
    inline for (comptime std.meta.tags(Providers.Family)) |family| retain(Providers.ForFamily(family));
}
test "leaf store bodies: all seven typed publication and original fresh-loading routes retained only" {
    std.mem.doNotOptimizeAway(&stwo_recursive_leaf_store_body_gate);
}
