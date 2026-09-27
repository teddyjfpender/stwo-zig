//! Independent nonproving durable-source fixtures; actual receiver retained only.
const std = @import("std");
test "source PAGE durable root" {
    _ = @import("prover/block_v5_memory_source_page_durable_test_v1.zig");
}
test "source PAGE durable bodies: actual policy exporter reader original inventory and complete detached receiver" {
    const Policy = @import("prover/block_v5_memory_source_page_policy_file_v1.zig");
    const Loader = @import("prover/block_v5_memory_source_page_durable_loader_v1.zig").Loader;
    inline for (.{ &Policy.write, &Policy.read, &Policy.reconstruct, &@import("prover/block_v5_memory_source_page_policy_export_v1.zig").write, &Loader.init, &Loader.createJoin, &Loader.pageLoader, &Loader.withProofAllocator, &Loader.requireConsumed, &Loader.deinit, &@import("prover/block_v5_cpu_source_pages_detached_receive_v1.zig").verify }) |body| std.mem.doNotOptimizeAway(body);
}
