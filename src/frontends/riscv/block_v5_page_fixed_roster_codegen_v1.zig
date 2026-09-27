//! Addresses retain complete production bodies; no factory, PCS commitment,
//! private witness, original proof verifier or key derivation is invoked.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
fn Bodies(comptime kind: @import("prover/block_v5_memory_source_page_semantic_columns_v1.zig").Kind) type {
    @setEvalBranchQuota(30_000);
    const Public = @import("recursion/block_v5_memory_source_page_recursive_fixed_public_v1.zig").ForKind(kind);
    const Sources = @import("recursion/block_v5_memory_source_page_recursive_fixed_sources_v1.zig").ForKind(kind);
    const Roster = @import("recursion/block_v5_memory_source_page_recursive_fixed_roster_v1.zig").ForKind(kind);
    const Bus = @import("recursion/block_v5_memory_source_page_recursive_public_bus_v1.zig").ForKind(kind);
    return struct {
        fn keep() void {
            inline for (.{ &Public.Owned.derive, &Public.Owned.validateAgainst, &Public.Owned.deinit, &Sources.derive, &Sources.validateAgainst, &Roster.Owned.derive, &Roster.Owned.validateAgainst, &Roster.Owned.validateLive, &Roster.Owned.deinit, &Roster.ForBackend(Cpu).deriveKey, &Bus.prepare }) |body| std.mem.doNotOptimizeAway(body);
        }
    };
}
pub export fn stwo_page_fixed_roster_body_gate() void {
    @setEvalBranchQuota(100_000);
    Bodies(.raw).keep();
    Bodies(.fold).keep();
    // Original default private/roster and both old fused live families share
    // the edited kernels. Keep real bodies, including live value checks.
    std.mem.doNotOptimizeAway(&@import("recursion/air/block_v5_recursive_parent_fixed_sources_v1.zig").Owned.init);
    std.mem.doNotOptimizeAway(&@import("recursion/block_v5_recursive_parent_fixed_roster_v1.zig").Owned.init);
    std.mem.doNotOptimizeAway(&@import("recursion/block_v5_native_capacity_fused_recursive_public_bus_v1.zig").prepare);
    std.mem.doNotOptimizeAway(&@import("recursion/block_v5_caller_fused_recursive_public_bus_v1.zig").prepare);
}
