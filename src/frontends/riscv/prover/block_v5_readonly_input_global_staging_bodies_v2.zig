//! Actual production body retention. None of these functions is invoked by a test.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Stage = @import("block_v5_readonly_input_global_staging_v2.zig");
const Collection = @import("block_v5_readonly_input_collection_v1.zig");
const Roster = @import("block_v5_readonly_input_global_roster_v2.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Api = Stage.ForBackend(Cpu);
pub export fn readonly_global_staging_collect_body(a: *const std.mem.Allocator, dir: *const std.fs.Dir, collection: *const Collection.Owned, config: *const core.pcs.PcsConfig, limits: *const Stage.Limits, out: *Stage.Owned) callconv(.c) bool {
    out.* = Api.collect(a.*, dir.*, collection, config.*, limits.*) catch return false;
    return true;
}
pub export fn readonly_global_staging_prove_body(a: *const std.mem.Allocator, dir: *const std.fs.Dir, staged: *const Stage.Owned, authority: *const Roster.Authority, sealed: *const Seal.Sealed, pins: *const Seal.Pins, entries: [*]const Seal.Entry, n: usize, inverses: *const @import("block_v5_range16_inverse_table_v1.zig").Table, index: u32, out: *Stage.Pair) callconv(.c) bool {
    out.* = Api.proveStaged(a.*, dir.*, staged, authority, sealed.*, pins.*, entries[0..n], inverses, index) catch return false;
    return true;
}
pub export fn readonly_global_staging_bind_body(staged: *const Stage.Owned, collection: *Collection.Owned, out: *[32]u8) callconv(.c) bool {
    out.* = staged.bindRoster(collection) catch return false;
    return true;
}
test "global readonly staging: actual provider range collection replay prove and teardown bodies retained" {
    @setEvalBranchQuota(1_000_000);
    std.mem.doNotOptimizeAway(&readonly_global_staging_collect_body);
    std.mem.doNotOptimizeAway(&readonly_global_staging_prove_body);
    std.mem.doNotOptimizeAway(&readonly_global_staging_bind_body);
    std.mem.doNotOptimizeAway(&Stage.Pair.deinit);
    std.mem.doNotOptimizeAway(&Stage.Owned.deinit);
}
