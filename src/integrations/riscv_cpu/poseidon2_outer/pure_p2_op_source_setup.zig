//! Pinned source setup construction shared by independently framed OP routes.
//! This never chooses a wire flavor or weakens admission predicates.
const std = @import("std");
const R = @import("../word16_global_execution/services/roster.zig");
pub fn init(a: std.mem.Allocator, image: *const @import("../word16_execution/expected_image.zig").Owner, declaration: @import("../word16_global_execution/services/wire.zig").CpuDeclaration, metadata: *@import("../word16_execution/program_metadata.zig").Cache) !R.CpuSetup {
    return R.CpuSetup.initForOpWithAuthorityAndSuiteAndCaches(a, &image.authority, declaration.geometry, declaration.bridges, @import("../word16_execution/pcs_suite.zig").Suite.production(), .{ .program = metadata });
}
/// Use only after the new independently derived FIXED key has retained all
/// needed source information. Preserve the original legacy source root/logs.
pub fn retireLegacy(a: std.mem.Allocator, setup: *R.CpuSetup) !void {
    if (setup.key.root_only) return error.OpSourceFixedAlreadyRetired;
    const logs = try a.alloc(u32, setup.key.tree.columns.len);
    defer a.free(logs);
    for (setup.key.tree.columns, logs) |column, *log| log.* = column.log_size;
    var digest = try @import("../word16_global_execution/keccak/shared/key.zig").Key.rootOnly(a, setup.key.suite, setup.key.root, logs);
    errdefer digest.deinit();
    try setup.releaseFixedWitness();
    var old = setup.key;
    setup.key = digest;
    old.deinit();
}
