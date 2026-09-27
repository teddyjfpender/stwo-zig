//! Bounded shared runtime extractor recovery regressions. No AIR proof,
//! commitment, FRI, guest, device or segment invocation.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const Runtime = @import("../air/extract/runtime_program.zig");
const Symbolic = @import("../air/extract/symbolic.zig");
const Model = @import("../air/extract/model.zig");
const Program = @import("../air/constraint_program.zig").Builder(Symbolic.Scalar);
const Trace = @import("../runner/trace.zig");

fn oracle(a: std.mem.Allocator, family: Trace.OpcodeFamily) !engine.air.component_prover.OwnedLookupPolynomialProgram {
    // Old successful extraction recipe retained solely as a parity oracle;
    // failing allocators only enter the recoverable production constructors.
    var arena = Symbolic.Arena.init(a);
    defer arena.deinit();
    Symbolic.begin(&arena);
    defer Symbolic.end();
    const count = Program.mainColumnCount(family);
    var columns: [Trace.MAX_FAMILY_COLUMNS]Symbolic.Scalar = undefined;
    try Model.declareColumns(&arena, family, columns[0..count]);
    const events = (try Program.buildLookups(family, columns[0..count])).lookup_entries;
    return Runtime.ownLookupProgram(a, &arena, &events, count);
}
test "capacity fused runtime recoverable lookup extraction preserves every family's exact successful DAG and event roots" {
    for (0..Trace.N_FAMILIES) |index| {
        const family: Trace.OpcodeFamily = @enumFromInt(index);
        var expected = try oracle(std.testing.allocator, family);
        defer expected.deinit();
        var actual = try Runtime.buildLookups(std.testing.allocator, family);
        defer actual.deinit();
        try std.testing.expectEqualDeep(expected.nodes, actual.nodes);
        try std.testing.expectEqual(expected.column_count, actual.column_count);
        try std.testing.expectEqual(expected.batch_size, actual.batch_size);
        try std.testing.expectEqual(expected.entries.len, actual.entries.len);
        for (actual.entries, expected.entries) |have, want| {
            try std.testing.expectEqual(want.numerator, have.numerator);
            try std.testing.expectEqual(want.arity, have.arity);
            try std.testing.expectEqualSlices(u32, want.values[0..want.arity], have.values[0..have.arity]);
        }
    }
}
fn extractionFailure(a: std.mem.Allocator, family: Trace.OpcodeFamily) !void {
    var direct = try Runtime.build(a, family);
    defer direct.deinit();
    var lookup = try Runtime.buildLookups(a, family);
    defer lookup.deinit();
    try direct.validate();
    try lookup.validate();
}
fn authorityFailure(a: std.mem.Allocator) !void {
    const authority = @import("../air/lang/typed_lui_authority.zig").Authority.pinned();
    var direct = try Runtime.buildLuiFromAuthority(a, &authority);
    defer direct.deinit();
    var lookup = try Runtime.buildLuiLookupsFromAuthority(a, &authority);
    defer lookup.deinit();
    try direct.validate();
    try lookup.validate();
}
test "capacity fused runtime direct lookup and authority extraction propagate every allocation failure and clear installed arena" {
    for ([_]Trace.OpcodeFamily{ .base_alu_imm, .load_store }) |family|
        try std.testing.checkAllAllocationFailures(std.testing.allocator, extractionFailure, .{family});
    try std.testing.checkAllAllocationFailures(std.testing.allocator, authorityFailure, .{});

    // Ownership adapters must reject a failed graph before reading its inert
    // IDs or allocating/publishing an invalid program, even if called directly.
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var failed = Symbolic.Arena.initRecoverable(failing.allocator());
    defer failed.deinit();
    const inert = failed.column("failed-input");
    try std.testing.expectError(error.OutOfMemory, failed.checkAllocation());
    var partial_columns: [Trace.MAX_FAMILY_COLUMNS]Symbolic.Scalar = undefined;
    try std.testing.expectError(error.OutOfMemory, Model.declareColumns(&failed, .base_alu_imm, partial_columns[0..Program.mainColumnCount(.base_alu_imm)]));
    try std.testing.expectError(error.OutOfMemory, Runtime.ownDirectProgram(std.testing.allocator, &failed, &.{inert}, 1));
    const events = @import("../air/lookups/entry.zig").Builder(Symbolic.Scalar).List{};
    try std.testing.expectError(error.OutOfMemory, Runtime.ownLookupProgram(std.testing.allocator, &failed, &events, 1));

    // All failed transactions ran deferred symbolic.end: a genuine subsequent
    // successful construction must be possible on the same thread.
    var next = try Runtime.buildLookups(std.testing.allocator, .load_store);
    defer next.deinit();
    try next.validate();
}
