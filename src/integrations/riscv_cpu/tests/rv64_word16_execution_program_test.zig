const std = @import("std");
const front = @import("stwo_riscv_frontend");
const X = front.rv64_air.word16_execution;
const Full = @import("../rv64_full.zig");
const Program = @import("../word16_execution/program.zig").Program;
const a = std.testing.allocator;
const AND: u32 = 0x0020f1b3;
fn branch(offset: u13) u32 {
    return 0x00000063 | (@as(u32, (offset >> 11) & 1) << 7) | (@as(u32, (offset >> 1) & 15) << 8) | (@as(u32, (offset >> 5) & 63) << 25) | (@as(u32, offset >> 12) << 31);
}
test "full execution program derives all immutable edges and binds invalid raw words" {
    const words = [_]u32{ branch(8), AND, 0, 0x00100073, 0x00008067, 0x00000073 };
    var program = try Program.init(a, .{ .base = 1024, .words = &words });
    defer program.deinit();
    try std.testing.expectEqual(@as(usize, 7), program.row_to_entry.len);
    const index = try program.lookup(1024);
    const first = try program.factIndex(index, false);
    const taken = try program.factIndex(index, true);
    try std.testing.expectEqual(first + 1, taken);
    try std.testing.expect(!program.row_taken[first] and program.row_taken[taken]);
    try std.testing.expectEqual(index, program.row_to_entry[taken]);
    try std.testing.expectError(error.InvalidExecutionProgramWord, program.lookup(1032));
    try std.testing.expectError(error.InvalidExecutionProgramWord, program.lookup(1036));
    try std.testing.expect(program.entries[try program.lookup(1040)].dynamic_next);
    try std.testing.expectEqual(@as(u5, 10), program.entries[try program.lookup(1044)].ids[0]);
    try std.testing.expectEqual(@as(u5, 17), program.entries[try program.lookup(1044)].ids[1]);
    const n = program.size();
    for (program.row_to_entry.len..n) |logical| try std.testing.expect(program.fixed[X.layout.physical(logical, program.log_size)].isZero());
    var other_words = words;
    other_words[2] = 0xffffffff;
    var other = try Program.init(a, .{ .base = 1024, .words = &other_words });
    defer other.deinit();
    try std.testing.expectEqualSlices(@TypeOf(program.fixed[0]), program.fixed, other.fixed);
    try std.testing.expect(!std.mem.eql(u8, &program.identity, &other.identity));
}
test "full program reuses admitted immutable decoded authority without copying raw arrays" {
    const words = [_]u32{ branch(8), AND, 0, 0x00000073 };
    var authority = try Full.ProgramAuthority.init(a, .{ .base = 1024, .words = &words }, .ethereum_services_v2);
    defer authority.deinit();
    var cached = try Program.initWithAuthority(a, &authority);
    defer cached.deinit();
    var fresh = try Program.init(a, .{ .base = 1024, .words = &words });
    defer fresh.deinit();
    try std.testing.expect(!cached.owns_raw);
    try std.testing.expect(cached.words.ptr == authority.words.ptr);
    try std.testing.expect(cached.addresses.ptr == authority.program.addresses.ptr);
    try std.testing.expectEqualSlices(u8, &fresh.identity, &cached.identity);
    try std.testing.expectEqualSlices(@TypeOf(fresh.fixed[0]), fresh.fixed, cached.fixed);
    // Default invalid cache instruction is FENCE; validity must still reject it.
    try std.testing.expectError(error.InvalidExecutionProgramWord, cached.lookup(1032));
    var plain = try Program.initWithProfile(a, .{ .base = 1024, .words = &words }, .rv64im);
    defer plain.deinit();
    try std.testing.expectError(error.InvalidExecutionProgramWord, plain.lookup(1036));
}
test "full program lookup preserves sparse high64 aliases wrapping and branch alignment" {
    const high: u64 = 0x8000000000000400;
    var sparse = try Program.init(a, .{ .base = 1024, .words = &.{ AND, AND }, .addresses = &.{ 1024, high } });
    defer sparse.deinit();
    try std.testing.expectEqual(@as(usize, 1), try sparse.lookup(high));
    try std.testing.expectEqual(@as(usize, 0), try sparse.lookup(1024));
    try std.testing.expectError(error.UnknownExecutionPc, sparse.lookup(high + 1));
    var top = try Program.init(a, .{ .base = std.math.maxInt(u64) - 3, .words = &.{AND} });
    defer top.deinit();
    try std.testing.expectEqual(@as(u64, 0), top.entries[0].staticNext(false));
    try std.testing.expectError(error.UnknownExecutionPc, top.lookup(0));
    var unaligned = try Program.init(a, .{ .base = 1024, .words = &.{branch(2)} });
    defer unaligned.deinit();
    try std.testing.expectError(error.InvalidExecutionBranchEdge, unaligned.factIndex(0, true));
}
fn allocationCase(allocator: std.mem.Allocator) !void {
    var program = try Program.init(allocator, .{ .base = 1024, .words = &.{ branch(8), 0, AND, 0x00000073 } });
    defer program.deinit();
}
test "full program owner unwinds every allocation failure" {
    try std.testing.checkAllAllocationFailures(a, allocationCase, .{});
}

test "full execution immutable material roster matches all physical fixed columns" {
    const Setup = @import("../word16_execution/setup.zig");
    var material = try Setup.Materials.init(a, .{ .base = 1024, .words = &.{AND} }, .{ .cpu_log = 5 });
    defer material.deinit();
    const actual = material.shapes();
    try std.testing.expectEqual(@as(usize, 17), actual.len);
    const columns = try material.fixedColumns(a);
    defer a.free(columns);
    const logs = try material.logs(a, 0);
    defer a.free(logs);
    try std.testing.expectEqual(logs.len, columns.len);
    for (columns, logs) |column, log| try std.testing.expectEqual(@as(usize, 1) << @intCast(log), column.values.len);
    const cells = try Setup.G.cells(&actual);
    try std.testing.expect(cells.fixed > 0 and cells.main > 0 and cells.interaction > 0);
}

test "full execution complete fixed key leases preserve root and fresh transcript" {
    const Setup = @import("../word16_execution/setup.zig");
    var setup = try Setup.Setup.init(a, .{ .base = 1024, .words = &.{AND} }, .{ .cpu_log = 5 });
    defer setup.deinit();
    var scheme = try Setup.T.Scheme.init(a, Setup.T.P.config());
    defer scheme.deinit(a);
    var channel = Setup.T.P.Channel{};
    try setup.appendFixed(a, &scheme, &channel);
    var roots = try scheme.roots(a);
    defer roots.deinit(a);
    try std.testing.expectEqualDeep(setup.fixed_root.value, roots.items[0]);
    try std.testing.expectError(error.InvalidExecutionFixedPhase, setup.appendFixed(a, &scheme, &channel));
    var second = try Setup.T.Scheme.init(a, Setup.T.P.config());
    defer second.deinit(a);
    var second_channel = Setup.T.P.Channel{};
    second_channel.mixU64(1234);
    try setup.appendFixed(a, &second, &second_channel);
    var second_roots = try second.roots(a);
    defer second_roots.deinit(a);
    try std.testing.expectEqualDeep(setup.fixed_root.value, second_roots.items[0]);
}

test "full execution concrete component roster matches every immutable physical shape" {
    const Setup = @import("../word16_execution/setup.zig");
    const Components = @import("../word16_execution/components.zig").Components;
    const Protocol = @import("../word16_execution/protocol.zig");
    const core = @import("stwo_core");
    var materials = try Setup.Materials.init(a, .{ .base = 1024, .words = &.{AND} }, .{ .cpu_log = 5 });
    defer materials.deinit();
    const request = Protocol.Request{ .cpu = .{ .steps = 1, .initial_pc = 1024, .final_pc = 1028, .initial_registers = @splat(0), .final_registers = @splat(0), .register_clocks = @splat(0) }, .epoch = 1, .division_requests = 0, .multiplication_requests = 0, .memory = .{ .initial = &.{}, .terminal = &.{}, .epoch = 1, .ls_count = 0 } };
    var channel = Setup.T.P.Channel{};
    const draw = Protocol.draw(&channel);
    const claims = std.mem.zeroes(Protocol.Claims);
    var components = try Components.init(&materials, request, draw, claims);
    const provers = try components.provers(a);
    defer a.free(provers);
    const verifiers = try components.verifiers(a);
    defer a.free(verifiers);
    for (provers, verifiers, materials.shapes()) |prover, verifier, shape| {
        var plogs = try prover.traceLogDegreeBounds(a);
        defer {
            for (plogs.items) |columns| a.free(columns);
            plogs.deinit(a);
        }
        var vlogs = try verifier.traceLogDegreeBounds(a);
        defer {
            for (vlogs.items) |columns| a.free(columns);
            vlogs.deinit(a);
        }
        try std.testing.expectEqualDeep(plogs.items, vlogs.items);
        for (plogs.items, shape.widths) |columns, width| try std.testing.expectEqual(width, columns.len);
    }
    const measured = try @import("../word16_execution/measurement.zig").inspect(a, &components);
    for (measured.components) |component| {
        try std.testing.expectEqual(@as(u32, 1), component.composition_log_split);
        const extra: u32 = 1;
        try std.testing.expectEqual(component.source_log + extra, component.native_evaluation_log);
        try std.testing.expectEqual(component.source_log + 1, component.composition_contribution_bound_log);
    }
    const joined_p = try components.proversForDegree4Join(a);
    defer a.free(joined_p);
    const joined_v = try components.verifiersForDegree4Join(a);
    defer a.free(joined_v);
    for (provers, verifiers, joined_p, joined_v, materials.shapes()) |native_p, native_v, jp, jv, shape| {
        try std.testing.expectEqual(shape.log + 1, native_p.maxConstraintLogDegreeBound());
        try std.testing.expectEqual(shape.log + 1, native_v.maxConstraintLogDegreeBound());
        try std.testing.expectEqual(@as(u32, 1), native_p.compositionLogSplit());
        try std.testing.expectEqual(@as(u32, 1), native_v.compositionLogSplit());
        try std.testing.expectEqual(shape.log + 2, jp.maxConstraintLogDegreeBound());
        try std.testing.expectEqual(shape.log + 2, jv.maxConstraintLogDegreeBound());
        try std.testing.expectEqual(@as(u32, 2), jp.compositionLogSplit());
        try std.testing.expectEqual(@as(u32, 2), jv.compositionLogSplit());
    }
    var bad = claims;
    bad.initial.owner = core.fields.qm31.QM31.one();
    try std.testing.expectError(error.UnconstrainedMemoryClaim, Components.init(&materials, request, draw, bad));
}
