const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const component = @import("memory_component.zig");
const trace_mod = @import("memory_component_trace.zig");
const transition = @import("memory_transition.zig");
const instance = @import("memory_instance.zig");
const support = @import("../../recursion/air/test_support.zig");
const lang = @import("../lang/definition.zig");
const tables = @import("../lookups/tables/schema.zig");

fn satisfied(definition: *const component.Definition, row: *const component.Row) !bool {
    const values = try support.evaluateArena(std.testing.allocator, &definition.arena, row);
    defer std.testing.allocator.free(values);
    for (definition.arena.constraintsView()) |constraint| if (!values[lang.types.idIndex(constraint.root)].isZero()) return false;
    for (definition.arena.effectsView(), 0..) |effect, index| {
        if (values[lang.types.idIndex(effect.liveness.?)].isZero()) continue;
        const ids = definition.arena.effectValues(@enumFromInt(index)).?;
        const tuple = [2]M{ values[lang.types.idIndex(ids[0])], values[lang.types.idIndex(ids[1])] };
        _ = tables.indexBase(.range_check_8_8, &tuple) catch return false;
    }
    return true;
}

const first = transition.Transition{ .space = 1, .address = 4096, .clock = 1, .before = 7, .after = 8 };
const second = transition.Transition{ .space = 1, .address = 4096, .clock = 5, .before = 8, .after = 9 };
const third = transition.Transition{ .space = 1, .address = 4096, .clock = 9, .before = 9, .after = 10 };

test "sorted memory row AIR pins exact boundary, predecessor and same-key continuity" {
    const summary: instance.Summary = .{ .first_row = 0, .rows = 2, .first = first, .last = second };
    const claim = try component.Claim.fromSummary(summary, 3, 1, null);
    var definition = try component.build(std.testing.allocator, claim);
    defer definition.deinit();
    var trace = try trace_mod.Trace.init(std.testing.allocator, claim);
    defer trace.deinit();
    var trusted_fixed = try trace_mod.FixedTrace.init(std.testing.allocator, claim);
    defer trusted_fixed.deinit();
    for (0..trace_mod.fixed_column_count) |column| try std.testing.expectEqualSlices(M, trace.fixedColumn(column), trusted_fixed.column(column));
    try trace.append(first);
    try trace.append(second);
    try trace.seal();
    var row0 = trace.inputRow(0);
    var row1 = trace.inputRow(1);
    try std.testing.expect(try satisfied(&definition, &row0));
    try std.testing.expect(try satisfied(&definition, &row1));
    row1[component.Layout.shifted_previous + 13] = M.zero();
    try std.testing.expect(!try satisfied(&definition, &row1));
    row1 = trace.inputRow(1);
    row1[component.Layout.linked_previous + 13] = M.zero();
    try std.testing.expect(!try satisfied(&definition, &row1));
    row1 = trace.inputRow(1);
    row1[component.Layout.after] = M.zero();
    try std.testing.expect(!try satisfied(&definition, &row1));
    row0[component.Layout.first] = M.zero();
    try std.testing.expect(!try satisfied(&definition, &row0));
}

test "independent memory instance pins public preceding row without a padded proof" {
    const summary: instance.Summary = .{ .first_row = 2, .rows = 1, .first = third, .last = third };
    const claim = try component.Claim.fromSummary(summary, 3, 1, second);
    var definition = try component.build(std.testing.allocator, claim);
    defer definition.deinit();
    var trace = try trace_mod.Trace.init(std.testing.allocator, claim);
    defer trace.deinit();
    try trace.append(third);
    try trace.seal();
    var row = trace.inputRow(0);
    try std.testing.expect(try satisfied(&definition, &row));
    row[component.Layout.linked_previous + 13] = M.zero();
    try std.testing.expect(!try satisfied(&definition, &row));
    const padding = trace.inputRow(1);
    try std.testing.expect(try satisfied(&definition, &padding));
}

test "cross-instance memory value discontinuity is rejected before PCS commitment" {
    var forged = second;
    forged.after = 8;
    const summary: instance.Summary = .{ .first_row = 2, .rows = 1, .first = third, .last = third };
    const claim = try component.Claim.fromSummary(summary, 3, 1, forged);
    var trace = try trace_mod.Trace.init(std.testing.allocator, claim);
    defer trace.deinit();
    try std.testing.expectError(error.MemoryValueDiscontinuity, trace.append(third));
    try std.testing.expectError(error.InvalidMemoryComponentPhase, trace.append(third));
}

test "public memory proof roster rejects omitted duplicate and forged-boundary instances" {
    const first_claim = try component.Claim.fromSummary(.{ .first_row = 0, .rows = 2, .first = first, .last = second }, 3, 1, null);
    const final_claim = try component.Claim.fromSummary(.{ .first_row = 2, .rows = 1, .first = third, .last = third }, 3, 1, second);
    try component.admitSequence(&.{ first_claim, final_claim }, 3);
    try std.testing.expectError(error.InvalidMemoryInstanceCensus, component.admitSequence(&.{first_claim}, 3));
    try std.testing.expectError(error.InvalidMemoryInstanceCensus, component.admitSequence(&.{ first_claim, first_claim, final_claim }, 3));
    var forged = final_claim;
    forged.preceding = first;
    try std.testing.expectError(error.InvalidMemoryInstanceCensus, component.admitSequence(&.{ first_claim, forged }, 3));
    try std.testing.expectError(error.InvalidMemoryInstanceCensus, component.admitSequence(&.{ first_claim, final_claim }, 4));
}

test "memory component trace rejects wrong boundary and incomplete census" {
    const summary: instance.Summary = .{ .first_row = 0, .rows = 2, .first = first, .last = second };
    const claim = try component.Claim.fromSummary(summary, 2, 1, null);
    var bad = try trace_mod.Trace.init(std.testing.allocator, claim);
    defer bad.deinit();
    try std.testing.expectError(error.MemoryFirstBoundaryMismatch, bad.append(second));
    try std.testing.expectError(error.InvalidMemoryComponentPhase, bad.append(first));
    var short = try trace_mod.Trace.init(std.testing.allocator, claim);
    defer short.deinit();
    try short.append(first);
    try std.testing.expectError(error.MemoryInstanceCensusUnderflow, short.seal());
    try std.testing.expectError(error.InvalidMemoryComponentPhase, short.append(second));
}

test "one-pass memory trace learns public first and last without a second sorted scan" {
    var planned = try trace_mod.Trace.initPlanned(std.testing.allocator, 0, 2, 2, 1, null);
    defer planned.deinit();
    try planned.append(first);
    try planned.append(second);
    try planned.seal();
    try std.testing.expectEqualDeep(first, planned.claim.first);
    try std.testing.expectEqualDeep(second, planned.claim.last);
    var fixed_only = try trace_mod.FixedTrace.init(std.testing.allocator, planned.claim);
    defer fixed_only.deinit();
    for (0..trace_mod.fixed_column_count) |column| try std.testing.expectEqualSlices(M, planned.fixedColumn(column), fixed_only.column(column));
}

test "sorted partitioner streams directly into independently sized committed memory trace" {
    const spool = @import("memory_spool.zig");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var writer = try spool.Spool.init(std.testing.allocator, tmp.dir, 2);
    defer writer.deinit();
    try writer.append(.{ .space = 1, .address = 4096, .clock = 1, .value = 8 });
    try writer.append(.{ .space = 1, .address = 4096, .clock = 5, .value = 9 });
    const Loader = struct {
        fn load(_: *anyopaque, _: u1, _: u32) anyerror!u32 {
            return 7;
        }
    };
    var opaque_context: u8 = 0;
    var reader = transition.Reader{ .sorted = try writer.finish(), .initial = .{ .context = &opaque_context, .load = Loader.load } };
    defer reader.deinit();
    var partitioner = try instance.Partitioner.init(&reader, 2, 2);
    var trace = try trace_mod.Trace.initPlanned(std.testing.allocator, 0, 2, 2, 1, null);
    defer trace.deinit();
    const summary = (try partitioner.next(trace.partitionSink())).?;
    try trace.seal();
    try std.testing.expectEqualDeep(summary.first, trace.claim.first);
    try std.testing.expectEqualDeep(summary.last, trace.claim.last);
    try std.testing.expect((try partitioner.next(trace.partitionSink())) == null);
}

test "five sorted events stream into exact unequal memory instances and public roster" {
    const spool = @import("memory_spool.zig");
    const relation = @import("../../prover/block_memory_relation_v2.zig");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var writer = try spool.Spool.init(std.testing.allocator, tmp.dir, 2);
    defer writer.deinit();
    for (0..5) |i| try writer.append(.{
        .space = 1,
        .address = 4096,
        .clock = @as(u64, @intCast(i)) * 4 + 1,
        .value = @intCast(i + 1),
    });
    const Loader = struct {
        fn load(_: *anyopaque, _: u1, _: u32) anyerror!u32 {
            return 0;
        }
    };
    var context: u8 = 0;
    var reader = transition.Reader{ .sorted = try writer.finish(), .initial = .{ .context = &context, .load = Loader.load } };
    defer reader.deinit();
    var partitioner = try instance.Partitioner.init(&reader, 5, 2);
    var traces: [3]trace_mod.Trace = undefined;
    var initialized: usize = 0;
    defer for (traces[0..initialized]) |*trace| trace.deinit();
    var claims: [3]component.Claim = undefined;
    for (&traces, &claims, 0..) |*trace, *claim, index| {
        const first_row: u64 = @intCast(index * 2);
        const rows: u32 = if (index == 2) 1 else 2;
        trace.* = (try trace_mod.Trace.nextFromPartitioner(std.testing.allocator, &partitioner, 1)).?;
        initialized += 1;
        try std.testing.expectEqual(first_row, trace.claim.first_row);
        try std.testing.expectEqual(rows, trace.claim.rows);
        try std.testing.expect(trace.sealed);
        claim.* = trace.claim;
    }
    try std.testing.expect((try trace_mod.Trace.nextFromPartitioner(std.testing.allocator, &partitioner, 1)) == null);
    try component.admitSequence(&claims, 5);
    try std.testing.expectEqualDeep(traces[0].eventRow(1).emitted, traces[1].eventRow(0).consumed);
    try std.testing.expectEqualDeep(traces[1].eventRow(1).emitted, traces[2].eventRow(0).consumed);
    try std.testing.expect(!traces[2].eventRow(0).link_emit);
    var missing = claims;
    try std.testing.expectError(error.InvalidMemoryInstanceCensus, component.admitSequence(missing[0..2], 5));
    missing[1] = claims[2];
    try std.testing.expectError(error.InvalidMemoryInstanceCensus, component.admitSequence(missing[0..2], 5));
    const sealed = @import("../../prover/block_commitment_manifest.zig").Sealed{ .digest = @splat(23), .instance_count = 3 };
    const challenges = try relation.Challenges.draw(std.testing.allocator, sealed);
    var link_sum = core.fields.qm31.QM31.zero();
    for (&traces, 0..) |*trace, index| {
        var interaction = try relation.generateInteractionFromSource(std.testing.allocator, &challenges, @intCast(index), .sorted, trace, trace.claim.log_size);
        defer interaction.deinit(std.testing.allocator);
        link_sum = link_sum.add(interaction.claim.link_sum);
    }
    try std.testing.expect(link_sum.isZero());
}

test "v2 sorted memory tuples and ordinal links match across unequal instances" {
    const relation = @import("../../prover/block_memory_relation_v2.zig");
    const first_summary: instance.Summary = .{ .first_row = 0, .rows = 2, .first = first, .last = second };
    const second_summary: instance.Summary = .{ .first_row = 2, .rows = 1, .first = third, .last = third };
    var left = try trace_mod.Trace.init(std.testing.allocator, try component.Claim.fromSummary(first_summary, 3, 1, null));
    defer left.deinit();
    var right = try trace_mod.Trace.init(std.testing.allocator, try component.Claim.fromSummary(second_summary, 3, 1, second));
    defer right.deinit();
    try left.append(first);
    try left.append(second);
    try left.seal();
    try right.append(third);
    try right.seal();
    const a = left.eventRow(0);
    const b = left.eventRow(1);
    const c = right.eventRow(0);
    const padding = right.eventRow(1);
    try std.testing.expectEqualDeep(relation.transitionTuple(first), a.transition);
    try std.testing.expectEqualDeep(relation.transitionTuple(second), b.transition);
    try std.testing.expectEqualDeep(relation.transitionTuple(third), c.transition);
    try std.testing.expect(a.initial_request);
    try std.testing.expectEqualDeep(relation.initialTuple(first), a.initial);
    try std.testing.expect(!b.initial_request and !c.initial_request);
    try std.testing.expect(!a.link_consume);
    try std.testing.expect(!c.link_emit);
    try std.testing.expectEqualDeep(a.emitted, b.consumed);
    try std.testing.expectEqualDeep(b.emitted, c.consumed);
    try std.testing.expect(!padding.active and !padding.link_emit and !padding.link_consume);
}

test "first-value bus requests every newly sorted address exactly once" {
    const relation = @import("../../prover/block_memory_relation_v2.zig");
    const other = transition.Transition{ .space = 1, .address = 4100, .clock = 1, .before = 12, .after = 13 };
    const summary: instance.Summary = .{ .first_row = 0, .rows = 2, .first = first, .last = other };
    var trace = try trace_mod.Trace.init(std.testing.allocator, try component.Claim.fromSummary(summary, 2, 1, null));
    defer trace.deinit();
    try trace.append(first);
    try trace.append(other);
    try trace.seal();
    const first_row = trace.eventRow(0);
    const next_key = trace.eventRow(1);
    try std.testing.expect(first_row.initial_request and next_key.initial_request);
    try std.testing.expectEqualDeep(relation.initialTuple(first), first_row.initial);
    try std.testing.expectEqualDeep(relation.initialTuple(other), next_key.initial);
}
