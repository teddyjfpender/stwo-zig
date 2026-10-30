const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const T = @import("../blake3_transcript_witness.zig");
const Plan = @import("../blake3_transcript_plan.zig").Plan;
const Fanout = @import("../blake3_transcript_fanout_v1.zig");
const Binding = @import("../universal_relation_binding.zig");
const prefix_ops = [_]T.Operation{ .{ .words = &.{ 42, 19 } }, .{ .secure = .{ .output = .{ .universal = 0 }, .attempts = 0, .values = @splat(M.zero()), .consumption = .two } } };
const suffix_ops = [_]T.Operation{ .{ .words = &.{ 17, 8 } }, .{ .secure = .{ .output = .{ .universal = 1 }, .attempts = 0, .values = @splat(M.zero()), .consumption = .two } } };

test "authenticated digest continuation preserves native bytes and cold identity" {
    const a = std.testing.allocator;
    var before = try T.prepareBounded(a, 100, &prefix_ops, 2);
    defer before.deinit();
    var prefix_plan = try Plan.initBoundary(a, .{ .namespace = 100, .attempt_capacity = 2 }, &prefix_ops, .{ .final_state_uses = @splat(1) });
    defer prefix_plan.deinit();
    const output = prefix_plan.fixed.exported_state.?;
    var suffix_plan = try Plan.initBoundary(a, .{ .namespace = 200, .attempt_capacity = 2 }, &suffix_ops, .{ .resume_before_absorb = .{ .source = output.source, .value = @splat(0) } });
    defer suffix_plan.deinit();
    const uses = suffix_plan.fixed.resumed_state.?.uses;
    var actual_prefix_plan = try Plan.initBoundary(a, .{ .namespace = 100, .attempt_capacity = 2 }, &prefix_ops, .{ .final_state_uses = uses });
    defer actual_prefix_plan.deinit();
    var prefix = try actual_prefix_plan.prepareBoundary(a, &prefix_ops, .{ .final_state_uses = uses });
    defer prefix.deinit();
    var suffix = try suffix_plan.prepareBoundary(a, &suffix_ops, .{ .resume_before_absorb = .{ .source = output.source, .value = prefix.final_digest.? } });
    defer suffix.deinit();
    var whole = try T.prepareBounded(a, 300, &(prefix_ops ++ suffix_ops), 2);
    defer whole.deinit();
    try std.testing.expectEqualDeep(whole.final_digest, suffix.final_digest);
    try std.testing.expectEqual(whole.next_draw, suffix.next_draw);
    try std.testing.expectEqualDeep(before.final_digest, prefix.final_digest);
    try std.testing.expectEqualDeep(prefix.exported_state.?, suffix.resumed_state.?);
    const Join = @import("../blake3_transcript_continuation_v1.zig");
    try Join.requireExact(prefix.exported_state.?, &.{suffix.resumed_state.?});
    try std.testing.expectError(error.InvalidTranscriptStateJoin, Join.requireExact(prefix.exported_state.?, &.{ suffix.resumed_state.?, suffix.resumed_state.? }));
    try std.testing.expectError(error.InvalidTranscriptStateJoin, Join.requireExact(prefix.exported_state.?, &.{}));
    var bad_port = suffix.resumed_state.?;
    bad_port.source.first_wire += 1;
    try std.testing.expectError(error.InvalidTranscriptStateJoin, Join.requireExact(prefix.exported_state.?, &.{bad_port}));
    var changed_boundary = T.Boundary{ .resume_before_absorb = .{ .source = output.source, .value = prefix.final_digest.? } };
    changed_boundary.resume_before_absorb.?.value[0] ^= 1;
    var changed = try suffix_plan.prepareBoundary(a, &suffix_ops, changed_boundary);
    defer changed.deinit();
    try std.testing.expect(!std.meta.eql(suffix.final_digest, changed.final_digest));
    // A wrong digest is not rejected by setup: it is a witness. The exact
    // joined wire multiset below must reject it; pinning it in fixed data would
    // make this an untrusted key specialization instead of authentication.
    try requireWireClosure(a, &.{ &prefix, &suffix }, &.{}, &.{});
    try std.testing.expectError(error.OpenContinuationWire, requireWireClosure(a, &.{ &prefix, &changed }, &.{}, &.{}));
    // The hostile suffix is itself a valid hash computation for the wrong
    // external digest; rejection is the original AIR's cross-component wire
    // relation, not a host comparison of witness digest bytes.
    inline for (@import("../blake3_transcript_plan.zig").Airs, @import("../blake3_transcript_plan.zig").rows(&changed)) |Air, rows| try std.testing.expect(try constraintsSatisfied(Air, a, rows));
    try std.testing.expectError(error.OpenContinuationWire, requireWireClosure(a, &.{&suffix}, &.{}, &.{}));

    changed_boundary.resume_before_absorb.?.source.first_wire += 1;
    try std.testing.expectError(error.Blake3TranscriptPlanMismatch, suffix_plan.prepareBoundary(a, &suffix_ops, changed_boundary));
    try std.testing.expectError(error.InvalidBlake3Continuation, T.trustedBoundedBoundary(a, 200, suffix_ops[1..], 2, .{ .resume_before_absorb = .{ .source = output.source, .value = @splat(0) } }));
    try std.testing.expectError(error.InvalidBlake3Continuation, T.trustedBoundedBoundary(a, 200, &suffix_ops, 2, .{ .resume_before_absorb = .{ .source = .{ .circuit = 200, .first_wire = 0 }, .value = @splat(0) } }));
    var legacy = try Plan.init(a, .{ .namespace = 100, .attempt_capacity = 2 }, &prefix_ops);
    defer legacy.deinit();
    var unchanged = try Plan.initBoundary(a, .{ .namespace = 100, .attempt_capacity = 2 }, &prefix_ops, .{});
    defer unchanged.deinit();
    try std.testing.expectEqualDeep(legacy.id, unchanged.id);

    // Independent epochs are witness data at a routed public root. Their
    // physical prefix key is reusable, while a wrong joined state still fails.
    const routed_one = [_]T.Operation{.{ .routed_root = .{ .source = .{ .circuit = 10, .first_wire = 0 }, .value = @splat(17) } }};
    const routed_two = [_]T.Operation{.{ .routed_root = .{ .source = .{ .circuit = 10, .first_wire = 0 }, .value = @splat(91) } }};
    var epoch_one = try Plan.initBoundary(a, .{ .namespace = 100, .attempt_capacity = 2 }, &routed_one, .{ .final_state_uses = uses });
    defer epoch_one.deinit();
    var epoch_two = try Plan.initBoundary(a, .{ .namespace = 100, .attempt_capacity = 2 }, &routed_two, .{ .final_state_uses = uses });
    defer epoch_two.deinit();
    try std.testing.expectEqualDeep(epoch_one.id, epoch_two.id);
    const counter_saved = prefix.counter_rows[0];
    prefix.counter_rows[0][0] = prefix.counter_rows[0][0].add(M.one());
    try std.testing.expectError(error.OpenContinuationWire, requireWireClosure(a, &.{ &prefix, &suffix }, &.{}, &.{}));
    prefix.counter_rows[0] = counter_saved;
    const control_saved = prefix.control_rows[0];
    prefix.control_rows[0][2] = prefix.control_rows[0][2].add(M.one());
    try std.testing.expect(!try constraintsSatisfied(T.retry_control, a, &.{prefix.control_rows[0]}));
    prefix.control_rows[0] = control_saved;
    try compareBoundaryFormats(a, &actual_prefix_plan, &prefix_ops, .{ .final_state_uses = uses });
    try compareBoundaryFormats(a, &suffix_plan, &suffix_ops, .{ .resume_before_absorb = .{ .source = output.source, .value = prefix.final_digest.? } });
}

fn compareBoundaryFormats(a: std.mem.Allocator, full: *const Plan, operations: []const T.Operation, boundary_config: T.Boundary) !void {
    var compact = try Plan.initBoundaryCompact(a, full.config, operations, boundary_config);
    defer compact.deinit();
    try std.testing.expectEqualDeep(full.id, compact.id);
    var expected = try full.prepareBoundary(a, operations, boundary_config);
    defer expected.deinit();
    const Support = @import("../blake3_main_column_test_support.zig");
    var output_arena = std.heap.ArenaAllocator.init(a);
    defer output_arena.deinit();
    const count = compact.fixed.hashCounts();
    const columns = try Support.allocate(output_arena.allocator(), count.g, count.xor);
    var actual = try compact.prepareBoundaryMainColumns(a, operations, boundary_config, columns);
    defer actual.deinit();
    try Support.expectRows(columns, expected, compact.fixed);
    try std.testing.expectEqualDeep(expected.final_digest, actual.final_digest);
    try std.testing.expectEqual(expected.next_draw, actual.next_draw);
    try std.testing.expectEqualDeep(expected.resumed_state, actual.resumed_state);
    try std.testing.expectEqualDeep(expected.exported_state, actual.exported_state);
    try std.testing.expectEqual(@as(usize, 0), actual.g_rows.len);
    try std.testing.expectEqual(@as(usize, 0), actual.xor_rows.len);
    inline for (.{ 2, 6, 7, 8, 14, 15 }) |slot| {
        const view = try actual.nonhash.?.columns.view(slot);
        const rows = expected.cohortRows(slot);
        try std.testing.expectEqual(rows.len, view.rowCount());
        try std.testing.expectEqual(@as(usize, 0), actual.cohortRows(slot).len);
        for (rows, 0..) |row, i| try std.testing.expectEqualDeep(row, view.rowAt(i));
    }
    var bad = boundary_config;
    if (bad.resume_before_absorb) |*continuation| {
        continuation.source.first_wire += 1;
    } else {
        bad.final_state_uses[0] += 1;
    }
    try std.testing.expectError(error.Blake3TranscriptPlanMismatch, compact.prepareBoundaryMainColumns(a, operations, bad, columns));
}

test "continued transcript and fanout prove with original AIRs" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = @import("../blake3_proof_fixture.zig");
    const F = @import("../blake3_fixture_roster.zig").WithExtras(.{ T.challenge, T.route, T.query_mask, T.retry_control, T.counter_step, Fanout.Air });
    var candidate = try Plan.initBoundary(a, .{ .namespace = 100, .attempt_capacity = 2 }, &prefix_ops, .{ .final_state_uses = @splat(1) });
    defer candidate.deinit();
    const port = candidate.fixed.exported_state.?.source;
    var tail_plan = try Plan.initBoundary(a, .{ .namespace = 200, .attempt_capacity = 2 }, &suffix_ops, .{ .resume_before_absorb = .{ .source = port, .value = @splat(0) } });
    defer tail_plan.deinit();
    const boundary_config = T.Boundary{ .final_state_uses = tail_plan.fixed.resumed_state.?.uses };
    var head_plan = try Plan.initBoundary(a, .{ .namespace = 100, .attempt_capacity = 2 }, &prefix_ops, boundary_config);
    defer head_plan.deinit();
    var head = try head_plan.prepareBoundary(a, &prefix_ops, boundary_config);
    defer head.deinit();
    var tail = try tail_plan.prepareBoundary(a, &suffix_ops, .{ .resume_before_absorb = .{ .source = port, .value = head.final_digest.? } });
    defer tail.deinit();
    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(prefix_ops[0].words);
    const fields = try channel.drawSecureFelts(a, 2);
    const values = fields[0].toM31Array() ++ fields[1].toM31Array();
    var route = try Fanout.prepare(a, 900, head.draw_outputs, &@as([8]u32, @splat(2)), &values);
    defer route.deinit();
    var cold_route = try Fanout.prepare(a, 900, head.draw_outputs, &@as([8]u32, @splat(2)), &@as([8]M, @splat(M.zero())));
    defer cold_route.deinit();
    var consumers: [24]T.boundary.Row = undefined;
    for (0..2) |child| for (values, 0..) |value, i| {
        consumers[8 * child + i] = try T.boundary.logicalCoordinates(900, @intCast(i), M.one().neg(), .{ value, M.zero(), M.zero(), M.zero() });
    };
    channel.mixU32s(suffix_ops[0].words);
    const tail_fields = try channel.drawSecureFelts(a, 2);
    for (tail_fields[0].toM31Array() ++ tail_fields[1].toM31Array(), 0..) |value, i| consumers[16 + i] = try T.boundary.logicalCoordinates(tail.draw_outputs[0].source.circuit, @intCast(i), M.one().neg(), .{ value, M.zero(), M.zero(), M.zero() });
    try requireWireClosure(a, &.{ &head, &tail }, route.rows, &consumers);
    comptime var types: [9]type = undefined;
    inline for (F.Airs, 0..) |Air, i| types[i] = []Air.Row;
    var rows: std.meta.Tuple(&types) = undefined;
    var trusted_rows: std.meta.Tuple(&types) = undefined;
    var logs: [9]u32 = undefined;
    const head_rows = @import("../blake3_transcript_plan.zig").rows(&head);
    const tail_rows = @import("../blake3_transcript_plan.zig").rows(&tail);
    const head_fixed = @import("../blake3_transcript_plan.zig").rows(&head_plan.fixed);
    const tail_fixed = @import("../blake3_transcript_plan.zig").rows(&tail_plan.fixed);
    inline for (F.Airs, 0..) |Air, i| {
        const unpadded = if (i == 8) route.rows else if (i == 2) try std.mem.concat(a, Air.Row, &.{ head_rows[i], tail_rows[i], &consumers }) else try std.mem.concat(a, Air.Row, &.{ head_rows[i], tail_rows[i] });
        trusted_rows[i] = if (i == 8) cold_route.rows else if (i == 2) try std.mem.concat(a, Air.Row, &.{ head_fixed[i], tail_fixed[i], &consumers }) else try std.mem.concat(a, Air.Row, &.{ head_fixed[i], tail_fixed[i] });
        logs[i] = if (unpadded.len <= 1) 1 else std.math.log2_int_ceil(usize, unpadded.len);
        rows[i] = try f.padded(Air, a, unpadded, logs[i]);
        try std.testing.expect(try constraintsSatisfied(Air, a, unpadded));
    }
    var trusted: std.ArrayList(f.Column) = .empty;
    inline for (F.Airs, 0..) |Air, i| try f.project(Air, a, trusted_rows[i], logs[i], 0, &trusted);
    for (f.kinds) |kind| try f.tablePreprocessed(a, kind, &trusted);
    trusted_rows[8][0][3] = M.one(); // Independently wrong fan-out schedule.
    var wrong: std.ArrayList(f.Column) = .empty;
    inline for (F.Airs, 0..) |Air, i| try f.project(Air, a, trusted_rows[i], logs[i], 0, &wrong);
    for (f.kinds) |kind| try f.tablePreprocessed(a, kind, &wrong);
    try @import("../blake3_proof_gate_test_support.zig").runFor(F, a, rows, logs, trusted.items, wrong.items);
}

fn constraintsSatisfied(comptime Air: type, a: std.mem.Allocator, rows: []const Air.Row) !bool {
    var definition = try Air.build(a);
    defer definition.deinit();
    for (rows) |row| {
        const values = try @import("../test_support.zig").evaluateArena(a, &definition.arena, &row);
        defer a.free(values);
        for (definition.arena.constraintsView()) |constraint| if (!values[@import("../../../air/lang/mod.zig").types.idIndex(constraint.root)].isZero()) return false;
    }
    return true;
}

test "continuation challenge fanout authenticates every scalar and exact multiplicity" {
    const a = std.testing.allocator;
    var prefix = try T.prepareBounded(a, 100, &prefix_ops, 2);
    defer prefix.deinit();
    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(prefix_ops[0].words);
    const values = try channel.drawSecureFelts(a, 2);
    defer a.free(values);
    const scalars = values[0].toM31Array() ++ values[1].toM31Array();
    var route = try Fanout.prepare(a, 900, prefix.draw_outputs, &@as([8]u32, @splat(2)), &scalars);
    defer route.deinit();
    var cold = try Fanout.prepare(a, 900, prefix.draw_outputs, &@as([8]u32, @splat(2)), &@as([8]M, @splat(M.zero())));
    defer cold.deinit();
    for (route.rows, cold.rows) |row, fixed| try std.testing.expectEqualSlices(M, row[1..], fixed[1..]);
    // Two independent exact consumers, represented by original boundary AIR
    // rows. Their multiplicity is fixed, and their supplied values constrained.
    var consumers: [16]T.boundary.Row = undefined;
    for (0..2) |child| for (scalars, 0..) |value, i| {
        consumers[8 * child + i] = try T.boundary.logicalCoordinates(900, @intCast(i), M.one().neg(), .{ value, M.zero(), M.zero(), M.zero() });
    };
    try requireWireClosure(a, &.{&prefix}, route.rows, &consumers);
    route.rows[0][0] = route.rows[0][0].add(M.one());
    try std.testing.expectError(error.OpenContinuationWire, requireWireClosure(a, &.{&prefix}, route.rows, &consumers));
    route.rows[0][0] = scalars[0];
    route.rows[0][3] = M.one();
    try std.testing.expectError(error.OpenContinuationWire, requireWireClosure(a, &.{&prefix}, route.rows, &consumers));
    route.rows[0][3] = M.fromCanonical(2);
    consumers[0][0] = consumers[0][0].add(M.one());
    try std.testing.expectError(error.OpenContinuationWire, requireWireClosure(a, &.{&prefix}, route.rows, &consumers));
    try std.testing.expectError(error.InvalidTranscriptFanout, Fanout.prepare(a, prefix.draw_outputs[0].source.circuit, prefix.draw_outputs, &@as([8]u32, @splat(2)), &scalars));
    try std.testing.expectError(error.InvalidTranscriptFanout, Fanout.prepare(a, 900, prefix.draw_outputs, &@as([8]u32, @splat(0)), &scalars));
}

const Key = [6][4]u32;
const Ledger = std.AutoHashMap(Key, Q);
fn addRows(comptime Air: type, a: std.mem.Allocator, ledger: *Ledger, rows: []const Air.Row) !void {
    var definition = try Air.build(a);
    defer definition.deinit();
    const plan = try Binding.Binding(Air).authenticate(&definition);
    for (rows) |row| for (plan.preparedEntries(row)) |entry| {
        if (entry.domain != .recursion_wire or entry.numerator.isZero()) continue;
        var key: Key = undefined;
        for (entry.values[0..6], &key) |value, *limbs| {
            for (value.toM31Array(), limbs) |limb, *out| out.* = limb.toU32();
        }
        const found = try ledger.getOrPut(key);
        if (!found.found_existing) found.value_ptr.* = Q.zero();
        found.value_ptr.* = found.value_ptr.add(entry.numerator);
    };
}
fn requireWireClosure(a: std.mem.Allocator, parts: []const *const T.Prepared, routes: []const Fanout.Air.Row, consumers: []const T.boundary.Row) !void {
    var ledger = Ledger.init(a);
    defer ledger.deinit();
    for (parts) |part| {
        inline for (@import("../blake3_transcript_plan.zig").Airs, @import("../blake3_transcript_plan.zig").rows(part)) |Air, rows| try addRows(Air, a, &ledger, rows);
        // Unconsumed original challenge outputs are closed only for this digest
        // test. Fan-out test instead supplies its actual constrained consumers.
        if (routes.len == 0) for (part.draw_outputs) |output| {
            for (0..output.words) |i| {
                // Read the selected coordinate from the original retry rows;
                // this is test witness recovery, never a production authority.
                var value = M.zero();
                for (part.control_rows) |row| if (row[22].toU32() == output.source.circuit and row[2].eql(M.one())) {
                    value = row[4 + i];
                };
                const row = try T.boundary.logicalCoordinates(output.source.circuit, output.source.first_wire + @as(u32, @intCast(i)), M.one().neg(), .{ value, M.zero(), M.zero(), M.zero() });
                try addRows(T.boundary, a, &ledger, &.{row});
            }
        };
    }
    try addRows(Fanout.Air, a, &ledger, routes);
    try addRows(T.boundary, a, &ledger, consumers);
    var values = ledger.valueIterator();
    while (values.next()) |value| if (!value.isZero()) return error.OpenContinuationWire;
}
