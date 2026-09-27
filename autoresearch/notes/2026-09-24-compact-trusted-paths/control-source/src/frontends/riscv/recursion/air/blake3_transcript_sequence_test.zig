const std = @import("std");
const f = @import("blake3_proof_fixture.zig");
const sequence = @import("blake3_transcript_witness.zig");
const plan_mod = @import("blake3_transcript_plan.zig");
const F = @import("blake3_fixture_roster.zig").WithExtras(.{ sequence.challenge, sequence.route, sequence.query_mask });
const words = [_]u32{ 0, 0x80000000, 0xffffffff, 17 };
const felts = [_]f.core.fields.qm31.QM31{f.core.fields.qm31.QM31.fromM31Array(.{ f.M31.one(), f.M31.fromCanonical(2147483646), f.M31.fromCanonical(23), f.M31.fromCanonical(91) })};
const root: [32]u8 = @splat(0xf7);
fn operations(query_values: *[9]u32) ![20]sequence.Operation {
    var channel = f.core.channel.blake3.Channel{};
    channel.mixU64(@import("blake3_rejection_fixture.zig").SEED);
    const first = secure(&channel);
    const second = secure(&channel);
    channel.mixU64(42);
    const third = secure(&channel);
    channel.mixU32s(&words);
    const fourth = secure(&channel);
    channel.mixFelts(&felts);
    const fifth = secure(&channel);
    channel.mixRoot(root);
    const sixth = secure(&channel);
    const native = try f.core.queries.drawQueries(&channel, std.testing.allocator, 20, 9);
    defer std.testing.allocator.free(native);
    for (query_values, native) |*value, index| value.* = @intCast(index);
    const seventh = secure(&channel);
    channel.mixU64(77);
    const eighth = secure(&channel);
    const nonce = channel.grind(8);
    const after_pow = secure(&channel);
    channel.mixU64(nonce);
    return .{ .{ .integer = @import("blake3_rejection_fixture.zig").SEED }, first, second, .{ .integer = 42 }, third, .{ .words = &words }, fourth, .{ .felts = &felts }, fifth, .{ .root = root }, sixth, .{ .queries = .{ .log_domain_size = 20, .values = query_values } }, seventh, .{ .integer = 77 }, .{ .queries = .{ .log_domain_size = 20, .values = &.{} } }, eighth, .{ .pow = .{ .bits = 8, .nonce = nonce } }, after_pow, .{ .integer = nonce }, secure(&channel) };
}
fn secure(channel: *f.core.channel.blake3.Channel) sequence.Operation {
    const start = channel.n_draws;
    var values: [8]f.M31 = @splat(f.M31.zero());
    values[0..4].* = channel.drawSecureFelt().toM31Array();
    return .{ .secure = .{ .attempts = @intCast(channel.n_draws - start), .values = values } };
}
test "BLAKE3 transcript sequence derives native counters resets and private state links" {
    const a = std.testing.allocator;
    var query_values: [9]u32 = undefined;
    const ops = try operations(&query_values);
    var live = try sequence.prepare(a, 901, &ops);
    defer live.deinit();
    var fixed = try sequence.trusted(a, 901, &ops);
    defer fixed.deinit();
    try std.testing.expectEqual(@as(u32, 2), ops[1].secure.attempts);
    try std.testing.expectEqual(@as(u32, 0), live.challenge_rows[0][70].v);
    try std.testing.expectEqual(@as(u32, 1), live.challenge_rows[1][70].v);
    try std.testing.expectEqual(@as(u64, 1), live.next_draw);
    try std.testing.expectEqual(@as(usize, 11), live.challenge_rows.len);
    try std.testing.expectEqual(@as(usize, 10), live.query_rows.len);
    inline for (F.Airs, .{ live.g_rows, live.xor_rows, live.boundary_rows, live.challenge_rows, live.route_rows, live.query_rows }, .{ fixed.g_rows, fixed.xor_rows, fixed.boundary_rows, fixed.challenge_rows, fixed.route_rows, fixed.query_rows }) |Air, actual, expected| {
        try std.testing.expectEqual(actual.len, expected.len);
        for (actual, expected) |row, trusted_row| try std.testing.expectEqualSlices(f.M31, row[Air.PHYSICAL_MAIN_COLUMN_COUNT..], trusted_row[Air.PHYSICAL_MAIN_COLUMN_COUNT..]);
    }
    try std.testing.expect(try boundariesSatisfied(live.boundary_rows));
    var wrong = ops;
    wrong[4] = ops[2]; // Reuse the pre-reset challenge instead of the reset draw.
    var changed = try sequence.prepare(a, 901, &wrong);
    defer changed.deinit();
    try std.testing.expect(!try boundariesSatisfied(changed.boundary_rows));
    wrong[1].secure.attempts = 0;
    try std.testing.expectError(error.InvalidBlake3Transcript, sequence.trusted(a, 901, &wrong));
    try std.testing.expectError(error.InvalidBlake3Transcript, sequence.trusted(a, f.core.fields.m31.Modulus - 2, &ops));
    try std.testing.checkAllAllocationFailures(a, allocationCase, .{});
    var channel = f.core.channel.blake3.Channel{};
    channel.mixU32s(&.{});
    channel.mixFelts(&.{});
    const empty_ops = [_]sequence.Operation{ .{ .words = &.{} }, .{ .felts = &.{} }, secure(&channel) };
    var empty = try sequence.prepare(a, 901, &empty_ops);
    defer empty.deinit();
    try std.testing.expect(try boundariesSatisfied(empty.boundary_rows));
    const initial_channel = f.core.channel.blake3.Channel{};
    var bad_nonce: u64 = 0;
    while (initial_channel.verifyPowNonce(8, bad_nonce)) bad_nonce += 1;
    const bad_pow = [_]sequence.Operation{.{ .pow = .{ .bits = 8, .nonce = bad_nonce } }};
    var invalid = try sequence.prepare(a, 901, &bad_pow);
    defer invalid.deinit();
    try std.testing.expect(!try boundariesSatisfied(invalid.boundary_rows));
    const zero_pow = [_]sequence.Operation{.{ .pow = .{ .bits = 0, .nonce = 0xffffffffffffffff } }};
    var zero = try sequence.prepare(a, 901, &zero_pow);
    defer zero.deinit();
    try std.testing.expect(try boundariesSatisfied(zero.boundary_rows));
    try std.testing.expectEqual(@as(u64, 0), zero.next_draw);
    try std.testing.expectError(error.InvalidBlake3Transcript, sequence.trusted(a, 901, &.{.{ .pow = .{ .bits = 33, .nonce = 0 } }}));
}
fn allocationCase(a: std.mem.Allocator) !void {
    var query_values: [9]u32 = undefined;
    const ops = try operations(&query_values);
    var prepared = try sequence.prepare(a, 901, ops[9..11]);
    defer prepared.deinit();
    var fixed = try sequence.trusted(a, 901, ops[9..11]);
    defer fixed.deinit();
}
fn boundariesSatisfied(rows: []const sequence.boundary.Row) !bool {
    const lang = @import("../../air/lang/mod.zig");
    const a = std.testing.allocator;
    var definition = try sequence.boundary.build(a);
    defer definition.deinit();
    for (rows) |row| {
        const values = try @import("test_support.zig").evaluateArena(a, &definition.arena, &row);
        defer a.free(values);
        for (definition.arena.constraintsView()) |constraint| if (!values[lang.types.idIndex(constraint.root)].isZero()) return false;
    }
    return true;
}
test "BLAKE3 native transcript sequence verifies in a complete CPU proof" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var query_values: [9]u32 = undefined;
    const ops = try operations(&query_values);
    var live = try sequence.prepare(a, 901, &ops);
    defer live.deinit();
    const logs = live.logs();
    const rows = .{ try f.padded(f.g, a, live.g_rows, logs[0]), try f.padded(f.xor, a, live.xor_rows, logs[1]), try f.padded(f.boundary, a, live.boundary_rows, logs[2]), try f.padded(sequence.challenge, a, live.challenge_rows, logs[3]), try f.padded(sequence.route, a, live.route_rows, logs[4]), try f.padded(sequence.query_mask, a, live.query_rows, logs[5]) };
    const trusted = try preprocessing(a, &ops);
    var wrong = ops;
    wrong[4].secure.values[0] = wrong[4].secure.values[0].add(f.M31.one());
    const false_pp = try preprocessing(a, &wrong);
    try @import("blake3_proof_gate_test_support.zig").runFor(F, a, rows, logs, trusted, false_pp);
}
fn preprocessing(a: std.mem.Allocator, ops: []const sequence.Operation) ![]f.Column {
    var data = try sequence.trusted(a, 901, ops);
    defer data.deinit();
    const logs = data.logs();
    var columns: std.ArrayList(f.Column) = .empty;
    inline for (F.Airs, .{ data.g_rows, data.xor_rows, data.boundary_rows, data.challenge_rows, data.route_rows, data.query_rows }, 0..) |Air, rows, i| try f.project(Air, a, rows, logs[i], 0, &columns);
    for (f.kinds) |kind| try f.tablePreprocessed(a, kind, &columns);
    return columns.toOwnedSlice(a);
}

const Bounded = @import("blake3_fixture_roster.zig").WithExtras(.{ sequence.challenge, sequence.route, sequence.query_mask, sequence.retry_control, sequence.counter_step });
fn boundedRows(data: *const sequence.Prepared) @TypeOf(.{ data.g_rows, data.xor_rows, data.boundary_rows, data.challenge_rows, data.route_rows, data.query_rows, data.control_rows, data.counter_rows }) {
    return .{ data.g_rows, data.xor_rows, data.boundary_rows, data.challenge_rows, data.route_rows, data.query_rows, data.control_rows, data.counter_rows };
}
fn boundedLogs(data: *const sequence.Prepared) [8]u32 {
    var logs: [8]u32 = undefined;
    inline for (boundedRows(data), 0..) |rows, i| logs[i] = if (rows.len <= 1) 1 else std.math.log2_int_ceil(usize, rows.len);
    return logs;
}
test "BLAKE3 bounded transcript proves retries counter chaining resets and raw queries" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var query_values: [9]u32 = undefined;
    const base = try operations(&query_values);
    var ops: [21]sequence.Operation = undefined;
    ops[0..2].* = base[0..2].*;
    // Empty raw extraction must preserve the previous draw's counter port.
    ops[2] = .{ .queries = .{ .log_domain_size = 20, .values = &.{} } };
    ops[3..21].* = base[2..20].*;
    var channel = f.core.channel.blake3.Channel{};
    channel.mixU64(@import("blake3_rejection_fixture.zig").SEED);
    _ = channel.drawSecureFelt();
    const pair = try channel.drawSecureFelts(a, 2);
    ops[3].secure.consumption = .two;
    ops[3].secure.values = pair[0].toM31Array() ++ pair[1].toM31Array();
    try boundedCase(&ops, 1, 30, 32, 5);
    try std.testing.expectError(error.Blake3RetryCapacityExhausted, sequence.prepareBounded(a, 901, &ops, 1));
    try std.testing.expectError(error.InvalidBlake3Transcript, sequence.trustedBounded(a, 901, &ops, 0));
    // Independently initialize this transcript: absorption resets the counter,
    // but preserves the prior digest in its preimage.
    channel = .{};
    channel.mixU64(@import("blake3_rejection_fixture.zig").SEED);
    try std.testing.expectEqual(@as(u32, 0xffffffff), channel.drawU32s()[0]);
    const raw_ops = [_]sequence.Operation{ base[0], .{ .queries = .{ .log_domain_size = 31, .values = &.{0x7fffffff} } }, secure(&channel) };
    try boundedCase(&raw_ops, channel.n_draws, 3, 4, 2);
}
fn boundedCase(ops: []const sequence.Operation, next: u64, controls: usize, counters: usize, wrong_draw: usize) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var key = try plan_mod.Plan.init(a, .{ .namespace = 901, .attempt_capacity = 3 }, ops);
    defer key.deinit();
    var live = try key.prepare(a, ops);
    defer live.deinit();
    const placeholders = try a.dupe(sequence.Operation, ops);
    for (placeholders) |*op| if (op.* == .secure) {
        op.secure.attempts = 0;
    };
    const fixed = &key.fixed;
    var metadata = try key.prepare(a, placeholders);
    defer metadata.deinit();
    inline for (Bounded.Airs, boundedRows(&live), boundedRows(fixed), boundedRows(&metadata)) |Air, actual, trusted, unchanged| {
        try std.testing.expectEqual(actual.len, trusted.len);
        try std.testing.expectEqualSlices(Air.Row, actual, unchanged);
        for (actual, trusted) |row, expected| try std.testing.expectEqualSlices(f.M31, row[Air.PHYSICAL_MAIN_COLUMN_COUNT..], expected[Air.PHYSICAL_MAIN_COLUMN_COUNT..]);
    }
    try std.testing.expectEqual(next, live.next_draw);
    try std.testing.expectEqual(controls, live.control_rows.len);
    try std.testing.expectEqual(counters, live.counter_rows.len);
    try std.testing.expect(try boundariesSatisfied(live.boundary_rows));
    const logs = boundedLogs(&live);
    var rows = boundedRows(&live);
    inline for (Bounded.Airs, 0..) |Air, i| rows[i] = try f.padded(Air, a, rows[i], logs[i]);
    const trusted = try boundedPreprocessing(a, placeholders);
    placeholders[wrong_draw].secure.values[0] = placeholders[wrong_draw].secure.values[0].add(f.M31.one());
    const false_pp = try boundedPreprocessing(a, placeholders);
    try @import("blake3_proof_gate_test_support.zig").runFor(Bounded, a, rows, logs, trusted, false_pp);
}
fn boundedPreprocessing(a: std.mem.Allocator, ops: []const sequence.Operation) ![]f.Column {
    var key = try plan_mod.Plan.init(a, .{ .namespace = 901, .attempt_capacity = 3 }, ops);
    defer key.deinit();
    const data = &key.fixed;
    const logs = boundedLogs(data);
    var columns: std.ArrayList(f.Column) = .empty;
    inline for (Bounded.Airs, boundedRows(data), 0..) |Air, rows, i| try f.project(Air, a, rows, logs[i], 0, &columns);
    for (f.kinds) |kind| try f.tablePreprocessed(a, kind, &columns);
    return columns.toOwnedSlice(a);
}
