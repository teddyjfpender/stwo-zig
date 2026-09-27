const std = @import("std");
const core = @import("stwo_core");
const plan = @import("blake3_transcript_plan.zig");
const t = @import("blake3_transcript_witness.zig");
const M = core.fields.m31.M31;
test "BLAKE3 transcript plan reuses private preprocessing and binds capacity and roles" {
    const a = std.testing.allocator;
    try compactAdmission(a);
    var ops = [_]t.Operation{
        .{ .routed_integer = .{ .value = @import("blake3_rejection_fixture.zig").SEED, .source = .{ .circuit = 10, .first_wire = 0 } } },
        .{ .secure = .{ .output = .oods, .attempts = 0, .values = @splat(M.zero()) } },
    };
    var key = try plan.Plan.init(a, .{ .namespace = 100, .attempt_capacity = 3 }, &ops);
    defer key.deinit();
    var live = try key.prepare(a, &ops);
    defer live.deinit();
    try std.testing.expectEqual(@as(u64, 2), live.next_draw);
    const id = key.id;
    ops[0].routed_integer.value = 42;
    ops[1].secure.attempts = 999;
    var changed = try key.prepare(a, &ops);
    defer changed.deinit();
    try std.testing.expect(!std.mem.eql(u8, &live.final_digest.?, &changed.final_digest.?));
    var same = try plan.Plan.init(a, key.config, &ops);
    defer same.deinit();
    try std.testing.expectEqualSlices(u8, &id, &same.id);
    ops[1].secure.output = .composition;
    try std.testing.expectError(error.Blake3TranscriptPlanMismatch, key.prepare(a, &ops));
    ops[1].secure.output = .oods;
    const public_ops = [_]t.Operation{ .{ .integer = 42 }, ops[1] };
    try std.testing.expectError(error.Blake3TranscriptPlanMismatch, key.prepare(a, &public_ops));
    var narrow = try plan.Plan.init(a, .{ .namespace = 100, .attempt_capacity = 1 }, &ops);
    defer narrow.deinit();
    try std.testing.expect(!std.mem.eql(u8, &id, &narrow.id));
    ops[0].routed_integer.value = @import("blake3_rejection_fixture.zig").SEED;
    try std.testing.expectError(error.Blake3RetryCapacityExhausted, narrow.prepare(a, &ops));
    key.config.attempt_capacity = 1;
    try std.testing.expectError(error.CorruptBlake3TranscriptPlan, key.prepare(a, &ops));
    key.config.attempt_capacity = 3;
    key.fixed.boundary_rows[0][t.boundary.PHYSICAL_MAIN_COLUMN_COUNT] = M.zero();
    try std.testing.expectError(error.CorruptBlake3TranscriptPlan, key.validate());
    try std.testing.expectError(error.InvalidBlake3Transcript, plan.Plan.init(a, .{ .namespace = 100, .attempt_capacity = 0 }, &ops));
    try hashOwnerCase(a);
    try std.testing.checkAllAllocationFailures(a, hashOwnerCase, .{});
    try mainColumnCase(a);
    try std.testing.checkAllAllocationFailures(a, allocationCase, .{});
}
fn allocationCase(a: std.mem.Allocator) !void {
    const queries = [_]u32{ 0, 0 };
    const ops = [_]t.Operation{
        .{ .routed_integer = .{ .value = 42, .source = .{ .circuit = 10, .first_wire = 0 } } },
        .{ .pow = .{ .bits = 0, .nonce = 19, .nonce_source = .{ .circuit = 11, .first_wire = 0 } } },
        .{ .queries = .{ .log_domain_size = 0, .values = &queries, .export_outputs = true } },
        .{ .secure = .{ .output = .oods, .attempts = 0, .values = @splat(M.zero()) } },
        .{ .routed_integer = .{ .value = 99, .source = .{ .circuit = 12, .first_wire = 0 } } },
    };
    var key = try plan.Plan.init(a, .{ .namespace = 100, .attempt_capacity = 3 }, &ops);
    var live = key.prepare(a, &ops) catch |err| {
        key.deinit();
        return err;
    };
    defer live.deinit();
    var fixed = key.intoFixed();
    defer fixed.deinit();
    // Force arena growth after transfer; one owner must free every new block.
    const extra = try fixed.arena.allocator().alloc(u8, 1_000_000);
    @memset(extra, 0);
}

test "BLAKE3 native transcript planning retains ownership on failed emission" {
    const a = std.testing.allocator;
    const native = @import("blake3_native_transcript.zig");
    var arena = std.heap.ArenaAllocator.init(a);
    var owns_arena = true;
    defer if (owns_arena) arena.deinit();
    const operations = try arena.allocator().dupe(t.Operation, &.{.{ .integer = 42 }});
    var end = core.channel.blake3.Channel{};
    end.mixU64(42);
    const key = try plan.Plan.init(a, .{ .namespace = 100, .attempt_capacity = 1 }, operations);
    var planned = native.Planned{ .arena = arena, .operations = operations, .claim_payloads = &.{}, .plan = key, .end = end };
    owns_arena = false;
    var owns_planned = true;
    defer if (owns_planned) planned.deinit();
    const counts = try planned.hashCounts();
    const support = @import("blake3_main_column_test_support.zig");
    var output_arena = std.heap.ArenaAllocator.init(a);
    defer output_arena.deinit();
    const out = try support.allocate(output_arena.allocator(), counts.g, counts.xor);
    var oracle = try planned.plan.prepare(a, planned.operations);
    defer oracle.deinit();
    var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, planned.emitMainColumns(failing.allocator(), out));
    try planned.plan.validate();
    planned.end.n_draws += 1;
    try std.testing.expectError(error.InvalidNativeBlake3Transcript, planned.emitMainColumns(a, out));
    planned.end = end;
    var emitted = try planned.emitMainColumns(a, out);
    owns_planned = false;
    defer emitted.deinit();
    try std.testing.expectEqual(counts.g, emitted.live.hash_metadata.?.g_rows.len);
    try std.testing.expectEqual(counts.xor, emitted.live.hash_metadata.?.xor_rows.len);
    try std.testing.expectEqualSlices(u8, &end.digestBytes(), &emitted.live.final_digest.?);
    try emitted.plan.validate();
    try support.expectRows(out, oracle, emitted.plan.fixed);
}

fn mainColumnCase(a: std.mem.Allocator) !void {
    const support = @import("blake3_main_column_test_support.zig");
    const words = [_]u32{ 0xffffffff, 19 };
    const felts = [_]core.fields.qm31.QM31{core.fields.qm31.QM31.one()};
    const query_values = [_]u32{0} ** 9;
    var ops = [_]t.Operation{
        .{ .routed_integer = .{ .value = 42, .source = .{ .circuit = 10, .first_wire = 0 } } },
        .{ .pow = .{ .bits = 0, .nonce = 19, .nonce_source = .{ .circuit = 11, .first_wire = 0 } } },
        .{ .queries = .{ .log_domain_size = 0, .values = &query_values, .export_outputs = true } },
        .{ .secure = .{ .output = .oods, .attempts = 0, .values = @splat(M.zero()) } },
        .{ .root = @splat(17) },
        .{ .routed_root = .{ .value = @splat(29), .source = .{ .circuit = 12, .first_wire = 0 } } },
        .{ .routed_words = .{ .values = &words, .source = .{ .circuit = 13, .first_wire = 0 } } },
        .{ .routed_felts = .{ .values = &felts, .source = .{ .circuit = 14, .first_wire = 0 } } },
    };
    var key = try plan.Plan.init(a, .{ .namespace = 100, .attempt_capacity = 3 }, &ops);
    defer key.deinit();
    var expected = try key.prepare(a, &ops);
    defer expected.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const out = try support.allocate(arena.allocator(), expected.g_rows.len, expected.xor_rows.len);
    {
        var actual = try key.prepareMainColumns(a, &ops, out);
        defer actual.deinit();
        try support.expectReceipts(expected, actual);
    }
    try support.expectRows(out, expected, key.fixed);
    support.poison(out);
    var bad = out;
    bad.xor_rows.metadata = bad.xor_rows.metadata[1..];
    try std.testing.expectError(error.InvalidBlake3WitnessDestination, key.prepareMainColumns(a, &ops, bad));
    try support.expectPoison(out);
    @memset(out.g_rows.columns[0], M.fromCanonical(123));
    ops[3].secure.output = .composition;
    try std.testing.expectError(error.Blake3TranscriptPlanMismatch, key.prepareMainColumns(a, &ops, out));
    ops[3].secure.output = .oods;
    try std.testing.checkAllAllocationFailures(a, columnAllocationCase, .{ &key, &ops, out });
    // A successful retry overwrites unpublished outputs left by injected failures.
    var actual = try key.prepareMainColumns(a, &ops, out);
    defer actual.deinit();
    try support.expectRows(out, expected, key.fixed);
}
fn columnAllocationCase(a: std.mem.Allocator, key: *const plan.Plan, ops: []const t.Operation, out: t.MainColumns) !void {
    var actual = try key.prepareMainColumns(a, ops, out);
    defer actual.deinit();
}

fn hashOwnerCase(a: std.mem.Allocator) !void {
    const Owner = @import("../blake3_native_hash_columns.zig").Owner;
    var owner = try Owner.init(a, .{ .transcript = .{ .g = 3, .xor = 2 }, .paths = .{ .g = 2, .xor = 1 }, .total = .{ .g = 5, .xor = 3 }, .logs = .{ 3, 2 } });
    defer owner.deinit();
    const transcript = try owner.transcript();
    const paths = try owner.paths();
    try std.testing.expectEqual(@as(usize, 3), paths.g_rows.first);
    try std.testing.expectEqual(@as(usize, 2), paths.xor_rows.first);
    try std.testing.expectEqual(owner.g_metadata.ptr, transcript.g_rows.metadata.ptr);
    try std.testing.expectEqual(owner.g_metadata[3..].ptr, paths.g_rows.metadata.ptr);
    for (owner.main) |columns| for (columns) |column| for (column.values) |value| try std.testing.expect(value.isZero());
}

fn compactAdmission(a: std.mem.Allocator) !void {
    const storage = @import("blake3_parent_row_storage.zig");
    inline for (0..2) |cohort| {
        const Air = storage.Airs[cohort];
        var trusted: [2]Air.Row = undefined;
        var compact: [2]storage.FixedRow(Air) = undefined;
        for (&trusted, &compact, 0..) |*row, *tail, r| {
            for (row, 0..) |*value, c| value.* = M.fromU64(r * 1000 + c + 1);
            tail.* = storage.compactFixed(Air, row.*);
        }
        const trusted_compact = compact;
        var b = storage.Builder.init(a);
        defer b.deinit();
        try b.appendMetadata(cohort, &compact, &trusted);
        try std.testing.expectEqualDeep(&compact, b.fixed[cohort].items);
        for (0..compact[1].len) |i| {
            compact[1][i] = compact[1][i].add(M.one());
            try std.testing.expectError(error.InvalidNativeParentRows, b.appendMetadata(cohort, &compact, &trusted));
            try std.testing.expectError(error.InvalidNativeParentRows, b.appendMetadata(cohort, &compact, &trusted_compact));
            try std.testing.expectEqual(@as(usize, 2), b.fixed[cohort].items.len);
            compact[1][i] = compact[1][i].sub(M.one());
        }
        try std.testing.expectError(error.InvalidNativeParentRows, b.appendMetadata(cohort, compact[0..1], &trusted));
        const Case = struct {
            fn run(allocator: std.mem.Allocator, tail: *const [2]storage.FixedRow(Air), rows: *const [2]Air.Row) !void {
                var builder = storage.Builder.init(allocator);
                defer builder.deinit();
                try builder.appendMetadata(cohort, tail, rows);
                const trusted_tails = [2]storage.FixedRow(Air){ storage.compactFixed(Air, rows[0]), storage.compactFixed(Air, rows[1]) };
                try builder.appendMetadata(cohort, tail, &trusted_tails);
            }
        };
        try std.testing.checkAllAllocationFailures(a, Case.run, .{ &compact, &trusted });
    }
}
