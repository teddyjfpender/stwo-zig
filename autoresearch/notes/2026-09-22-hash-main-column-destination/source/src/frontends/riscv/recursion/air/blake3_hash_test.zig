const std = @import("std");
const core = @import("stwo_core");
const graph = @import("blake3_hash_plan.zig");
const witness = @import("blake3_hash_witness.zig");
const g = @import("blake3_g_call.zig");
const xor = @import("blake3_xor_call.zig");
const boundary = @import("blake3_boundary.zig");
const binding = @import("universal_relation_binding.zig");
const lang = @import("../../air/lang/mod.zig");
const M31 = core.fields.m31.M31;

test "BLAKE3 hash DAG matches standard hashing across blocks chunks and unbalanced trees" {
    const a = std.testing.allocator;
    var input: [8193]u8 = undefined;
    for (&input, 0..) |*byte, i| byte.* = @intCast(i % 251);
    for ([_]usize{ 0, 1, 3, 4, 63, 64, 65, 127, 128, 1023, 1024, 1025, 2048, 2049, 3072, 4096, 4097, 8193 }) |len| {
        var expected: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash(input[0..len], &expected, .{});
        var prepared = try witness.prepare(a, 991, input[0..len], expected);
        defer prepared.rows.deinit();
        try std.testing.expectEqualSlices(u8, &expected, &prepared.digest);
        var trusted = try witness.trustedRows(a, 991, input[0..len], expected);
        defer trusted.deinit();
        inline for (.{ g, xor, boundary }, .{ prepared.rows.g_rows, prepared.rows.xor_rows, prepared.rows.boundary_rows }, .{ trusted.g_rows, trusted.xor_rows, trusted.boundary_rows }) |Air, actual, fixed| {
            for (actual, fixed) |left, right| try std.testing.expectEqualSlices(M31, left[Air.PHYSICAL_MAIN_COLUMN_COUNT..], right[Air.PHYSICAL_MAIN_COLUMN_COUNT..]);
        }
        var plan = try graph.build(a, len);
        defer plan.deinit();
        const gs = try a.alloc(g.Row, prepared.rows.g_rows.len);
        defer a.free(gs);
        const xs = try a.alloc(xor.Row, prepared.rows.xor_rows.len);
        defer a.free(xs);
        const bs = try a.alloc(boundary.Row, prepared.rows.boundary_rows.len);
        defer a.free(bs);
        const destination = witness.Destination{ .g_rows = gs, .xor_rows = xs, .boundary_rows = bs };
        const actual_digest = try witness.prepareInto(a, 991, input[0..len], expected, destination);
        try std.testing.expectEqualSlices(u8, &expected, &actual_digest);
        inline for (.{ gs, xs, bs }, .{ prepared.rows.g_rows, prepared.rows.xor_rows, prepared.rows.boundary_rows }) |actual, wanted| {
            for (actual, wanted) |x, y| try std.testing.expectEqualSlices(M31, &x, &y);
        }
        var short = destination;
        short.g_rows = gs[1..];
        const saved = gs[0];
        try std.testing.expectError(error.InvalidBlake3WitnessDestination, witness.prepareInto(a, 991, input[0..len], expected, short));
        try std.testing.expectEqualSlices(M31, &saved, &gs[0]);
        const chunks = @max(1, (len + 1023) / 1024);
        try std.testing.expectEqual(@max(1, (len + 63) / 64) + chunks - 1, plan.calls.len);
    }
    try std.testing.expectError(error.Blake3GraphTooLarge, graph.build(a, std.math.maxInt(usize)));
}

test "BLAKE3 hash global wires reject chaining flags and digest substitutions" {
    const a = std.testing.allocator;
    var input: [1025]u8 = @splat(37);
    var digest: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(&input, &digest, .{});
    var prepared = try witness.prepare(a, 73, &input, digest);
    defer prepared.rows.deinit();
    try std.testing.expect(try closed(&prepared.rows));
    // First G of block two consumes the previous compression's CV directly.
    const saved = prepared.rows.g_rows[56][0];
    prepared.rows.g_rows[56][0] = saved.add(M31.one());
    try std.testing.expect(!try closed(&prepared.rows));
    prepared.rows.g_rows[56][0] = saved;
    // Fixed initial flags are public-boundary sources, not witness authority.
    var plan = try graph.build(a, input.len);
    defer plan.deinit();
    const flags_wire = plan.calls[plan.calls.len - 1].initial[15];
    var found_flags = false;
    for (plan.sources, 0..) |source, i| if (source.wire == flags_wire) {
        found_flags = true;
        const row = prepared.rows.boundary_rows[i];
        prepared.rows.boundary_rows[i][0] = row[0].add(M31.one());
        prepared.rows.boundary_rows[i][8] = prepared.rows.boundary_rows[i][0];
        try std.testing.expect(!try closed(&prepared.rows));
        prepared.rows.boundary_rows[i] = row;
        break;
    };
    try std.testing.expect(found_flags);
    const last = prepared.rows.boundary_rows.len - 1;
    prepared.rows.boundary_rows[last][0] = prepared.rows.boundary_rows[last][0].add(M31.one());
    prepared.rows.boundary_rows[last][8] = prepared.rows.boundary_rows[last][0];
    try std.testing.expect(!try closed(&prepared.rows));
}
fn closed(rows: *const witness.Rows) !bool {
    const a = std.testing.allocator;
    var counts = std.AutoHashMap([6]u32, M31).init(a);
    defer counts.deinit();
    inline for (.{ g, xor, boundary }, .{ rows.g_rows, rows.xor_rows, rows.boundary_rows }) |Air, values| {
        var d = try Air.build(a);
        defer d.deinit();
        const plan = try binding.Binding(Air).authenticate(&d);
        for (values) |row| for (plan.preparedEntries(row)) |entry| {
            if (entry.schema != lang.relation.id(.recursion_wire)) continue;
            var key: [6]u32 = undefined;
            for (&key, entry.values[0..6]) |*word, value| word.* = (try value.tryIntoM31()).toU32();
            const slot = try counts.getOrPut(key);
            if (!slot.found_existing) slot.value_ptr.* = M31.zero();
            slot.value_ptr.* = slot.value_ptr.*.add(try entry.numerator.tryIntoM31());
        };
    }
    var values = counts.valueIterator();
    while (values.next()) |value| if (!value.isZero()) return false;
    return true;
}

test "BLAKE3 hash graph releases every partial allocation" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationProbe, .{});
}
fn allocationProbe(a: std.mem.Allocator) !void {
    var plan = try graph.build(a, 1025);
    defer plan.deinit();
    var prepared = try witness.prepare(a, 19, "allocation boundary", @splat(0));
    defer prepared.rows.deinit();
}

test "BLAKE3 hash emits directly into committed columns with offsets" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var input: [1025]u8 = undefined;
    for (&input, 0..) |*byte, i| byte.* = @intCast(i % 251);
    for ([_]usize{ 0, 65, 1025 }) |len| {
        var digest: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash(input[0..len], &digest, .{});
        var expected = try witness.prepare(a, 73, input[0..len], digest);
        defer expected.rows.deinit();
        var destination: witness.ColumnDestination = undefined;
        inline for (.{ g, xor, boundary }, .{ "g_rows", "xor_rows", "boundary_rows" }) |Air, name| {
            const rows = @field(expected.rows, name);
            const log = std.math.log2_int_ceil(usize, rows.len + 5);
            var columns: [Air.LOGICAL_INPUT_COUNT][]M31 = undefined;
            for (&columns) |*column| {
                column.* = try a.alloc(M31, @as(usize, 1) << @intCast(log));
                @memset(column.*, M31.fromCanonical(123));
            }
            @field(destination, name) = .{ .columns = columns, .log_size = log, .first = 3 };
        }
        const actual = try witness.prepareColumns(a, 73, input[0..len], digest, destination);
        try std.testing.expectEqualSlices(u8, &digest, &actual);
        inline for (.{ "g_rows", "xor_rows", "boundary_rows" }) |name| {
            const dst = @field(destination, name);
            const rows = @field(expected.rows, name);
            for (dst.columns, 0..) |column, coordinate| for (0..column.len) |logical| {
                const committed = @import("framework_interaction.zig").committedRow(logical, dst.log_size);
                const want = if (logical >= dst.first and logical < dst.first + rows.len) rows[logical - dst.first][coordinate] else M31.fromCanonical(123);
                try std.testing.expect(column[committed].eql(want));
            };
        }
        const framework = @import("framework_interaction.zig");
        const relations = @import("universal_challenges.zig").UniversalRelations.dummy();
        inline for (.{ g, xor, boundary }, .{ "g_rows", "xor_rows", "boundary_rows" }) |Air, name| {
            var definition = try Air.build(a);
            defer definition.deinit();
            const plan = try binding.Binding(Air).authenticate(&definition);
            const Runtime = framework.Runtime(binding.Binding(Air).Runtime);
            const dst = @field(destination, name);
            const rows = @field(expected.rows, name);
            var source = Runtime.ColumnRows{ .columns = undefined, .first = dst.first, .count = rows.len };
            for (&source.columns, dst.columns) |*column, data| column.* = data;
            const projection = @import("blake3_row_columns.zig");
            var projected: std.ArrayList(@import("stwo_prover_engine").pcs.ColumnEvaluation) = .empty;
            defer {
                for (projected.items) |column| a.free(column.values);
                projected.deinit(a);
            }
            const chunks = [_][]const Air.Row{ &.{}, rows[0 .. rows.len / 2], &.{}, rows[rows.len / 2 ..], &.{} };
            try projection.projectChunks(Air, a, &chunks, dst.log_size, 1, &projected);
            for (projected.items, 0..) |column, coordinate| {
                for (0..column.values.len) |logical| {
                    const expected_value = if (logical < rows.len) rows[logical][coordinate] else M31.zero();
                    try std.testing.expect(column.values[framework.committedRow(logical, dst.log_size)].eql(expected_value));
                }
            }
            const original_columns = projected.items.len;
            try std.testing.expectError(error.InvalidTraceShape, projection.projectChunks(Air, a, &chunks, 0, 1, &projected));
            const oversized = [_][]const Air.Row{rows} ** 9;
            try std.testing.expectError(error.InvalidTraceShape, projection.projectChunks(Air, a, &oversized, dst.log_size, 1, &projected));
            try std.testing.expectEqual(original_columns, projected.items.len);
            const Counter = @import("../../air/lookups/tables/counter.zig").Counter;
            var row_counters = [2]Counter{ try Counter.init(a, .bitwise), try Counter.init(a, .range_check_8_8) };
            defer for (&row_counters) |*counter| counter.deinit(a);
            var column_counters = [2]Counter{ try Counter.init(a, .bitwise), try Counter.init(a, .range_check_8_8) };
            defer for (&column_counters) |*counter| counter.deinit(a);
            try projection.register(Air, &plan, rows, &row_counters);
            try projection.registerColumns(Air, &plan, source, dst.log_size, &column_counters);
            for (row_counters, column_counters) |left, right| for (left.values, right.values) |x, y| try std.testing.expect(x.eql(y));
            const padding: Air.Row = @splat(M31.zero());
            var row_result = try Runtime.generatePreparedWithPadding(a, &plan, rows, dst.log_size, &relations, padding);
            defer row_result.deinit(a);
            var column_result = try Runtime.generatePreparedFromColumns(a, &plan, source, dst.log_size, &relations, padding);
            defer column_result.deinit(a);
            try std.testing.expect(row_result.claimed_sum.eql(column_result.claimed_sum));
            for (row_result.columns, column_result.columns) |left, right| for (left, right) |x, y| try std.testing.expect(x.eql(y));
            var inversion = try Runtime.Workspace.init(a, dst.log_size);
            defer inversion.deinit();
            var borrowed_result = try Runtime.generatePreparedFromColumnsWithWorkspace(a, &inversion, &plan, source, dst.log_size, &relations, padding);
            defer borrowed_result.deinit(a);
            try std.testing.expect(row_result.claimed_sum.eql(borrowed_result.claimed_sum));
            for (row_result.columns, borrowed_result.columns) |left, right| for (left, right) |x, y| try std.testing.expect(x.eql(y));
            var invalid_inversion = inversion;
            invalid_inversion.scratch = inversion.scratch[1..];
            try std.testing.expectError(error.WorkspaceCapacityMismatch, Runtime.generatePreparedFromColumnsWithWorkspace(a, &invalid_inversion, &plan, source, dst.log_size, &relations, padding));
            var failing_output = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
            try std.testing.expectError(error.OutOfMemory, Runtime.generatePreparedFromColumnsWithWorkspace(failing_output.allocator(), &inversion, &plan, source, dst.log_size, &relations, padding));
            source.first = source.columns[0].len;
            try std.testing.expectError(error.InvalidTraceShape, Runtime.generatePreparedFromColumns(a, &plan, source, dst.log_size, &relations, padding));
        }
        var invalid = destination;
        invalid.xor_rows.columns[0] = invalid.xor_rows.columns[0][1..];
        @memset(destination.g_rows.columns[0], M31.fromCanonical(987));
        try std.testing.expectError(error.InvalidBlake3WitnessDestination, witness.prepareColumns(a, 73, input[0..len], digest, invalid));
        for (destination.g_rows.columns[0]) |value| try std.testing.expectEqual(@as(u32, 987), value.v);
        invalid = destination;
        invalid.boundary_rows.first = invalid.boundary_rows.columns[0].len;
        try std.testing.expectError(error.InvalidBlake3WitnessDestination, witness.prepareColumns(a, 73, input[0..len], digest, invalid));
        for (destination.g_rows.columns[0]) |value| try std.testing.expectEqual(@as(u32, 987), value.v);
    }
}

test "BLAKE3 hash emits native main columns and separate witness metadata" {
    const a = std.testing.allocator;
    const framework = @import("framework_interaction.zig");
    var input: [1025]u8 = undefined;
    for (&input, 0..) |*byte, i| byte.* = @truncate(i);
    for ([_]usize{ 0, 65, 1025 }) |len| {
        var claim: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash(input[0..len], &claim, .{});
        var expected = try witness.prepare(a, 73, input[0..len], claim);
        defer expected.rows.deinit();
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const temp = arena.allocator();
        const destination = witness.MainColumnDestination{
            .g_rows = try mainTestBuffer(g, temp, expected.rows.g_rows.len),
            .xor_rows = try mainTestBuffer(xor, temp, expected.rows.xor_rows.len),
            .boundary_rows = try temp.alloc(boundary.Row, expected.rows.boundary_rows.len),
        };
        const digest = try witness.prepareMainColumns(a, 73, input[0..len], claim, destination);
        try std.testing.expectEqualSlices(u8, &claim, &digest);
        try std.testing.expectEqualDeep(expected.rows.boundary_rows, destination.boundary_rows);
        const relations = @import("universal_challenges.zig").UniversalRelations.dummy();
        inline for (.{ g, xor }, .{ destination.g_rows, destination.xor_rows }, .{ expected.rows.g_rows, expected.rows.xor_rows }) |Air, dst, rows| {
            var definition = try Air.build(a);
            defer definition.deinit();
            const plan = try binding.Binding(Air).authenticate(&definition);
            const Runtime = framework.Runtime(binding.Binding(Air).Runtime);
            var view = Runtime.ColumnRows{ .columns = @splat(&.{}), .first = dst.first, .count = rows.len, .main_count = Air.PHYSICAL_MAIN_COLUMN_COUNT, .metadata = dst.metadata };
            for (view.columns[0..Air.PHYSICAL_MAIN_COLUMN_COUNT], dst.columns) |*column, values| column.* = values;
            try view.validate(dst.log_size);
            for (rows, 0..) |row, index| {
                try std.testing.expectEqualDeep(row, view.read(index, dst.log_size));
                for (dst.metadata[index][0..Air.PHYSICAL_MAIN_COLUMN_COUNT]) |value| try std.testing.expect(value.isZero());
            }
            const size = @as(usize, 1) << @intCast(dst.log_size);
            for (0..size) |logical| if (logical < dst.first or logical >= dst.first + rows.len) {
                for (dst.columns) |column| try std.testing.expectEqual(@as(u32, 123), column[framework.committedRow(logical, dst.log_size)].v);
            };
            var oracle = try Runtime.generatePreparedWithPadding(a, &plan, rows, dst.log_size, &relations, @splat(M31.zero()));
            defer oracle.deinit(a);
            var actual = try Runtime.generatePreparedFromColumns(a, &plan, view, dst.log_size, &relations, @splat(M31.zero()));
            defer actual.deinit(a);
            try std.testing.expect(oracle.claimed_sum.eql(actual.claimed_sum));
            for (oracle.columns, actual.columns) |left, right| try std.testing.expectEqualSlices(M31, left, right);
        }
        @memset(destination.g_rows.columns[0], M31.fromCanonical(987));
        var bad = destination;
        bad.xor_rows.metadata = bad.xor_rows.metadata[1..];
        try std.testing.expectError(error.InvalidBlake3WitnessDestination, witness.prepareMainColumns(a, 73, input[0..len], claim, bad));
        bad = destination;
        bad.boundary_rows = bad.boundary_rows[1..];
        try std.testing.expectError(error.InvalidBlake3WitnessDestination, witness.prepareMainColumns(a, 73, input[0..len], claim, bad));
        bad = destination;
        bad.xor_rows.columns[0] = bad.xor_rows.columns[0][1..];
        try std.testing.expectError(error.InvalidBlake3WitnessDestination, witness.prepareMainColumns(a, 73, input[0..len], claim, bad));
        bad = destination;
        bad.xor_rows.first = bad.xor_rows.columns[0].len;
        try std.testing.expectError(error.InvalidBlake3WitnessDestination, witness.prepareMainColumns(a, 73, input[0..len], claim, bad));
        var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
        try std.testing.expectError(error.OutOfMemory, witness.prepareMainColumns(failing.allocator(), 73, input[0..len], claim, destination));
        for (destination.g_rows.columns[0]) |value| try std.testing.expectEqual(@as(u32, 987), value.v);
    }
}
fn mainTestBuffer(comptime Air: type, a: std.mem.Allocator, count: usize) !witness.MainColumnBuffer(Air) {
    const log = std.math.log2_int_ceil(usize, count + 3);
    var out = witness.MainColumnBuffer(Air){ .columns = undefined, .metadata = try a.alloc(Air.Row, count), .log_size = log, .first = 3 };
    for (&out.columns) |*column| {
        column.* = try a.alloc(M31, @as(usize, 1) << @intCast(log));
        @memset(column.*, M31.fromCanonical(123));
    }
    return out;
}
