const std = @import("std");
const core = @import("stwo_core");
const frame = @import("blake3_frame_witness.zig");
const g = @import("blake3_g_call.zig");
const xor = @import("blake3_xor_call.zig");
const boundary = @import("blake3_boundary.zig");
const bindings = [_]frame.Binding{.{ .role = .state, .caller = .{ .circuit = 1, .first_wire = 40 } }};
const message = core.channel.blake3.Frame{ .integer = .{ .state = @splat(0xa7), .value = 42 } };
test "BLAKE3 routed frame witness hides digest bytes from fixed columns and owns allocations" {
    const a = std.testing.allocator;
    const digest = message.hash();
    var live = try frame.prepare(a, 2, message, &bindings, digest);
    defer live.deinit();
    const placeholder = core.channel.blake3.Frame{ .integer = .{ .state = @splat(0), .value = 42 } };
    var fixed = try frame.trusted(a, 2, placeholder, &bindings, digest);
    defer fixed.deinit();
    try std.testing.expectEqualSlices(u8, &digest, &live.digest.?);
    try std.testing.expect(fixed.digest == null);
    try std.testing.expectEqualDeep(live.source_uses, fixed.source_uses);
    inline for (.{ g, xor, boundary, frame.route }, .{ live.rows.g_rows, live.rows.xor_rows, live.rows.boundary_rows, live.route_rows }, .{ fixed.rows.g_rows, fixed.rows.xor_rows, fixed.rows.boundary_rows, fixed.route_rows }) |Air, actual, expected| {
        try std.testing.expectEqual(actual.len, expected.len);
        for (actual, expected) |row, trusted_row| try std.testing.expectEqualSlices(core.fields.m31.M31, row[Air.PHYSICAL_MAIN_COLUMN_COUNT..], trusted_row[Air.PHYSICAL_MAIN_COLUMN_COUNT..]);
    }
    try mainColumnCase(a, message, &bindings, null);
    try destinationCase(a, true);
    try std.testing.checkAllAllocationFailures(a, destinationCase, .{false});
    try std.testing.checkAllAllocationFailures(a, allocationCase, .{});
    try payloadCases(a);
    try groupMainColumnCase(a);
    try planCacheCase(a);
    try groupDestinationAllocationCase(a, true);
    try std.testing.checkAllAllocationFailures(a, groupDestinationAllocationCase, .{false});
}
fn allocationCase(a: std.mem.Allocator) !void {
    var live = try frame.prepare(a, 2, message, &bindings, @splat(0));
    defer live.deinit();
    var fixed = try frame.trusted(a, 2, message, &bindings, @splat(0));
    defer fixed.deinit();
}

fn payloadCases(a: std.mem.Allocator) !void {
    const M31 = core.fields.m31.M31;
    const QM31 = core.fields.qm31.QM31;
    const values = [_]M31{ M31.one(), M31.fromCanonical(2147483646), M31.fromCanonical(256), M31.fromCanonical(19) };
    const fields = [_]QM31{QM31.fromM31Array(values)};
    const zeros = [_]M31{ M31.zero(), M31.zero(), M31.zero(), M31.zero() };
    const zero_fields = [_]QM31{QM31.zero()};
    const raw = [_]u32{ 0, 0xffffffff, 0x80000000, 19 };
    const zero_raw = [_]u32{ 0, 0, 0, 0 };
    const frames = [_]core.channel.blake3.Frame{ .{ .leaf = &values }, .{ .felts = .{ .state = @splat(0xa7), .values = &fields } }, .{ .words = .{ .state = @splat(0xa7), .values = &raw } } };
    const placeholders = [_]core.channel.blake3.Frame{ .{ .leaf = &zeros }, .{ .felts = .{ .state = @splat(0), .values = &zero_fields } }, .{ .words = .{ .state = @splat(0), .values = &zero_raw } } };
    const roles = [_]core.channel.blake3.framing.PayloadRole{ .leaf, .felts, .words };
    for (frames, placeholders, roles, 0..) |message_frame, placeholder, role, i| {
        const payload = frame.PayloadBinding{ .role = role, .caller = .{ .circuit = 2, .first_wire = 80 }, .word_count = 4 };
        const active = bindings[0..if (i == 0) @as(usize, 0) else 1];
        var live = try frame.preparePayload(a, 3, message_frame, active, payload, message_frame.hash());
        defer live.deinit();
        var fixed = try frame.trustedPayload(a, 3, placeholder, active, payload, message_frame.hash());
        defer fixed.deinit();
        try std.testing.expectEqualSlices(u32, live.payload_uses, fixed.payload_uses);
        for (live.payload_uses) |uses| try std.testing.expect(uses > 0 and uses <= 2);
        inline for (.{ g, xor, boundary, frame.route }, .{ live.rows.g_rows, live.rows.xor_rows, live.rows.boundary_rows, live.route_rows }, .{ fixed.rows.g_rows, fixed.rows.xor_rows, fixed.rows.boundary_rows, fixed.route_rows }) |Air, actual, expected| {
            try std.testing.expectEqual(actual.len, expected.len);
            for (actual, expected) |row, trusted_row| try std.testing.expectEqualSlices(M31, row[Air.PHYSICAL_MAIN_COLUMN_COUNT..], trusted_row[Air.PHYSICAL_MAIN_COLUMN_COUNT..]);
        }
        try mainColumnCase(a, message_frame, active, payload);
        var bad = payload;
        bad.word_count += 1;
        try std.testing.expectError(error.InvalidBlake3FrameCaller, frame.trustedPayload(a, 3, placeholder, active, bad, message_frame.hash()));
        bad = payload;
        bad.role = if (role == .leaf) .words else .leaf;
        try std.testing.expectError(error.InvalidBlake3FrameCaller, frame.trustedPayload(a, 3, placeholder, active, bad, message_frame.hash()));
    }
    try std.testing.checkAllAllocationFailures(a, payloadAllocationCase, .{});
}
fn payloadAllocationCase(a: std.mem.Allocator) !void {
    const values = [_]core.fields.m31.M31{core.fields.m31.M31.one()};
    const payload = frame.PayloadBinding{ .role = .leaf, .caller = .{ .circuit = 1, .first_wire = 0 }, .word_count = 1 };
    var live = try frame.preparePayload(a, 2, .{ .leaf = &values }, &.{}, payload, @splat(0));
    defer live.deinit();
    var fixed = try frame.trustedPayload(a, 2, .{ .leaf = &values }, &.{}, payload, @splat(0));
    defer fixed.deinit();
}

fn destinationCase(a: std.mem.Allocator, check_invalid: bool) !void {
    const M = core.fields.m31.M31;
    var expected = try frame.prepare(a, 2, message, &bindings, message.hash());
    defer expected.deinit();
    var trusted = try frame.trusted(a, 2, message, &bindings, message.hash());
    defer trusted.deinit();
    const gs = try a.alloc(g.Row, expected.rows.g_rows.len);
    defer a.free(gs);
    const xs = try a.alloc(xor.Row, expected.rows.xor_rows.len);
    defer a.free(xs);
    const destination = frame.HashDestination{ .g_rows = gs, .xor_rows = xs };
    {
        var result = try frame.prepareInto(a, 2, message, &bindings, null, message.hash(), destination);
        defer result.deinit();
        try std.testing.expectEqual(gs.ptr, result.rows.g_rows.ptr);
        try std.testing.expectEqual(xs.ptr, result.rows.xor_rows.ptr);
        try std.testing.expectEqualDeep(expected.rows, result.rows);
        try std.testing.expectEqualDeep(expected.route_rows, result.route_rows);
        try std.testing.expectEqualDeep(expected.source_uses, result.source_uses);
        try std.testing.expectEqualDeep(expected.digest, result.digest);
    }
    // Borrowed buffers survive receipt destruction and are reusable by fixed generation.
    try std.testing.expectEqualDeep(expected.rows.g_rows, gs);
    try std.testing.expectEqualDeep(expected.rows.xor_rows, xs);
    {
        var result = try frame.trustedInto(a, 2, message, &bindings, null, message.hash(), destination);
        defer result.deinit();
        try std.testing.expectEqualDeep(trusted.rows, result.rows);
        try std.testing.expectEqualDeep(trusted.route_rows, result.route_rows);
        try std.testing.expect(result.digest == null);
    }
    if (!check_invalid) return;
    @memset(gs, @splat(M.fromCanonical(123)));
    var invalid = destination;
    invalid.xor_rows = xs[1..];
    try std.testing.expectError(error.InvalidBlake3WitnessDestination, frame.prepareInto(a, 2, message, &bindings, null, message.hash(), invalid));
    try std.testing.expectError(error.InvalidBlake3WitnessDestination, frame.trustedInto(a, 2, message, &bindings, null, message.hash(), invalid));
    for (gs) |row| for (row) |value| try std.testing.expectEqual(@as(u32, 123), value.v);
}

fn groupDestinationAllocationCase(a: std.mem.Allocator, check_invalid: bool) !void {
    const group = @import("blake3_merkle_group_witness.zig");
    const directions = [_]group.select.Endpoint{.{ .circuit = 80, .wire = 0 }};
    const statement = group.Statement{ .namespace = 1000, .payload = .{ .circuit = 77, .first_wire = 0 }, .leaf_count = 2, .words_per_leaf = 1, .index = 1, .depth = 1, .root = @splat(0), .root_source = .{ .circuit = 78, .first_wire = 0 }, .directions = &directions };
    const values = [_]core.fields.m31.M31{ .one(), .fromCanonical(19) };
    const siblings = [_][32]u8{@splat(11)};
    var live = try group.prepare(a, statement, &values, &siblings);
    defer live.deinit();
    var fixed = try group.trusted(a, statement);
    defer fixed.deinit();
    try std.testing.expect(live.computed_root != null);
    try std.testing.expectEqualSlices(u32, live.payload_uses, fixed.payload_uses);
    inline for (.{ g, xor }, .{ live.g_rows, live.xor_rows }, .{ fixed.g_rows, fixed.xor_rows }) |Air, rows, trusted_rows| {
        try std.testing.expectEqual(rows.len, trusted_rows.len);
        for (rows, trusted_rows) |row, trusted_row| try std.testing.expectEqualSlices(core.fields.m31.M31, row[Air.PHYSICAL_MAIN_COLUMN_COUNT..], trusted_row[Air.PHYSICAL_MAIN_COLUMN_COUNT..]);
    }
    const counts = try group.requiredHashRows(a, statement);
    const gs = try a.alloc(g.Row, counts.g);
    defer a.free(gs);
    const xs = try a.alloc(xor.Row, counts.xor);
    defer a.free(xs);
    const out = group.HashDestination{ .g_rows = gs, .xor_rows = xs };
    {
        var result = try group.prepareInto(a, statement, &values, &siblings, out);
        defer result.deinit();
        try std.testing.expectEqual(gs.ptr, result.g_rows.ptr);
        try std.testing.expectEqual(xs.ptr, result.xor_rows.ptr);
        try std.testing.expectEqualDeep(live.g_rows, result.g_rows);
        try std.testing.expectEqualDeep(live.xor_rows, result.xor_rows);
        try std.testing.expectEqualDeep(live.computed_root, result.computed_root);
        try std.testing.expectEqualDeep(live.route_rows, result.route_rows);
    }
    try std.testing.expectEqualDeep(live.g_rows, gs);
    {
        var result = try group.trustedInto(a, statement, out);
        defer result.deinit();
        try std.testing.expectEqualDeep(fixed.g_rows, result.g_rows);
        try std.testing.expectEqualDeep(fixed.xor_rows, result.xor_rows);
    }
    if (check_invalid) {
        @memset(gs, @splat(core.fields.m31.M31.fromCanonical(123)));
        var invalid = out;
        invalid.xor_rows = xs[1..];
        try std.testing.expectError(error.InvalidBlake3WitnessDestination, group.prepareInto(a, statement, &values, &siblings, invalid));
        try std.testing.expectError(error.InvalidBlake3WitnessDestination, group.trustedInto(a, statement, invalid));
        for (gs) |row| for (row) |value| try std.testing.expectEqual(@as(u32, 123), value.v);
    }
}

// Reconstruct against the existing row oracle, but admit metadata against a
// separately generated trusted frame. The output planes belong to the caller.
fn mainColumnCase(a: std.mem.Allocator, value: core.channel.blake3.Frame, active: []const frame.Binding, payload: ?frame.PayloadBinding) !void {
    const M = core.fields.m31.M31;
    const framework = @import("framework_interaction.zig");
    const binding = @import("universal_relation_binding.zig");
    var expected = if (payload) |p| try frame.preparePayload(a, 3, value, active, p, value.hash()) else try frame.prepare(a, 3, value, active, value.hash());
    defer expected.deinit();
    var fixed = if (payload) |p| try frame.trustedPayload(a, 3, value, active, p, value.hash()) else try frame.trusted(a, 3, value, active, value.hash());
    defer fixed.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const out = frame.MainColumns{
        .g_rows = try mainBuffer(g, arena.allocator(), expected.rows.g_rows.len),
        .xor_rows = try mainBuffer(xor, arena.allocator(), expected.rows.xor_rows.len),
    };
    {
        var actual = try frame.prepareMainColumns(a, 3, value, active, payload, value.hash(), out);
        defer actual.deinit();
        try std.testing.expect(actual.hash_metadata != null);
        try std.testing.expect(expected.hash_metadata == null);
        try std.testing.expectEqual(out.g_rows.metadata.ptr, actual.hash_metadata.?.g_rows.ptr);
        try std.testing.expectEqual(out.xor_rows.metadata.ptr, actual.hash_metadata.?.xor_rows.ptr);
        try std.testing.expectEqualDeep(expected.rows.boundary_rows, actual.rows.boundary_rows);
        try std.testing.expectEqualDeep(expected.route_rows, actual.route_rows);
        try std.testing.expectEqualDeep(expected.source_uses, actual.source_uses);
        try std.testing.expectEqualDeep(expected.payload_uses, actual.payload_uses);
        try std.testing.expectEqualDeep(expected.digest, actual.digest);
    }
    // Read after receipt destruction to exercise the borrowed-storage contract.
    inline for (.{ g, xor }, .{ out.g_rows, out.xor_rows }, .{ expected.rows.g_rows, expected.rows.xor_rows }, .{ fixed.rows.g_rows, fixed.rows.xor_rows }) |Air, dst, rows, trusted_rows| {
        const Runtime = framework.Runtime(binding.Binding(Air).Runtime);
        var view = Runtime.ColumnRows{ .columns = @splat(&.{}), .first = dst.first, .count = rows.len, .main_count = Air.PHYSICAL_MAIN_COLUMN_COUNT, .compact_metadata = std.mem.bytesAsSlice(@import("stwo_core").fields.m31.M31, std.mem.sliceAsBytes(dst.metadata)) };
        for (view.columns[0..Air.PHYSICAL_MAIN_COLUMN_COUNT], dst.columns) |*column, values| column.* = values;
        try view.validate(dst.log_size);
        for (rows, trusted_rows, 0..) |row, trusted_row, i| {
            try std.testing.expectEqualDeep(row, view.read(i, dst.log_size));
            try std.testing.expectEqualSlices(M, trusted_row[Air.PHYSICAL_MAIN_COLUMN_COUNT..], &dst.metadata[i]);
        }
        for (0..dst.columns[0].len) |logical| if (logical < dst.first or logical >= dst.first + rows.len) {
            for (dst.columns) |column| try std.testing.expectEqual(@as(u32, 123), column[framework.committedRow(logical, dst.log_size)].v);
        };
    }
    @memset(out.g_rows.columns[0], M.fromCanonical(987));
    var bad = out;
    bad.xor_rows.columns[0] = bad.xor_rows.columns[0][1..];
    try std.testing.expectError(error.InvalidBlake3WitnessDestination, frame.prepareMainColumns(a, 3, value, active, payload, value.hash(), bad));
    bad = out;
    bad.xor_rows.metadata = bad.xor_rows.metadata[1..];
    try std.testing.expectError(error.InvalidBlake3WitnessDestination, frame.prepareMainColumns(a, 3, value, active, payload, value.hash(), bad));
    var plan = try @import("blake3_hash_plan.zig").build(a, try value.encodedSize());
    defer plan.deinit();
    const unrelated = frame.HashDestination{ .g_rows = expected.rows.g_rows, .xor_rows = expected.rows.xor_rows };
    try std.testing.expectError(error.InvalidBlake3WitnessDestination, frame.destinationWithPlan(a, 3, value, active, payload, value.hash(), true, unrelated, out, &plan));
    try std.testing.expectError(error.InvalidBlake3Frame, frame.destinationWithPlan(a, 3, value, active, payload, value.hash(), false, unrelated, out, &plan));
    for (out.g_rows.columns[0]) |field| try std.testing.expectEqual(@as(u32, 987), field.v);
}
fn mainBuffer(comptime Air: type, a: std.mem.Allocator, count: usize) !@import("blake3_hash_witness.zig").MainColumnBuffer(Air) {
    const M = core.fields.m31.M31;
    const log = std.math.log2_int_ceil(usize, count + 3);
    var out = @import("blake3_hash_witness.zig").MainColumnBuffer(Air){ .columns = undefined, .metadata = try a.alloc(@import("blake3_hash_metadata.zig").Row(Air), count), .log_size = log, .first = 3 };
    for (&out.columns) |*column| {
        column.* = try a.alloc(M, @as(usize, 1) << @intCast(log));
        @memset(column.*, M.fromCanonical(123));
    }
    return out;
}

fn groupMainColumnCase(a: std.mem.Allocator) !void {
    const group = @import("blake3_merkle_group_witness.zig");
    const framework = @import("framework_interaction.zig");
    const binding = @import("universal_relation_binding.zig");
    const M = core.fields.m31.M31;
    const directions = [_]group.select.Endpoint{.{ .circuit = 80, .wire = 0 }};
    const values = [_]M{ .one(), .fromCanonical(19) };
    const siblings = [_][32]u8{@splat(11)};
    for ([_]bool{ false, true }) |selected| {
        const statement = group.Statement{ .namespace = 1000, .payload = .{ .circuit = 77, .first_wire = 0 }, .leaf_count = 2, .words_per_leaf = 1, .index = 1, .depth = 1, .root = @splat(0), .root_source = if (selected) .{ .circuit = 78, .first_wire = 0 } else null, .directions = if (selected) &directions else null };
        var expected = try group.prepare(a, statement, &values, &siblings);
        defer expected.deinit();
        var fixed = try group.trusted(a, statement);
        defer fixed.deinit();
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const out = group.MainColumns{
            .g_rows = try mainBuffer(g, arena.allocator(), expected.g_rows.len),
            .xor_rows = try mainBuffer(xor, arena.allocator(), expected.xor_rows.len),
        };
        var cache = group.PlanCache.init(a);
        defer cache.deinit();
        const metadata = try @import("blake3_hash_metadata.zig").Rows.allocate(a, fixed.g_rows.len, fixed.xor_rows.len);
        defer metadata.free(a);
        {
            var compact = try group.trustedIntoCached(a, statement, .{ .fixed = metadata }, &cache);
            defer compact.deinit();
            try @import("blake3_main_column_test_support.zig").expectReceipts(fixed, compact);
            try @import("blake3_main_column_test_support.zig").expectFixedMetadata(fixed, metadata);
            try std.testing.expectEqual(@as(usize, 0), compact.g_rows.len);
            try std.testing.expectEqual(@as(usize, 0), compact.xor_rows.len);
            var bad_metadata = metadata;
            bad_metadata.g_rows = metadata.g_rows[1..];
            try std.testing.expectError(error.InvalidBlake3WitnessDestination, group.trustedIntoCached(a, statement, .{ .fixed = bad_metadata }, &cache));
            try std.testing.expectError(error.InvalidBlake3WitnessDestination, group.trustedIntoCached(a, statement, .{ .fixed = metadata, .g_rows = fixed.g_rows }, &cache));
            try std.testing.expectError(error.InvalidBlake3WitnessDestination, group.prepareIntoCached(a, statement, &values, &siblings, .{ .fixed = metadata }, &cache));
            try std.testing.expectError(error.InvalidBlake3WitnessDestination, metadata.slice(metadata.g_rows.len + 1, 0, 0, 0));
        }
        try std.testing.checkAllAllocationFailures(a, compactTrustedGroupCase, .{statement});
        for (0..2) |_| {
            var actual = try group.prepareMainColumnsCached(a, statement, &values, &siblings, out, &cache);
            defer actual.deinit();
            try std.testing.expect(actual.hash_metadata != null);
            try std.testing.expect(expected.hash_metadata == null);
            try std.testing.expectEqual(out.g_rows.metadata.ptr, actual.hash_metadata.?.g_rows.ptr);
            try std.testing.expectEqual(out.xor_rows.metadata.ptr, actual.hash_metadata.?.xor_rows.ptr);
            inline for (.{ "boundary_rows", "route_rows", "word_rows", "select_rows", "payload_uses", "computed_root" }) |name| try std.testing.expectEqualDeep(@field(expected, name), @field(actual, name));
        }
        inline for (.{ g, xor }, .{ out.g_rows, out.xor_rows }, .{ expected.g_rows, expected.xor_rows }, .{ fixed.g_rows, fixed.xor_rows }) |Air, dst, rows, trusted_rows| {
            const Runtime = framework.Runtime(binding.Binding(Air).Runtime);
            var view = Runtime.ColumnRows{ .columns = @splat(&.{}), .first = dst.first, .count = rows.len, .main_count = Air.PHYSICAL_MAIN_COLUMN_COUNT, .compact_metadata = std.mem.bytesAsSlice(@import("stwo_core").fields.m31.M31, std.mem.sliceAsBytes(dst.metadata)) };
            for (view.columns[0..Air.PHYSICAL_MAIN_COLUMN_COUNT], dst.columns) |*column, fields| column.* = fields;
            try view.validate(dst.log_size);
            for (rows, trusted_rows, 0..) |row, trusted_row, i| {
                try std.testing.expectEqualDeep(row, view.read(i, dst.log_size));
                try std.testing.expectEqualSlices(M, trusted_row[Air.PHYSICAL_MAIN_COLUMN_COUNT..], &dst.metadata[i]);
            }
        }
        @memset(out.g_rows.columns[0], M.fromCanonical(987));
        var bad = out;
        bad.xor_rows.first = bad.xor_rows.columns[0].len;
        try std.testing.expectError(error.InvalidBlake3WitnessDestination, group.prepareMainColumns(a, statement, &values, &siblings, bad));
        bad = out;
        bad.xor_rows.metadata = bad.xor_rows.metadata[1..];
        try std.testing.expectError(error.InvalidBlake3WitnessDestination, group.prepareMainColumns(a, statement, &values, &siblings, bad));
        for (out.g_rows.columns[0]) |field| try std.testing.expectEqual(@as(u32, 987), field.v);
        try std.testing.expectError(error.InvalidBlake3WitnessDestination, out.slice(out.g_rows.metadata.len + 1, 0, 0, 0));
        try std.testing.expectError(error.InvalidBlake3WitnessDestination, out.slice(0, 0, 0, out.xor_rows.metadata.len + 1));
    }
}

fn planCacheCase(a: std.mem.Allocator) !void {
    const Cache = @import("blake3_merkle_plan_cache.zig").Cache;
    const graph = @import("blake3_hash_plan.zig");
    var failing = std.testing.FailingAllocator.init(a, .{});
    var cache = Cache.init(failing.allocator());
    defer cache.deinit();
    const first = try cache.get(67);
    const node = first.node;
    for (0..4) |_| {
        const again = try cache.get(67);
        try std.testing.expectEqual(first.leaf, again.leaf);
        try std.testing.expectEqual(node, again.node);
    }
    try std.testing.expectEqual(@as(usize, 2), cache.builds);
    failing.fail_index = failing.alloc_index;
    try std.testing.expectError(error.OutOfMemory, cache.get(131));
    try std.testing.expectEqual(@as(usize, 67), cache.leaf.?.input_len);
    try std.testing.expectEqual(@as(usize, 2), cache.builds);
    failing.fail_index = std.math.maxInt(usize);
    const changed = try cache.get(131);
    try std.testing.expectEqual(node, changed.node);
    try std.testing.expectEqual(@as(usize, 3), cache.builds);
    var expected = try graph.build(a, 131);
    defer expected.deinit();
    inline for (.{ "g", "xor", "sources", "uses", "output", "calls" }) |name|
        try std.testing.expectEqualDeep(@field(expected, name), @field(changed.leaf.*, name));
    const shared = try cache.get(node.input_len);
    try std.testing.expectEqual(shared.leaf, shared.node);
    try std.testing.expectEqual(@as(usize, 3), cache.builds);
}

fn compactTrustedGroupCase(a: std.mem.Allocator, statement: @import("blake3_merkle_group_witness.zig").Statement) !void {
    const group = @import("blake3_merkle_group_witness.zig");
    var cache = group.PlanCache.init(a);
    defer cache.deinit();
    const counts = try group.requiredHashRowsCached(a, statement, &cache);
    const metadata = try @import("blake3_hash_metadata.zig").Rows.allocate(a, counts.g, counts.xor);
    defer metadata.free(a);
    var fixed = try group.trustedIntoCached(a, statement, .{ .fixed = metadata }, &cache);
    defer fixed.deinit();
}
