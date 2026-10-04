const std = @import("std");
const tree = @import("../../air/memory_commitment/blake3_state_tree.zig");
test "BLAKE3 Span memory word tree preserves sparse defaults and full digest roots" {
    const hasher = tree.TreeHasher.init(.memory);
    const empty = try hasher.root(&.{});
    try std.testing.expectEqual(empty, try hasher.root(&.{ .{ .index = 0, .value = 0 }, .{ .index = tree.MEMORY_WORD_LIMIT - 1, .value = 0 } }));
    var expected = hasher.leaf(255);
    const address: u32 = 0x1234567;
    for (0..tree.DEPTH) |height| {
        const sibling = hasher.defaults[tree.DEPTH - height];
        expected = if ((address >> @intCast(height)) & 1 == 0) hasher.pair(expected, sibling) else hasher.pair(sibling, expected);
    }
    try std.testing.expectEqual(expected, try hasher.root(&.{.{ .index = address, .value = 255 }}));
    try std.testing.expect(!std.meta.eql(expected, try hasher.root(&.{.{ .index = address + 1, .value = 255 }})));
    const program = tree.TreeHasher.init(.program);
    try std.testing.expect(!std.meta.eql(empty, try program.root(&.{})));
    _ = try hasher.root(&.{.{ .index = 1, .value = 0xffffffff }});
    try std.testing.expectError(error.StateIndexOutOfRange, hasher.root(&.{.{ .index = tree.ADDRESS_LIMIT, .value = 1 }}));
    try std.testing.expectError(error.UnsortedOrDuplicateByte, hasher.root(&.{ .{ .index = 1, .value = 1 }, .{ .index = 1, .value = 2 } }));
}

test "BLAKE3 Span memory node routes both full child digests through typed hash" {
    const witness = @import("../air/blake3_frame_witness.zig");
    const routing = @import("../air/blake3_frame_route.zig");
    const boundary = @import("../air/blake3_boundary.zig");
    const support = @import("../air/blake3_hash_test_support.zig");
    const M = @import("stwo_core").fields.m31.M31;
    const a = std.testing.allocator;
    const hasher = tree.TreeHasher.init(.memory);
    const left = hasher.leaf(12);
    const right = hasher.leaf(250);
    const frame = tree.Frame{ .node = .{ .kind = .memory, .left = left, .right = right } };
    const expected = frame.hash();
    const callers = [_]witness.Binding{ .{ .role = .left, .caller = .{ .circuit = 31, .first_wire = 0 } }, .{ .role = .right, .caller = .{ .circuit = 32, .first_wire = 0 } } };
    var live = try witness.prepareDigestFrame(a, 33, frame, &callers, expected.bytes);
    defer live.deinit();
    const placeholders = tree.Frame{ .node = .{ .kind = .memory, .left = .{ .bytes = @splat(0) }, .right = .{ .bytes = @splat(0) } } };
    var trusted = try witness.trustedDigestFrame(a, 33, placeholders, &callers, expected.bytes);
    defer trusted.deinit();
    try std.testing.expectEqual(expected.bytes, live.digest.?);
    for (live.route_rows, trusted.route_rows) |row, fixed| try std.testing.expectEqualSlices(M, row[12..], fixed[12..]);
    var producers: [16]boundary.Row = undefined;
    for ([_]tree.Digest{ left, right }, 0..) |digest, child| for (0..8) |word| {
        producers[child * 8 + word] = try boundary.logicalRow(callers[child].caller.circuit, @intCast(word), M.fromCanonical(live.source_uses[child][word]), std.mem.readInt(u32, digest.bytes[word * 4 ..][0..4], .little));
    };
    const rows = @import("../air/blake3_hash_witness.zig").Rows{ .allocator = a, .g_rows = live.rows.g_rows, .xor_rows = live.rows.xor_rows, .boundary_rows = live.rows.boundary_rows };
    try std.testing.expect(try support.closedRouted(&rows, live.route_rows, &producers));
    producers[15][0] = producers[15][0].add(M.one());
    try std.testing.expect(!try support.closedRouted(&rows, live.route_rows, &producers));
    try std.testing.expectError(error.InvalidBlake3FrameCaller, routing.buildWithPayload(a, 33, frame, callers[0..1], null));
}

test "BLAKE3 Span memory leaf binds every byte of a full-width word" {
    const leaf = @import("../air/blake3_memory_leaf.zig");
    const boundary = @import("../air/blake3_boundary.zig");
    const support = @import("../air/blake3_hash_test_support.zig");
    const bridge = @import("../air/blake3_input_bridge.zig");
    const direct = @import("../air/direct_constraint_program.zig");
    const M = @import("stwo_core").fields.m31.M31;
    const a = std.testing.allocator;
    var d = try bridge.build(a);
    defer d.deinit();
    const constraints = try direct.authenticate(&d.arena, bridge.SEMANTIC_DIGEST, bridge.LOGICAL_INPUT_COUNT);
    const hasher = tree.TreeHasher.init(.memory);
    for ([_]u32{ 0, 1, 128, 255, 0x80000000, 0xffffffff }) |byte| {
        const expected = hasher.leaf(byte);
        var live = try leaf.prepare(a, .memory, .{ .circuit = 31, .wire = 9 }, 32, byte, expected);
        defer live.deinit();
        var trusted = try leaf.trusted(a, .memory, .{ .circuit = 31, .wire = 9 }, 32, expected);
        defer trusted.deinit();
        try std.testing.expectEqual(expected.bytes, live.digest.?);
        try std.testing.expectEqualSlices(M, live.input[4..], trusted.input[4..]);
        try std.testing.expectEqualSlices(boundary.Row, live.rows.boundary_rows, trusted.rows.boundary_rows);
        const source = try boundary.logicalRow(31, 9, M.one(), byte);
        try std.testing.expect(try support.closedBridged(&live.rows, &.{live.input}, &.{source}));
        var roots: [bridge.DIRECT_CONSTRAINT_COUNT]M = undefined;
        var scratch: [direct.MAX_NODES]M = undefined;
        try constraints.evaluateBaseInto(&live.input, &scratch, &roots);
        for (roots) |root| try std.testing.expect(root.isZero());
        // All four limbs are live. A changed limb must break the authenticated
        // source/hash lookup, even though no limb is constrained to constant zero.
        for (0..4) |coordinate| {
            var forged = live.input;
            forged[coordinate] = forged[coordinate].add(M.one());
            try std.testing.expect(!try support.closedBridged(&live.rows, &.{forged}, &.{source}));
        }
        const wrong = try boundary.logicalRow(31, 9, M.one(), byte ^ 1);
        try std.testing.expect(!try support.closedBridged(&live.rows, &.{live.input}, &.{wrong}));
    }
}

test "BLAKE3 Span memory path connects every level with private siblings" {
    const path = @import("../air/blake3_memory_path.zig");
    const M = @import("stwo_core").fields.m31.M31;
    const hasher = tree.TreeHasher.init(.memory);
    const address: u32 = 0x1234567;
    const root = try hasher.root(&.{.{ .index = address, .value = 255 }});
    var siblings: [tree.DEPTH]tree.Digest = undefined;
    for (&siblings, 0..) |*digest, height| digest.* = hasher.defaults[tree.DEPTH - height];
    const statement = path.Statement{ .namespace = 100, .source = .{ .circuit = 99, .wire = 0 }, .kind = .memory, .address = address, .root = root };
    var live = try path.prepare(std.testing.allocator, statement, 255, &siblings);
    defer live.deinit();
    var fixed = try path.trusted(std.testing.allocator, statement);
    defer fixed.deinit();
    try std.testing.expectEqual(root, live.computed_root.?);
    try std.testing.expectEqual(@as(?tree.Digest, null), fixed.computed_root);
    inline for (.{ @import("../air/blake3_g_call.zig"), @import("../air/blake3_xor_call.zig"), @import("../air/blake3_boundary.zig"), @import("../air/blake3_byte_route.zig"), @import("../air/blake3_private_word.zig") }, .{ live.g_rows, live.xor_rows, live.boundary_rows, live.route_rows, live.word_rows }, .{ fixed.g_rows, fixed.xor_rows, fixed.boundary_rows, fixed.route_rows, fixed.word_rows }) |Air, actual, trusted| {
        try std.testing.expectEqual(actual.len, trusted.len);
        for (actual, trusted) |row, pp| try std.testing.expectEqualSlices(M, row[Air.PHYSICAL_MAIN_COLUMN_COUNT..], pp[Air.PHYSICAL_MAIN_COLUMN_COUNT..]);
    }
    try std.testing.expectEqual(@as(usize, 28 * 8), live.word_rows.len);
    siblings[28].bytes[0] ^= 1;
    try std.testing.expectError(error.InvalidMemoryPathSibling, path.prepare(std.testing.allocator, statement, 255, &siblings));
    siblings[28].bytes[0] ^= 1;
    try std.testing.expect(try pathClosed(&live, 255));
    live.word_rows[0][0] = live.word_rows[0][0].add(M.one());
    try std.testing.expect(!try pathClosed(&live, 255));
    var invalid = statement;
    invalid.source.circuit = 130;
    try std.testing.expectError(error.InvalidMemoryPath, path.trusted(std.testing.allocator, invalid));
}

fn pathClosed(path: *const @import("../air/blake3_memory_path.zig").Prepared, byte: u8) !bool {
    const a = std.testing.allocator;
    const M = @import("stwo_core").fields.m31.M31;
    const boundary = @import("../air/blake3_boundary.zig");
    const binding = @import("../air/universal_relation_binding.zig");
    const lang = @import("../../air/lang/mod.zig");
    var ledger = std.AutoHashMap([6]u32, M).init(a);
    defer ledger.deinit();
    const source = try boundary.logicalRow(99, 0, M.one(), byte);
    inline for (.{ @import("../air/blake3_g_call.zig"), @import("../air/blake3_xor_call.zig"), boundary, @import("../air/blake3_byte_route.zig"), @import("../air/blake3_private_word.zig"), @import("../air/blake3_input_bridge.zig"), boundary }, .{ path.g_rows, path.xor_rows, path.boundary_rows, path.route_rows, path.word_rows, &@as([1]@import("../air/blake3_input_bridge.zig").Row, .{path.input}), &@as([1]boundary.Row, .{source}) }) |Air, rows| {
        var definition = try Air.build(a);
        defer definition.deinit();
        const plan = try binding.Binding(Air).authenticate(&definition);
        for (rows) |row| for (plan.preparedEntries(row)) |entry| {
            if (entry.schema != lang.relation.id(.recursion_wire)) continue;
            var key: [6]u32 = undefined;
            for (&key, entry.values[0..6]) |*word, value| word.* = (try value.tryIntoM31()).toU32();
            const slot = try ledger.getOrPut(key);
            if (!slot.found_existing) slot.value_ptr.* = M.zero();
            slot.value_ptr.* = slot.value_ptr.*.add(try entry.numerator.tryIntoM31());
        };
    }
    var values = ledger.valueIterator();
    while (values.next()) |value| if (!value.isZero()) return false;
    return true;
}

test "BLAKE3 Span memory openings derive from sparse snapshot traversal" {
    const leaves = [_]tree.Leaf{ .{ .index = 0, .value = 7 }, .{ .index = 3, .value = 0 }, .{ .index = 4, .value = 128 }, .{ .index = 0x1234567, .value = 255 }, .{ .index = tree.MEMORY_WORD_LIMIT - 1, .value = 42 } };
    const hasher = tree.TreeHasher.init(.memory);
    const root = try hasher.root(&leaves);
    for ([_]u32{ 0, 1, 3, 4, 5, 0x1234567, 0x08000000, tree.MEMORY_WORD_LIMIT - 1 }) |address| {
        var opening = try hasher.opening(&leaves, address);
        try std.testing.expectEqual(root, opening.root);
        try std.testing.expectEqual(root, opening.computedRoot(&hasher));
        opening.siblings[17].bytes[31] ^= 0x80;
        try std.testing.expect(!std.meta.eql(root, opening.computedRoot(&hasher)));
    }
    const empty = try hasher.opening(&.{}, 123);
    try std.testing.expectEqual(try hasher.root(&.{}), empty.computedRoot(&hasher));
    try std.testing.expectEqual(@as(u8, 0), empty.value);
    try std.testing.expectError(error.StateIndexOutOfRange, hasher.opening(&leaves, tree.ADDRESS_LIMIT));
    try std.testing.expectEqual(@as(u32, 0xffffffff), (try hasher.opening(&.{.{ .index = 1, .value = 0xffffffff }}, 1)).value);
}

test "BLAKE3 Span memory update shares siblings between old and new roots" {
    const update = @import("../air/blake3_memory_update.zig");
    const hasher = tree.TreeHasher.init(.memory);
    const before = [_]tree.Leaf{ .{ .index = 0, .value = 7 }, .{ .index = 12, .value = 42 }, .{ .index = 900, .value = 8 } };
    var after = before;
    after[1].value = 255;
    const opening = try hasher.opening(&before, 12);
    const after_root = try hasher.root(&after);
    const statement = update.Statement{ .namespace = 100, .kind = .memory, .address = 12, .before_source = .{ .circuit = 99, .wire = 0 }, .after_source = .{ .circuit = 99, .wire = 1 }, .before_root = opening.root, .after_root = after_root };
    var live = try update.prepare(std.testing.allocator, statement, 42, 255, &opening.siblings);
    defer live.deinit();
    var trusted = try update.trusted(std.testing.allocator, statement);
    defer trusted.deinit();
    try std.testing.expectEqual(opening.root, live.before.computed_root.?);
    try std.testing.expectEqual(after_root, live.after.computed_root.?);
    try std.testing.expectEqual(@as(usize, 224), live.before.word_rows.len);
    try std.testing.expectEqual(@as(usize, 0), live.after.word_rows.len);
    for (live.before.word_rows, trusted.before.word_rows) |row, pp| {
        try std.testing.expectEqual(@as(u32, 2), row[7].toU32());
        try std.testing.expectEqualSlices(@import("stwo_core").fields.m31.M31, row[4..], pp[4..]);
    }
    var alias = statement;
    alias.after_source = alias.before_source;
    try std.testing.expectError(error.InvalidMemoryUpdate, update.trusted(std.testing.allocator, alias));
}

test "BLAKE3 Span state tree rejects aliased and out-of-range word addresses" {
    try std.testing.expectEqual(@as(u32, 3), try tree.memoryIndex(12));
    try std.testing.expectError(error.InvalidMemoryWordAddress, tree.memoryIndex(13));
    try std.testing.expectError(error.InvalidMemoryWordAddress, tree.memoryIndex(tree.ADDRESS_LIMIT));
    const hasher = tree.TreeHasher.init(.memory);
    try std.testing.expectError(error.StateIndexOutOfRange, hasher.root(&.{.{ .index = tree.MEMORY_WORD_LIMIT, .value = 1 }}));
}
