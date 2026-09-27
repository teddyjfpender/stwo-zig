//! Nonproving scalar/equation/schedule/ownership fixtures only.
const std = @import("std");
const core = @import("stwo_core");
const T = @import("../recursion/blake3_words_tail_v1.zig");
const P = @import("../recursion/air/blake3_words_tail_plan_v1.zig");
const W = @import("../recursion/air/blake3_words_tail_witness_v1.zig");
const G = @import("../recursion/air/blake3_g_call.zig");
const X = @import("../recursion/air/blake3_xor_call.zig");
const B = @import("../recursion/air/blake3_boundary.zig");
const R = @import("../recursion/air/blake3_byte_route.zig");
const Word = @import("../recursion/air/blake3_private_word.zig");
const M = core.fields.m31.M31;
const Frame = core.channel.blake3.framing.Frame;

test "original words tail: scalar original framing parity at956 and chunk tree edges" {
    var domain_digest: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(T.DOMAIN_LABEL, &domain_digest, .{});
    try std.testing.expectEqualSlices(u8, &domain_digest, &T.DOMAIN_STATE);
    var words: [4097]u32 = undefined;
    for (&words, 0..) |*word, i| word.* = @truncate(i *% 0xa3018ffd);
    for ([_]usize{ 0, 1, 15, 16, 17, 238, 239, 240, 241, 495, 496, 497, 751, 752, 753, 1007, 1008, 1009, 1263, 1264, 1265, 1519, 1520, 1521, 1791, 1792, 2031, 2032, 2033, 2047, 2048, 4097 }) |count| {
        const input = words[0..count];
        var tail = try T.ScalarTail.init(std.testing.allocator, input);
        defer tail.deinit();
        for ([_][32]u8{ @splat(0), @splat(0xa7), T.DOMAIN_STATE }) |state| {
            const frame = Frame{ .words = .{ .state = state, .values = input } };
            const encoded = try frame.encode(std.testing.allocator);
            defer std.testing.allocator.free(encoded);
            var expected: [32]u8 = undefined;
            std.crypto.hash.Blake3.hash(encoded, &expected, .{});
            try std.testing.expectEqualSlices(u8, &expected, &try tail.fold(state, input));
            try std.testing.expectEqualSlices(u8, &frame.hash(), &expected);
            const view = try T.WordsView.init(state, input);
            var captured: [1024]u8 = undefined;
            var first: usize = 0;
            while (first < encoded.len) {
                const length = @min(captured.len, encoded.len - first);
                try view.read(first, captured[0..length]);
                try std.testing.expectEqualSlices(u8, encoded[first..][0..length], captured[0..length]);
                first += length;
            }
        }
    }
    // The authoritative 68-byte header leaves exactly239 full input words.
    const view = try T.WordsView.init(@splat(0), &words);
    var split: [4]u8 = undefined;
    try view.read(1024, &split);
    try std.testing.expectEqual(@as(u8, @truncate(words[239])), split[0]);
    try std.testing.expectEqual(@as(u8, @truncate(words[239] >> 24)), split[3]);
}
test "original words tail: exact disjoint frontier and independent counter geometry" {
    for (0..10000) |words| {
        const geometry = try T.Geometry.init(words);
        var next: usize = 1;
        for (geometry.frontier()) |range| {
            try std.testing.expectEqual(next, range.first);
            next += range.count;
        }
        try std.testing.expectEqual(geometry.chunks, next);
        try geometry.require(words);
    }
    var shape = try T.Geometry.init(753);
    shape.ranges[0].first += 1;
    try std.testing.expectError(error.UntrustedBlake3TailGeometry, shape.require(753));
    try std.testing.expectError(error.Blake3TailExtentOverflow, T.Geometry.init(std.math.maxInt(usize)));
}
test "original words tail: generic1024-byte no-tail ROOT and absolute final chunk counters" {
    const HashPlan = @import("../recursion/air/blake3_hash_plan.zig");
    const Hash = @import("../recursion/air/blake3_hash_witness.zig");
    const a = std.testing.allocator;
    var bytes: [1025]u8 = undefined;
    for (&bytes, 0..) |*byte, i| byte.* = @truncate(i *% 71);
    for ([_]usize{ 1023, 1024 }) |length| {
        var plan = try HashPlan.buildPrefixFold(a, length);
        defer plan.deinit();
        var expected: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash(bytes[0..length], &expected, .{});
        var actual = try Hash.prepareWithPlan(a, 911, bytes[0..length], expected, &plan);
        defer actual.rows.deinit();
        try std.testing.expectEqualSlices(u8, &expected, &actual.digest);
        const flag_wire = plan.calls[plan.calls.len - 1].initial[15];
        for (plan.sources) |source| if (source.wire == flag_wire) {
            try std.testing.expectEqual(@as(u32, 10), source.value.constant);
        };
    }
    var tail = try HashPlan.buildSubtreeAt(a, bytes.len, 1, 1);
    defer tail.deinit();
    const first_call = tail.calls[0];
    inline for (.{ 12, 13, 14, 15 }, .{ 1, 0, 1, 3 }) |coordinate, expected| {
        var found = false;
        for (tail.sources) |source| if (source.wire == first_call.initial[coordinate]) {
            try std.testing.expectEqual(@as(u32, expected), source.value.constant);
            found = true;
        };
        try std.testing.expect(found);
    }
    try std.testing.expectError(error.InvalidBlake3Subtree, HashPlan.buildSubtreeAt(a, bytes.len, 2, 1));
}
fn originals(words: []const u32, count: usize, out: *[4]W.Original) []const W.Original {
    for (out[0..count], 0..) |*original, i| {
        const state: [32]u8 = @splat(@as(u8, @intCast(37 + i)));
        original.* = .{ .state = state, .claim = (Frame{ .words = .{ .state = state, .values = words } }).hash(), .source = .{ .circuit = @intCast(20 + i), .first_wire = 40 } };
    }
    return out[0..count];
}
fn statement(words: []const u32, actual: []const W.Original) W.Statement {
    return .{ .namespace = 1000, .word_count = words.len, .expected_input_root = (Frame{ .words = .{ .state = T.DOMAIN_STATE, .values = words } }).hash(), .originals = actual };
}
test "original words tail: actual joined hash equations and shared byte source supplies" {
    const a = std.testing.allocator;
    var words: [497]u32 = undefined;
    for (&words, 0..) |*word, i| word.* = @truncate(i *% 0x9e3779b9);
    for ([_]usize{ 0, 1, 239, 240, 497 }) |count| {
        var original: [4]W.Original = undefined;
        const s = statement(words[0..count], originals(words[0..count], 2, &original));
        var live = try W.prepare(a, s, words[0..count], .{});
        defer live.deinit();
        var fixed = try W.trusted(a, s, .{});
        defer fixed.deinit();
        try std.testing.expectEqualSlices(u8, &s.expected_input_root, &live.input_root);
        for (s.originals, live.original_digests) |expected, digest| try std.testing.expectEqualSlices(u8, &expected.claim, &digest);
        try std.testing.expectEqualDeep(live.external_uses, fixed.external_uses);
        try std.testing.expectEqualDeep(live.route_schedules, fixed.route_schedules);
        inline for (.{ G, X, B, R, Word }, .{ live.rows.g_rows, live.rows.xor_rows, live.rows.boundary_rows, live.route_rows, live.word_rows }, .{ fixed.rows.g_rows, fixed.rows.xor_rows, fixed.rows.boundary_rows, fixed.route_rows, fixed.word_rows }) |Air, rows, trusted| {
            try std.testing.expectEqual(rows.len, trusted.len);
            for (rows, trusted) |row, preprocessing| try std.testing.expectEqualSlices(M, row[Air.PHYSICAL_MAIN_COLUMN_COUNT..], preprocessing[Air.PHYSICAL_MAIN_COLUMN_COUNT..]);
        }
        try std.testing.expect(try constraints(&live));
        try std.testing.expect(try closed(&live, s, true));
        try std.testing.expect(!try closed(&live, s, false));
        if (count > 0) {
            const saved = live.word_rows[0];
            live.word_rows[0][0] = saved[0].add(M.one());
            try std.testing.expect(!try closed(&live, s, true));
            live.word_rows[0] = saved;
        }
        const route_saved = live.route_rows[0];
        live.route_rows[0][8] = route_saved[8].add(M.one());
        try std.testing.expect(!try constraints(&live));
        live.route_rows[0] = route_saved;
        if (live.tail_outputs.len > 0) {
            const saved = live.rows.xor_rows[0];
            live.rows.xor_rows[0][0] = saved[0].add(M.one());
            try std.testing.expect(!try closed(&live, s, true));
            live.rows.xor_rows[0] = saved;
        }
    }
}
test "original words tail: tail is evaluated once and exactly shared by four frames plus input root" {
    const words: [1009]u32 = @splat(0xabcdef98);
    var original: [4]W.Original = undefined;
    const s = statement(&words, originals(&words, 4, &original));
    var plan = try P.Plan.init(std.testing.allocator, words.len, 4, .{});
    defer plan.deinit();
    var expected_calls: usize = plan.prefix.calls.len * 5;
    for (plan.tail) |part| {
        expected_calls += part.calls.len;
        for (part.output) |wire| try std.testing.expectEqual(@as(u32, 5), part.uses[wire]);
    }
    var live = try W.prepare(std.testing.allocator, s, &words, .{});
    defer live.deinit();
    try std.testing.expectEqual(expected_calls * 56, live.rows.g_rows.len);
    try std.testing.expect(try closed(&live, s, true));
    try plan.require(words.len, 4, .{});
    const flags = plan.prefix.calls[plan.prefix.calls.len - 1].initial[15];
    for (plan.prefix.sources) |*source| if (source.wire == flags) {
        source.value.constant ^= 8;
        break;
    };
    try std.testing.expectError(error.UntrustedBlake3TailPlan, plan.require(words.len, 4, .{}));
}
test "original words tail: independent root claim mutation cannot close original graph" {
    const words: [240]u32 = @splat(0x932ad714);
    var original: [4]W.Original = undefined;
    var s = statement(&words, originals(&words, 1, &original));
    s.expected_input_root[17] ^= 1;
    var live = try W.prepare(std.testing.allocator, s, &words, .{});
    defer live.deinit();
    try std.testing.expect(try constraints(&live));
    try std.testing.expect(!try closed(&live, s, true));
    try std.testing.expect(!std.meta.eql(live.input_root, s.expected_input_root));
}
test "original words tail: bounded fanin and foreign source namespaces reject before rows" {
    var original: [4]W.Original = undefined;
    const values = [_]u32{0};
    var s = statement(&values, originals(&values, 1, &original));
    original[0].source.circuit = s.namespace;
    try std.testing.expectError(error.InvalidBlake3TailNamespace, W.prepare(std.testing.allocator, s, &values, .{}));
    s = statement(&values, originals(&values, 1, &original));
    try std.testing.expectError(error.Blake3TailResourceLimit, W.prepare(std.testing.allocator, s, &values, .{ .max_words = 0 }));
    try std.testing.expectError(error.Blake3TailResourceLimit, P.Plan.init(std.testing.allocator, 1, 5, .{}));
    try std.testing.expectError(error.InvalidBlake3TailExtent, W.prepare(std.testing.allocator, s, &.{}, .{}));
}
test "original words tail: plan witness preprocessing construction failure rollback" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationCase, .{});
}
fn allocationCase(a: std.mem.Allocator) !void {
    var original: [4]W.Original = undefined;
    const words = [_]u32{ 0xffffffff, 0x80000000, 7 };
    const s = statement(&words, originals(&words, 1, &original));
    var live = try W.prepare(a, s, &words, .{});
    defer live.deinit();
    var trusted = try W.trusted(a, s, .{});
    defer trusted.deinit();
}
test "original words tail: owned rows retain shared budget after original owner release" {
    const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
    const budget = try Budget.create(std.testing.allocator, 64 << 20);
    var original: [4]W.Original = undefined;
    const words = [_]u32{1};
    const s = statement(&words, originals(&words, 1, &original));
    var rows = try W.prepare(budget.allocator(), s, &words, .{});
    budget.destroy();
    rows.deinit();
}

fn constraints(prepared: *const W.Prepared) !bool {
    const lang = @import("../air/lang/mod.zig");
    const support = @import("../recursion/air/test_support.zig");
    inline for (.{ G, X, B, R, Word }, .{ prepared.rows.g_rows, prepared.rows.xor_rows, prepared.rows.boundary_rows, prepared.route_rows, prepared.word_rows }) |Air, rows| {
        var definition = try Air.build(std.testing.allocator);
        defer definition.deinit();
        for (rows) |row| {
            const values = try support.evaluateArena(std.testing.allocator, &definition.arena, &row);
            defer std.testing.allocator.free(values);
            for (definition.arena.constraintsView()) |constraint| if (!values[lang.types.idIndex(constraint.root)].isZero()) return false;
        }
    }
    return true;
}
fn closed(prepared: *const W.Prepared, independent: W.Statement, include_original_producers: bool) !bool {
    const binding = @import("../recursion/air/universal_relation_binding.zig");
    const lang = @import("../air/lang/mod.zig");
    const a = std.testing.allocator;
    var counts = std.AutoHashMap([6]u32, M).init(a);
    defer counts.deinit();
    var originals_supply: [32]B.Row = undefined;
    const supplied = if (include_original_producers) independent.originals.len * 8 else 0;
    for (originals_supply[0..supplied], 0..) |*row, i| {
        const child = i / 8;
        const word = i % 8;
        const source = independent.originals[child];
        row.* = try B.logicalRow(source.source.circuit, source.source.first_wire + @as(u32, @intCast(word)), M.fromCanonical(prepared.external_uses[child][word]), std.mem.readInt(u32, source.state[word * 4 ..][0..4], .little));
    }
    inline for (.{ G, X, B, R, Word, B }, .{ prepared.rows.g_rows, prepared.rows.xor_rows, prepared.rows.boundary_rows, prepared.route_rows, prepared.word_rows, originals_supply[0..supplied] }) |Air, rows| {
        var definition = try Air.build(a);
        defer definition.deinit();
        const plan = try binding.Binding(Air).authenticate(&definition);
        for (rows) |row| for (plan.preparedEntries(row)) |entry| {
            if (entry.schema != lang.relation.id(.recursion_wire)) continue;
            var key: [6]u32 = undefined;
            for (&key, entry.values[0..6]) |*word, value| word.* = (try value.tryIntoM31()).toU32();
            const slot = try counts.getOrPut(key);
            if (!slot.found_existing) slot.value_ptr.* = M.zero();
            slot.value_ptr.* = slot.value_ptr.*.add(try entry.numerator.tryIntoM31());
        };
    }
    var values = counts.valueIterator();
    while (values.next()) |value| if (!value.isZero()) return false;
    return true;
}
