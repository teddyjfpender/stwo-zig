const std = @import("std");
const core = @import("stwo_core");
const inputs = @import("blake3_span_identity_inputs.zig");
const identity = @import("../span_identity_blake3.zig");
const fixture = @import("../span_statement_blake3_test_fixture.zig");
const pack = @import("qm31_pack_wire.zig");
const encoding = @import("blake3_field_bytes.zig");
const route = @import("blake3_byte_route.zig");
const binding = @import("universal_relation_binding.zig");
const lang = @import("../../air/lang/mod.zig");
const M = core.fields.m31.M31;
const circuits = inputs.Circuits{ .scalar = 21, .packing = 22, .bytes = 23, .hash = 24 };

test "BLAKE3 Span identity canonical input chain closes internal wires" {
    const context = try fixture.job(1);
    const words = try (try fixture.leaf(context, 0, context.complete.initial_state, context.complete.final_state)).canonicalWords();
    var nodes: [525]u32 = undefined;
    for (&nodes, 0..) |*node, i| node.* = @intCast(100 + i);
    for ([_]identity.Purpose{ .statement, .job }) |purpose| {
        var plan = try inputs.build(std.testing.allocator, purpose, circuits, &nodes);
        defer plan.deinit();
        var rows = try inputs.prepare(&plan, &words);
        try std.testing.expect(try closed(&plan, &rows, &words));
        for (plan.source_uses[0..524]) |uses| try std.testing.expectEqual(@as(u32, 1), uses);
        try std.testing.expectEqual(@as(u32, 4), plan.source_uses[524]);
        try std.testing.expectEqual([3]u32{ 0, 0, 0 }, plan.encoding[131].uses[1..4].*);
        // Bypass the constructor: a malicious witness substitutes a byte while
        // the source scalar remains fixed. The internal lookup must not close.
        rows.encoding[0][4] = rows.encoding[0][4].add(M.one());
        if (purpose == .statement) try std.testing.expect(!try closed(&plan, &rows, &words));
    }
    var duplicate = nodes;
    duplicate[524] = nodes[0];
    try std.testing.expectError(error.InvalidSpanIdentityNodes, inputs.build(std.testing.allocator, .statement, circuits, &duplicate));
    var aliased = circuits;
    aliased.bytes = aliased.scalar;
    try std.testing.expectError(error.InvalidSpanIdentityCircuits, inputs.build(std.testing.allocator, .job, aliased, &nodes));
}

fn closed(plan: *const inputs.Plan, rows: *const inputs.Rows, words: *const identity.StatementWords) !bool {
    const a = std.testing.allocator;
    var counts = std.AutoHashMap([6]u32, M).init(a);
    defer counts.deinit();
    inline for (.{ pack, encoding }, .{ rows.packing, rows.encoding }) |Air, values| {
        var definition = try Air.build(a);
        defer definition.deinit();
        const authenticated = try binding.Binding(Air).authenticate(&definition);
        for (values) |row| for (authenticated.preparedEntries(row)) |entry| try add(&counts, entry);
    }
    var definition = try route.build(a);
    defer definition.deinit();
    const authenticated = try binding.Binding(route).authenticate(&definition);
    for (plan.routes.schedules) |schedule| {
        var values: [2]u32 = @splat(0);
        if (schedule.sources[0]) |endpoint| values[0] = words[endpoint.wire].toU32();
        const row = try route.logicalRow(schedule, values);
        for (authenticated.preparedEntries(row)) |entry| try add(&counts, entry);
    }
    var iterator = counts.valueIterator();
    while (iterator.next()) |value| if (!value.isZero()) return false;
    return true;
}
fn add(counts: *std.AutoHashMap([6]u32, M), entry: anytype) !void {
    if (entry.schema != lang.relation.id(.recursion_wire)) return;
    var key: [6]u32 = undefined;
    for (&key, entry.values[0..6]) |*word, value| word.* = (try value.tryIntoM31()).toU32();
    // Boundary obligations remain with the authenticated statement producer
    // and the hash graph. Here we qualify the two complete internal joins.
    if (key[0] != circuits.packing and key[0] != circuits.bytes) return;
    const slot = try counts.getOrPut(key);
    if (!slot.found_existing) slot.value_ptr.* = M.zero();
    slot.value_ptr.* = slot.value_ptr.*.add(try entry.numerator.tryIntoM31());
}
