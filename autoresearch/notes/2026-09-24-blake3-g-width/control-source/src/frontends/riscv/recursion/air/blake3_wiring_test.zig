const std = @import("std");
const core = @import("stwo_core");
const g = @import("blake3_g_call.zig");
const xor = @import("blake3_xor_call.zig");
const topology = @import("blake3_compression_plan.zig");
const binding = @import("universal_relation_binding.zig");
const lang = @import("../../air/lang/mod.zig");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Entry = @import("relation_interaction.zig").Entry;
const compression = core.crypto.blake3_compression;
test "BLAKE3 call components pin semantics and authenticate relation plans" {
    inline for (.{ g, xor }) |Air| {
        const hash = try Air.computeSemanticDigest(std.testing.allocator);
        try std.testing.expectEqualSlices(u8, &Air.SEMANTIC_DIGEST, &hash);
        var d = try Air.build(std.testing.allocator);
        defer d.deinit();
        var degrees = try lang.degree.analyze(std.testing.allocator, &d.arena);
        defer degrees.deinit();
        try std.testing.expect(degrees.maximumConstraintDegree() <= 2);
        _ = binding.Binding(Air).authenticate(&d) catch |err| {
            std.debug.print("AUTH_ERROR {s} nodes={d}\n", .{ @errorName(err), d.arena.nodeCount() });
            return err;
        };
    }
}
test "BLAKE3 fixed compression wire graph closes and rejects endpoint substitutions" {
    const allocator = std.testing.allocator;
    var gd = try g.build(allocator);
    defer gd.deinit();
    var xd = try xor.build(allocator);
    defer xd.deinit();
    const gp = try binding.Binding(g).authenticate(&gd);
    const xp = try binding.Binding(xor).authenticate(&xd);
    const plan = topology.canonical();
    const cv = compression.IV;
    const block: [16]u32 = @splat(0x01234567);
    const prepared = try @import("blake3_compression_witness.zig").prepare(991, cv, block, 0, 64, 11);
    var entries: std.ArrayList(Entry) = .empty;
    defer entries.deinit(allocator);
    for (prepared.g_rows) |row| {
        const values = try @import("test_support.zig").evaluateArena(allocator, &gd.arena, &row);
        defer allocator.free(values);
        for (gd.arena.constraintsView()) |constraint| try std.testing.expect(values[lang.types.idIndex(constraint.root)].isZero());
        try entries.appendSlice(allocator, &gp.preparedEntries(row));
    }
    for (prepared.xor_rows) |row| try entries.appendSlice(allocator, &xp.preparedEntries(row));
    const expected = try compression.compress(cv, block, 0, 64, 11);
    try std.testing.expectEqualSlices(u32, &expected, &prepared.output);
    // Boundary emissions must ultimately come from authenticated statement/hash
    // framing components. Here their exact public values are explicit fixtures.
    const template = entries.items[56];
    for (prepared.initial, 0..) |word, id| try entries.append(allocator, wireEntry(template, @intCast(id), word, plan.uses[id]));
    for (plan.output, prepared.output) |id, word| {
        var e = wireEntry(template, id, word, 1);
        e.numerator = e.numerator.neg();
        try entries.append(allocator, e);
    }
    try std.testing.expect(closedWires(entries.items));
    try appendProviderRows(allocator, &entries);
    try std.testing.expect(try closedAll(entries.items));
    const provider_index = entries.items.len - 1;
    const provider_numerator = entries.items[provider_index].numerator;
    entries.items[provider_index].numerator = provider_numerator.add(QM31.one());
    try std.testing.expect(!try closedAll(entries.items));
    entries.items[provider_index].numerator = provider_numerator;

    const original = entries.items[56];
    for (0..6) |coordinate| {
        entries.items[56] = original;
        entries.items[56].values[coordinate] = original.values[coordinate].add(QM31.one());
        try std.testing.expect(!closedWires(entries.items));
    }
    entries.items[56] = original;
    entries.items[56].numerator = original.numerator.add(QM31.one());
    try std.testing.expect(!closedWires(entries.items));
}
fn wireEntry(template: Entry, id: u32, word: u32, count: u32) Entry {
    var out = template;
    out.values[0] = QM31.fromBase(M31.fromCanonical(991));
    out.values[1] = QM31.fromBase(M31.fromCanonical(id));
    for (0..4) |i| out.values[2 + i] = QM31.fromBase(M31.fromCanonical((word >> @as(u5, @intCast(i * 8))) & 255));
    out.numerator = QM31.fromBase(M31.fromCanonical(count));
    return out;
}
fn closedWires(entries: []const Entry) bool {
    for (entries) |key| {
        if (key.schema != lang.relation.id(.recursion_wire)) continue;
        var sum = QM31.zero();
        for (entries) |entry| {
            if (entry.schema != key.schema) continue;
            var equal = true;
            for (entry.values[0..6], key.values[0..6]) |a, b| equal = equal and a.eql(b);
            if (equal) sum = sum.add(entry.numerator);
        }
        if (!sum.isZero()) return false;
    }
    return true;
}

test "BLAKE3 ordered call construction releases partial allocations" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationProbe, .{});
}
fn allocationProbe(allocator: std.mem.Allocator) !void {
    var d = try g.build(allocator);
    defer d.deinit();
}

fn appendProviderRows(allocator: std.mem.Allocator, entries: *std.ArrayList(Entry)) !void {
    const tables = @import("../../air/lookups/tables/schema.zig");
    const Counter = @import("../../air/lookups/tables/counter.zig").Counter;
    const sources = entries.items.len;
    inline for (.{ tables.Kind.bitwise, .range_check_8_8 }) |kind| {
        var counter = try Counter.init(allocator, kind);
        defer counter.deinit(allocator);
        const domain: lang.relation.Domain = if (kind == .bitwise) .bitwise else .range_check_8_8;
        var template: ?Entry = null;
        for (entries.items[0..sources]) |entry| {
            if (entry.schema != lang.relation.id(domain)) continue;
            template = entry;
            try counter.registerRaw(entry.numerator, entry.values[0..entry.arity]);
        }
        for (counter.values, 0..) |count, index| {
            if (count.isZero()) continue;
            const tuple = try tables.tupleAt(kind, index);
            var entry = template.?;
            for (tuple.slice(), 0..) |value, i| entry.values[i] = QM31.fromBase(value);
            entry.numerator = QM31.fromBase(count.neg());
            try entries.append(allocator, entry);
        }
    }
}
fn closedAll(entries: []const Entry) !bool {
    var counts = std.AutoHashMap([8]u32, M31).init(std.testing.allocator);
    defer counts.deinit();
    for (entries) |entry| {
        var key: [8]u32 = @splat(0);
        key[0] = @intFromEnum(entry.schema);
        key[1] = entry.arity;
        for (entry.values[0..entry.arity], 0..) |value, i| key[2 + i] = (try value.tryIntoM31()).toU32();
        const slot = try counts.getOrPut(key);
        if (!slot.found_existing) slot.value_ptr.* = M31.zero();
        slot.value_ptr.* = slot.value_ptr.add(try entry.numerator.tryIntoM31());
    }
    var values = counts.valueIterator();
    while (values.next()) |value| if (!value.isZero()) return false;
    return true;
}
