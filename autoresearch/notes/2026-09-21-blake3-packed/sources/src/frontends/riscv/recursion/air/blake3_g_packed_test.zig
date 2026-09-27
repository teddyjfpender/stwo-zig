const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../../air/lang/mod.zig");
const component = @import("blake3_g_packed.zig");
const reference = @import("blake3_g_reference.zig");
const support = @import("test_support.zig");
const M31 = core.fields.m31.M31;
// Exact membership predicates of the existing universal preprocessed tables.
// This checks emitted requests, not a replacement for production LogUp closure.
fn membership(domain: lang.relation.Domain, v: []const u32) bool {
    return switch (domain) {
        .range_check_8_8 => v[0] < 256 and v[1] < 256,
        .bitwise => v[0] < 256 and v[1] < 256 and v[2] < 256 and v[3] == 2 and (v[0] ^ v[1]) == v[2],
        else => false,
    };
}
const Result = struct { algebraic: bool, lookups: bool, output: [4]u32 };
fn evaluate(d: *const component.Definition, row: *const component.Row) !Result {
    const values = try support.evaluateArena(std.testing.allocator, &d.arena, row);
    defer std.testing.allocator.free(values);
    var out = Result{ .algebraic = true, .lookups = true, .output = @splat(0) };
    for (d.arena.constraintsView()) |c| out.algebraic = out.algebraic and values[lang.types.idIndex(c.root)].isZero();
    for (d.arena.effectsView(), 0..) |event, i| {
        const id: lang.types.EffectId = @enumFromInt(i);
        const tuple = d.arena.effectValues(id).?;
        var words: [4]u32 = undefined;
        for (tuple, 0..) |value, j| words[j] = values[lang.types.idIndex(value)].toU32();
        const schema = event.binding.?.schema;
        var found = false;
        inline for (.{ lang.relation.Domain.range_check_8_8, .bitwise }) |domain| {
            if (schema == lang.relation.id(domain)) {
                found = true;
                out.lookups = out.lookups and membership(domain, words[0..tuple.len]);
            }
        }
        try std.testing.expect(found);
        try std.testing.expectEqual(lang.relation.Role.request, event.binding.?.role);
        try std.testing.expectEqual(@as(u32, 1), values[lang.types.idIndex(event.liveness.?)].toU32());
    }
    for (d.output, 0..) |word, i| for (word, 0..) |value, j| {
        out.output[i] |= values[lang.types.idIndex(value)].toU32() << @as(u5, @intCast(j * 8));
    };
    return out;
}
test "BLAKE3 compact G matches typed bit reference and canonical lookup schemas" {
    var d = try component.build(std.testing.allocator);
    defer d.deinit();
    var r = try reference.build(std.testing.allocator);
    defer r.deinit();
    var degrees = try lang.degree.analyze(std.testing.allocator, &d.arena);
    defer degrees.deinit();
    try std.testing.expectEqual(@as(u32, 2), degrees.maximumConstraintDegree());
    const identity = try lang.digest.computeIdentity(&d.arena);
    try std.testing.expectEqualSlices(u8, &component.SEMANTIC_DIGEST, &identity.bytes);
    var prng = std.Random.DefaultPrng.init(0x5041434b4544);
    for (0..128) |case| {
        var input: [6]u32 = undefined;
        for (&input) |*word| word.* = switch (case) {
            0 => 0,
            1 => 0xffffffff,
            2 => 0x80000000,
            else => prng.random().int(u32),
        };
        const row = try component.witness(input);
        const result = try evaluate(&d, &row);
        try std.testing.expect(result.algebraic and result.lookups);
        const reference_row = try reference.witness(input);
        const values = try support.evaluateArena(std.testing.allocator, &r.arena, &reference_row);
        defer std.testing.allocator.free(values);
        for (r.output, result.output) |bits, want| {
            var actual: u32 = 0;
            for (bits, 0..) |bit, i| actual |= values[lang.types.idIndex(bit)].toU32() << @as(u5, @intCast(i));
            try std.testing.expectEqual(want, actual);
        }
    }
}
test "BLAKE3 compact G rejects coordinate mutations and requires lookup bounds" {
    var d = try component.build(std.testing.allocator);
    defer d.deinit();
    const row = try component.witness(.{ 0xffffffff, 1, 0x80000000, 0x7fffffff, 0x12345678, 0xabcdef01 });
    for (0..component.COLUMN_COUNT) |i| {
        var changed = row;
        changed[i] = changed[i].add(M31.one());
        const result = try evaluate(&d, &changed);
        try std.testing.expect(!result.algebraic or !result.lookups);
        changed[i] = M31.fromCanonical(256);
        const range_result = try evaluate(&d, &changed);
        try std.testing.expect(!range_result.algebraic or !range_result.lookups);
    }
    // Input a and message x have equal and opposite changes. Their sum is
    // preserved in the first two additions, so compensate intermediate a+b.
    // The negative field value is not a byte: only lookup membership rejects it.
    var changed = try component.witness(@splat(0));
    changed[0] = M31.one().neg(); // a low byte
    changed[16] = M31.one(); // x low byte
    changed[24] = M31.one().neg(); // first addition's low byte
    const result = try evaluate(&d, &changed);
    try std.testing.expect(result.algebraic);
    try std.testing.expect(!result.lookups);
}

test "BLAKE3 compact G covers all seven rounds of a native compression trace" {
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const compression = core.crypto.blake3_compression;
    var block: [16]u32 = undefined;
    for (&block, 0..) |*word, i| word.* = @as(u32, @intCast(i)) *% 0xabcdef01;
    const trace = try compression.trace(compression.IV, block, 0x123456789abcdef0, 63, 11);
    for (trace.calls) |call| {
        const row = try component.witness(call.input);
        const result = try evaluate(&definition, &row);
        try std.testing.expect(result.algebraic and result.lookups);
        try std.testing.expectEqualSlices(u32, &call.output, &result.output);
    }
}
