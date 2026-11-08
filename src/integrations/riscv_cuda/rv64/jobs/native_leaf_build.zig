//! Class-only statement tape programs, in the receiver's leaf_tape order.
const std = @import("std");
const L = @import("native_leaf_wire.zig");
const NG = @import("native_gkr.zig");
const Slab = @import("slab.zig");
const NE = @import("native_encode.zig");

fn op(list: *std.ArrayListUnmanaged(L.Op), a: std.mem.Allocator, kind: L.Kind, source: L.Source, offset: usize, count: usize) !void {
    try list.append(a, .{ .kind = kind, .source = source, .offset = std.math.cast(u32, offset) orelse return error.NativeLeafProgramShape, .count = std.math.cast(u32, count) orelse return error.NativeLeafProgramShape });
}

/// `public_words` is cpu_leaf.expectedWords with zero placeholders for live
/// proof data. Only its immutable public prefix/tail are used by the program.
pub fn cpu(a: std.mem.Allocator, geometry: L.Geometry, plan: *const NG.Plan, section: *const Slab.ProofLayout, physical: *const NE.Program, coefficient_counts: []const u32, public_words: []const u32, claims: usize) !L.Program {
    const first_public = 41 + 8 * claims;
    if (public_words.len < first_public) return error.NativeLeafProgramShape;
    var tail: std.ArrayListUnmanaged(L.Op) = .empty;
    defer tail.deinit(a);
    var frame: std.ArrayListUnmanaged(L.Op) = .empty;
    defer frame.deinit(a);
    try op(&tail, a, .word, .pool, 0, 9); // ordinal, statement
    try op(&tail, a, .word, .manifest, 0, 8);
    const fields = plan.fields;
    var at: usize = 0;
    for (0..plan.traversal.layers) |depth| {
        const records = try section.get(.gkr_section, fields.records(@intCast(depth)));
        for (0..depth) |round| {
            if (at >= coefficient_counts.len) return error.NativeLeafPolynomialShape;
            try op(&tail, a, .polynomial, .section, records.offset + 44 * round, coefficient_counts[at]);
            at += 1;
        }
    }
    if (at != coefficient_counts.len) return error.NativeLeafPolynomialShape;
    const max_variables = plan.traversal.layers;
    for (plan.variables, 0..) |variables, i| {
        for (0..variables) |layer| {
            const remaining = variables - @as(u32, @intCast(layer));
            const depth = max_variables - remaining;
            const masks = try section.get(.gkr_section, fields.masks(depth));
            var before: usize = 0;
            for (plan.variables[0..i]) |prior| before += @intFromBool(prior >= remaining);
            try op(&tail, a, .felts, .section, masks.offset + 32 * before, 4);
        }
    }
    const roots = try section.get(.gkr_section, fields.roots());
    try op(&tail, a, .felts, .section, roots.offset, 2 * plan.variables.len);
    try op(&tail, a, .felts, .claims, 0, claims);
    try op(&tail, a, .word, .pool, first_public, public_words.len - first_public);

    try op(&frame, a, .word, .pool, 0, 17); // ordinal, statement, FIXED
    try op(&frame, a, .word, .pcs, physical.get(.off_roots) + 8, 8); // MAIN
    try op(&frame, a, .word, .manifest, 0, 8);
    try op(&frame, a, .word, .receipt, 0, 8);
    try op(&frame, a, .felts, .claims, 0, claims);
    try op(&frame, a, .word, .pool, first_public, public_words.len - first_public);
    return L.Program.build(a, geometry, public_words, tail.items, frame.items);
}

/// Classic Keccak and V3 truths share this field order; only their physical
/// claim counts differ (five versus one).
pub fn truth(a: std.mem.Allocator, geometry: L.Geometry, physical: *const NE.Program, ordinal: u32, first: u32, calls: u32, statement: [32]u8, claims: usize) !L.Program {
    var pool: [11]u32 = undefined;
    pool[0..3].* = .{ ordinal, first, calls };
    for (0..8) |i| pool[3 + i] = std.mem.readInt(u32, statement[4 * i ..][0..4], .little);
    const tail = [_]L.Op{ .{ .kind = .word, .source = .pool, .offset = 0, .count = 11 }, .{ .kind = .word, .source = .manifest, .offset = 0, .count = 8 }, .{ .kind = .felts, .source = .claims, .offset = 0, .count = @intCast(claims) } };
    const frame = [_]L.Op{ .{ .kind = .word, .source = .pool, .offset = 0, .count = 11 }, .{ .kind = .word, .source = .manifest, .offset = 0, .count = 8 }, .{ .kind = .word, .source = .pcs, .offset = physical.get(.off_roots) + 8, .count = 8 }, .{ .kind = .felts, .source = .claims, .offset = 0, .count = @intCast(claims) } };
    return L.Program.build(a, geometry, &pool, &tail, &frame);
}
