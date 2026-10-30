const std = @import("std");
const Admission = @import("admission.zig");
const Statement = @import("statement.zig");
const b = @import("stwo_circuit_frontend").builder;
const Q = @import("stwo_core").fields.qm31.QM31;

test "RISC direct original reject intermediate mixed parent before allocation or metadata access" {
    const parent = [_]u8{ 0, 0xff, 0x52, 0x38 };
    for (1..parent.len + 1) |length| {
        // Every field except root is intentionally unavailable: rejection must
        // precede allocation, ELF/checkpoint access and legacy proof decoding.
        var metadata: Admission.Metadata = .{ .mixed = undefined };
        metadata.mixed.input.root = parent[0..length];
        try std.testing.expectError(error.IntermediateParentInOriginalWindowMetadata, Admission.Owned.derive(std.testing.failing_allocator, metadata));
    }
}

test "RISC direct original CPU ports preserve full width and asymmetric byte order" {
    const words = [_]u32{ 0xffffffff, 0x80000000, 0x7fffffff, 0x01234567, 0x89abcdef, 0xfedcba98 };
    // Literal little-endian bytes check both limb and byte ordering, including
    // values that cannot be represented as one canonical M31 base element.
    const expected = [_][4]u8{
        .{ 0xff, 0xff, 0xff, 0xff },
        .{ 0x00, 0x00, 0x00, 0x80 },
        .{ 0xff, 0xff, 0xff, 0x7f },
        .{ 0x67, 0x45, 0x23, 0x01 },
        .{ 0xef, 0xcd, 0xab, 0x89 },
        .{ 0x98, 0xba, 0xdc, 0xfe },
    };
    var ctx = try b.Context(Q).init(std.testing.allocator, 0);
    defer ctx.deinit();
    var wires: Statement.Wires = undefined;
    // Only the 66 CPU words are read by cpuBytes; no statement hashing or
    // independently authorized Span is involved in this extraction test.
    for (wires.words[32..98], 0..) |*wire, i| {
        wire.* = try b.wrappers.guessU32(Q, &ctx, b.wrappers.u32Value(Q, words[i % words.len]));
    }
    const bytes = try wires.cpuBytes(Q, &ctx);
    for (bytes, 0..) |wire, i| {
        const value = Q.fromU32Unchecked(expected[(i / 4) % expected.len][i % 4], 0, 0, 0);
        try std.testing.expectEqualDeep(value, ctx.get(wire));
        try ctx.eq(wire, try ctx.constant(value));
    }
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
}
