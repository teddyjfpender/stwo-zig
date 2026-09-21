//! Independent typed compact lowering checks, including deliberately off-trace rows.
const std = @import("std");
const typed = @import("typed_poseidon2_compact.zig");
const layout = @import("../memory_commitment/poseidon2_universal_layout_v1.zig");
const specialized = @import("../memory_commitment/poseidon2_universal_equations_v1.zig");
const witness = @import("../memory_commitment/poseidon2_universal_degree3_v1.zig");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;

fn compare(comptime S: type, definition: *const typed.Definition, row: [layout.N_MAIN_COLUMNS]S) !void {
    const actual = try definition.evaluate(S, std.testing.allocator, row);
    try std.testing.expectEqualDeep(specialized.evaluateGeneric(S, row), actual.direct);
    try std.testing.expectEqualDeep(specialized.outputGeneric(S, row), actual.output);
    const expected = specialized.entriesGeneric(S, row);
    try std.testing.expectEqual(expected.len, actual.lookups.len);
    try std.testing.expectEqual(expected.batch_size, actual.lookups.batch_size);
    for (expected.entries[0..expected.len], actual.lookups.entries[0..actual.lookups.len]) |left, right| {
        try std.testing.expectEqual(left.domain, right.domain);
        try std.testing.expectEqual(left.role, right.role);
        try std.testing.expectEqual(left.arity, right.arity);
        try std.testing.expectEqualDeep(left.numerator, right.numerator);
        try std.testing.expectEqualSlices(S, left.values[0..left.arity], right.values[0..right.arity]);
    }
}

test "compact typed lowering preserves all ordered roots outputs and lookups off trace" {
    var definition = try typed.Definition.init(std.testing.allocator);
    defer definition.deinit();
    var degrees = try @import("degree.zig").analyze(std.testing.allocator, &definition.arena);
    defer degrees.deinit();
    try std.testing.expectEqual(@as(u32, 3), degrees.maximumConstraintDegree());
    try std.testing.expectEqual(@as(usize, 288), definition.arena.constraints.items.len);
    for (0..4) |sample| {
        var base: [layout.N_MAIN_COLUMNS]M31 = undefined;
        var secure: [layout.N_MAIN_COLUMNS]QM31 = undefined;
        for (&base, &secure, 0..) |*word, *extension, index| {
            word.* = M31.fromU64((sample + 3) * (index + 17) * 1_234_567);
            extension.* = QM31.fromM31(word.*, M31.fromU64(index + 1), M31.fromU64(sample + 2), M31.fromU64(index * 31 + sample));
        }
        try compare(M31, &definition, base);
        try compare(QM31, &definition, secure);
    }
}

test "compact typed constraints admit each provider mode and expose every materialized-column mutation" {
    var definition = try typed.Definition.init(std.testing.allocator);
    defer definition.deinit();
    for (0..3) |mode| {
        const row = try witness.fill(.{ .input = .{ 1, 2 } ++ .{0} ** 14, .wide = mode == 1, .io = mode == 2 });
        const result = try definition.evaluate(M31, std.testing.allocator, row);
        for (result.direct) |value| try std.testing.expect(value.isZero());
        try compare(M31, &definition, row);
    }
    const padding = witness.paddingRow();
    const result = try definition.evaluate(M31, std.testing.allocator, padding);
    for (result.direct) |value| try std.testing.expect(value.isZero());
    for (result.lookups.entries[0..result.lookups.len]) |event| try std.testing.expect(event.numerator.isZero());
    for (17..layout.WIDE_COLUMN) |column| {
        var row = padding;
        row[column] = row[column].add(M31.one());
        const changed = try definition.evaluate(M31, std.testing.allocator, row);
        try std.testing.expect(!changed.direct[4 + column - 17].isZero());
    }
}

test "compact typed authority releases partial logical and physical construction" {
    for ([_]usize{ 0, 1, 8, 32, 128, 512, 2048, 8192 }) |fail_index| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = fail_index });
        var definition = typed.Definition.init(failing.allocator()) catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            continue;
        };
        defer definition.deinit();
        try std.testing.expect(!failing.has_induced_failure);
    }
}

test "compact typed lowering preserves symbolic expressions modulo commutative operand ordering" {
    const symbolic = @import("../extract/symbolic.zig");
    var definition = try typed.Definition.init(std.testing.allocator);
    defer definition.deinit();
    var arena = symbolic.Arena.init(std.testing.allocator);
    defer arena.deinit();
    symbolic.begin(&arena);
    defer symbolic.end();
    var main: [layout.N_MAIN_COLUMNS]symbolic.Scalar = undefined;
    for (&main) |*value| value.* = arena.column("main");
    const actual = try definition.evaluate(symbolic.Scalar, std.testing.allocator, main);
    const direct = specialized.evaluateGeneric(symbolic.Scalar, main);
    const lookups = specialized.entriesGeneric(symbolic.Scalar, main);
    const normalized = try @import("../extract/canonical_digest.zig").commutativeExpressions(std.testing.allocator, arena.nodes.items, arena.names.items.len);
    defer std.testing.allocator.free(normalized);
    for (direct, actual.direct) |expected, value| try std.testing.expectEqualSlices(u8, &normalized[expected.id], &normalized[value.id]);
    for (lookups.entries[0..lookups.len], actual.lookups.entries[0..actual.lookups.len]) |expected, value| {
        try std.testing.expectEqualSlices(u8, &normalized[expected.numerator.id], &normalized[value.numerator.id]);
        for (expected.values[0..expected.arity], value.values[0..value.arity]) |left, right|
            try std.testing.expectEqualSlices(u8, &normalized[left.id], &normalized[right.id]);
    }
}

test "typed specialization equivalence permits only commutative operand ordering" {
    const symbolic = @import("../extract/symbolic.zig");
    const canonical = @import("../extract/canonical_digest.zig");
    var arena = symbolic.Arena.init(std.testing.allocator);
    defer arena.deinit();
    symbolic.begin(&arena);
    defer symbolic.end();
    const a = arena.column("a");
    const b = arena.column("b");
    const c = arena.column("c");
    const sum = a.add(b);
    const reverse_sum = b.add(a);
    const product = a.mul(b);
    const reverse_product = b.mul(a);
    const difference = a.sub(b);
    const reverse_difference = b.sub(a);
    const left_group = a.add(b).add(c);
    const right_group = a.add(b.add(c));
    const normalized = try canonical.commutativeExpressions(std.testing.allocator, arena.nodes.items, arena.names.items.len);
    defer std.testing.allocator.free(normalized);
    const ordered = try canonical.expressions(std.testing.allocator, arena.nodes.items, arena.names.items.len);
    defer std.testing.allocator.free(ordered);
    try std.testing.expectEqualSlices(u8, &normalized[sum.id], &normalized[reverse_sum.id]);
    try std.testing.expectEqualSlices(u8, &normalized[product.id], &normalized[reverse_product.id]);
    try std.testing.expect(!std.mem.eql(u8, &normalized[difference.id], &normalized[reverse_difference.id]));
    try std.testing.expect(!std.mem.eql(u8, &normalized[left_group.id], &normalized[right_group.id]));
    try std.testing.expect(!std.mem.eql(u8, &ordered[sum.id], &ordered[reverse_sum.id]));
    try std.testing.expect(!std.mem.eql(u8, &ordered[sum.id], &normalized[sum.id]));
}
