const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const full = @import("qm31_mul_add_v1.zig");
const fusion = @import("detached_arithmetic_fusion_plan.zig");
const graph = @import("composition_circuit.zig");
const lowering = @import("verifier_arithmetic_lowering.zig");
const support = @import("test_support.zig");
const degree = @import("../../air/lang/degree.zig");

test "multiply-add semantic identity and degree" {
    const identity = try full.computeSemanticDigest(std.testing.allocator);
    std.debug.print("qm31_mul_add_v1 semantic digest: {s}\n", .{std.fmt.bytesToHex(identity, .lower)});
    try std.testing.expectEqualSlices(u8, &full.SEMANTIC_DIGEST, &identity);
    var definition = try full.build(std.testing.allocator);
    defer definition.deinit();
    var degrees = try degree.analyze(std.testing.allocator, &definition.arena);
    defer degrees.deinit();
    try std.testing.expectEqual(@as(degree.Degree, 2), degrees.maximumConstraintDegree());
}

test "multiply-add constrains all extension coordinates and signed modes" {
    var definition = try full.build(std.testing.allocator);
    defer definition.deinit();
    var random = std.Random.DefaultPrng.init(983742);
    for (0..32) |_| {
        var words: [12]u32 = undefined;
        for (&words) |*word| word.* = random.random().uintLessThan(u32, core.fields.m31.Modulus);
        const a = QM31.fromU32Unchecked(words[0], words[1], words[2], words[3]);
        const b = QM31.fromU32Unchecked(words[4], words[5], words[6], words[7]);
        const c = QM31.fromU32Unchecked(words[8], words[9], words[10], words[11]);
        inline for (std.meta.tags(full.Operation)) |op| {
            const addend = if (op == .multiply) QM31.zero() else c;
            const row = try full.logicalRow(.{ .circuit = 501, .output = 17, .lhs = 4, .rhs = 7, .addend = if (op == .multiply) 0 else 9, .uses = 3, .operation = op }, a, b, addend);
            try std.testing.expect(try valid(&definition, row));
            for (13..17) |column| {
                var bad = row;
                bad[column] = bad[column].add(M31.one());
                try std.testing.expect(!try valid(&definition, bad));
            }
        }
    }
    try std.testing.expect(try valid(&definition, @splat(M31.zero())));
}
fn valid(definition: *const full.Definition, row: full.Row) !bool {
    const values = try support.evaluateArena(std.testing.allocator, &definition.arena, &row);
    defer std.testing.allocator.free(values);
    for (definition.roots) |root| if (!values[@intFromEnum(root)].isZero()) return false;
    return true;
}

test "fusion preserves shared and exported products and reserved subgraphs" {
    const nodes = [_]graph.Node{
        .{ .op = .{ .constant = .{ 2, 3, 5, 7 } } },
        .{ .op = .{ .constant = .{ 11, 13, 17, 19 } } },
        .{ .op = .{ .mul = .{ .lhs = 0, .rhs = 1 } } },
        .{ .op = .{ .sub = .{ .lhs = 0, .rhs = 2 } } },
    };
    const g = try graph.CircuitGraph.authenticate(&nodes, &.{3}, graph.computeGraphDigest(&nodes, &.{3}));
    var counts: [nodes.len]u32 = undefined;
    _ = try lowering.computeUseCountsInto(g, &counts);
    var reserved = [_]bool{false} ** nodes.len;
    const match = fusion.matchAt(g, &counts, &reserved, 3).?;
    try std.testing.expectEqual(@as(u32, 2), match.multiply_node);
    try std.testing.expectEqual(full.Operation.addend_minus_product, match.operation);
    counts[2] += 1; // another consumer or an admitted cross-circuit export
    try std.testing.expect(fusion.matchAt(g, &counts, &reserved, 3) == null);
    counts[2] -= 1;
    reserved[2] = true;
    try std.testing.expect(fusion.matchAt(g, &counts, &reserved, 3) == null);
    reserved[2] = false;
    var matches: std.ArrayList(fusion.Match) = .empty;
    defer matches.deinit(std.testing.allocator);
    try fusion.reserve(&matches, std.testing.allocator, g, &counts, &reserved);
    try std.testing.expectEqual(@as(usize, 1), matches.items.len);
    try std.testing.expect(reserved[2] and reserved[3]);
    try std.testing.expect(fusion.matchAt(g, &counts, &reserved, 3) == null);
}

test "multiply-add exact wire boundary equals separate authenticated operations" {
    const binding = @import("universal_relation_binding.zig");
    const old_mul = @import("qm31_mul_full.zig");
    const old_lin = @import("linear_ops.zig");
    const mul_witness = @import("qm31_mul_full_witness.zig");
    const lin_witness = @import("linear_ops_witness.zig");
    const Entry = @import("relation_interaction.zig").Entry;
    var definition = try full.build(std.testing.allocator);
    defer definition.deinit();
    var mul_definition = try old_mul.build(std.testing.allocator, .generated);
    defer mul_definition.deinit();
    var lin_definition = try old_lin.build(std.testing.allocator, .generated);
    defer lin_definition.deinit();
    const new_plan = try binding.Binding(full).authenticate(&definition);
    const mul_plan = try binding.Binding(old_mul).authenticate(&mul_definition);
    const lin_plan = try binding.Binding(old_lin).authenticate(&lin_definition);
    const a = QM31.fromU32Unchecked(3, 5, 7, 11);
    const b = QM31.fromU32Unchecked(13, 17, 19, 23);
    const c = QM31.fromU32Unchecked(29, 31, 37, 41);
    const metadata = mul_witness.CircuitMetadata{ .circuit_id = M31.fromCanonical(501), .node_id = M31.fromCanonical(10), .lhs_id = M31.fromCanonical(1), .rhs_id = M31.fromCanonical(2), .uses = M31.one() };
    const mul_row = mul_witness.logicalInputs(mul_witness.mainRow(.{ .a = a, .b = b, .circuit = metadata }), mul_witness.preprocessedRow(.{ .binary = metadata }), .binary_node);
    const mul_entries = mul_plan.preparedEntries(mul_row);
    for ([_]full.Operation{ .product_plus_addend, .product_minus_addend, .addend_minus_product }) |op| {
        const reverse = op == .addend_minus_product;
        const linear_metadata = lin_witness.CircuitMetadata{ .circuit_id = metadata.circuit_id, .node_id = M31.fromCanonical(11), .lhs_id = M31.fromCanonical(if (reverse) 3 else 10), .rhs_id = M31.fromCanonical(if (reverse) 10 else 3), .uses = M31.fromCanonical(7) };
        const linear_op: lin_witness.Operation = if (op == .product_plus_addend) .add else .sub;
        const linear_row = lin_witness.logicalInputs(try lin_witness.mainRow(.{ .operation = linear_op, .lhs = if (reverse) c else a.mul(b), .rhs = if (reverse) a.mul(b) else c, .circuit = linear_metadata }), lin_witness.preprocessedRow(.{ .binary = .{ .operation = linear_op, .circuit = linear_metadata } }), .binary_node);
        const new_row = try full.logicalRow(.{ .circuit = 501, .output = 11, .lhs = 1, .rhs = 2, .addend = 3, .uses = 7, .operation = op }, a, b, c);
        var entries: [10]Entry = mul_entries ++ lin_plan.preparedEntries(linear_row) ++ new_plan.preparedEntries(new_row);
        for (entries[6..]) |*entry| entry.numerator = entry.numerator.neg();
        for (entries) |entry| {
            var sum = QM31.zero();
            for (entries) |candidate| {
                if (entry.domain != candidate.domain or entry.arity != candidate.arity) continue;
                var equal = true;
                for (entry.values[0..entry.arity], candidate.values[0..candidate.arity]) |lhs, rhs| equal = equal and lhs.eql(rhs);
                if (equal) sum = sum.add(candidate.numerator);
            }
            try std.testing.expect(sum.isZero());
        }
    }
}
