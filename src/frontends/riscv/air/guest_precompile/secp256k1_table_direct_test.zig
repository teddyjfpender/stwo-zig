const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const affine = @import("secp256k1_affine.zig");
const ecdsa = @import("secp256k1_ecdsa.zig");
const fixture = @import("secp256k1_affine_test.zig").csp_input;
const direct = @import("secp256k1_table_direct.zig");
const relations_mod = @import("secp256k1_relations.zig");

const Sink = struct {
    failures: usize = 0,
    maximum_degree: u8 = 0,

    pub fn add(self: *Sink, value: anytype, degree: u8) void {
        const lifted = if (@TypeOf(value) == M31) QM31.fromBase(value) else value;
        self.failures += @intFromBool(!lifted.isZero());
        self.maximum_degree = @max(self.maximum_degree, degree);
    }
};

test "secp256k1 table AIR: fixed and derived signed entries vanish" {
    var tape = try cspTape();
    defer tape.deinit();
    const multiplicities = tableMultiplicities(&tape);
    for (tape.tables.items, 0..) |*table, table_index| {
        var previous: [direct.Layout.main_columns]M31 = @splat(M31.zero());
        for (0..affine.signed_table_size) |code| {
            const row = try direct.rowFromEntry(
                &tape,
                table,
                code,
                multiplicities[table_index][code],
            );
            var sink = Sink{};
            direct.evaluateDirect(
                M31,
                &row,
                &previous,
                &sink,
            );
            try std.testing.expectEqual(@as(usize, 0), sink.failures);
            try std.testing.expect(sink.maximum_degree <= direct.maximum_constraint_degree);
            previous = row;
        }
    }
}

test "secp256k1 table AIR: derivation requests cancel exact authorities" {
    var tape = try cspTape();
    defer tape.deinit();
    const relations = relations_mod.Relations.dummy();
    const multiplicities = tableMultiplicities(&tape);
    for (tape.tables.items, 0..) |*table, table_index| {
        var previous: [direct.Layout.main_columns]M31 = @splat(M31.zero());
        for (0..affine.signed_table_size) |code| {
            const row = try direct.rowFromEntry(
                &tape,
                table,
                code,
                multiplicities[table_index][code],
            );
            const positive_code = if (code > affine.odd_table_size)
                code - affine.odd_table_size
            else
                code;
            var sum = try pairSum(&direct.rowPairs(
                M31,
                &row,
                &previous,
                &relations,
            ));
            const table_tuple = relations_mod.tableTupleForEntry(
                table.kind,
                code,
                table.entries[code],
            );
            sum = sum.sub((relations_mod.combineTable(
                M31,
                relations.table,
                table_tuple,
            ).inv() catch unreachable).mulM31(M31.fromCanonical(
                multiplicities[table_index][code],
            )));

            const variable = table.kind == .public_key or
                table.kind == .public_key_endomorphism;
            if (variable and code == 1) {
                const root = relations_mod.tableRootTuple(
                    M31,
                    M31.fromU64(@intFromEnum(table.kind)),
                    &relations_mod.encodePoint(table.source),
                );
                sum = sum.add(relations_mod.combineTableRoot(
                    M31,
                    relations.table_root,
                    root,
                ).inv() catch unreachable);
                const point = &tape.points.items[table.point_start];
                sum = sum.add(relations_mod.combinePoint(
                    M31,
                    relations.point,
                    relations_mod.pointTupleForRecord(point),
                ).inv() catch unreachable);
                if (table.kind == .public_key_endomorphism) {
                    const product = &tape.products.items[table.root_product_index];
                    sum = sum.add(relations_mod.combineProduct(
                        M31,
                        relations.product,
                        relations_mod.productTupleForRecord(product),
                    ).inv() catch unreachable);
                }
            } else if (variable and code > 1 and code <= affine.odd_table_size) {
                const point = &tape.points.items[table.point_start + code - 1];
                sum = sum.add(relations_mod.combinePoint(
                    M31,
                    relations.point,
                    relations_mod.pointTupleForRecord(point),
                ).inv() catch unreachable);
            } else if (variable and code > affine.odd_table_size) {
                const linear = &tape.linears.items[
                    table.negation_linear_start + positive_code - 1
                ];
                sum = sum.add(relations_mod.combineLinear(
                    M31,
                    relations.linear,
                    relations_mod.linearTupleForRecord(linear),
                ).inv() catch unreachable);
            }
            try std.testing.expect(sum.isZero());
            previous = row;
        }
    }
}

test "secp256k1 table AIR: fixed and variable mutations fail closed" {
    var tape = try cspTape();
    defer tape.deinit();
    var previous: [direct.Layout.main_columns]M31 = @splat(M31.zero());
    var row = try direct.rowFromEntry(&tape, &tape.tables.items[0], 1, 0);
    var forged = row;
    forged[direct.Layout.point + 5] = forged[direct.Layout.point + 5].add(M31.one());
    var sink = Sink{};
    direct.evaluateDirect(M31, &forged, &previous, &sink);
    try std.testing.expect(sink.failures != 0);

    const variable = &tape.tables.items[2];
    previous = try direct.rowFromEntry(&tape, variable, 8, 0);
    row = try direct.rowFromEntry(&tape, variable, 9, 0);
    forged = row;
    forged[direct.Layout.point + 9] = forged[direct.Layout.point + 9].add(M31.one());
    sink = .{};
    direct.evaluateDirect(M31, &forged, &previous, &sink);
    try std.testing.expect(sink.failures != 0);
}

test "secp256k1 table AIR: byte custody is delegated to derivation relations" {
    var tape = try cspTape();
    defer tape.deinit();
    var row = try direct.rowFromEntry(&tape, &tape.tables.items[2], 1, 0);
    const pairs = direct.rangePairs(M31, &row);
    try std.testing.expectEqual(@as(usize, 0), pairs.len);
    _ = &row;
}

fn cspTape() !affine.Tape {
    var tape = affine.Tape.init(std.testing.allocator);
    errdefer tape.deinit();
    if (!try ecdsa.verify(
        &tape,
        fixture[0..32].*,
        fixture[32..97].*,
        fixture[97..129].*,
        fixture[129..161].*,
    )) return error.InvalidFixture;
    return tape;
}

fn tableMultiplicities(tape: *const affine.Tape) [4][affine.signed_table_size]u32 {
    var result: [4][affine.signed_table_size]u32 = @splat(@splat(0));
    for (tape.scalar_steps.items) |step| {
        for (step.digits, 0..) |digit, table| {
            if (digit != 0) result[table][affine.signedTableIndex(digit)] += 1;
        }
    }
    return result;
}

fn pairSum(pairs: *const [direct.batch_count]@import("../logup.zig").RowPair) !QM31 {
    var result = QM31.zero();
    for (pairs) |pair| {
        result = result.add(pair.n1.mul(try pair.d1.inv()));
        result = result.add(pair.n2.mul(try pair.d2.inv()));
    }
    return result;
}
