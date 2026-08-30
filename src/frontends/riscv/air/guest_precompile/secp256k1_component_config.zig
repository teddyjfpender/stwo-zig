//! Compile-time row configurations for the compact secp256k1 component family.

const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const affine = @import("secp256k1_affine.zig");
const ecdsa = @import("secp256k1_ecdsa_direct.zig");
const field = @import("secp256k1_field.zig");
const linear = @import("secp256k1_linear_direct.zig");
const logup = @import("../logup.zig");
const mul = @import("secp256k1_mul_direct.zig");
const point = @import("secp256k1_point_direct.zig");
const relations_mod = @import("secp256k1_relations.zig");
const scalar_program = @import("secp256k1_scalar_direct.zig");
const split = @import("secp256k1_split_direct.zig");
const table = @import("secp256k1_table_direct.zig");

pub fn Product(comptime modulus: affine.ModulusKind) type {
    return struct {
        pub const stable_name = if (modulus == .base)
            "secp256k1_product_base"
        else
            "secp256k1_product_scalar";
        pub const main_column_count = mul.Layout.main_columns;
        pub const direct_constraint_count = mul.constraint_count;
        pub const batch_count = 1 + mul.range_pair_count;
        pub const maximum_constraint_degree: u8 = 3;

        pub fn evaluate(
            comptime S: type,
            main: *const [main_column_count]S,
            previous: *const [main_column_count]S,
            next: *const [main_column_count]S,
            group_first: S,
            group_last: S,
            relations: *const relations_mod.Relations,
            sink: anytype,
        ) void {
            _ = previous;
            _ = next;
            _ = group_first;
            _ = group_last;
            mul.evaluateGeneric(S, main, modulus.modulus(), relations.product.alpha, sink);
        }

        pub fn rowPairs(
            comptime S: type,
            main: *const [main_column_count]S,
            previous: *const [main_column_count]S,
            next: *const [main_column_count]S,
            relations: *const relations_mod.Relations,
        ) [batch_count]logup.RowPair {
            _ = previous;
            _ = next;
            const active = main[mul.Layout.is_active];
            const lhs = value(S, main, mul.Layout.lhs);
            const rhs = value(S, main, mul.Layout.rhs);
            const result = value(S, main, mul.Layout.result);
            const tuple = relations_mod.productTuple(
                S,
                scalar(S, @intFromEnum(modulus)),
                &lhs,
                &rhs,
                &result,
            );
            const semantic = [1]logup.RowPair{emit(
                S,
                active,
                relations_mod.combineProduct(S, relations.product, tuple),
            )};
            return appendByteRanges(
                S,
                1,
                mul.range_pair_count,
                semantic,
                mul.rangePairs(S, main),
                active,
                relations,
            );
        }
    };
}

pub fn Linear(comptime modulus: affine.ModulusKind) type {
    return struct {
        pub const stable_name = if (modulus == .base)
            "secp256k1_linear_base"
        else
            "secp256k1_linear_scalar";
        pub const main_column_count = linear.Layout.main_columns;
        pub const direct_constraint_count = linear.constraint_count;
        pub const batch_count = 1 + linear.range_pair_count;
        pub const maximum_constraint_degree: u8 = 3;

        pub fn evaluate(
            comptime S: type,
            main: *const [main_column_count]S,
            previous: *const [main_column_count]S,
            next: *const [main_column_count]S,
            group_first: S,
            group_last: S,
            relations: *const relations_mod.Relations,
            sink: anytype,
        ) void {
            _ = previous;
            _ = next;
            _ = group_first;
            _ = group_last;
            _ = relations;
            linear.evaluateGeneric(S, main, modulus.modulus(), sink);
        }

        pub fn rowPairs(
            comptime S: type,
            main: *const [main_column_count]S,
            previous: *const [main_column_count]S,
            next: *const [main_column_count]S,
            relations: *const relations_mod.Relations,
        ) [batch_count]logup.RowPair {
            _ = previous;
            _ = next;
            const active = main[linear.Layout.is_active];
            const lhs = value(S, main, linear.Layout.lhs);
            const rhs = value(S, main, linear.Layout.rhs);
            const result = value(S, main, linear.Layout.result);
            const kind = main[linear.Layout.selector_subtract]
                .add(main[linear.Layout.selector_reduce_once].mul(scalar(S, 2)));
            const tuple = relations_mod.linearTuple(
                S,
                kind,
                scalar(S, @intFromEnum(modulus)),
                &lhs,
                &rhs,
                &result,
            );
            const semantic = [1]logup.RowPair{emit(
                S,
                active,
                relations_mod.combineLinear(S, relations.linear, tuple),
            )};
            return appendByteRanges(
                S,
                1,
                linear.range_pair_count,
                semantic,
                linear.rangePairs(S, main),
                active,
                relations,
            );
        }
    };
}

pub const Point = basic(
    "secp256k1_point",
    point,
    point.Layout.main_columns,
    point.constraint_count,
    point.batch_count,
    point.range_pair_count,
    struct {
        fn evaluate(comptime S: type, main: anytype, previous: anytype, next: anytype, first: S, last: S, relations: anytype, sink: anytype) void {
            _ = previous;
            _ = next;
            _ = first;
            _ = last;
            _ = relations;
            point.evaluateDirect(S, main, sink);
        }
        fn pairs(comptime S: type, main: anytype, previous: anytype, next: anytype, relations: anytype) [point.batch_count]logup.RowPair {
            _ = previous;
            _ = next;
            return point.rowPairs(S, main, relations);
        }
    },
);

pub const Split = basic(
    "secp256k1_split",
    split,
    split.Layout.main_columns,
    split.constraint_count,
    split.batch_count,
    split.range_pair_count,
    struct {
        fn evaluate(comptime S: type, main: anytype, previous: anytype, next: anytype, first: S, last: S, relations: anytype, sink: anytype) void {
            _ = previous;
            _ = next;
            _ = first;
            _ = last;
            _ = relations;
            split.evaluateDirect(S, main, sink);
        }
        fn pairs(comptime S: type, main: anytype, previous: anytype, next: anytype, relations: anytype) [split.batch_count]logup.RowPair {
            _ = previous;
            _ = next;
            return split.rowPairs(S, main, relations);
        }
    },
);

pub const ScalarProgram = basic(
    "secp256k1_scalar_program",
    scalar_program,
    scalar_program.Layout.main_columns,
    scalar_program.constraint_count,
    scalar_program.batch_count,
    scalar_program.range_pair_count,
    struct {
        fn evaluate(comptime S: type, main: anytype, previous: anytype, next: anytype, first: S, last: S, relations: anytype, sink: anytype) void {
            _ = relations;
            scalar_program.evaluateDirect(S, main, previous, next, first, last, sink);
        }
        fn pairs(comptime S: type, main: anytype, previous: anytype, next: anytype, relations: anytype) [scalar_program.batch_count]logup.RowPair {
            _ = next;
            return scalar_program.rowPairs(S, main, previous, relations);
        }
    },
);

pub const Table = basic(
    "secp256k1_signed_table",
    table,
    table.Layout.main_columns,
    table.constraint_count,
    table.batch_count,
    table.range_pair_count,
    struct {
        fn evaluate(comptime S: type, main: anytype, previous: anytype, next: anytype, first: S, last: S, relations: anytype, sink: anytype) void {
            _ = next;
            _ = first;
            _ = last;
            _ = relations;
            table.evaluateDirect(S, main, previous, sink);
        }
        fn pairs(comptime S: type, main: anytype, previous: anytype, next: anytype, relations: anytype) [table.batch_count]logup.RowPair {
            _ = next;
            return table.rowPairs(S, main, previous, relations);
        }
    },
);

pub const Ecdsa = basic(
    "secp256k1_ecdsa",
    ecdsa,
    ecdsa.Layout.main_columns,
    ecdsa.constraint_count,
    ecdsa.batch_count,
    ecdsa.range_pair_count,
    struct {
        fn evaluate(comptime S: type, main: anytype, previous: anytype, next: anytype, first: S, last: S, relations: anytype, sink: anytype) void {
            _ = previous;
            _ = next;
            _ = first;
            _ = last;
            _ = relations;
            ecdsa.evaluateDirect(S, main, sink);
        }
        fn pairs(comptime S: type, main: anytype, previous: anytype, next: anytype, relations: anytype) [ecdsa.batch_count]logup.RowPair {
            _ = previous;
            _ = next;
            return ecdsa.rowPairs(S, main, relations);
        }
    },
);

pub const ByteTable = struct {
    pub const stable_name = "secp256k1_byte_table";
    pub const main_column_count: usize = 11;
    pub const direct_constraint_count: usize = 10;
    pub const batch_count: usize = 1;
    pub const maximum_constraint_degree: u8 = 3;

    pub fn row(value_: u8, multiplicity: M31) [main_column_count]M31 {
        var result: [main_column_count]M31 = @splat(M31.zero());
        result[0] = M31.one();
        result[1] = multiplicity;
        result[2] = M31.fromU64(value_);
        for (0..8) |bit| result[3 + bit] = M31.fromU64((value_ >> @intCast(bit)) & 1);
        return result;
    }

    pub fn evaluate(
        comptime S: type,
        main: *const [main_column_count]S,
        previous: *const [main_column_count]S,
        next: *const [main_column_count]S,
        group_first: S,
        group_last: S,
        relations: *const relations_mod.Relations,
        sink: anytype,
    ) void {
        _ = previous;
        _ = next;
        _ = group_first;
        _ = group_last;
        _ = relations;
        const active = main[0];
        sink.add(active.mul(active.sub(scalar(S, 1))), 2);
        var reconstructed = S.zero();
        for (0..8) |bit| {
            const value_bit = main[3 + bit];
            sink.add(value_bit.mul(value_bit.sub(active)), 2);
            reconstructed = reconstructed.add(value_bit.mul(scalar(S, @as(u64, 1) << @intCast(bit))));
        }
        sink.add(active.mul(main[2].sub(reconstructed)), 2);
    }

    pub fn rowPairs(
        comptime S: type,
        main: *const [main_column_count]S,
        previous: *const [main_column_count]S,
        next: *const [main_column_count]S,
        relations: *const relations_mod.Relations,
    ) [batch_count]logup.RowPair {
        _ = previous;
        _ = next;
        return .{emit(
            S,
            main[1],
            relations_mod.combineByte(S, relations.byte, .{main[2]}),
        )};
    }
};

fn basic(
    comptime name: []const u8,
    comptime Direct: type,
    comptime main_count: usize,
    comptime direct_count: usize,
    comptime semantic_batches: usize,
    comptime range_pairs: usize,
    comptime Hooks: type,
) type {
    return struct {
        pub const stable_name = name;
        pub const main_column_count = main_count;
        pub const direct_constraint_count = direct_count;
        pub const batch_count = semantic_batches + range_pairs;
        pub const maximum_constraint_degree: u8 = @max(3, Direct.maximum_constraint_degree);

        pub fn evaluate(
            comptime S: type,
            main: *const [main_column_count]S,
            previous: *const [main_column_count]S,
            next: *const [main_column_count]S,
            group_first: S,
            group_last: S,
            relations: *const relations_mod.Relations,
            sink: anytype,
        ) void {
            Hooks.evaluate(S, main, previous, next, group_first, group_last, relations, sink);
        }

        pub fn rowPairs(
            comptime S: type,
            main: *const [main_column_count]S,
            previous: *const [main_column_count]S,
            next: *const [main_column_count]S,
            relations: *const relations_mod.Relations,
        ) [batch_count]logup.RowPair {
            const semantic = Hooks.pairs(S, main, previous, next, relations);
            return appendByteRanges(
                S,
                semantic_batches,
                range_pairs,
                semantic,
                Direct.rangePairs(S, main),
                main[0],
                relations,
            );
        }
    };
}

fn appendByteRanges(
    comptime S: type,
    comptime semantic_batches: usize,
    comptime range_pair_count: usize,
    semantic: [semantic_batches]logup.RowPair,
    ranges: [range_pair_count][2]S,
    active: S,
    relations: *const relations_mod.Relations,
) [semantic_batches + range_pair_count]logup.RowPair {
    var result: [semantic_batches + range_pair_count]logup.RowPair = undefined;
    @memcpy(result[0..semantic_batches], &semantic);
    for (ranges, 0..) |pair, index| result[semantic_batches + index] = .{
        .n1 = lift(S, active).neg(),
        .d1 = relations_mod.combineByte(S, relations.byte, .{pair[0]}),
        .n2 = lift(S, active).neg(),
        .d2 = relations_mod.combineByte(S, relations.byte, .{pair[1]}),
    };
    return result;
}

fn value(
    comptime S: type,
    main: anytype,
    offset: usize,
) [field.limb_count]S {
    return main[offset..][0..field.limb_count].*;
}

fn emit(comptime S: type, coefficient: S, denominator: QM31) logup.RowPair {
    return logup.RowPair.single(lift(S, coefficient), denominator);
}

fn lift(comptime S: type, value_: S) QM31 {
    if (S == M31) return QM31.fromBase(value_);
    if (S == QM31) return value_;
    @compileError("secp256k1 components support only M31 and QM31");
}

fn scalar(comptime S: type, value_: anytype) S {
    const canonical: u64 = @intCast(value_);
    if (S == M31) return M31.fromU64(canonical);
    if (S == QM31) return QM31.fromBase(M31.fromU64(canonical));
    @compileError("secp256k1 components support only M31 and QM31");
}
