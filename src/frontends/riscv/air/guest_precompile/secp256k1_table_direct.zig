//! Signed width-5 table AIR for the compact secp256k1 scalar program.
//!
//! Fixed generator tables are verifier-known constants. Variable tables bind
//! their root to the scalar program, derive odd positive entries through one
//! double and seven additions, and derive negative entries through scalar
//! linear rows. A weighted table emission serves repeated digit selections.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const affine = @import("secp256k1_affine.zig");
const field = @import("secp256k1_field.zig");
const logup = @import("../logup.zig");
const relations_mod = @import("secp256k1_relations.zig");

pub const Layout = struct {
    pub const is_active: usize = 0;
    pub const multiplicity: usize = 1;
    pub const kind_selectors: usize = 2;
    pub const code_selectors: usize = kind_selectors + 4;
    pub const point: usize = code_selectors + affine.signed_table_size;
    pub const twice: usize = point + relations_mod.encoded_point_size;
    pub const source: usize = twice + relations_mod.encoded_point_size;
    pub const positive: usize = source + relations_mod.encoded_point_size;
    pub const transition_kind: usize = positive + relations_mod.encoded_point_size;
    pub const main_columns: usize = transition_kind + 1;

    pub fn kindSelector(kind: affine.TableKind) usize {
        return kind_selectors + @intFromEnum(kind);
    }

    pub fn codeSelector(code: usize) usize {
        return code_selectors + code;
    }
};

pub const event_count: usize = 6;
pub const batch_count: usize = event_count / 2;
/// Fixed rows are constants; variable rows inherit byte custody through the
/// point/product/linear and table-root buses.
pub const range_pair_count: usize = 0;
pub const maximum_constraint_degree: u8 = 3;
pub const constraint_count: usize = 479;

pub const Error = error{
    InvalidTableRecord,
    InvalidPointSequence,
    InvalidLinearSequence,
    InvalidProductSequence,
};

comptime {
    if (Layout.main_columns != 284 or range_pair_count != 0 or batch_count != 3)
        @compileError("secp256k1 signed-table geometry drifted");
}

pub fn rowFromEntry(
    tape: *const affine.Tape,
    table: *const affine.TableRecord,
    code: usize,
    multiplicity: u32,
) Error![Layout.main_columns]M31 {
    if (code >= affine.signed_table_size) return error.InvalidTableRecord;
    var row: [Layout.main_columns]M31 = @splat(M31.zero());
    row[Layout.is_active] = M31.one();
    row[Layout.multiplicity] = M31.fromCanonical(multiplicity);
    row[Layout.kindSelector(table.kind)] = M31.one();
    row[Layout.codeSelector(code)] = M31.one();
    writePoint(&row, Layout.point, table.entries[code]);
    writePoint(
        &row,
        Layout.positive,
        table.entries[
            if (code > affine.odd_table_size)
                code - affine.odd_table_size
            else
                code
        ],
    );
    const fixed = affine.fixedSignedTable(table.kind);
    if (fixed) |expected| {
        if (!affine.Point.eql(expected[code], table.entries[code]))
            return error.InvalidTableRecord;
        return row;
    }

    writePoint(&row, Layout.twice, table.twice);
    writePoint(&row, Layout.source, table.source);
    if (code == 0) return row;
    if (code == 1) {
        if (table.point_start >= tape.points.items.len) return error.InvalidPointSequence;
        const doubled = &tape.points.items[table.point_start];
        try expectPoint(doubled, table.entries[1], .{}, table.twice);
        row[Layout.transition_kind] = M31.fromU64(@intFromEnum(doubled.kind));
        if (table.kind == .public_key) {
            if (!affine.Point.eql(table.entries[1], table.source))
                return error.InvalidTableRecord;
        } else if (table.kind == .public_key_endomorphism) {
            if (table.root_product_index >= tape.products.items.len)
                return error.InvalidProductSequence;
            const product = &tape.products.items[table.root_product_index];
            const beta = field.bytesFromInteger(affine.endomorphism_beta);
            try expectProduct(product, table.source.x, beta, table.entries[1].x);
            if (!std.mem.eql(u8, &table.source.y, &table.entries[1].y))
                return error.InvalidTableRecord;
        } else return error.InvalidTableRecord;
        return row;
    }
    if (code <= affine.odd_table_size) {
        const point_index = table.point_start + code - 1;
        if (point_index >= tape.points.items.len) return error.InvalidPointSequence;
        const transition = &tape.points.items[point_index];
        try expectPoint(
            transition,
            table.entries[code - 1],
            table.twice,
            table.entries[code],
        );
        row[Layout.transition_kind] = M31.fromU64(@intFromEnum(transition.kind));
        return row;
    }

    const positive_code = code - affine.odd_table_size;
    const linear_index = table.negation_linear_start + positive_code - 1;
    if (linear_index >= tape.linears.items.len) return error.InvalidLinearSequence;
    const linear = &tape.linears.items[linear_index];
    const zero: affine.Value = @splat(0);
    try expectLinear(
        linear,
        zero,
        table.entries[positive_code].y,
        table.entries[code].y,
    );
    if (!std.mem.eql(u8, &table.entries[positive_code].x, &table.entries[code].x))
        return error.InvalidTableRecord;
    return row;
}

pub fn evaluateDirect(
    comptime S: type,
    main: *const [Layout.main_columns]S,
    previous: *const [Layout.main_columns]S,
    sink: anytype,
) void {
    comptime requireSupportedField(S);
    const active = main[Layout.is_active];
    sink.add(active.mul(active.sub(scalar(S, 1))), 2);
    var kind_sum = S.zero();
    inline for (std.meta.tags(affine.TableKind)) |kind| {
        const selector = main[Layout.kindSelector(kind)];
        sink.add(selector.mul(selector.sub(active)), 2);
        kind_sum = kind_sum.add(selector);
    }
    sink.add(kind_sum.sub(active), 1);
    var code_sum = S.zero();
    for (0..affine.signed_table_size) |code| {
        const selector = main[Layout.codeSelector(code)];
        sink.add(selector.mul(selector.sub(active)), 2);
        code_sum = code_sum.add(selector);
    }
    sink.add(code_sum.sub(active), 1);

    const point = pointView(S, main, Layout.point);
    const positive = pointView(S, main, Layout.positive);
    const code_zero = main[Layout.codeSelector(0)];
    const code_one = main[Layout.codeSelector(1)];
    sink.add(point[0].sub(code_zero), 1);

    inline for (.{ affine.TableKind.generator, affine.TableKind.generator_endomorphism }) |kind| {
        const fixed = affine.fixedSignedTable(kind).?;
        const kind_selector = main[Layout.kindSelector(kind)];
        for (0..relations_mod.encoded_point_size) |index| {
            var expected = S.zero();
            for (0..affine.signed_table_size) |code| {
                expected = expected.add(main[Layout.codeSelector(code)].mul(
                    liftBase(S, relations_mod.encodePoint(fixed[code])[index]),
                ));
            }
            sink.add(kind_selector.mul(point[index].sub(expected)), 2);
        }
    }

    const twice = pointView(S, main, Layout.twice);
    const source = pointView(S, main, Layout.source);
    const previous_twice = pointView(S, previous, Layout.twice);
    const previous_source = pointView(S, previous, Layout.source);
    var code_after_one = S.zero();
    for (2..affine.signed_table_size) |code| {
        code_after_one = code_after_one.add(main[Layout.codeSelector(code)]);
    }
    for (0..relations_mod.encoded_point_size) |index| {
        sink.add(code_after_one.mul(twice[index].sub(previous_twice[index])), 2);
        sink.add(code_after_one.mul(source[index].sub(previous_source[index])), 2);
    }
    for (point[1..]) |coordinate| sink.add(code_zero.mul(coordinate), 2);
    const public_key = main[Layout.kindSelector(.public_key)];
    const public_key_endomorphism = main[Layout.kindSelector(.public_key_endomorphism)];
    for (0..relations_mod.encoded_point_size) |index| {
        sink.add(code_one.mul(public_key).mul(point[index].sub(source[index])), 3);
    }
    sink.add(code_one.mul(public_key_endomorphism).mul(point[0].sub(source[0])), 3);
    for (0..field.limb_count) |index| {
        sink.add(code_one.mul(public_key_endomorphism).mul(
            point[1 + field.limb_count + index]
                .sub(source[1 + field.limb_count + index]),
        ), 3);
    }
    var negative = S.zero();
    for (affine.odd_table_size + 1..affine.signed_table_size) |code| {
        negative = negative.add(main[Layout.codeSelector(code)]);
    }
    for (0..field.limb_count) |index| {
        sink.add(negative.mul(point[1 + index].sub(positive[1 + index])), 2);
    }
}

pub fn rowPairs(
    comptime S: type,
    main: *const [Layout.main_columns]S,
    previous: *const [Layout.main_columns]S,
    relations: *const relations_mod.Relations,
) [batch_count]logup.RowPair {
    comptime requireSupportedField(S);
    const point = pointView(S, main, Layout.point);
    const twice = pointView(S, main, Layout.twice);
    const source = pointView(S, main, Layout.source);
    const positive = pointView(S, main, Layout.positive);
    const kind = selectorValue(S, main, Layout.kind_selectors, 4);
    const code = selectorValue(
        S,
        main,
        Layout.code_selectors,
        affine.signed_table_size,
    );
    const identity: [relations_mod.encoded_point_size]S = blk: {
        var value: [relations_mod.encoded_point_size]S = @splat(S.zero());
        value[0] = scalar(S, 1);
        break :blk value;
    };
    const zero: [field.limb_count]S = @splat(S.zero());
    const beta = constantValue(S, affine.endomorphism_beta);
    var events: [event_count]logup.RowPair = undefined;
    const table_tuple = relations_mod.tableTuple(
        S,
        kind,
        code,
        &point,
    );
    events[0] = emit(
        S,
        main[Layout.multiplicity],
        relations_mod.combineTable(S, relations.table, table_tuple),
    );

    const code_one = main[Layout.codeSelector(1)];
    const variable_kind = main[Layout.kindSelector(.public_key)]
        .add(main[Layout.kindSelector(.public_key_endomorphism)]);
    const variable_root = code_one.mul(variable_kind);
    const root_tuple = relations_mod.tableRootTuple(
        S,
        kind,
        &source,
    );
    events[1] = request(
        S,
        variable_root,
        relations_mod.combineTableRoot(S, relations.table_root, root_tuple),
    );

    const endomorphism_root = code_one.mul(
        main[Layout.kindSelector(.public_key_endomorphism)],
    );
    events[2] = productRequest(
        S,
        endomorphism_root,
        pointX(S, &source),
        &beta,
        pointX(S, &point),
        relations,
    );
    const variable_positive_root = variable_root;
    events[3] = pointRequest(
        S,
        variable_positive_root,
        main[Layout.transition_kind],
        &point,
        &identity,
        &twice,
        relations,
    );
    var positive_code = S.zero();
    for (2..affine.odd_table_size + 1) |index| {
        positive_code = positive_code.add(main[Layout.codeSelector(index)]);
    }
    const variable_positive = positive_code.mul(variable_kind);
    const previous_point = pointView(S, previous, Layout.point);
    events[4] = pointRequest(
        S,
        variable_positive,
        main[Layout.transition_kind],
        &previous_point,
        &twice,
        &point,
        relations,
    );
    var negative_code = S.zero();
    for (affine.odd_table_size + 1..affine.signed_table_size) |index| {
        negative_code = negative_code.add(main[Layout.codeSelector(index)]);
    }
    const variable_negative = negative_code.mul(variable_kind);
    events[5] = linearRequest(
        S,
        variable_negative,
        &zero,
        pointY(S, &positive),
        pointY(S, &point),
        relations,
    );
    var result: [batch_count]logup.RowPair = undefined;
    for (&result, 0..) |*pair, index| pair.* = .{
        .n1 = events[2 * index].n1,
        .d1 = events[2 * index].d1,
        .n2 = events[2 * index + 1].n1,
        .d2 = events[2 * index + 1].d1,
    };
    return result;
}

pub fn rangePairs(
    comptime S: type,
    main: *const [Layout.main_columns]S,
) [range_pair_count][2]S {
    comptime requireSupportedField(S);
    _ = main;
    return .{};
}

fn selectorValue(
    comptime S: type,
    main: *const [Layout.main_columns]S,
    offset: usize,
    count: usize,
) S {
    var result = S.zero();
    for (0..count) |index| {
        result = result.add(main[offset + index].mul(scalar(S, index)));
    }
    return result;
}

fn productRequest(
    comptime S: type,
    coefficient: S,
    lhs: *const [field.limb_count]S,
    rhs: *const [field.limb_count]S,
    result: *const [field.limb_count]S,
    relations: *const relations_mod.Relations,
) logup.RowPair {
    const tuple = relations_mod.productTuple(
        S,
        scalar(S, @intFromEnum(affine.ModulusKind.base)),
        lhs,
        rhs,
        result,
    );
    return request(S, coefficient, relations_mod.combineProduct(S, relations.product, tuple));
}

fn linearRequest(
    comptime S: type,
    coefficient: S,
    lhs: *const [field.limb_count]S,
    rhs: *const [field.limb_count]S,
    result: *const [field.limb_count]S,
    relations: *const relations_mod.Relations,
) logup.RowPair {
    const tuple = relations_mod.linearTuple(
        S,
        scalar(S, @intFromEnum(affine.LinearKind.subtract)),
        scalar(S, @intFromEnum(affine.ModulusKind.base)),
        lhs,
        rhs,
        result,
    );
    return request(S, coefficient, relations_mod.combineLinear(S, relations.linear, tuple));
}

fn pointRequest(
    comptime S: type,
    coefficient: S,
    kind: S,
    lhs: *const [relations_mod.encoded_point_size]S,
    rhs: *const [relations_mod.encoded_point_size]S,
    result: *const [relations_mod.encoded_point_size]S,
    relations: *const relations_mod.Relations,
) logup.RowPair {
    const tuple = relations_mod.pointTuple(S, kind, lhs, rhs, result);
    return request(S, coefficient, relations_mod.combinePoint(S, relations.point, tuple));
}

fn expectPoint(
    record: *const affine.PointRecord,
    lhs: affine.Point,
    rhs: affine.Point,
    result: affine.Point,
) Error!void {
    if (!affine.Point.eql(record.lhs, lhs) or
        !affine.Point.eql(record.rhs, rhs) or
        !affine.Point.eql(record.result, result))
    {
        return error.InvalidPointSequence;
    }
}

fn expectProduct(
    record: *const affine.ProductRecord,
    lhs: affine.Value,
    rhs: affine.Value,
    result: affine.Value,
) Error!void {
    if (record.modulus != .base or
        !std.mem.eql(u8, &record.witness.lhs, &lhs) or
        !std.mem.eql(u8, &record.witness.rhs, &rhs) or
        !std.mem.eql(u8, &record.witness.result, &result))
    {
        return error.InvalidProductSequence;
    }
}

fn expectLinear(
    record: *const affine.LinearRecord,
    lhs: affine.Value,
    rhs: affine.Value,
    result: affine.Value,
) Error!void {
    if (record.kind != .subtract or record.modulus != .base or
        !std.mem.eql(u8, &record.lhs, &lhs) or
        !std.mem.eql(u8, &record.rhs, &rhs) or
        !std.mem.eql(u8, &record.result, &result))
    {
        return error.InvalidLinearSequence;
    }
}

fn pointView(
    comptime S: type,
    main: *const [Layout.main_columns]S,
    offset: usize,
) [relations_mod.encoded_point_size]S {
    return main[offset..][0..relations_mod.encoded_point_size].*;
}

fn pointX(comptime S: type, point: *const [relations_mod.encoded_point_size]S) *const [field.limb_count]S {
    return point[1..][0..field.limb_count];
}

fn pointY(comptime S: type, point: *const [relations_mod.encoded_point_size]S) *const [field.limb_count]S {
    return point[1 + field.limb_count ..][0..field.limb_count];
}

fn constantValue(comptime S: type, value: u256) [field.limb_count]S {
    const encoded = field.bytesFromInteger(value);
    var result: [field.limb_count]S = undefined;
    for (encoded, 0..) |byte, index| result[index] = scalar(S, byte);
    return result;
}

fn request(comptime S: type, coefficient: S, denominator: QM31) logup.RowPair {
    return logup.RowPair.single(lift(S, coefficient).neg(), denominator);
}

fn emit(comptime S: type, coefficient: S, denominator: QM31) logup.RowPair {
    return logup.RowPair.single(lift(S, coefficient), denominator);
}

fn lift(comptime S: type, value: S) QM31 {
    if (S == M31) return QM31.fromBase(value);
    if (S == QM31) return value;
    @compileError("secp256k1 table AIR supports only M31 and QM31");
}

fn liftBase(comptime S: type, value: M31) S {
    if (S == M31) return value;
    if (S == QM31) return QM31.fromBase(value);
    @compileError("secp256k1 table AIR supports only M31 and QM31");
}

fn scalar(comptime S: type, value: anytype) S {
    const canonical: u64 = @intCast(value);
    if (S == M31) return M31.fromU64(canonical);
    if (S == QM31) return QM31.fromBase(M31.fromU64(canonical));
    @compileError("secp256k1 table AIR supports only M31 and QM31");
}

fn writePoint(row: *[Layout.main_columns]M31, offset: usize, point: affine.Point) void {
    row[offset] = M31.fromU64(@intFromBool(point.infinity));
    for (point.x, 0..) |byte, index| row[offset + 1 + index] = M31.fromU64(byte);
    for (point.y, 0..) |byte, index| {
        row[offset + 1 + field.limb_count + index] = M31.fromU64(byte);
    }
}

fn requireSupportedField(comptime S: type) void {
    if (S != M31 and S != QM31)
        @compileError("secp256k1 table AIR supports only M31 and QM31");
}
