const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const affine = @import("secp256k1_affine.zig");
const direct = @import("secp256k1_linear_direct.zig");
const field = @import("secp256k1_field.zig");

const Sink = struct {
    count: usize = 0,
    failures: usize = 0,
    maximum_degree: u8 = 0,

    pub fn add(self: *Sink, value: anytype, degree: u8) void {
        const lifted = if (@TypeOf(value) == M31) QM31.fromBase(value) else value;
        self.count += 1;
        self.failures += @intFromBool(!lifted.isZero());
        self.maximum_degree = @max(self.maximum_degree, degree);
    }
};

test "secp256k1 linear AIR: honest add subtract and reduction rows vanish" {
    var tape = affine.Tape.init(std.testing.allocator);
    defer tape.deinit();
    const base = field.base_modulus.integer();
    const scalar = field.scalar_modulus.integer();
    _ = try tape.add(.base, bytes(base - 7), bytes(19));
    _ = try tape.sub(.base, bytes(5), bytes(19));
    _ = try tape.add(.scalar, bytes(scalar - 99), bytes(123));
    _ = try tape.sub(.scalar, bytes(77), bytes(123));
    _ = try tape.reduceScalarOnce(bytes(std.math.maxInt(u256)));

    for (tape.linears.items) |*record| {
        const row = try direct.rowFromRecord(record);
        var sink = Sink{};
        direct.evaluateGeneric(M31, &row, record.modulus.modulus(), &sink);
        try std.testing.expectEqual(direct.constraint_count, sink.count);
        try std.testing.expectEqual(@as(usize, 0), sink.failures);
        try std.testing.expectEqual(direct.maximum_constraint_degree, sink.maximum_degree);
    }
}

test "secp256k1 linear AIR: row mutations fail closed" {
    var tape = affine.Tape.init(std.testing.allocator);
    defer tape.deinit();
    _ = try tape.sub(.base, bytes(5), bytes(19));
    const record = &tape.linears.items[0];
    const honest = try direct.rowFromRecord(record);
    const columns = [_]usize{
        direct.Layout.is_active,
        direct.Layout.selector_add,
        direct.Layout.selector_subtract,
        direct.Layout.quotient,
        direct.Layout.lhs + 3,
        direct.Layout.rhs + 7,
        direct.Layout.result + 11,
        direct.Layout.carry_code + 13,
        direct.Layout.canonical_sum + 17,
        direct.Layout.canonical_carry + 19,
    };
    for (columns) |column| {
        var row = honest;
        row[column] = row[column].add(M31.one());
        var sink = Sink{};
        direct.evaluateGeneric(M31, &row, field.base_modulus, &sink);
        try std.testing.expect(sink.failures != 0);
    }
}

test "secp256k1 linear AIR: invalid records are rejected before materialization" {
    const canonical = field.bytesFromInteger(7);
    var wrong = affine.LinearRecord{
        .kind = .add,
        .modulus = .base,
        .lhs = canonical,
        .rhs = canonical,
        .result = field.bytesFromInteger(15),
    };
    try std.testing.expectError(error.InvalidResult, direct.rowFromRecord(&wrong));
    wrong.kind = .reduce_once;
    try std.testing.expectError(error.InvalidOperation, direct.rowFromRecord(&wrong));
    wrong.kind = .add;
    wrong.lhs = field.base_modulus.bytes;
    try std.testing.expectError(error.NonCanonicalOperand, direct.rowFromRecord(&wrong));
}

test "secp256k1 linear AIR: M31 and QM31 evaluations agree" {
    var tape = affine.Tape.init(std.testing.allocator);
    defer tape.deinit();
    _ = try tape.add(.scalar, bytes(123456789), bytes(987654321));
    const base_row = try direct.rowFromRecord(&tape.linears.items[0]);
    var secure_row: [direct.Layout.main_columns]QM31 = undefined;
    for (&secure_row, base_row) |*out, value| out.* = QM31.fromBase(value);
    var base_sink = Sink{};
    direct.evaluateGeneric(M31, &base_row, field.scalar_modulus, &base_sink);
    var secure_sink = Sink{};
    direct.evaluateGeneric(QM31, &secure_row, field.scalar_modulus, &secure_sink);
    try std.testing.expectEqual(base_sink.count, secure_sink.count);
    try std.testing.expectEqual(base_sink.failures, secure_sink.failures);
}

test "secp256k1 linear AIR: all guest-native bytes are range-covered" {
    var tape = affine.Tape.init(std.testing.allocator);
    defer tape.deinit();
    _ = try tape.add(.base, bytes(123), bytes(456));
    var row = try direct.rowFromRecord(&tape.linears.items[0]);
    const pairs = direct.rangePairs(M31, &row);
    try std.testing.expectEqual(@as(usize, 64), pairs.len);
    for (pairs) |pair| {
        try std.testing.expect(pair[0].toU32() <= 255);
        try std.testing.expect(pair[1].toU32() <= 255);
    }
    row[direct.Layout.canonical_sum + 9] = M31.fromU64(256);
    const forged = direct.rangePairs(M31, &row);
    var rejected = false;
    for (forged) |pair| rejected = rejected or
        pair[0].toU32() > 255 or pair[1].toU32() > 255;
    try std.testing.expect(rejected);
}

fn bytes(value: u256) affine.Value {
    return field.bytesFromInteger(value);
}
