//! Exact RV32M witnesses from pinned Stark-V `runner/src/ops/muldiv.rs`.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const M31 = m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const mul_semantics = @import("../../air/semantics/mod.zig").mul;
const mulh_semantics = @import("../../air/semantics/mod.zig").mulh;
const div_semantics = @import("../../air/semantics/mod.zig").div;
const Opcode = @import("../decode.zig").Opcode;
const w = @import("writer.zig");

pub fn mul(columns: anytype, index: usize, row: anytype) void {
    w.set(columns, index, 0, M31.one());
    w.common(columns, index, 1, row);
    w.rd(columns, index, 3, row);
    w.rs1(columns, index, 13, row);
    w.rs2(columns, index, 23, row);
    const product: u32 = @truncate(@as(u64, row.rs1_val) *% @as(u64, row.rs2_val));
    w.writeLimbs(columns, index, 33, product);
    w.destination(columns, index, 37, row.rd);
}

fn mulhProduct(lhs: u32, rhs: u32, opcode: Opcode) u64 {
    return switch (opcode) {
        .MULH => @bitCast(
            @as(i64, @as(i32, @bitCast(lhs))) *%
                @as(i64, @as(i32, @bitCast(rhs))),
        ),
        .MULHSU => @bitCast(
            @as(i64, @as(i32, @bitCast(lhs))) * @as(i64, rhs),
        ),
        .MULHU => @as(u64, lhs) * @as(u64, rhs),
        else => unreachable,
    };
}

pub fn mulh(columns: anytype, index: usize, row: anytype) void {
    const product = mulhProduct(row.rs1_val, row.rs2_val, row.opcode);
    const rs1_signed = row.opcode == .MULH or row.opcode == .MULHSU;
    const rs2_signed = row.opcode == .MULH;
    w.common(columns, index, 0, row);
    w.rd(columns, index, 2, row);
    w.rs1(columns, index, 12, row);
    w.rs2(columns, index, 22, row);
    for (w.limbs(@truncate(product)), 0..) |limb, limb_index| {
        w.set(columns, index, 32 + limb_index, limb);
    }
    w.set(columns, index, 36, w.bit(rs1_signed and row.rs1_val >> 31 == 1));
    w.set(columns, index, 37, w.bit(rs2_signed and row.rs2_val >> 31 == 1));
    w.set(columns, index, 38, w.bit(row.opcode == .MULH));
    w.set(columns, index, 39, w.bit(row.opcode == .MULHSU));
    w.set(columns, index, 40, w.bit(row.opcode == .MULHU));
    w.writeLimbs(columns, index, 41, @truncate(product >> 32));
    w.destination(columns, index, 45, row.rd);
}

const DivWitness = struct {
    zero_divisor: bool,
    r_zero: bool,
    quotient: u32,
    remainder: u32,
    b_sign: bool,
    c_sign: bool,
    q_sign: bool,
    sign_xor: bool,
    c_sum_inv: M31,
    r_sum_inv: M31,
    r_abs: [4]u32,
    r_inv: [4]M31,
    lt_markers: [4]u32,
    lt_diff: u32,
};

fn inverseOrZero(value: u32) M31 {
    if (value == 0) return M31.zero();
    return M31.fromCanonical(value).invUncheckedNonZero();
}

fn negateLimbs(limbs: [4]u32) [4]u32 {
    var carry: u32 = 1;
    var result: [4]u32 = undefined;
    for (limbs, 0..) |limb, index| {
        const value = 256 + carry - 1 - limb;
        carry = value >> 8;
        result[index] = value & 0xff;
    }
    return result;
}

fn computeDivWitness(lhs: u32, rhs: u32, signed: bool) DivWitness {
    const b = [_]u32{ lhs & 0xff, (lhs >> 8) & 0xff, (lhs >> 16) & 0xff, lhs >> 24 };
    const c = [_]u32{ rhs & 0xff, (rhs >> 8) & 0xff, (rhs >> 16) & 0xff, rhs >> 24 };
    const b_sign = signed and b[3] & 0x80 != 0;
    const c_sign = signed and c[3] & 0x80 != 0;
    const zero_divisor = rhs == 0;
    const overflow = signed and lhs == 0x8000_0000 and rhs == 0xffff_ffff;

    var quotient: u32 = undefined;
    var remainder: u32 = undefined;
    var q_sign = false;
    if (zero_divisor) {
        quotient = std.math.maxInt(u32);
        remainder = lhs;
        q_sign = signed;
    } else if (overflow) {
        quotient = lhs;
        remainder = 0;
    } else if (signed) {
        const signed_lhs: i32 = @bitCast(lhs);
        const signed_rhs: i32 = @bitCast(rhs);
        quotient = @bitCast(@divTrunc(signed_lhs, signed_rhs));
        remainder = @bitCast(@rem(signed_lhs, signed_rhs));
        q_sign = quotient >> 31 == 1;
    } else {
        quotient = lhs / rhs;
        remainder = lhs % rhs;
    }

    const sign_xor = b_sign != c_sign;
    const r_zero = remainder == 0 and !zero_divisor;
    const r = [_]u32{
        remainder & 0xff,
        (remainder >> 8) & 0xff,
        (remainder >> 16) & 0xff,
        remainder >> 24,
    };
    const r_abs = if (sign_xor) negateLimbs(r) else r;
    var r_inv: [4]M31 = undefined;
    for (&r_inv, r_abs) |*inverse, limb| {
        inverse.* = M31.fromCanonical(m31.Modulus - 256 + limb).invUncheckedNonZero();
    }

    var lt_markers = [_]u32{0} ** 4;
    var lt_diff: u32 = 0;
    if (!zero_divisor and !r_zero and !overflow) {
        var index: usize = 4;
        while (index > 0) {
            index -= 1;
            if (c[index] == r_abs[index]) continue;
            lt_markers[index] = 1;
            lt_diff = if (c_sign)
                r_abs[index] -% c[index]
            else
                c[index] -% r_abs[index];
            break;
        }
    }

    var c_sum: u32 = 0;
    var r_sum: u32 = 0;
    for (c) |limb| c_sum += limb;
    for (r) |limb| r_sum += limb;
    return .{
        .zero_divisor = zero_divisor,
        .r_zero = r_zero,
        .quotient = quotient,
        .remainder = remainder,
        .b_sign = b_sign,
        .c_sign = c_sign,
        .q_sign = q_sign,
        .sign_xor = sign_xor,
        .c_sum_inv = inverseOrZero(c_sum),
        .r_sum_inv = inverseOrZero(r_sum),
        .r_abs = r_abs,
        .r_inv = r_inv,
        .lt_markers = lt_markers,
        .lt_diff = lt_diff,
    };
}

pub fn div(columns: anytype, index: usize, row: anytype) void {
    const signed = row.opcode == .DIV or row.opcode == .REM;
    const witness = computeDivWitness(row.rs1_val, row.rs2_val, signed);
    w.common(columns, index, 0, row);
    w.rd(columns, index, 2, row);
    w.rs1(columns, index, 12, row);
    w.rs2(columns, index, 22, row);
    w.set(columns, index, 32, w.bit(witness.zero_divisor));
    w.set(columns, index, 33, w.bit(witness.r_zero));
    for (w.limbs(witness.quotient), 0..) |limb, limb_index| {
        w.set(columns, index, 34 + limb_index, limb);
    }
    for (w.limbs(witness.remainder), 0..) |limb, limb_index| {
        w.set(columns, index, 38 + limb_index, limb);
    }
    w.set(columns, index, 42, w.bit(witness.b_sign));
    w.set(columns, index, 43, w.bit(witness.c_sign));
    w.set(columns, index, 44, w.bit(witness.q_sign));
    w.set(columns, index, 45, w.bit(witness.sign_xor));
    w.set(columns, index, 46, witness.c_sum_inv);
    w.set(columns, index, 47, witness.r_sum_inv);
    for (witness.r_abs, 0..) |limb, limb_index| {
        w.set(columns, index, 48 + limb_index, w.u(limb));
    }
    for (witness.r_inv, 0..) |inverse, limb_index| {
        w.set(columns, index, 52 + limb_index, inverse);
    }
    for (witness.lt_markers, 0..) |marker, limb_index| {
        w.set(columns, index, 56 + limb_index, w.u(marker));
    }
    w.set(columns, index, 60, w.u(witness.lt_diff));
    w.set(columns, index, 61, w.bit(row.opcode == .DIV));
    w.set(columns, index, 62, w.bit(row.opcode == .DIVU));
    w.set(columns, index, 63, w.bit(row.opcode == .REM));
    w.set(columns, index, 64, w.bit(row.opcode == .REMU));
    w.destination(columns, index, 65, row.rd);
}

const TestRow = struct {
    clk: u32 = 9,
    pc: u32 = 0x1000,
    opcode: Opcode,
    rd: u5 = 3,
    rs1: u5 = 1,
    rs2: u5 = 2,
    rs1_val: u32,
    rs2_val: u32,
    rs1_prev_clk: u32 = 2,
    rs2_prev_clk: u32 = 3,
    rd_prev_val: u32 = 0,
    rd_prev_clk: u32 = 4,
    rd_val: u32,
};

const MAX_COLUMNS: usize = 67;

fn filledColumns(comptime n: usize, comptime writer: anytype, row: TestRow) [n]QM31 {
    var storage: [MAX_COLUMNS][1]M31 = .{.{M31.zero()}} ** MAX_COLUMNS;
    var columns: [MAX_COLUMNS][]M31 = undefined;
    for (&columns, &storage) |*column, *values| column.* = values;
    writer(&columns, 0, row);
    var result: [n]QM31 = undefined;
    for (&result, columns[0..n]) |*value, column| value.* = QM31.fromBase(column[0]);
    return result;
}

fn baseValue(value: QM31) !u32 {
    return (try value.tryIntoM31()).toU32();
}

fn expectRangePair(request: anytype, first_bound: u32, second_bound: u32) !void {
    if (request.numerator.isZero()) return;
    try std.testing.expect(try baseValue(request.tuple.limb_0) < first_bound);
    try std.testing.expect(try baseValue(request.tuple.limb_1) < second_bound);
}

fn expectClockRanges(requests: anytype) !void {
    inline for (.{ requests.rd, requests.rs1, requests.rs2 }) |access| {
        try std.testing.expect(try baseValue(access.clock_gap.tuple.value) < 1 << 20);
    }
}

fn mulResult(lhs: u32, rhs: u32) u32 {
    return lhs *% rhs;
}

fn mulhResult(lhs: u32, rhs: u32, opcode: Opcode) u32 {
    return @truncate(mulhProduct(lhs, rhs, opcode) >> 32);
}

fn divResult(lhs: u32, rhs: u32, opcode: Opcode) u32 {
    const witness = computeDivWitness(lhs, rhs, opcode == .DIV or opcode == .REM);
    return if (opcode == .DIV or opcode == .DIVU) witness.quotient else witness.remainder;
}

test "RV32M production MUL rows are enabler-first and range-valid" {
    const cases = [_][2]u32{
        .{ 0, std.math.maxInt(u32) },
        .{ std.math.maxInt(u32), std.math.maxInt(u32) },
        .{ 0x8000_0000, 2 },
    };
    for (cases) |case| {
        const row = TestRow{
            .opcode = .MUL,
            .rs1_val = case[0],
            .rs2_val = case[1],
            .rd_val = mulResult(case[0], case[1]),
        };
        var columns = filledColumns(mul_semantics.N_ORACLE_COLUMNS, mul, row);
        const semantic_row = try mul_semantics.Row.fromOracleColumns(&columns);
        try std.testing.expect(mul_semantics.evaluate(semantic_row).allZero());
        try std.testing.expect(mul_semantics.placementConstraint(semantic_row, QM31.one()).isZero());
        try std.testing.expect(semantic_row.enabler.eql(QM31.one()));
        try std.testing.expect(semantic_row.clock.eql(QM31.fromBase(w.u(row.clk))));
        const requests = mul_semantics.lookups(semantic_row);
        for (requests.product_ranges) |request| try expectRangePair(request, 256, 1 << 11);
        try expectClockRanges(requests);
    }
}

test "RV32M high-multiply matrix has bounded Sail-compatible carries" {
    const Case = struct { opcode: Opcode, lhs: u32, rhs: u32 };
    const cases = [_]Case{
        .{ .opcode = .MULH, .lhs = 0xffff_ffff, .rhs = 0xffff_ffff },
        .{ .opcode = .MULH, .lhs = 0x8000_0000, .rhs = 2 },
        .{ .opcode = .MULHSU, .lhs = 0x8000_0000, .rhs = 0xffff_ffff },
        .{ .opcode = .MULHU, .lhs = 0xffff_ffff, .rhs = 0xffff_ffff },
    };
    for (cases) |case| {
        const row = TestRow{
            .opcode = case.opcode,
            .rs1_val = case.lhs,
            .rs2_val = case.rhs,
            .rd_val = mulhResult(case.lhs, case.rhs, case.opcode),
        };
        var columns = filledColumns(mulh_semantics.N_ORACLE_COLUMNS, mulh, row);
        const semantic_row = try mulh_semantics.Row.fromOracleColumns(&columns);
        try std.testing.expect(mulh_semantics.evaluate(semantic_row).allZero());
        try std.testing.expect(mulh_semantics.placementConstraint(semantic_row, QM31.one()).isZero());
        const requests = mulh_semantics.lookups(semantic_row);
        for (requests.product_ranges) |request| {
            try std.testing.expect(try baseValue(request.tuple.limb_0) < 256);
            const carry = try baseValue(request.tuple.limb_1);
            try std.testing.expect(carry < 1 << 11);
        }
        for (requests.sign_ranges) |request| {
            if (request.numerator.isZero()) continue;
            try std.testing.expectEqual(@as(u32, 0), try baseValue(request.tuple.limb_0));
            try std.testing.expect(try baseValue(request.tuple.limb_1) < 128);
        }
        try expectClockRanges(requests);
    }
}

test "RV32M production DIV and REM rows cover every architectural edge" {
    const Case = struct { opcode: Opcode, lhs: u32, rhs: u32 };
    const cases = [_]Case{
        .{ .opcode = .DIV, .lhs = 7, .rhs = 3 },
        .{ .opcode = .DIV, .lhs = @bitCast(@as(i32, -7)), .rhs = 3 },
        .{ .opcode = .DIV, .lhs = 7, .rhs = @bitCast(@as(i32, -3)) },
        .{ .opcode = .DIV, .lhs = 0x8000_0000, .rhs = 0xffff_ffff },
        .{ .opcode = .DIV, .lhs = 0x8000_0000, .rhs = 0 },
        .{ .opcode = .DIVU, .lhs = 0xffff_ffff, .rhs = 2 },
        .{ .opcode = .DIVU, .lhs = 7, .rhs = 0 },
        .{ .opcode = .REM, .lhs = @bitCast(@as(i32, -7)), .rhs = 3 },
        .{ .opcode = .REM, .lhs = 0x8000_0000, .rhs = 0xffff_ffff },
        .{ .opcode = .REM, .lhs = 0x8000_0000, .rhs = 0 },
        .{ .opcode = .REMU, .lhs = 0xffff_ffff, .rhs = 256 },
    };
    for (cases) |case| {
        const row = TestRow{
            .opcode = case.opcode,
            .rs1_val = case.lhs,
            .rs2_val = case.rhs,
            .rd_val = divResult(case.lhs, case.rhs, case.opcode),
        };
        var columns = filledColumns(div_semantics.N_ORACLE_COLUMNS, div, row);
        const semantic_row = try div_semantics.Row.fromOracleColumns(&columns);
        try std.testing.expect(div_semantics.evaluate(semantic_row).allZero());
        try std.testing.expect(div_semantics.placementConstraint(semantic_row, QM31.one()).isZero());
        const requests = div_semantics.lookups(semantic_row);
        for (requests.quotient_remainder_ranges) |request| {
            try expectRangePair(request, 256, 1 << 11);
        }
        try expectRangePair(requests.sign_range, 256, 256);
        if (!requests.positive_remainder_diff.numerator.isZero()) {
            try std.testing.expect(try baseValue(requests.positive_remainder_diff.tuple.value) < 1 << 20);
        }
        try expectClockRanges(requests);
    }
}
