//! RV32M `MULH`, `MULHSU`, and `MULHU` semantics.
//!
//! This follows Sail's `mult_to_bits_half` semantics. The witness carries both
//! halves of the 64-bit product. Eight `range_check_8_11` requests enforce the
//! byte-wise carry chain, while two `range_check_m31` requests bind each signed
//! operand's sign witness to bit 31.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const common = @import("common.zig");
const control = @import("control_common.zig");
const Opcode = @import("../program/opcode.zig").Opcode;

pub const N_ORACLE_COLUMNS: usize = 47;
pub const N_CONSTRAINTS: usize = 15;
pub const LOOKUP_BATCH_SIZE: usize = 1;
pub const BITWISE_LOOKUP_COUNT: usize = 0;
pub const CURRENT_TRACE_COMPATIBLE = true;
pub const MISSING_CURRENT_WITNESS_COLUMNS = [_][]const u8{};

pub const Row = struct {
    clock: QM31,
    pc: QM31,
    rd: common.Access,
    rs1: common.Access,
    rs2: common.Access,
    rd_high: [4]QM31,
    rs1_sign: QM31,
    rs2_sign: QM31,
    is_mulh: QM31,
    is_mulhsu: QM31,
    is_mulhu: QM31,
    result: [4]QM31,
    destination: common.Destination,

    pub fn fromOracleColumns(columns: []const QM31) !Row {
        if (columns.len != N_ORACLE_COLUMNS) return error.InvalidOracleTraceShape;
        return .{
            .clock = columns[0],
            .pc = columns[1],
            .rd = common.accessFromColumns(columns[2..12]),
            .rs1 = common.accessFromColumns(columns[12..22]),
            .rs2 = common.accessFromColumns(columns[22..32]),
            .rd_high = columns[32..36].*,
            .rs1_sign = columns[36],
            .rs2_sign = columns[37],
            .is_mulh = columns[38],
            .is_mulhsu = columns[39],
            .is_mulhu = columns[40],
            .result = columns[41..45].*,
            .destination = common.destinationFromColumns(columns[45..47]),
        };
    }

    pub fn active(self: Row) QM31 {
        return self.is_mulh.add(self.is_mulhsu).add(self.is_mulhu);
    }
};

pub const Derived = struct {
    carries: [8]QM31,
};

pub fn derive(row: Row) Derived {
    @setEvalBranchQuota(100_000);
    const a_fill = row.rs1_sign.mul(common.q(255));
    const b_fill = row.rs2_sign.mul(common.q(255));
    var a: [8]QM31 = undefined;
    var b: [8]QM31 = undefined;
    var product: [8]QM31 = undefined;
    @memcpy(a[0..4], &row.rs1.next);
    @memcpy(b[0..4], &row.rs2.next);
    @memcpy(product[0..4], &row.rd_high);
    @memcpy(product[4..8], &row.result);
    for (4..8) |limb| {
        a[limb] = a_fill;
        b[limb] = b_fill;
    }

    var carry: [8]QM31 = undefined;
    var previous = QM31.zero();
    for (0..8) |output_limb| {
        var numerator = previous;
        for (0..output_limb + 1) |lhs_limb| {
            numerator = numerator.add(a[lhs_limb].mul(b[output_limb - lhs_limb]));
        }
        carry[output_limb] = numerator.sub(product[output_limb])
            .mul(common.INV_BYTE_RADIX);
        previous = carry[output_limb];
    }
    return .{ .carries = carry };
}

pub const Constraints = common.ConstraintSet(N_CONSTRAINTS);

fn booleanConstraint(value: QM31) QM31 {
    return value.mul(QM31.one().sub(value));
}

pub fn evaluate(row: Row) Constraints {
    const active = row.active();
    var out: [N_CONSTRAINTS]QM31 = undefined;
    out[0..8].* = .{
        booleanConstraint(active),
        booleanConstraint(row.is_mulh),
        booleanConstraint(row.is_mulhsu),
        booleanConstraint(row.is_mulhu),
        booleanConstraint(row.rs1_sign),
        booleanConstraint(row.rs2_sign),
        QM31.one().sub(row.is_mulh).sub(row.is_mulhsu).mul(row.rs1_sign),
        QM31.one().sub(row.is_mulh).mul(row.rs2_sign),
    };
    @memcpy(out[8..11], &common.destinationConstraints(row.rd.addr, row.destination));
    @memcpy(
        out[11..15],
        &common.destinationResultConstraints(row.rd, row.result, row.destination),
    );
    return .{ .values = out };
}

pub fn placementConstraint(row: Row, is_active: QM31) QM31 {
    return row.active().sub(is_active);
}

pub fn programLookup(row: Row) common.ProgramTuple {
    const opcode_id = row.is_mulh.mul(common.q(Opcode.mulh.protocolId()))
        .add(row.is_mulhsu.mul(common.q(Opcode.mulhsu.protocolId())))
        .add(row.is_mulhu.mul(common.q(Opcode.mulhu.protocolId())));
    return .{
        .pc = row.pc,
        .opcode_id = opcode_id,
        .rd = row.rd.addr,
        .rs1 = row.rs1.addr,
        .operand = row.rs2.addr,
    };
}

pub const Lookups = struct {
    /// Fields retain the exact `schema.rs` declaration order.
    program: control.Request(common.ProgramTuple),
    state: control.StateLookups,
    rs1: control.RegisterAccessLookups,
    rs2: control.RegisterAccessLookups,
    product_ranges: [8]control.Request(control.RangePairTuple),
    sign_ranges: [2]control.Request(control.RangePairTuple),
    rd: control.RegisterAccessLookups,
};

pub fn lookups(row: Row) Lookups {
    const active = row.active();
    const carries = derive(row).carries;
    var ranges: [8]control.Request(control.RangePairTuple) = undefined;
    for (&ranges, 0..) |*request, limb| {
        const result_limb = if (limb < 4) row.rd_high[limb] else row.result[limb - 4];
        request.* = control.rangePairRequest(active, result_limb, carries[limb]);
    }
    const signed_rs1 = row.is_mulh.add(row.is_mulhsu);
    const signed_rs2 = row.is_mulh;
    return .{
        .program = control.programRequest(active, programLookup(row)),
        .state = control.stateLookups(row.pc, row.clock, row.pc.add(common.q(4)), active),
        .rs1 = control.registerAccessLookups(row.rs1, row.clock, active),
        .rs2 = control.registerAccessLookups(row.rs2, row.clock, active),
        .product_ranges = ranges,
        // `range_check_m31` accepts `(lo8, hi7)`. Keeping `lo8 = 0`
        // proves `top_byte - 128 * sign` is a seven-bit value, which is
        // equivalent to `sign == bit31` for an already byte-ranged operand.
        .sign_ranges = .{
            control.rangePairRequest(
                signed_rs1,
                QM31.zero(),
                row.rs1.next[3].sub(row.rs1_sign.mul(common.q(128))),
            ),
            control.rangePairRequest(
                signed_rs2,
                QM31.zero(),
                row.rs2.next[3].sub(row.rs2_sign.mul(common.q(128))),
            ),
        },
        .rd = control.registerAccessLookups(row.rd, row.clock, active),
    };
}

fn zeroAccess() common.Access {
    return .{
        .addr = QM31.zero(),
        .previous = .{QM31.zero()} ** 4,
        .previous_clock = QM31.zero(),
        .next = .{QM31.zero()} ** 4,
    };
}

fn honestUnsignedMaxRow() Row {
    var rd = zeroAccess();
    rd.addr = common.q(3);
    rd.next = .{ common.q(254), common.q(255), common.q(255), common.q(255) };
    var rs1 = zeroAccess();
    rs1.addr = common.q(1);
    rs1.next = .{common.q(255)} ** 4;
    var rs2 = zeroAccess();
    rs2.addr = common.q(2);
    rs2.next = .{common.q(255)} ** 4;
    return .{
        .clock = common.q(9),
        .pc = common.q(0x1000),
        .rd = rd,
        .rs1 = rs1,
        .rs2 = rs2,
        .rd_high = .{ QM31.one(), QM31.zero(), QM31.zero(), QM31.zero() },
        .rs1_sign = QM31.zero(),
        .rs2_sign = QM31.zero(),
        .is_mulh = QM31.zero(),
        .is_mulhsu = QM31.zero(),
        .is_mulhu = QM31.one(),
        .result = rd.next,
        .destination = .{
            .nonzero = QM31.one(),
            .inverse = common.q(3).inv() catch unreachable,
        },
    };
}

test "mulh: unsigned maximal product has eight bounded carry requests" {
    const row = honestUnsignedMaxRow();
    try std.testing.expect(evaluate(row).allZero());
    const requests = lookups(row);
    try std.testing.expect(requests.program.tuple.opcode_id.eql(common.q(40)));
    for (requests.product_ranges) |request| {
        const limb = try request.tuple.limb_0.tryIntoM31();
        const carry = try request.tuple.limb_1.tryIntoM31();
        try std.testing.expect(limb.toU32() < 256);
        try std.testing.expect(carry.toU32() < 2048);
    }
}

test "mulh: unsigned opcode rejects a forged signed witness" {
    var row = honestUnsignedMaxRow();
    row.rs1_sign = QM31.one();
    try std.testing.expect(!evaluate(row).allZero());
}

test "mulh: signed operand sign is bound to bit 31" {
    var row = honestUnsignedMaxRow();
    row.is_mulhu = QM31.zero();
    row.is_mulh = QM31.one();
    row.rs1_sign = QM31.one();
    row.rs2_sign = QM31.one();
    try std.testing.expect(evaluate(row).allZero());

    const honest = lookups(row);
    try std.testing.expect(
        honest.sign_ranges[0].tuple.limb_1.eql(common.q(127)),
    );
    try std.testing.expect(
        honest.sign_ranges[1].tuple.limb_1.eql(common.q(127)),
    );

    row.rs1_sign = QM31.zero();
    const forged = lookups(row);
    const forged_top = try forged.sign_ranges[0].tuple.limb_1.tryIntoM31();
    try std.testing.expect(forged_top.toU32() >= 128);
}

test "mulh: forged high product escapes constraints but fails range table" {
    var row = honestUnsignedMaxRow();
    row.rd.next[0] = common.q(255);
    row.result[0] = common.q(255);
    try std.testing.expect(evaluate(row).allZero());
    const forged_carry = try derive(row).carries[4].tryIntoM31();
    try std.testing.expect(forged_carry.toU32() >= 2048);
}

test "mulh: adapter follows access then witness then flag order" {
    var columns = [_]QM31{QM31.zero()} ** N_ORACLE_COLUMNS;
    columns[2] = common.q(1);
    columns[12] = common.q(2);
    columns[22] = common.q(3);
    columns[32] = common.q(4);
    columns[36] = common.q(5);
    columns[40] = common.q(6);
    const row = try Row.fromOracleColumns(&columns);
    try std.testing.expect(row.rd.addr.eql(common.q(1)));
    try std.testing.expect(row.rs1.addr.eql(common.q(2)));
    try std.testing.expect(row.rs2.addr.eql(common.q(3)));
    try std.testing.expect(row.rd_high[0].eql(common.q(4)));
    try std.testing.expect(row.rs1_sign.eql(common.q(5)));
    try std.testing.expect(row.is_mulhu.eql(common.q(6)));
}
