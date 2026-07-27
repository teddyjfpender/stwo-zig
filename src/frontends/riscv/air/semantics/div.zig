//! Stark-V-derived `DIV`, `DIVU`, `REM`, and `REMU` semantics, tightened with
//! local divisor-byte and quotient-sign bindings.
//!
//! The 67-column oracle witness proves `rs1 = rs2 * q + r` over eight
//! sign-extended limbs, handles RISC-V's zero-divisor and signed-overflow
//! rules, and proves the regular-case remainder bound with a high-to-low scan.
//! Oracle: pinned `crates/air/src/schema.rs` and `runner/src/ops/muldiv.rs`.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const M31 = m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const common = @import("common.zig");
const control = @import("control_common.zig");
const Opcode = @import("../program/opcode.zig").Opcode;

pub const N_ORACLE_COLUMNS: usize = 67;
pub const N_CONSTRAINTS: usize = 78;
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
    zero_divisor: QM31,
    r_zero: QM31,
    q: [4]QM31,
    r: [4]QM31,
    b_sign: QM31,
    c_sign: QM31,
    q_sign: QM31,
    sign_xor: QM31,
    c_sum_inv: QM31,
    r_sum_inv: QM31,
    r_abs: [4]QM31,
    r_inv: [4]QM31,
    lt_markers: [4]QM31,
    lt_diff: QM31,
    is_div: QM31,
    is_divu: QM31,
    is_rem: QM31,
    is_remu: QM31,
    destination: common.Destination,

    pub fn fromOracleColumns(columns: []const QM31) !Row {
        if (columns.len != N_ORACLE_COLUMNS) return error.InvalidOracleTraceShape;
        return .{
            .clock = columns[0],
            .pc = columns[1],
            .rd = common.accessFromColumns(columns[2..12]),
            .rs1 = common.accessFromColumns(columns[12..22]),
            .rs2 = common.accessFromColumns(columns[22..32]),
            .zero_divisor = columns[32],
            .r_zero = columns[33],
            .q = columns[34..38].*,
            .r = columns[38..42].*,
            .b_sign = columns[42],
            .c_sign = columns[43],
            .q_sign = columns[44],
            .sign_xor = columns[45],
            .c_sum_inv = columns[46],
            .r_sum_inv = columns[47],
            .r_abs = columns[48..52].*,
            .r_inv = columns[52..56].*,
            .lt_markers = columns[56..60].*,
            .lt_diff = columns[60],
            .is_div = columns[61],
            .is_divu = columns[62],
            .is_rem = columns[63],
            .is_remu = columns[64],
            .destination = common.destinationFromColumns(columns[65..67]),
        };
    }

    pub fn active(self: Row) QM31 {
        return self.is_div.add(self.is_divu).add(self.is_rem).add(self.is_remu);
    }
};

pub const Derived = struct {
    active: QM31,
    is_division: QM31,
    is_signed: QM31,
    special_case: QM31,
    valid_not_zero_divisor: QM31,
    valid_not_special: QM31,
    q_sum: QM31,
    c_sum: QM31,
    r_sum: QM31,
    diffs: [4]QM31,
    result: [4]QM31,
    negation_carries: [4]QM31,
    prefixes: [4]QM31,
    product_carries: [8]QM31,
    sign_checks: [2]QM31,
};

fn sumLimbs(limbs: [4]QM31) QM31 {
    return limbs[0].add(limbs[1]).add(limbs[2]).add(limbs[3]);
}

pub fn derive(row: Row) Derived {
    @setEvalBranchQuota(100_000);
    const active = row.active();
    const is_division = row.is_div.add(row.is_divu);
    const is_signed = row.is_div.add(row.is_rem);
    const special_case = row.zero_divisor.add(row.r_zero);
    const q_sum = sumLimbs(row.q);
    const c_sum = sumLimbs(row.rs2.next);
    const r_sum = sumLimbs(row.r);
    const sign_factor = QM31.one().sub(row.c_sign.mul(common.q(2)));

    var diffs: [4]QM31 = undefined;
    var result: [4]QM31 = undefined;
    var negation_carries: [4]QM31 = undefined;
    for (0..4) |limb| {
        diffs[limb] = sign_factor.mul(row.rs2.next[limb].sub(row.r_abs[limb]));
        result[limb] = is_division.mul(row.q[limb])
            .add(QM31.one().sub(is_division).mul(row.r[limb]));
        const previous = if (limb == 0) QM31.zero() else negation_carries[limb - 1];
        negation_carries[limb] = previous.add(row.r[limb]).add(row.r_abs[limb])
            .mul(common.INV_BYTE_RADIX);
    }

    var prefixes: [4]QM31 = undefined;
    var prefix = special_case;
    var limb: usize = 4;
    while (limb > 0) {
        limb -= 1;
        prefix = prefix.add(row.lt_markers[limb]);
        prefixes[limb] = prefix;
    }

    const c_hi = row.c_sign.mul(common.q(255));
    const q_hi = row.q_sign.mul(common.q(255));
    const b_hi = row.b_sign.mul(common.q(255));
    const r_hi = row.b_sign.mul(QM31.one().sub(row.r_zero)).mul(common.q(255));
    const b = row.rs1.next;
    const c = row.rs2.next;
    const q = row.q;
    const r = row.r;
    var carry: [8]QM31 = undefined;
    carry[0] = c[0].mul(q[0]).add(r[0]).sub(b[0]).mul(common.INV_BYTE_RADIX);
    carry[1] = carry[0].add(c[0].mul(q[1])).add(c[1].mul(q[0]))
        .add(r[1]).sub(b[1]).mul(common.INV_BYTE_RADIX);
    carry[2] = carry[1].add(c[0].mul(q[2])).add(c[1].mul(q[1]))
        .add(c[2].mul(q[0])).add(r[2]).sub(b[2]).mul(common.INV_BYTE_RADIX);
    carry[3] = carry[2].add(c[0].mul(q[3])).add(c[1].mul(q[2]))
        .add(c[2].mul(q[1])).add(c[3].mul(q[0])).add(r[3])
        .sub(b[3]).mul(common.INV_BYTE_RADIX);
    carry[4] = carry[3].add(c[0].mul(q_hi)).add(c[1].mul(q[3]))
        .add(c[2].mul(q[2])).add(c[3].mul(q[1])).add(c_hi.mul(q[0]))
        .add(r_hi).sub(b_hi).mul(common.INV_BYTE_RADIX);
    carry[5] = carry[4].add(c[0].add(c[1]).mul(q_hi)).add(c[2].mul(q[3]))
        .add(c[3].mul(q[2])).add(c_hi.mul(q[0].add(q[1])))
        .add(r_hi).sub(b_hi).mul(common.INV_BYTE_RADIX);
    carry[6] = carry[5].add(c_sum.sub(c[3]).mul(q_hi)).add(c[3].mul(q[3]))
        .add(c_hi.mul(q_sum.sub(q[3]))).add(r_hi).sub(b_hi)
        .mul(common.INV_BYTE_RADIX);
    carry[7] = carry[6].add(c_sum.mul(q_hi)).add(c_hi.mul(q_sum))
        .add(r_hi).sub(b_hi).mul(common.INV_BYTE_RADIX);

    return .{
        .active = active,
        .is_division = is_division,
        .is_signed = is_signed,
        .special_case = special_case,
        .valid_not_zero_divisor = active.sub(row.zero_divisor),
        .valid_not_special = active.sub(special_case),
        .q_sum = q_sum,
        .c_sum = c_sum,
        .r_sum = r_sum,
        .diffs = diffs,
        .result = result,
        .negation_carries = negation_carries,
        .prefixes = prefixes,
        .product_carries = carry,
        .sign_checks = .{
            is_signed.mul(row.rs1.next[3].sub(row.b_sign.mul(common.q(128))))
                .mul(common.q(2)),
            is_signed.mul(row.rs2.next[3].sub(row.c_sign.mul(common.q(128))))
                .mul(common.q(2)),
        },
    };
}

pub const Constraints = common.ConstraintSet(N_CONSTRAINTS);

fn booleanConstraint(value: QM31) QM31 {
    return value.mul(QM31.one().sub(value));
}

pub fn evaluate(row: Row) Constraints {
    @setEvalBranchQuota(100_000);
    var out: [N_CONSTRAINTS]QM31 = undefined;
    var n: usize = 0;
    const d = derive(row);

    out[n] = booleanConstraint(d.active);
    n += 1;
    for ([_]QM31{ row.is_div, row.is_divu, row.is_rem, row.is_remu }) |flag| {
        out[n] = booleanConstraint(flag);
        n += 1;
    }
    for ([_]QM31{
        row.zero_divisor,
        row.r_zero,
        row.b_sign,
        row.c_sign,
        row.q_sign,
        row.sign_xor,
    }) |value| {
        out[n] = booleanConstraint(value);
        n += 1;
    }
    for (row.lt_markers) |marker| {
        out[n] = booleanConstraint(marker);
        n += 1;
    }
    for ([_]QM31{ d.special_case, d.valid_not_zero_divisor, d.valid_not_special }) |value| {
        out[n] = booleanConstraint(value);
        n += 1;
    }

    for (row.rs2.next) |limb| {
        out[n] = row.zero_divisor.mul(limb);
        n += 1;
    }
    for (row.q) |limb| {
        out[n] = row.zero_divisor.mul(limb.sub(common.q(255)));
        n += 1;
    }
    out[n] = d.valid_not_zero_divisor.mul(d.c_sum.mul(row.c_sum_inv).sub(QM31.one()));
    n += 1;
    for (row.r) |limb| {
        out[n] = row.r_zero.mul(limb);
        n += 1;
    }
    out[n] = d.valid_not_special.mul(d.r_sum.mul(row.r_sum_inv).sub(QM31.one()));
    n += 1;

    out[n] = QM31.one().sub(d.is_signed).mul(row.b_sign);
    n += 1;
    out[n] = QM31.one().sub(d.is_signed).mul(row.c_sign);
    n += 1;
    out[n] = d.active.mul(row.sign_xor.sub(row.b_sign).sub(row.c_sign)
        .add(row.b_sign.mul(row.c_sign).mul(common.q(2))));
    n += 1;
    out[n] = QM31.one().sub(row.zero_divisor).mul(d.q_sum)
        .mul(row.q_sign.sub(row.sign_xor));
    n += 1;
    out[n] = QM31.one().sub(row.zero_divisor).mul(row.q_sign.sub(row.sign_xor))
        .mul(row.q_sign);
    n += 1;
    // The runner defines the zero-divisor quotient as all ones. Pin its sign
    // witness explicitly instead of relying on the product carry chain.
    out[n] = row.zero_divisor.mul(row.q_sign.sub(d.is_signed));
    n += 1;

    for (0..4) |limb| {
        const previous = if (limb == 0) QM31.zero() else d.negation_carries[limb - 1];
        const carry = d.negation_carries[limb];
        out[n] = QM31.one().sub(row.sign_xor).mul(row.r_abs[limb].sub(row.r[limb]));
        n += 1;
        out[n] = if (limb == 0)
            row.sign_xor.mul(carry).mul(carry.sub(QM31.one()))
        else
            row.sign_xor.mul(carry.sub(previous)).mul(carry.sub(QM31.one()));
        n += 1;
        out[n] = row.sign_xor.mul(QM31.one().sub(carry)).mul(row.r_abs[limb]);
        n += 1;
        out[n] = row.sign_xor.mul(
            row.r_abs[limb].sub(common.q(256)).mul(row.r_inv[limb]).sub(QM31.one()),
        );
        n += 1;
    }

    var scan_limb: usize = 4;
    while (scan_limb > 0) {
        scan_limb -= 1;
        out[n] = QM31.one().sub(d.prefixes[scan_limb]).mul(d.diffs[scan_limb]);
        n += 1;
        out[n] = row.lt_markers[scan_limb].mul(row.lt_diff.sub(d.diffs[scan_limb]));
        n += 1;
    }
    out[n] = d.active.mul(QM31.one().sub(d.prefixes[0]));
    n += 1;
    for (common.destinationConstraints(row.rd.addr, row.destination)) |constraint| {
        out[n] = constraint;
        n += 1;
    }
    for (common.destinationResultConstraints(row.rd, d.result, row.destination)) |constraint| {
        out[n] = constraint;
        n += 1;
    }
    // Source registers are read-only: the emitted `next` limbs must equal the
    // consumed `previous` limbs, otherwise the operand is a free prover choice
    // that is also written back onto the register bus.
    for (common.readOnlyAccessConstraints(row.rs1, d.active)) |constraint| {
        out[n] = constraint;
        n += 1;
    }
    for (common.readOnlyAccessConstraints(row.rs2, d.active)) |constraint| {
        out[n] = constraint;
        n += 1;
    }
    std.debug.assert(n == out.len);
    return .{ .values = out };
}

pub fn placementConstraint(row: Row, is_active: QM31) QM31 {
    return row.active().sub(is_active);
}

pub fn programLookup(row: Row) common.ProgramTuple {
    const opcode_id = row.is_div.mul(common.q(Opcode.div.protocolId()))
        .add(row.is_divu.mul(common.q(Opcode.divu.protocolId())))
        .add(row.is_rem.mul(common.q(Opcode.rem.protocolId())))
        .add(row.is_remu.mul(common.q(Opcode.remu.protocolId())));
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
    divisor_ranges: [2]control.Request(control.RangePairTuple),
    quotient_remainder_ranges: [8]control.Request(control.RangePairTuple),
    quotient_sign_range: control.Request(control.RangePairTuple),
    sign_range: control.Request(control.RangePairTuple),
    positive_remainder_diff: control.Request(control.Range20Tuple),
    rd: control.RegisterAccessLookups,
};

pub fn lookups(row: Row) Lookups {
    const d = derive(row);
    var ranges: [8]control.Request(control.RangePairTuple) = undefined;
    for (&ranges, 0..) |*request, limb| {
        const value = if (limb < 4) row.q[limb] else row.r[limb - 4];
        request.* = control.rangePairRequest(d.active, value, d.product_carries[limb]);
    }
    return .{
        .program = control.programRequest(d.active, programLookup(row)),
        .state = control.stateLookups(row.pc, row.clock, row.pc.add(common.q(4)), d.active),
        .rs1 = control.registerAccessLookups(row.rs1, row.clock, d.active),
        .rs2 = control.registerAccessLookups(row.rs2, row.clock, d.active),
        .divisor_ranges = .{
            control.rangePairRequest(d.active, row.rs2.next[0], row.rs2.next[1]),
            control.rangePairRequest(d.active, row.rs2.next[2], row.rs2.next[3]),
        },
        .quotient_remainder_ranges = ranges,
        // q[3] is byte-ranged above. Requiring q[3] - 128*q_sign to fit seven
        // bits binds the ambiguous q == 0, sign_xor == 1 case. Both-negative
        // division is excluded because signed overflow intentionally represents
        // 0x80000000 with the algebraic extension q_sign = sign_xor = 0; for
        // that whole class the existing direct equations already force zero.
        .quotient_sign_range = control.rangePairRequest(
            d.valid_not_zero_divisor.sub(row.b_sign.mul(row.c_sign)),
            QM31.zero(),
            row.q[3].sub(row.q_sign.mul(common.q(128))),
        ),
        .sign_range = control.rangePairRequest(d.active, d.sign_checks[0], d.sign_checks[1]),
        .positive_remainder_diff = .{
            .numerator = d.valid_not_special.neg(),
            .tuple = .{ .value = row.lt_diff.sub(QM31.one()) },
        },
        .rd = control.registerAccessLookups(row.rd, row.clock, d.active),
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

fn baseRow() Row {
    return .{
        .clock = common.q(9),
        .pc = common.q(0x1000),
        .rd = zeroAccess(),
        .rs1 = zeroAccess(),
        .rs2 = zeroAccess(),
        .zero_divisor = QM31.zero(),
        .r_zero = QM31.zero(),
        .q = .{QM31.zero()} ** 4,
        .r = .{QM31.zero()} ** 4,
        .b_sign = QM31.zero(),
        .c_sign = QM31.zero(),
        .q_sign = QM31.zero(),
        .sign_xor = QM31.zero(),
        .c_sum_inv = QM31.zero(),
        .r_sum_inv = QM31.zero(),
        .r_abs = .{QM31.zero()} ** 4,
        .r_inv = .{QM31.zero()} ** 4,
        .lt_markers = .{QM31.zero()} ** 4,
        .lt_diff = QM31.zero(),
        .is_div = QM31.zero(),
        .is_divu = QM31.zero(),
        .is_rem = QM31.zero(),
        .is_remu = QM31.zero(),
        .destination = .{ .nonzero = QM31.zero(), .inverse = QM31.zero() },
    };
}

fn inverse(value: u32) QM31 {
    return QM31.fromBase(M31.fromCanonical(value).invUncheckedNonZero());
}

fn honestUnsignedRow() Row {
    var row = baseRow();
    row.is_divu = QM31.one();
    row.rd.addr = common.q(3);
    row.destination = .{
        .nonzero = QM31.one(),
        .inverse = inverse(3),
    };
    row.rd.next[0] = common.q(2);
    row.rs1.addr = common.q(1);
    row.rs1.next[0] = common.q(7);
    row.rs1.previous = row.rs1.next;
    row.rs2.addr = common.q(2);
    row.rs2.next[0] = common.q(3);
    row.rs2.previous = row.rs2.next;
    row.q[0] = common.q(2);
    row.r[0] = QM31.one();
    row.r_abs[0] = QM31.one();
    row.c_sum_inv = inverse(3);
    row.r_sum_inv = QM31.one();
    row.r_inv[0] = inverse(m31.Modulus - 255);
    for (1..4) |limb| row.r_inv[limb] = inverse(m31.Modulus - 256);
    row.lt_markers[0] = QM31.one();
    row.lt_diff = common.q(2);
    return row;
}

test "div: regular unsigned row satisfies exact constraints and requests" {
    const row = honestUnsignedRow();
    try std.testing.expect(evaluate(row).allZero());
    const requests = lookups(row);
    try std.testing.expect(requests.program.tuple.opcode_id.eql(common.q(42)));
    try std.testing.expect(requests.positive_remainder_diff.tuple.value.eql(QM31.one()));
    try std.testing.expect(requests.rd.emit.tuple.limbs[0].eql(common.q(2)));
    for (requests.quotient_remainder_ranges) |request| {
        const value = try request.tuple.limb_0.tryIntoM31();
        const carry = try request.tuple.limb_1.tryIntoM31();
        try std.testing.expect(value.toU32() < 256);
        try std.testing.expect(carry.toU32() < 2048);
    }
}

// The `[0, 0, 0, 256]` DIVU divisor forgery is covered end to end by
// `tests/riscv/divisor_byte_range_soundness_test.zig`: the committed row reaches a
// real proof and loses the global LogUp closure, because the two `divisor_ranges`
// requests above have no row in `range_check_8_8` to cancel against.

test "div: quotient sign range binds the zero quotient" {
    const table = @import("../lookups/tables/schema.zig");
    var row = baseRow();
    row.is_div = QM31.one();

    var request = lookups(row).quotient_sign_range;
    var tuple = request.tuple.values();
    _ = try table.indexSecure(.range_check_m31, &tuple);

    row.q_sign = QM31.one();
    request = lookups(row).quotient_sign_range;
    tuple = request.tuple.values();
    try std.testing.expectError(
        error.ValueOutOfRange,
        table.indexSecure(.range_check_m31, &tuple),
    );
}

test "div: forged quotient fails the carry range oracle" {
    var row = honestUnsignedRow();
    row.q[0] = common.q(3);
    row.rd.next[0] = common.q(3);
    try std.testing.expect(evaluate(row).allZero());
    const forged_carry = try derive(row).product_carries[0].tryIntoM31();
    try std.testing.expect(forged_carry.toU32() >= 2048);
}

test "div: REMU emits the remainder rather than the quotient" {
    var row = honestUnsignedRow();
    row.is_divu = QM31.zero();
    row.is_remu = QM31.one();
    row.rd.next[0] = QM31.one();
    try std.testing.expect(evaluate(row).allZero());
    const requests = lookups(row);
    try std.testing.expect(requests.program.tuple.opcode_id.eql(common.q(44)));
    try std.testing.expect(requests.rd.emit.tuple.limbs[0].eql(QM31.one()));
}

test "div: zero divisor requires all-one quotient" {
    var row = baseRow();
    row.is_divu = QM31.one();
    row.rd.addr = QM31.one();
    row.destination = .{ .nonzero = QM31.one(), .inverse = QM31.one() };
    row.zero_divisor = QM31.one();
    row.rs1.next[0] = common.q(7);
    row.rs1.previous = row.rs1.next;
    row.q = .{common.q(255)} ** 4;
    row.r[0] = common.q(7);
    row.r_abs[0] = common.q(7);
    row.rd.next = row.q;
    try std.testing.expect(evaluate(row).allZero());

    row.q_sign = QM31.one();
    try std.testing.expect(!evaluate(row).allZero());
    row.q_sign = QM31.zero();

    row.q[3] = common.q(254);
    try std.testing.expect(!evaluate(row).allZero());
}

test "div: signed negative quotient and remainder satisfy sign extension" {
    var row = baseRow();
    row.is_div = QM31.one();
    row.rd.addr = QM31.one();
    row.destination = .{ .nonzero = QM31.one(), .inverse = QM31.one() };
    row.rd.next = .{ common.q(254), common.q(255), common.q(255), common.q(255) };
    row.rs1.next = .{ common.q(249), common.q(255), common.q(255), common.q(255) };
    row.rs1.previous = row.rs1.next;
    row.rs2.next[0] = common.q(3);
    row.rs2.previous = row.rs2.next;
    row.q = row.rd.next;
    row.r = .{common.q(255)} ** 4;
    row.b_sign = QM31.one();
    row.q_sign = QM31.one();
    row.sign_xor = QM31.one();
    row.c_sum_inv = inverse(3);
    row.r_sum_inv = inverse(4 * 255);
    row.r_abs[0] = QM31.one();
    row.r_inv[0] = inverse(m31.Modulus - 255);
    for (1..4) |limb| row.r_inv[limb] = inverse(m31.Modulus - 256);
    row.lt_markers[0] = QM31.one();
    row.lt_diff = common.q(2);
    try std.testing.expect(evaluate(row).allZero());
    for (lookups(row).quotient_remainder_ranges) |request| {
        const carry = try request.tuple.limb_1.tryIntoM31();
        try std.testing.expect(carry.toU32() < 2048);
    }
}

test "div: source register write-back forgery is rejected" {
    var forged_rs1 = honestUnsignedRow();
    forged_rs1.rs1.previous[0] = common.q(200);
    try std.testing.expect(!evaluate(forged_rs1).allZero());

    var forged_rs2 = honestUnsignedRow();
    forged_rs2.rs2.previous[0] = common.q(200);
    try std.testing.expect(!evaluate(forged_rs2).allZero());
}

test "div: adapter preserves the 67-column oracle order" {
    var columns = [_]QM31{QM31.zero()} ** N_ORACLE_COLUMNS;
    columns[2] = common.q(1);
    columns[12] = common.q(2);
    columns[22] = common.q(3);
    columns[32] = common.q(4);
    columns[34] = common.q(5);
    columns[60] = common.q(6);
    columns[64] = common.q(7);
    const row = try Row.fromOracleColumns(&columns);
    try std.testing.expect(row.rd.addr.eql(common.q(1)));
    try std.testing.expect(row.rs1.addr.eql(common.q(2)));
    try std.testing.expect(row.rs2.addr.eql(common.q(3)));
    try std.testing.expect(row.zero_divisor.eql(common.q(4)));
    try std.testing.expect(row.q[0].eql(common.q(5)));
    try std.testing.expect(row.lt_diff.eql(common.q(6)));
    try std.testing.expect(row.is_remu.eql(common.q(7)));
}
