//! Sail-authoritative AIR semantics and lookup requests for JALR.
//!
//! This is an intentional soundness divergence from the pinned Stark-V layout.
//! Its original 32 columns remain an exact prefix; nine soundness columns are
//! appended. The source access is read-only and all four source limbs are
//! bytes. The target is committed both as four bytes and as the program AIR's
//! bounded `target / 4 = low20 + 2^20 * high8` split. A byte-carry recurrence
//! adds the sign-extended I-immediate to rs1 modulo 2^32 and proves that the
//! result is exactly `target + bit0`. Consequently bit 0 is not prover-chosen,
//! successful rows are 4-aligned and program-commitment-bounded locally, and
//! wraparound does not rely on an M31 field alias.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const common = @import("common.zig");
const control = @import("control_common.zig");
const Opcode = @import("../program/opcode.zig").Opcode;

pub const N_MAIN_COLUMNS: usize = 41;
pub const N_CONSTRAINTS: usize = 22;

pub const Row = struct {
    enabler: QM31,
    clock: QM31,
    pc: QM31,
    rd: common.Access,
    rs1: common.Access,
    to_pc_over_two: QM31,
    to_pc_lsb: QM31,
    imm_felt: QM31,
    result: [4]QM31,
    destination: common.Destination,
    target_word_low_20: QM31,
    target_word_high_8: QM31,
    target_limbs: [4]QM31,
    imm_byte_0: QM31,
    imm_nibble: QM31,
    imm_sign: QM31,

    pub fn fromMainColumns(columns: []const QM31) !Row {
        if (columns.len != N_MAIN_COLUMNS) return error.InvalidMainTraceShape;
        return .{
            .enabler = columns[0],
            .clock = columns[1],
            .pc = columns[2],
            .rd = control.accessFromColumns(columns, 3),
            .rs1 = control.accessFromColumns(columns, 13),
            .to_pc_over_two = columns[23],
            .to_pc_lsb = columns[24],
            .imm_felt = columns[25],
            .result = columns[26..30].*,
            .destination = common.destinationFromColumns(columns[30..32]),
            .target_word_low_20 = columns[32],
            .target_word_high_8 = columns[33],
            .target_limbs = columns[34..38].*,
            .imm_byte_0 = columns[38],
            .imm_nibble = columns[39],
            .imm_sign = columns[40],
        };
    }
};

pub const Constraints = common.ConstraintSet(N_CONSTRAINTS);

pub fn targetWord(row: Row) QM31 {
    return row.target_word_low_20.add(
        row.target_word_high_8.mul(common.q(@as(u32, 1) << 20)),
    );
}

pub fn jumpTarget(row: Row) QM31 {
    return common.q(4).mul(targetWord(row));
}

fn immediateLimbs(row: Row) [4]QM31 {
    return .{
        row.imm_byte_0,
        row.imm_nibble.add(row.imm_sign.mul(common.q(240))),
        row.imm_sign.mul(common.q(255)),
        row.imm_sign.mul(common.q(255)),
    };
}

pub fn evaluate(row: Row) Constraints {
    var out: [N_CONSTRAINTS]QM31 = undefined;
    var n: usize = 0;
    out[n] = common.bit(row.enabler);
    n += 1;
    out[n] = common.bit(row.to_pc_lsb);
    n += 1;
    out[n] = common.bit(row.imm_sign);
    n += 1;
    out[n] = row.imm_byte_0
        .add(row.imm_nibble.mul(common.q(256)))
        .sub(row.imm_sign.mul(common.q(4096)))
        .sub(row.imm_felt);
    n += 1;
    out[n] = common.composeU32(row.target_limbs).sub(jumpTarget(row));
    n += 1;
    out[n] = row.to_pc_over_two.sub(targetWord(row).mul(common.q(2)));
    n += 1;

    const immediate = immediateLimbs(row);
    var carry = QM31.zero();
    for (0..4) |limb| {
        const result_limb = row.target_limbs[limb].add(
            if (limb == 0) row.to_pc_lsb else QM31.zero(),
        );
        carry = row.rs1.next[limb]
            .add(immediate[limb])
            .add(carry)
            .sub(result_limb)
            .mul(common.INV_BYTE_RADIX);
        out[n] = common.bit(carry);
        n += 1;
    }

    out[n] = row.enabler.mul(
        common.composeU32(row.result).sub(row.pc.add(common.q(4))),
    );
    n += 1;
    @memcpy(out[n .. n + 3], &common.destinationConstraints(row.rd.addr, row.destination));
    n += 3;
    @memcpy(
        out[n .. n + 4],
        &common.destinationResultConstraints(row.rd, row.result, row.destination),
    );
    n += 4;
    // rs1 is a source operand: force the emitted access value to equal the
    // consumed one so the access chain cannot double as a register write.
    @memcpy(out[n .. n + 4], &common.readOnlyAccessConstraints(row.rs1, row.enabler));
    n += 4;
    std.debug.assert(n == out.len);
    return .{ .values = out };
}

pub fn placementConstraint(row: Row, is_active: QM31) QM31 {
    return row.enabler.sub(is_active);
}

pub fn programLookup(row: Row) common.ProgramTuple {
    return .{
        .pc = row.pc,
        .opcode_id = common.q(Opcode.jalr.protocolId()),
        .rd = row.rd.addr,
        .rs1 = row.rs1.addr,
        .operand = row.imm_felt,
    };
}

pub const Lookups = struct {
    /// The pinned prefix is followed by the row-local target and immediate
    /// bindings in declaration order.
    program: control.Request(common.ProgramTuple),
    rs1: control.RegisterAccessLookups,
    rs1_middle_bytes: control.Request(control.RangePairTuple),
    rs1_outer_bytes: control.Request(control.RangePairTuple),
    target_word_low_20: control.Request(control.Range20Tuple),
    target_word_high_8: control.Request(control.RangePairTuple),
    target_middle_bytes: control.Request(control.RangePairTuple),
    target_m31: control.Request(control.RangePairTuple),
    immediate_range: control.Request(control.RangeTripleTuple),
    state: control.StateLookups,
    rd_middle_bytes: control.Request(control.RangePairTuple),
    rd_m31: control.Request(control.RangePairTuple),
    rd: control.RegisterAccessLookups,
};

pub fn lookups(row: Row) Lookups {
    return .{
        .program = control.programRequest(row.enabler, programLookup(row)),
        .rs1 = control.registerAccessLookups(row.rs1, row.clock, row.enabler),
        .rs1_middle_bytes = control.rangePairRequest(
            row.enabler,
            row.rs1.next[1],
            row.rs1.next[2],
        ),
        .rs1_outer_bytes = control.rangePairRequest(
            row.enabler,
            row.rs1.next[0],
            row.rs1.next[3],
        ),
        .target_word_low_20 = control.range20Request(
            row.enabler,
            row.target_word_low_20,
        ),
        .target_word_high_8 = control.rangePairRequest(
            row.enabler,
            row.target_word_high_8,
            QM31.zero(),
        ),
        .target_middle_bytes = control.rangePairRequest(
            row.enabler,
            row.target_limbs[1],
            row.target_limbs[2],
        ),
        // Combined with the bounded target/4 split, the M31 outer-byte table
        // excludes the residual target+p byte decomposition.
        .target_m31 = control.rangePairRequest(
            row.enabler,
            row.target_limbs[0],
            row.target_limbs[3],
        ),
        .immediate_range = .{
            .numerator = row.enabler.neg(),
            .tuple = .{
                .limb_0 = row.imm_byte_0,
                .limb_1 = QM31.zero(),
                .limb_2 = row.imm_nibble
                    .sub(row.imm_sign.mul(common.q(8)))
                    .mul(common.q(2)),
            },
        },
        .state = control.stateLookups(
            row.pc,
            row.clock,
            jumpTarget(row),
            row.enabler,
        ),
        .rd_middle_bytes = control.rangePairRequest(
            row.enabler,
            row.result[1],
            row.result[2],
        ),
        .rd_m31 = control.rangePairRequest(
            row.enabler,
            row.result[0],
            row.result[3],
        ),
        .rd = control.registerAccessLookups(row.rd, row.clock, row.enabler),
    };
}

fn zeroRow() Row {
    const access = common.Access{
        .addr = QM31.zero(),
        .previous = .{QM31.zero()} ** 4,
        .previous_clock = QM31.zero(),
        .next = .{QM31.zero()} ** 4,
    };
    return .{
        .enabler = QM31.zero(),
        .clock = QM31.zero(),
        .pc = QM31.zero(),
        .rd = access,
        .rs1 = access,
        .to_pc_over_two = QM31.zero(),
        .to_pc_lsb = QM31.zero(),
        .imm_felt = QM31.zero(),
        .result = .{QM31.zero()} ** 4,
        .destination = .{ .nonzero = QM31.zero(), .inverse = QM31.zero() },
        .target_word_low_20 = QM31.zero(),
        .target_word_high_8 = QM31.zero(),
        .target_limbs = .{QM31.zero()} ** 4,
        .imm_byte_0 = QM31.zero(),
        .imm_nibble = QM31.zero(),
        .imm_sign = QM31.zero(),
    };
}

fn honestRow() Row {
    var row = zeroRow();
    row.enabler = QM31.one();
    row.clock = common.q(7);
    row.pc = common.q(0x1000);
    row.rd.addr = common.q(1);
    row.rd.next = .{ common.q(4), common.q(0x10), QM31.zero(), QM31.zero() };
    row.result = row.rd.next;
    row.destination = .{ .nonzero = QM31.one(), .inverse = QM31.one() };
    row.rs1.addr = common.q(2);
    row.rs1.next[0] = common.q(101);
    row.rs1.previous = row.rs1.next;
    row.to_pc_over_two = common.q(52);
    row.to_pc_lsb = QM31.one();
    row.target_word_low_20 = common.q(26);
    row.target_limbs[0] = common.q(104);
    row.imm_felt = common.q(4);
    row.imm_byte_0 = common.q(4);
    return row;
}

test "jalr: honest odd sum clears bit zero to an aligned target" {
    const row = honestRow();
    try std.testing.expect(evaluate(row).allZero());

    const requests = lookups(row);
    try std.testing.expect(requests.program.tuple.opcode_id.eql(common.q(34)));
    try std.testing.expect(requests.state.emit.tuple.pc.eql(common.q(104)));
    try std.testing.expect(requests.state.emit.tuple.clock.eql(common.q(8)));
    try std.testing.expect(requests.rs1_middle_bytes.numerator.eql(QM31.one().neg()));
    try std.testing.expect(requests.rs1_middle_bytes.tuple.limb_0.eql(row.rs1.next[1]));
    try std.testing.expect(requests.rs1_middle_bytes.tuple.limb_1.eql(row.rs1.next[2]));
    try std.testing.expect(requests.target_word_low_20.tuple.value.eql(common.q(26)));
}

test "jalr: rs1 write-back through the access chain is rejected" {
    var row = honestRow();
    row.rs1.previous[0] = common.q(100);
    const constraints = evaluate(row);
    for (constraints.values[0..18]) |value| try std.testing.expect(value.isZero());
    try std.testing.expect(!constraints.allZero());
}

test "jalr: target bit, word split, and link register are bound" {
    var row = honestRow();
    row.to_pc_lsb = QM31.zero();
    try std.testing.expect(!evaluate(row).allZero());

    row = honestRow();
    row.target_word_low_20 = common.q(25);
    try std.testing.expect(!evaluate(row).allZero());

    row = honestRow();
    row.rd.next[0] = common.q(105);
    row.result[0] = common.q(105);
    try std.testing.expect(!evaluate(row).allZero());
}

test "jalr: signed immediate and u32 wraparound use exact byte carries" {
    var negative = honestRow();
    negative.rs1.next = .{ common.q(4), common.q(0x10), QM31.zero(), QM31.zero() };
    negative.rs1.previous = negative.rs1.next;
    negative.to_pc_over_two = common.q(0x800);
    negative.to_pc_lsb = QM31.zero();
    negative.target_word_low_20 = common.q(0x400);
    negative.target_limbs = .{ QM31.zero(), common.q(0x10), QM31.zero(), QM31.zero() };
    negative.imm_felt = QM31.zero().sub(common.q(4));
    negative.imm_byte_0 = common.q(0xfc);
    negative.imm_nibble = common.q(0xf);
    negative.imm_sign = QM31.one();
    try std.testing.expect(evaluate(negative).allZero());

    var wrapped = honestRow();
    wrapped.rs1.next = .{
        QM31.one(),
        common.q(0xf8),
        common.q(0xff),
        common.q(0xff),
    };
    wrapped.rs1.previous = wrapped.rs1.next;
    wrapped.to_pc_over_two = QM31.zero();
    wrapped.to_pc_lsb = QM31.zero();
    wrapped.target_word_low_20 = QM31.zero();
    wrapped.target_limbs = .{QM31.zero()} ** 4;
    wrapped.imm_felt = common.q(0x7ff);
    wrapped.imm_byte_0 = common.q(0xff);
    wrapped.imm_nibble = common.q(7);
    try std.testing.expect(evaluate(wrapped).allZero());

    const table = @import("../lookups/tables/schema.zig");
    const outer = lookups(wrapped).rs1_outer_bytes.tuple.values();
    _ = try table.indexSecure(.range_check_8_8, &outer);
}

test "jalr: misaligned cleared target is rejected row locally" {
    var row = honestRow();
    row.rs1.next[0] = common.q(100);
    row.rs1.previous = row.rs1.next;
    row.to_pc_over_two = common.q(51);
    row.target_word_low_20 = common.q(25);
    row.target_limbs[0] = common.q(102);
    row.imm_felt = common.q(3);
    row.imm_byte_0 = common.q(3);
    try std.testing.expect(!evaluate(row).allZero());
}

test "jalr: exact adapter expands rd then rs1 after leading enabler" {
    var columns = [_]QM31{QM31.zero()} ** N_MAIN_COLUMNS;
    columns[0] = common.q(1);
    columns[3] = common.q(2);
    columns[13] = common.q(3);
    columns[23] = common.q(4);
    columns[24] = common.q(5);
    columns[25] = common.q(6);
    columns[32] = common.q(7);
    columns[33] = common.q(8);
    columns[34] = common.q(9);
    columns[38] = common.q(10);
    columns[39] = common.q(11);
    columns[40] = common.q(12);
    const row = try Row.fromMainColumns(&columns);
    try std.testing.expect(row.enabler.eql(common.q(1)));
    try std.testing.expect(row.rd.addr.eql(common.q(2)));
    try std.testing.expect(row.rs1.addr.eql(common.q(3)));
    try std.testing.expect(row.to_pc_over_two.eql(common.q(4)));
    try std.testing.expect(row.to_pc_lsb.eql(common.q(5)));
    try std.testing.expect(row.imm_felt.eql(common.q(6)));
    try std.testing.expect(row.target_word_low_20.eql(common.q(7)));
    try std.testing.expect(row.target_word_high_8.eql(common.q(8)));
    try std.testing.expect(row.target_limbs[0].eql(common.q(9)));
    try std.testing.expect(row.imm_byte_0.eql(common.q(10)));
    try std.testing.expect(row.imm_nibble.eql(common.q(11)));
    try std.testing.expect(row.imm_sign.eql(common.q(12)));
}
