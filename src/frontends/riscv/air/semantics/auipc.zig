//! Exact pinned Stark-V AIR semantics and lookup requests for AUIPC.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const common = @import("common.zig");
const control = @import("control_common.zig");
const Opcode = @import("../program/opcode.zig").Opcode;

pub const N_MAIN_COLUMNS: usize = 29;
pub const N_CONSTRAINTS: usize = 15;

pub const Row = struct {
    enabler: QM31,
    clock: QM31,
    pc: QM31,
    rd: common.Access,
    imm_felt: QM31,
    result: [4]QM31,
    destination: common.Destination,
    pc_limbs: [4]QM31,
    imm_limbs: [4]QM31,
    imm_sign: QM31,

    pub fn fromMainColumns(columns: []const QM31) !Row {
        if (columns.len != N_MAIN_COLUMNS) return error.InvalidMainTraceShape;
        return .{
            .enabler = columns[0],
            .clock = columns[1],
            .pc = columns[2],
            .rd = control.accessFromColumns(columns, 3),
            .imm_felt = columns[13],
            .result = columns[14..18].*,
            .destination = common.destinationFromColumns(columns[18..20]),
            .pc_limbs = columns[20..24].*,
            .imm_limbs = columns[24..28].*,
            .imm_sign = columns[28],
        };
    }
};

pub const Constraints = common.ConstraintSet(N_CONSTRAINTS);

pub fn evaluate(row: Row) Constraints {
    var out: [N_CONSTRAINTS]QM31 = undefined;
    var n: usize = 0;
    out[n] = common.bit(row.enabler);
    n += 1;
    out[n] = common.composeU32(row.pc_limbs).sub(row.pc);
    n += 1;
    // `imm_felt` is the signed i32 value bound by the decoded-program lookup.
    // In M31, converting its u32 bit pattern adds 2^32 == 2 for negatives.
    out[n] = common.composeU32(row.imm_limbs)
        .sub(row.imm_felt)
        .sub(row.imm_sign.mul(common.q(2)));
    n += 1;
    out[n] = common.bit(row.imm_sign);
    n += 1;
    var carry = QM31.zero();
    for (0..4) |limb| {
        const numerator = row.pc_limbs[limb]
            .add(row.imm_limbs[limb])
            .add(carry)
            .sub(row.result[limb]);
        carry = numerator.mul(common.INV_BYTE_RADIX);
        out[n] = common.bit(carry);
        n += 1;
    }
    @memcpy(out[n .. n + 3], &common.destinationConstraints(row.rd.addr, row.destination));
    n += 3;
    @memcpy(
        out[n .. n + 4],
        &common.destinationResultConstraints(row.rd, row.result, row.destination),
    );
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
        .opcode_id = common.q(Opcode.auipc.protocolId()),
        .rd = row.rd.addr,
        .rs1 = row.imm_felt,
        .operand = QM31.zero(),
    };
}

pub const RangeLookups = struct {
    result: [2]control.Request(control.RangePairTuple),
    pc: [2]control.Request(control.RangePairTuple),
    immediate: [2]control.Request(control.RangePairTuple),
};

pub const Lookups = struct {
    /// Fields retain `schema.rs` declaration order for interaction batching.
    program: control.Request(common.ProgramTuple),
    state: control.StateLookups,
    ranges: RangeLookups,
    rd: control.RegisterAccessLookups,
};

pub fn lookups(row: Row) Lookups {
    return .{
        .program = control.programRequest(row.enabler, programLookup(row)),
        .state = control.stateLookups(
            row.pc,
            row.clock,
            row.pc.add(common.q(4)),
            row.enabler,
        ),
        .ranges = .{
            .result = .{
                control.rangePairRequest(row.enabler, row.result[0], row.result[1]),
                control.rangePairRequest(row.enabler, row.result[2], row.result[3]),
            },
            // PC is profile-bounded below 2^30. `range_check_m31` on the
            // outer bytes additionally makes the field decomposition injective.
            .pc = .{
                control.rangePairRequest(row.enabler, row.pc_limbs[1], row.pc_limbs[2]),
                control.rangePairRequest(row.enabler, row.pc_limbs[0], row.pc_limbs[3]),
            },
            // The second tuple is consumed by range_check_m31: subtracting
            // 128*sign binds `imm_sign` to bit 31 while range-checking both
            // outer bytes.
            .immediate = .{
                control.rangePairRequest(row.enabler, row.imm_limbs[1], row.imm_limbs[2]),
                control.rangePairRequest(
                    row.enabler,
                    row.imm_limbs[0],
                    row.imm_limbs[3].sub(row.imm_sign.mul(common.q(128))),
                ),
            },
        },
        .rd = control.registerAccessLookups(row.rd, row.clock, row.enabler),
    };
}

fn zeroRow() Row {
    return .{
        .enabler = QM31.zero(),
        .clock = QM31.zero(),
        .pc = QM31.zero(),
        .rd = .{
            .addr = QM31.zero(),
            .previous = .{QM31.zero()} ** 4,
            .previous_clock = QM31.zero(),
            .next = .{QM31.zero()} ** 4,
        },
        .imm_felt = QM31.zero(),
        .result = .{QM31.zero()} ** 4,
        .destination = .{ .nonzero = QM31.zero(), .inverse = QM31.zero() },
        .pc_limbs = .{QM31.zero()} ** 4,
        .imm_limbs = .{QM31.zero()} ** 4,
        .imm_sign = QM31.zero(),
    };
}

test "auipc: honest result satisfies direct equation and exact ranges" {
    var row = zeroRow();
    row.enabler = QM31.one();
    row.clock = common.q(4);
    row.pc = common.q(0x1000);
    row.pc_limbs = .{ QM31.zero(), common.q(0x10), QM31.zero(), QM31.zero() };
    row.imm_felt = common.q(0x2000);
    row.imm_limbs = .{ QM31.zero(), common.q(0x20), QM31.zero(), QM31.zero() };
    row.rd.addr = common.q(8);
    row.destination = .{
        .nonzero = QM31.one(),
        .inverse = common.q(8).inv() catch unreachable,
    };
    row.rd.next = .{ common.q(0), common.q(0x30), common.q(0), common.q(0) };
    row.result = row.rd.next;
    try std.testing.expect(evaluate(row).allZero());

    const requests = lookups(row);
    try std.testing.expect(requests.program.tuple.opcode_id.eql(common.q(36)));
    try std.testing.expect(requests.program.tuple.rs1.eql(common.q(0x2000)));
    try std.testing.expect(requests.state.emit.tuple.pc.eql(common.q(0x1004)));
    try std.testing.expect(requests.ranges.result[0].tuple.limb_1.eql(common.q(0x30)));
}

test "auipc: forged destination is rejected" {
    var row = zeroRow();
    row.enabler = QM31.one();
    row.pc = common.q(100);
    row.pc_limbs[0] = common.q(100);
    row.imm_felt = common.q(20);
    row.imm_limbs[0] = common.q(20);
    row.rd.next[0] = common.q(121);
    try std.testing.expect(!evaluate(row).allZero());
}

test "auipc: exact adapter has upstream enabler first" {
    var columns = [_]QM31{QM31.zero()} ** N_MAIN_COLUMNS;
    columns[0] = common.q(1);
    columns[3] = common.q(2);
    columns[8] = common.q(3);
    columns[9] = common.q(4);
    columns[13] = common.q(5);
    const row = try Row.fromMainColumns(&columns);
    try std.testing.expect(row.enabler.eql(common.q(1)));
    try std.testing.expect(row.rd.addr.eql(common.q(2)));
    try std.testing.expect(row.rd.previous_clock.eql(common.q(3)));
    try std.testing.expect(row.rd.next[0].eql(common.q(4)));
    try std.testing.expect(row.imm_felt.eql(common.q(5)));
}
