//! Exact pinned Stark-V AIR semantics and lookup requests for JALR.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const common = @import("common.zig");
const control = @import("control_common.zig");
const Opcode = @import("../program/opcode.zig").Opcode;

pub const N_MAIN_COLUMNS: usize = 32;
pub const N_CONSTRAINTS: usize = 11;

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
        };
    }
};

pub const Constraints = common.ConstraintSet(N_CONSTRAINTS);

pub fn jumpTarget(row: Row) QM31 {
    return common.q(2).mul(row.to_pc_over_two);
}

pub fn evaluate(row: Row) Constraints {
    const rs1_felt = common.composeU32(row.rs1.next);
    var out: [N_CONSTRAINTS]QM31 = undefined;
    out[0] = common.bit(row.enabler);
    out[1] = common.bit(row.to_pc_lsb);
    out[2] = jumpTarget(row).add(row.to_pc_lsb).sub(rs1_felt.add(row.imm_felt));
    out[3] = row.enabler.mul(
        common.composeU32(row.result).sub(row.pc.add(common.q(4))),
    );
    @memcpy(out[4..7], &common.destinationConstraints(row.rd.addr, row.destination));
    @memcpy(
        out[7..11],
        &common.destinationResultConstraints(row.rd, row.result, row.destination),
    );
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
    /// Fields retain `schema.rs` declaration order for interaction batching.
    program: control.Request(common.ProgramTuple),
    rs1: control.RegisterAccessLookups,
    rs1_m31: control.Request(control.RangePairTuple),
    state: control.StateLookups,
    rd_middle_bytes: control.Request(control.RangePairTuple),
    rd_m31: control.Request(control.RangePairTuple),
    rd: control.RegisterAccessLookups,
};

pub fn lookups(row: Row) Lookups {
    return .{
        .program = control.programRequest(row.enabler, programLookup(row)),
        .rs1 = control.registerAccessLookups(row.rs1, row.clock, row.enabler),
        .rs1_m31 = control.rangePairRequest(
            row.enabler,
            row.rs1.next[0],
            row.rs1.next[3],
        ),
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
    };
}

test "jalr: honest odd target clears its low bit" {
    var row = zeroRow();
    row.enabler = QM31.one();
    row.clock = common.q(7);
    row.pc = common.q(0x1000);
    row.rd.addr = common.q(1);
    row.rd.next = .{ common.q(4), common.q(0x10), QM31.zero(), QM31.zero() };
    row.result = row.rd.next;
    row.destination = .{ .nonzero = QM31.one(), .inverse = QM31.one() };
    row.rs1.addr = common.q(2);
    row.rs1.next[0] = common.q(100);
    row.imm_felt = common.q(3);
    row.to_pc_over_two = common.q(51);
    row.to_pc_lsb = QM31.one();
    try std.testing.expect(evaluate(row).allZero());

    const requests = lookups(row);
    try std.testing.expect(requests.program.tuple.opcode_id.eql(common.q(34)));
    try std.testing.expect(requests.state.emit.tuple.pc.eql(common.q(102)));
    try std.testing.expect(requests.state.emit.tuple.clock.eql(common.q(8)));
}

test "jalr: forged target decomposition and link register are rejected" {
    var row = zeroRow();
    row.enabler = QM31.one();
    row.pc = common.q(100);
    row.rd.addr = QM31.one();
    row.rd.next[0] = common.q(104);
    row.result[0] = common.q(104);
    row.destination = .{ .nonzero = QM31.one(), .inverse = QM31.one() };
    row.rs1.next[0] = common.q(20);
    row.to_pc_over_two = common.q(10);
    row.to_pc_lsb = common.q(2);
    try std.testing.expect(!evaluate(row).allZero());

    row.to_pc_lsb = QM31.zero();
    row.rd.next[0] = common.q(105);
    row.result[0] = common.q(105);
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
    const row = try Row.fromMainColumns(&columns);
    try std.testing.expect(row.enabler.eql(common.q(1)));
    try std.testing.expect(row.rd.addr.eql(common.q(2)));
    try std.testing.expect(row.rs1.addr.eql(common.q(3)));
    try std.testing.expect(row.to_pc_over_two.eql(common.q(4)));
    try std.testing.expect(row.to_pc_lsb.eql(common.q(5)));
    try std.testing.expect(row.imm_felt.eql(common.q(6)));
}
