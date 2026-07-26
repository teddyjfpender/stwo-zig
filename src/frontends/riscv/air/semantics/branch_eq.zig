//! Exact pinned Stark-V AIR semantics for BEQ and BNE.
//!
//! The 30-column adapter follows `air::schema::branch_eq` at commit
//! d478f783055aa0d73a93768a433a3c6c31c91d1c.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const common = @import("common.zig");
const control = @import("control_common.zig");
const Opcode = @import("../program/opcode.zig").Opcode;

pub const N_MAIN_COLUMNS: usize = 30;
pub const N_CONSTRAINTS: usize = 17;

pub const Row = struct {
    clock: QM31,
    pc: QM31,
    rs1: common.Access,
    rs2: common.Access,
    imm_felt: QM31,
    cmp_result: QM31,
    diff_inv_markers: [4]QM31,
    opcode_beq_flag: QM31,
    opcode_bne_flag: QM31,

    pub fn fromMainColumns(columns: []const QM31) !Row {
        if (columns.len != N_MAIN_COLUMNS) return error.InvalidMainTraceShape;
        return .{
            .clock = columns[0],
            .pc = columns[1],
            .rs1 = control.accessFromColumns(columns, 2),
            .rs2 = control.accessFromColumns(columns, 12),
            .imm_felt = columns[22],
            .cmp_result = columns[23],
            .diff_inv_markers = columns[24..28].*,
            .opcode_beq_flag = columns[28],
            .opcode_bne_flag = columns[29],
        };
    }

    pub fn enabler(self: Row) QM31 {
        return self.opcode_beq_flag.add(self.opcode_bne_flag);
    }
};

pub const Constraints = common.ConstraintSet(N_CONSTRAINTS);

/// Pinned constraints in generated order: structural enabler booleanity,
/// opcode-flag booleanity, then the six family constraints from `schema.rs`.
pub fn evaluate(row: Row) Constraints {
    var out: [N_CONSTRAINTS]QM31 = undefined;
    var i: usize = 0;

    const enabler = row.enabler();
    out[i] = common.bit(enabler);
    i += 1;
    out[i] = common.bit(row.opcode_beq_flag);
    i += 1;
    out[i] = common.bit(row.opcode_bne_flag);
    i += 1;
    out[i] = common.bit(row.cmp_result);
    i += 1;

    const cmp_eq = row.cmp_result.mul(row.opcode_beq_flag)
        .add(QM31.one().sub(row.cmp_result).mul(row.opcode_bne_flag));
    for (0..4) |limb| {
        out[i] = cmp_eq.mul(row.rs1.next[limb].sub(row.rs2.next[limb]));
        i += 1;
    }

    var diff_inv_sum = cmp_eq;
    for (0..4) |limb| {
        diff_inv_sum = diff_inv_sum.add(
            row.rs1.next[limb]
                .sub(row.rs2.next[limb])
                .mul(row.diff_inv_markers[limb]),
        );
    }
    out[i] = enabler.mul(QM31.one().sub(diff_inv_sum));
    i += 1;

    // Branches write no register: both accesses are read-only, so their
    // emitted `next` limbs must equal the consumed `previous` limbs.
    for (common.readOnlyAccessConstraints(row.rs1, enabler)) |constraint| {
        out[i] = constraint;
        i += 1;
    }
    for (common.readOnlyAccessConstraints(row.rs2, enabler)) |constraint| {
        out[i] = constraint;
        i += 1;
    }

    std.debug.assert(i == out.len);
    return .{ .values = out };
}

/// Cross-shard placement binds the derived family enabler to its selector.
pub fn placementConstraint(row: Row, is_active: QM31) QM31 {
    return row.enabler().sub(is_active);
}

pub fn nextPc(row: Row) QM31 {
    return row.pc
        .add(row.imm_felt.mul(row.cmp_result))
        .add(common.q(4).mul(QM31.one().sub(row.cmp_result)));
}

pub fn programLookup(row: Row) common.ProgramTuple {
    const opcode_id = row.opcode_beq_flag.mul(common.q(Opcode.beq.protocolId()))
        .add(row.opcode_bne_flag.mul(common.q(Opcode.bne.protocolId())));
    return .{
        .pc = row.pc,
        .opcode_id = opcode_id,
        .rd = row.rs1.addr,
        .rs1 = row.rs2.addr,
        .operand = row.imm_felt,
    };
}

pub const Lookups = struct {
    /// Fields retain `schema.rs` declaration order for interaction batching.
    program: control.Request(common.ProgramTuple),
    rs1: control.RegisterAccessLookups,
    rs2: control.RegisterAccessLookups,
    state: control.StateLookups,
};

pub fn lookups(row: Row) Lookups {
    const enabler = row.enabler();
    return .{
        .program = control.programRequest(enabler, programLookup(row)),
        .rs1 = control.registerAccessLookups(row.rs1, row.clock, enabler),
        .rs2 = control.registerAccessLookups(row.rs2, row.clock, enabler),
        .state = control.stateLookups(row.pc, row.clock, nextPc(row), enabler),
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
        .clock = QM31.zero(),
        .pc = QM31.zero(),
        .rs1 = access,
        .rs2 = access,
        .imm_felt = QM31.zero(),
        .cmp_result = QM31.zero(),
        .diff_inv_markers = .{QM31.zero()} ** 4,
        .opcode_beq_flag = QM31.zero(),
        .opcode_bne_flag = QM31.zero(),
    };
}

test "branch eq: BEQ equality accepts and binds decoded program tuple" {
    var row = zeroRow();
    row.clock = common.q(9);
    row.pc = common.q(0x1000);
    row.imm_felt = common.q(12);
    row.cmp_result = QM31.one();
    row.opcode_beq_flag = QM31.one();
    row.rs1.addr = common.q(3);
    row.rs2.addr = common.q(4);
    row.rs1.next = .{ common.q(7), common.q(8), common.q(9), common.q(10) };
    row.rs1.previous = row.rs1.next;
    row.rs2.next = row.rs1.next;
    row.rs2.previous = row.rs2.next;

    try std.testing.expect(evaluate(row).allZero());
    const requests = lookups(row);
    try std.testing.expect(requests.program.tuple.opcode_id.eql(common.q(27)));
    try std.testing.expect(requests.program.tuple.rd.eql(common.q(3)));
    try std.testing.expect(requests.program.tuple.rs1.eql(common.q(4)));
    try std.testing.expect(requests.state.emit.tuple.pc.eql(common.q(0x100c)));
    try std.testing.expect(requests.state.emit.tuple.clock.eql(common.q(10)));
}

test "branch eq: forged equality over unequal limbs is rejected" {
    var row = zeroRow();
    row.opcode_beq_flag = QM31.one();
    row.cmp_result = QM31.one();
    row.rs1.next[2] = common.q(17);
    row.rs2.next[2] = common.q(18);
    try std.testing.expect(!evaluate(row).allZero());
}

test "branch eq: BNE inequality requires a valid inverse marker" {
    var row = zeroRow();
    row.opcode_bne_flag = QM31.one();
    row.cmp_result = QM31.one();
    row.rs1.next[0] = common.q(9);
    row.rs1.previous[0] = common.q(9);
    row.rs2.next[0] = common.q(6);
    row.rs2.previous[0] = common.q(6);
    row.diff_inv_markers[0] = try common.q(3).inv();
    try std.testing.expect(evaluate(row).allZero());

    row.diff_inv_markers[0] = QM31.zero();
    try std.testing.expect(!evaluate(row).allZero());
}

test "branch eq: read-only source access must emit the value it consumed" {
    var row = zeroRow();
    row.clock = common.q(9);
    row.pc = common.q(0x1000);
    row.imm_felt = common.q(12);
    row.cmp_result = QM31.one();
    row.opcode_beq_flag = QM31.one();
    row.rs1.addr = common.q(3);
    row.rs2.addr = common.q(4);
    // Consumed 0xdeadbeef limbs but emits 0x7f7f7f7f limbs on both sources:
    // the comparison over `next` passes, so only the read-only binding rejects.
    row.rs1.previous = .{ common.q(0xef), common.q(0xbe), common.q(0xad), common.q(0xde) };
    row.rs1.next = .{ common.q(0x7f), common.q(0x7f), common.q(0x7f), common.q(0x7f) };
    row.rs2.previous = row.rs1.next;
    row.rs2.next = row.rs1.next;
    try std.testing.expect(!evaluate(row).allZero());

    row.rs1.previous = row.rs1.next;
    try std.testing.expect(evaluate(row).allZero());

    row.rs2.next[1] = common.q(0x11);
    row.rs1.next[1] = common.q(0x11);
    row.rs1.previous[1] = common.q(0x11);
    try std.testing.expect(!evaluate(row).allZero());
}

test "branch eq: exact 30-column adapter follows pinned order" {
    var columns = [_]QM31{QM31.zero()} ** N_MAIN_COLUMNS;
    columns[2] = common.q(1);
    columns[7] = common.q(2);
    columns[8] = common.q(3);
    columns[12] = common.q(4);
    columns[17] = common.q(5);
    columns[18] = common.q(6);
    columns[22] = common.q(7);
    columns[28] = common.q(8);
    const row = try Row.fromMainColumns(&columns);
    try std.testing.expect(row.rs1.addr.eql(common.q(1)));
    try std.testing.expect(row.rs1.previous_clock.eql(common.q(2)));
    try std.testing.expect(row.rs1.next[0].eql(common.q(3)));
    try std.testing.expect(row.rs2.addr.eql(common.q(4)));
    try std.testing.expect(row.rs2.previous_clock.eql(common.q(5)));
    try std.testing.expect(row.rs2.next[0].eql(common.q(6)));
    try std.testing.expect(row.imm_felt.eql(common.q(7)));
    try std.testing.expect(row.opcode_beq_flag.eql(common.q(8)));
}
