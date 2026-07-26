//! Exact pinned Stark-V AIR semantics for BLT, BLTU, BGE, and BGEU.
//!
//! The comparison scans byte limbs from most to least significant and uses a
//! signed-MSB witness only for signed opcodes, matching `schema.rs` exactly.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const common = @import("common.zig");
const control = @import("control_common.zig");
const Opcode = @import("../program/opcode.zig").Opcode;

pub const N_MAIN_COLUMNS: usize = 37;
pub const N_CONSTRAINTS: usize = 32;

pub const Row = struct {
    clock: QM31,
    pc: QM31,
    rs1: common.Access,
    rs2: common.Access,
    rs1_msl_felt: QM31,
    rs2_msl_felt: QM31,
    imm_felt: QM31,
    cmp_result: QM31,
    cmp_lt: QM31,
    diff_markers: [4]QM31,
    diff_val: QM31,
    branch_target: QM31,
    opcode_blt_flag: QM31,
    opcode_bltu_flag: QM31,
    opcode_bge_flag: QM31,
    opcode_bgeu_flag: QM31,

    pub fn fromMainColumns(columns: []const QM31) !Row {
        if (columns.len != N_MAIN_COLUMNS) return error.InvalidMainTraceShape;
        return .{
            .clock = columns[0],
            .pc = columns[1],
            .rs1 = control.accessFromColumns(columns, 2),
            .rs2 = control.accessFromColumns(columns, 12),
            .rs1_msl_felt = columns[22],
            .rs2_msl_felt = columns[23],
            .imm_felt = columns[24],
            .cmp_result = columns[25],
            .cmp_lt = columns[26],
            .diff_markers = columns[27..31].*,
            .diff_val = columns[31],
            .branch_target = columns[32],
            .opcode_blt_flag = columns[33],
            .opcode_bltu_flag = columns[34],
            .opcode_bge_flag = columns[35],
            .opcode_bgeu_flag = columns[36],
        };
    }

    pub fn enabler(self: Row) QM31 {
        return self.opcode_blt_flag
            .add(self.opcode_bltu_flag)
            .add(self.opcode_bge_flag)
            .add(self.opcode_bgeu_flag);
    }
};

pub const Constraints = common.ConstraintSet(N_CONSTRAINTS);

pub fn evaluate(row: Row) Constraints {
    @setEvalBranchQuota(10_000);
    var out: [N_CONSTRAINTS]QM31 = undefined;
    var i: usize = 0;

    const enabler = row.enabler();
    const flags = [_]QM31{
        row.opcode_blt_flag,
        row.opcode_bltu_flag,
        row.opcode_bge_flag,
        row.opcode_bgeu_flag,
    };
    out[i] = common.bit(enabler);
    i += 1;
    for (flags) |flag| {
        out[i] = common.bit(flag);
        i += 1;
    }
    out[i] = common.bit(row.cmp_result);
    i += 1;
    for (row.diff_markers) |marker| {
        out[i] = common.bit(marker);
        i += 1;
    }

    const not_cmp = QM31.one().sub(row.cmp_result);
    const selected_target = row.pc
        .add(row.imm_felt.mul(row.cmp_result))
        .add(common.q(4).mul(not_cmp));
    out[i] = enabler.mul(row.branch_target.sub(selected_target));
    i += 1;

    const rs1_msl_gap = row.rs1.next[3].sub(row.rs1_msl_felt);
    const rs2_msl_gap = row.rs2.next[3].sub(row.rs2_msl_felt);
    out[i] = rs1_msl_gap.mul(common.q(1 << 8).sub(rs1_msl_gap));
    i += 1;
    out[i] = rs2_msl_gap.mul(common.q(1 << 8).sub(rs2_msl_gap));
    i += 1;

    const prefix = row.diff_markers[0]
        .add(row.diff_markers[1])
        .add(row.diff_markers[2])
        .add(row.diff_markers[3]);
    const lt_sign = common.q(2).mul(row.cmp_lt).sub(QM31.one());

    const m3 = row.diff_markers[3];
    const m2 = row.diff_markers[2];
    const m1 = row.diff_markers[1];
    const m0 = row.diff_markers[0];
    const diff3 = lt_sign.mul(row.rs2_msl_felt.sub(row.rs1_msl_felt));
    const diff2 = lt_sign.mul(row.rs2.next[2].sub(row.rs1.next[2]));
    const diff1 = lt_sign.mul(row.rs2.next[1].sub(row.rs1.next[1]));
    const diff0 = lt_sign.mul(row.rs2.next[0].sub(row.rs1.next[0]));

    out[i] = QM31.one().sub(m3).mul(diff3);
    i += 1;
    out[i] = m3.mul(row.diff_val.sub(diff3));
    i += 1;
    out[i] = QM31.one().sub(m3).sub(m2).mul(diff2);
    i += 1;
    out[i] = m2.mul(row.diff_val.sub(diff2));
    i += 1;
    out[i] = QM31.one().sub(m3).sub(m2).sub(m1).mul(diff1);
    i += 1;
    out[i] = m1.mul(row.diff_val.sub(diff1));
    i += 1;
    out[i] = QM31.one().sub(prefix).mul(diff0);
    i += 1;
    out[i] = m0.mul(row.diff_val.sub(diff0));
    i += 1;
    out[i] = common.bit(prefix);
    i += 1;
    out[i] = QM31.one().sub(prefix).mul(row.cmp_lt);
    i += 1;

    const lt = row.opcode_blt_flag.add(row.opcode_bltu_flag);
    const ge = row.opcode_bge_flag.add(row.opcode_bgeu_flag);
    const expected_cmp_lt = row.cmp_result.mul(lt).add(not_cmp.mul(ge));
    out[i] = row.cmp_lt.sub(expected_cmp_lt);
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

pub fn placementConstraint(row: Row, is_active: QM31) QM31 {
    return row.enabler().sub(is_active);
}

pub fn programLookup(row: Row) common.ProgramTuple {
    const opcode_id = row.opcode_blt_flag.mul(common.q(Opcode.blt.protocolId()))
        .add(row.opcode_bltu_flag.mul(common.q(Opcode.bltu.protocolId())))
        .add(row.opcode_bge_flag.mul(common.q(Opcode.bge.protocolId())))
        .add(row.opcode_bgeu_flag.mul(common.q(Opcode.bgeu.protocolId())));
    return .{
        .pc = row.pc,
        .opcode_id = opcode_id,
        .rd = row.rs1.addr,
        .rs1 = row.rs2.addr,
        .operand = row.imm_felt,
    };
}

pub const RangeLookups = struct {
    shifted_msls: control.Request(control.RangePairTuple),
    positive_difference: control.Request(control.Range20Tuple),
};

pub const Lookups = struct {
    program: control.Request(common.ProgramTuple),
    state: control.StateLookups,
    rs1: control.RegisterAccessLookups,
    rs2: control.RegisterAccessLookups,
    ranges: RangeLookups,
};

pub fn lookups(row: Row) Lookups {
    const enabler = row.enabler();
    const signed = row.opcode_blt_flag.add(row.opcode_bge_flag);
    const sign_shift = signed.mul(common.q(1 << 7));
    const prefix = row.diff_markers[0]
        .add(row.diff_markers[1])
        .add(row.diff_markers[2])
        .add(row.diff_markers[3]);
    return .{
        .program = control.programRequest(enabler, programLookup(row)),
        .state = control.stateLookups(row.pc, row.clock, row.branch_target, enabler),
        .rs1 = control.registerAccessLookups(row.rs1, row.clock, enabler),
        .rs2 = control.registerAccessLookups(row.rs2, row.clock, enabler),
        .ranges = .{
            .shifted_msls = control.rangePairRequest(
                enabler,
                row.rs1_msl_felt.add(sign_shift),
                row.rs2_msl_felt.add(sign_shift),
            ),
            .positive_difference = control.range20Request(
                prefix,
                row.diff_val.sub(QM31.one()),
            ),
        },
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
        .rs1_msl_felt = QM31.zero(),
        .rs2_msl_felt = QM31.zero(),
        .imm_felt = QM31.zero(),
        .cmp_result = QM31.zero(),
        .cmp_lt = QM31.zero(),
        .diff_markers = .{QM31.zero()} ** 4,
        .diff_val = QM31.zero(),
        .branch_target = QM31.zero(),
        .opcode_blt_flag = QM31.zero(),
        .opcode_bltu_flag = QM31.zero(),
        .opcode_bge_flag = QM31.zero(),
        .opcode_bgeu_flag = QM31.zero(),
    };
}

test "branch lt: honest BLTU row accepts and emits exact lookups" {
    var row = zeroRow();
    row.clock = common.q(5);
    row.pc = common.q(0x1000);
    row.imm_felt = common.q(16);
    row.rs1.addr = common.q(1);
    row.rs2.addr = common.q(2);
    row.rs1.next[0] = common.q(1);
    row.rs1.previous[0] = common.q(1);
    row.rs2.next[0] = common.q(2);
    row.rs2.previous[0] = common.q(2);
    row.cmp_result = QM31.one();
    row.cmp_lt = QM31.one();
    row.diff_markers[0] = QM31.one();
    row.diff_val = QM31.one();
    row.branch_target = common.q(0x1010);
    row.opcode_bltu_flag = QM31.one();

    try std.testing.expect(evaluate(row).allZero());
    const requests = lookups(row);
    try std.testing.expect(requests.program.tuple.opcode_id.eql(common.q(31)));
    try std.testing.expect(requests.state.emit.tuple.pc.eql(common.q(0x1010)));
    try std.testing.expect(requests.ranges.positive_difference.numerator.eql(QM31.one().neg()));
    try std.testing.expect(requests.ranges.positive_difference.tuple.value.isZero());
}

test "branch lt: signed BGE correctly does not take negative-one versus zero" {
    var row = zeroRow();
    row.pc = common.q(0x2000);
    row.rs1.next = .{ common.q(255), common.q(255), common.q(255), common.q(255) };
    row.rs1.previous = row.rs1.next;
    row.rs1_msl_felt = QM31.one().neg();
    row.rs2_msl_felt = QM31.zero();
    row.cmp_result = QM31.zero();
    row.cmp_lt = QM31.one();
    row.diff_markers[3] = QM31.one();
    row.diff_val = QM31.one();
    row.branch_target = common.q(0x2004);
    row.opcode_bge_flag = QM31.one();
    try std.testing.expect(evaluate(row).allZero());

    const shifted = lookups(row).ranges.shifted_msls.tuple;
    try std.testing.expect(shifted.limb_0.eql(common.q(127)));
    try std.testing.expect(shifted.limb_1.eql(common.q(128)));
}

test "branch lt: forged comparison and branch target are rejected" {
    var row = zeroRow();
    row.pc = common.q(100);
    row.imm_felt = common.q(20);
    row.rs1.next[0] = common.q(1);
    row.rs1.previous[0] = common.q(1);
    row.rs2.next[0] = common.q(2);
    row.rs2.previous[0] = common.q(2);
    row.cmp_result = QM31.one();
    row.cmp_lt = QM31.one();
    row.diff_markers[0] = QM31.one();
    row.diff_val = QM31.one();
    row.branch_target = common.q(121);
    row.opcode_bltu_flag = QM31.one();
    try std.testing.expect(!evaluate(row).allZero());

    row.branch_target = common.q(120);
    row.cmp_lt = QM31.zero();
    try std.testing.expect(!evaluate(row).allZero());
}

test "branch lt: read-only source access must emit the value it consumed" {
    var row = zeroRow();
    row.pc = common.q(0x1000);
    row.imm_felt = common.q(16);
    row.rs1.next[0] = common.q(1);
    row.rs1.previous[0] = common.q(1);
    row.rs2.next[0] = common.q(2);
    row.rs2.previous[0] = common.q(2);
    row.cmp_result = QM31.one();
    row.cmp_lt = QM31.one();
    row.diff_markers[0] = QM31.one();
    row.diff_val = QM31.one();
    row.branch_target = common.q(0x1010);
    row.opcode_bltu_flag = QM31.one();
    try std.testing.expect(evaluate(row).allZero());

    // The comparison runs over `next`, so swapping the consumed value is only
    // caught by the read-only binding.
    row.rs1.previous = .{ common.q(0xef), common.q(0xbe), common.q(0xad), common.q(0xde) };
    try std.testing.expect(!evaluate(row).allZero());

    row.rs1.previous = row.rs1.next;
    row.rs2.previous[3] = common.q(0x99);
    try std.testing.expect(!evaluate(row).allZero());
}

test "branch lt: exact 37-column adapter preserves final witnesses" {
    var columns = [_]QM31{QM31.zero()} ** N_MAIN_COLUMNS;
    columns[2] = common.q(1);
    columns[12] = common.q(2);
    columns[22] = common.q(3);
    columns[24] = common.q(4);
    columns[27] = common.q(5);
    columns[31] = common.q(6);
    columns[32] = common.q(7);
    columns[36] = common.q(8);
    const row = try Row.fromMainColumns(&columns);
    try std.testing.expect(row.rs1.addr.eql(common.q(1)));
    try std.testing.expect(row.rs2.addr.eql(common.q(2)));
    try std.testing.expect(row.rs1_msl_felt.eql(common.q(3)));
    try std.testing.expect(row.imm_felt.eql(common.q(4)));
    try std.testing.expect(row.diff_markers[0].eql(common.q(5)));
    try std.testing.expect(row.diff_val.eql(common.q(6)));
    try std.testing.expect(row.branch_target.eql(common.q(7)));
    try std.testing.expect(row.opcode_bgeu_flag.eql(common.q(8)));
}
