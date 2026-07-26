//! Exact pinned Stark-V SLL/SRL/SRA semantics and lookup requests.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const common = @import("common.zig");
const shift = @import("shift_common.zig");

pub const N_ORACLE_COLUMNS: usize = 60;
pub const N_CONSTRAINTS: usize = shift.N_CONSTRAINTS + 4;
pub const CURRENT_TRACE_COMPATIBLE = true;

pub const Row = struct {
    clk: QM31,
    pc: QM31,
    rs2: common.Access,
    semantic: shift.Row,

    /// Pinned `define_trace_tables!` committed-column order.
    pub fn fromOracleColumns(columns: []const QM31) !Row {
        if (columns.len != N_ORACLE_COLUMNS) return error.InvalidOracleTraceShape;
        const rd = common.accessFromColumns(columns[2..12]);
        const rs1 = common.accessFromColumns(columns[12..22]);
        const rs2 = common.accessFromColumns(columns[22..32]);
        return .{
            .clk = columns[0],
            .pc = columns[1],
            .rs2 = rs2,
            .semantic = .{
                .rd = rd,
                .rs1 = rs1,
                .rs1_sign = columns[32],
                .is_sll = columns[33],
                .is_srl = columns[34],
                .is_sra = columns[35],
                .bit_multiplier_left = columns[36],
                .bit_multiplier_right = columns[37],
                .bit_markers = columns[38..46].*,
                .limb_markers = columns[46..50].*,
                .carries = columns[50..54].*,
                .result = columns[54..58].*,
                .destination = common.destinationFromColumns(columns[58..60]),
            },
        };
    }
};

pub const Constraints = common.ConstraintSet(N_CONSTRAINTS);

pub fn evaluate(row: Row) Constraints {
    var out: [N_CONSTRAINTS]QM31 = undefined;
    const core = shift.evaluate(row.semantic);
    @memcpy(out[0..shift.N_CONSTRAINTS], &core.values);
    // rs2 is read-only: it must emit exactly the value it consumed.
    @memcpy(
        out[shift.N_CONSTRAINTS..],
        &common.readOnlyAccessConstraints(row.rs2, row.semantic.active()),
    );
    return .{ .values = out };
}

pub fn placementConstraint(row: Row, is_active: QM31) QM31 {
    return row.semantic.active().sub(is_active);
}

pub fn programLookup(row: Row) common.ProgramTuple {
    return .{
        .pc = row.pc,
        .opcode_id = row.semantic.is_sll.mul(common.q(2))
            .add(row.semantic.is_srl.mul(common.q(6)))
            .add(row.semantic.is_sra.mul(common.q(7))),
        .rd = row.semantic.rd.addr,
        .rs1 = row.semantic.rs1.addr,
        .operand = row.rs2.addr,
    };
}

pub const AccessLookups = struct {
    rd: common.AccessChain,
    rs1: common.AccessChain,
    rs2: common.AccessChain,
};

pub fn accessLookups(row: Row) AccessLookups {
    return .{
        .rd = common.registerAccessChain(row.semantic.rd, row.clk),
        .rs1 = common.registerAccessChain(row.semantic.rs1, row.clk),
        .rs2 = common.registerAccessChain(row.rs2, row.clk),
    };
}

pub fn stateLookup(row: Row) common.RegistersStateChain {
    return common.registersStateChain(row.pc, row.clk);
}

pub fn shiftAmountRangeLookup(row: Row) QM31 {
    const amount = shift.derive(row.semantic).shift_amount;
    return common.q(7).sub(row.rs2.next[0].sub(amount).mul(common.INV_32));
}

pub const carryRangePairs = shift.carryRangePairs;
pub const rdRangePairs = shift.rdRangePairs;
pub const signRangeLookup = shift.signRangeLookup;

fn zeroAccess() common.Access {
    return .{
        .addr = QM31.zero(),
        .previous = .{QM31.zero()} ** 4,
        .previous_clock = QM31.zero(),
        .next = .{QM31.zero()} ** 4,
    };
}

fn sllByOneRow() Row {
    const rd = common.Access{
        .addr = common.q(1),
        .previous = .{QM31.zero()} ** 4,
        .previous_clock = QM31.zero(),
        .next = .{ common.q(2), QM31.zero(), QM31.zero(), QM31.zero() },
    };
    var rs1 = zeroAccess();
    rs1.addr = common.q(2);
    rs1.next[0] = QM31.one();
    rs1.previous = rs1.next;
    var rs2 = zeroAccess();
    rs2.addr = common.q(3);
    rs2.next[0] = QM31.one();
    rs2.previous = rs2.next;
    return .{
        .clk = common.q(1),
        .pc = common.q(0x1000),
        .rs2 = rs2,
        .semantic = .{
            .rd = rd,
            .rs1 = rs1,
            .rs1_sign = QM31.zero(),
            .is_sll = QM31.one(),
            .is_srl = QM31.zero(),
            .is_sra = QM31.zero(),
            .bit_multiplier_left = common.q(2),
            .bit_multiplier_right = QM31.zero(),
            .bit_markers = .{ QM31.zero(), QM31.one(), QM31.zero(), QM31.zero(), QM31.zero(), QM31.zero(), QM31.zero(), QM31.zero() },
            .limb_markers = .{ QM31.one(), QM31.zero(), QM31.zero(), QM31.zero() },
            .carries = .{QM31.zero()} ** 4,
            .result = .{ common.q(2), QM31.zero(), QM31.zero(), QM31.zero() },
            .destination = .{ .nonzero = QM31.one(), .inverse = QM31.one() },
        },
    };
}

test "shifts reg: exact SLL row and tuple are accepted" {
    var row = sllByOneRow();
    std.mem.doNotOptimizeAway(&row);
    try std.testing.expect(evaluate(row).allZero());
    try std.testing.expect(programLookup(row).opcode_id.eql(common.q(2)));
    try std.testing.expect(shiftAmountRangeLookup(row).eql(common.q(7)));
}

test "shifts reg: forged output and non-hot markers are rejected" {
    var row = sllByOneRow();
    row.semantic.rd.next[0] = common.q(3);
    try std.testing.expect(!evaluate(row).allZero());

    row = sllByOneRow();
    row.semantic.bit_markers[2] = QM31.one();
    try std.testing.expect(!evaluate(row).allZero());
}

test "shifts reg: read-only sources must emit the value they consumed" {
    // The shift computes on `next`; a diverging `previous` would let the
    // instruction double as an arbitrary register write.
    var row = sllByOneRow();
    row.semantic.rs1.previous[0] = common.q(0xde);
    try std.testing.expect(!evaluate(row).allZero());

    row = sllByOneRow();
    row.rs2.previous[0] = common.q(0xad);
    try std.testing.expect(!evaluate(row).allZero());
}

test "shifts reg: arithmetic right shift binds sign extension" {
    var row = sllByOneRow();
    row.semantic.is_sll = QM31.zero();
    row.semantic.is_sra = QM31.one();
    row.semantic.rs1_sign = QM31.one();
    row.semantic.bit_multiplier_left = QM31.zero();
    row.semantic.bit_multiplier_right = common.q(2);
    row.semantic.rs1.next = .{ QM31.zero(), QM31.zero(), QM31.zero(), common.q(128) };
    row.semantic.rs1.previous = row.semantic.rs1.next;
    row.semantic.rd.next = .{ QM31.zero(), QM31.zero(), QM31.zero(), common.q(192) };
    row.semantic.result = row.semantic.rd.next;
    try std.testing.expect(evaluate(row).allZero());

    row.semantic.rs1_sign = QM31.zero();
    try std.testing.expect(!evaluate(row).allZero());
}

test "shifts reg: adapter follows oracle access-first order" {
    var columns = [_]QM31{QM31.zero()} ** N_ORACLE_COLUMNS;
    columns[2] = common.q(11);
    columns[12] = common.q(12);
    columns[22] = common.q(13);
    columns[32] = common.q(14);
    columns[50] = common.q(15);
    const row = try Row.fromOracleColumns(&columns);
    try std.testing.expect(row.semantic.rd.addr.eql(common.q(11)));
    try std.testing.expect(row.semantic.rs1.addr.eql(common.q(12)));
    try std.testing.expect(row.rs2.addr.eql(common.q(13)));
    try std.testing.expect(row.semantic.rs1_sign.eql(common.q(14)));
    try std.testing.expect(row.semantic.carries[0].eql(common.q(15)));
}
