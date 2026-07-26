//! Exact pinned Stark-V SLLI/SRLI/SRAI semantics and lookup requests.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const common = @import("common.zig");
const shift = @import("shift_common.zig");

pub const N_ORACLE_COLUMNS: usize = 51;
pub const N_CONSTRAINTS: usize = shift.N_CONSTRAINTS + 1;
pub const CURRENT_TRACE_COMPATIBLE = true;

pub const Row = struct {
    clk: QM31,
    pc: QM31,
    imm_truncated: QM31,
    semantic: shift.Row,

    pub fn fromOracleColumns(columns: []const QM31) !Row {
        if (columns.len != N_ORACLE_COLUMNS) return error.InvalidOracleTraceShape;
        const rd = common.accessFromColumns(columns[2..12]);
        const rs1 = common.accessFromColumns(columns[12..22]);
        return .{
            .clk = columns[0],
            .pc = columns[1],
            .imm_truncated = columns[23],
            .semantic = .{
                .rd = rd,
                .rs1 = rs1,
                .rs1_sign = columns[22],
                .is_sll = columns[24],
                .is_srl = columns[25],
                .is_sra = columns[26],
                .bit_multiplier_left = columns[27],
                .bit_multiplier_right = columns[28],
                .bit_markers = columns[29..37].*,
                .limb_markers = columns[37..41].*,
                .carries = columns[41..45].*,
                .result = columns[45..49].*,
                .destination = common.destinationFromColumns(columns[49..51]),
            },
        };
    }
};

pub const Constraints = common.ConstraintSet(N_CONSTRAINTS);

pub fn evaluate(row: Row) Constraints {
    var out: [N_CONSTRAINTS]QM31 = undefined;
    const core = shift.evaluate(row.semantic);
    @memcpy(out[0..shift.N_CONSTRAINTS], &core.values);
    out[shift.N_CONSTRAINTS] = row.imm_truncated.sub(shift.derive(row.semantic).shift_amount);
    return .{ .values = out };
}

pub fn placementConstraint(row: Row, is_active: QM31) QM31 {
    return row.semantic.active().sub(is_active);
}

pub fn programLookup(row: Row) common.ProgramTuple {
    return .{
        .pc = row.pc,
        .opcode_id = row.semantic.is_sll.mul(common.q(16))
            .add(row.semantic.is_srl.mul(common.q(17)))
            .add(row.semantic.is_sra.mul(common.q(18))),
        .rd = row.semantic.rd.addr,
        .rs1 = row.semantic.rs1.addr,
        .operand = row.imm_truncated,
    };
}

pub const AccessLookups = struct {
    rd: common.AccessChain,
    rs1: common.AccessChain,
};

pub fn accessLookups(row: Row) AccessLookups {
    return .{
        .rd = common.registerAccessChain(row.semantic.rd, row.clk),
        .rs1 = common.registerAccessChain(row.semantic.rs1, row.clk),
    };
}

pub fn stateLookup(row: Row) common.RegistersStateChain {
    return common.registersStateChain(row.pc, row.clk);
}

pub const carryRangePairs = shift.carryRangePairs;
pub const rdRangePairs = shift.rdRangePairs;
pub const signRangeLookup = shift.signRangeLookup;

fn slliByOneRow() Row {
    const rd = common.Access{
        .addr = common.q(1),
        .previous = .{QM31.zero()} ** 4,
        .previous_clock = QM31.zero(),
        .next = .{ common.q(2), QM31.zero(), QM31.zero(), QM31.zero() },
    };
    const rs1 = common.Access{
        .addr = common.q(2),
        .previous = .{QM31.zero()} ** 4,
        .previous_clock = QM31.zero(),
        .next = .{ QM31.one(), QM31.zero(), QM31.zero(), QM31.zero() },
    };
    return .{
        .clk = QM31.one(),
        .pc = common.q(0x1000),
        .imm_truncated = QM31.one(),
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

test "shifts imm: exact SLLI row is accepted" {
    var row = slliByOneRow();
    std.mem.doNotOptimizeAway(&row);
    try std.testing.expect(evaluate(row).allZero());
    try std.testing.expect(programLookup(row).opcode_id.eql(common.q(16)));
}

test "shifts imm: immediate and carry forgeries are rejected" {
    var row = slliByOneRow();
    row.imm_truncated = common.q(2);
    try std.testing.expect(!evaluate(row).allZero());

    row = slliByOneRow();
    row.semantic.carries[0] = QM31.one();
    try std.testing.expect(!evaluate(row).allZero());
}

test "shifts imm: adapter uses oracle access-first order" {
    var columns = [_]QM31{QM31.zero()} ** N_ORACLE_COLUMNS;
    columns[2] = common.q(11);
    columns[12] = common.q(12);
    columns[22] = common.q(13);
    columns[23] = common.q(14);
    columns[41] = common.q(15);
    const row = try Row.fromOracleColumns(&columns);
    try std.testing.expect(row.semantic.rd.addr.eql(common.q(11)));
    try std.testing.expect(row.semantic.rs1.addr.eql(common.q(12)));
    try std.testing.expect(row.semantic.rs1_sign.eql(common.q(13)));
    try std.testing.expect(row.imm_truncated.eql(common.q(14)));
    try std.testing.expect(row.semantic.carries[0].eql(common.q(15)));
}
