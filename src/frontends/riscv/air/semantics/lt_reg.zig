//! Exact pinned Stark-V SLT/SLTU semantics and lookup requests.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const common = @import("common.zig");

pub const N_ORACLE_COLUMNS: usize = 44;
pub const N_CONSTRAINTS: usize = 27;
pub const CURRENT_TRACE_COMPATIBLE = true;

pub const Row = struct {
    clk: QM31,
    pc: QM31,
    rd: common.Access,
    rs1: common.Access,
    rs2: common.Access,
    cmp_result: QM31,
    rs1_msl_felt: QM31,
    rs2_msl_felt: QM31,
    is_slt: QM31,
    is_sltu: QM31,
    diff_markers: [4]QM31,
    diff_val: QM31,
    destination: common.Destination,

    pub fn active(self: Row) QM31 {
        return self.is_slt.add(self.is_sltu);
    }

    pub fn fromOracleColumns(columns: []const QM31) !Row {
        if (columns.len != N_ORACLE_COLUMNS) return error.InvalidOracleTraceShape;
        return .{
            .clk = columns[0],
            .pc = columns[1],
            .rd = common.accessFromColumns(columns[2..12]),
            .rs1 = common.accessFromColumns(columns[12..22]),
            .rs2 = common.accessFromColumns(columns[22..32]),
            .cmp_result = columns[32],
            .rs1_msl_felt = columns[33],
            .rs2_msl_felt = columns[34],
            .is_slt = columns[35],
            .is_sltu = columns[36],
            .diff_markers = columns[37..41].*,
            .diff_val = columns[41],
            .destination = common.destinationFromColumns(columns[42..44]),
        };
    }
};

pub const Derived = struct {
    rs1_msl_gap: QM31,
    rs2_msl_gap: QM31,
    rs1_msl_shifted: QM31,
    rs2_msl_shifted: QM31,
    prefix_sum: QM31,
    cmp_sign: QM31,
};

pub fn derive(row: Row) Derived {
    var prefix = QM31.zero();
    for (row.diff_markers) |marker| prefix = prefix.add(marker);
    return .{
        .rs1_msl_gap = row.rs1.next[3].sub(row.rs1_msl_felt),
        .rs2_msl_gap = row.rs2.next[3].sub(row.rs2_msl_felt),
        .rs1_msl_shifted = row.rs1_msl_felt.add(row.is_slt.mul(common.q(128))),
        .rs2_msl_shifted = row.rs2_msl_felt.add(row.is_slt.mul(common.q(128))),
        .prefix_sum = prefix,
        .cmp_sign = row.cmp_result.mul(common.q(2)).sub(QM31.one()),
    };
}

pub const Constraints = common.ConstraintSet(N_CONSTRAINTS);

pub fn evaluate(row: Row) Constraints {
    var out: [N_CONSTRAINTS]QM31 = undefined;
    var n: usize = 0;
    const d = derive(row);

    out[n] = common.bit(row.active());
    n += 1;
    out[n] = common.bit(row.is_slt);
    n += 1;
    out[n] = common.bit(row.is_sltu);
    n += 1;

    out[n] = common.bit(row.cmp_result);
    n += 1;
    for (row.diff_markers) |marker| {
        out[n] = common.bit(marker);
        n += 1;
    }
    out[n] = d.rs1_msl_gap.mul(common.q(256).sub(d.rs1_msl_gap));
    n += 1;
    out[n] = d.rs2_msl_gap.mul(common.q(256).sub(d.rs2_msl_gap));
    n += 1;

    var more_significant = QM31.zero();
    var limb: usize = 4;
    while (limb > 0) {
        limb -= 1;
        const marker = row.diff_markers[limb];
        const lhs = if (limb == 3) row.rs1_msl_felt else row.rs1.next[limb];
        const rhs = if (limb == 3) row.rs2_msl_felt else row.rs2.next[limb];
        const oriented = d.cmp_sign.mul(rhs.sub(lhs));
        out[n] = QM31.one().sub(more_significant).sub(marker).mul(oriented);
        n += 1;
        out[n] = marker.mul(row.diff_val.sub(oriented));
        n += 1;
        more_significant = more_significant.add(marker);
    }
    out[n] = d.prefix_sum.mul(QM31.one().sub(d.prefix_sum));
    n += 1;
    out[n] = QM31.one().sub(d.prefix_sum).mul(row.cmp_result);
    n += 1;
    for (common.destinationConstraints(row.rd.addr, row.destination)) |constraint| {
        out[n] = constraint;
        n += 1;
    }
    for (common.destinationResultConstraints(
        row.rd,
        .{ row.cmp_result, QM31.zero(), QM31.zero(), QM31.zero() },
        row.destination,
    )) |constraint| {
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
    return .{
        .pc = row.pc,
        .opcode_id = row.is_slt.mul(common.q(3)).add(row.is_sltu.mul(common.q(4))),
        .rd = row.rd.addr,
        .rs1 = row.rs1.addr,
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
        .rd = common.registerAccessChain(row.rd, row.clk),
        .rs1 = common.registerAccessChain(row.rs1, row.clk),
        .rs2 = common.registerAccessChain(row.rs2, row.clk),
    };
}

pub fn stateLookup(row: Row) common.RegistersStateChain {
    return common.registersStateChain(row.pc, row.clk);
}

pub fn mslRangeLookup(row: Row) [2]QM31 {
    const d = derive(row);
    return .{ d.rs1_msl_shifted, d.rs2_msl_shifted };
}

pub const PositiveDiffLookup = struct { numerator: QM31, value: QM31 };

pub fn positiveDiffLookup(row: Row) PositiveDiffLookup {
    return .{ .numerator = derive(row).prefix_sum, .value = row.diff_val.sub(QM31.one()) };
}

fn zeroAccess() common.Access {
    return .{
        .addr = QM31.zero(),
        .previous = .{QM31.zero()} ** 4,
        .previous_clock = QM31.zero(),
        .next = .{QM31.zero()} ** 4,
    };
}

fn honestUnsignedRow() Row {
    var rd = zeroAccess();
    rd.addr = QM31.one();
    rd.next[0] = QM31.one();
    var rs1 = zeroAccess();
    rs1.addr = common.q(2);
    rs1.next[0] = QM31.one();
    var rs2 = zeroAccess();
    rs2.addr = common.q(3);
    rs2.next[0] = common.q(2);
    return .{
        .clk = QM31.one(),
        .pc = common.q(0x1000),
        .rd = rd,
        .rs1 = rs1,
        .rs2 = rs2,
        .cmp_result = QM31.one(),
        .rs1_msl_felt = QM31.zero(),
        .rs2_msl_felt = QM31.zero(),
        .is_slt = QM31.zero(),
        .is_sltu = QM31.one(),
        .diff_markers = .{ QM31.one(), QM31.zero(), QM31.zero(), QM31.zero() },
        .diff_val = QM31.one(),
        .destination = .{ .nonzero = QM31.one(), .inverse = QM31.one() },
    };
}

test "lt reg: exact unsigned comparison is accepted" {
    var row = honestUnsignedRow();
    std.mem.doNotOptimizeAway(&row);
    try std.testing.expect(evaluate(row).allZero());
    try std.testing.expect(programLookup(row).opcode_id.eql(common.q(4)));
    try std.testing.expect(accessLookups(row).rd.next.limbs[0].eql(QM31.one()));
}

test "lt reg: forged result and multiple diff markers are rejected" {
    var row = honestUnsignedRow();
    row.cmp_result = QM31.zero();
    try std.testing.expect(!evaluate(row).allZero());
    row = honestUnsignedRow();
    row.diff_markers[1] = QM31.one();
    try std.testing.expect(!evaluate(row).allZero());
}

test "lt reg: signed negative-to-zero comparison uses M31 limbs" {
    var row = honestUnsignedRow();
    row.is_slt = QM31.one();
    row.is_sltu = QM31.zero();
    row.rs1.next = .{ common.q(255), common.q(255), common.q(255), common.q(255) };
    row.rs2.next = .{QM31.zero()} ** 4;
    row.rs1_msl_felt = QM31.zero().sub(QM31.one());
    row.rs2_msl_felt = QM31.zero();
    row.diff_markers = .{ QM31.zero(), QM31.zero(), QM31.zero(), QM31.one() };
    row.diff_val = QM31.one();
    try std.testing.expect(evaluate(row).allZero());
}

test "lt reg: adapter preserves oracle witness order" {
    var columns = [_]QM31{QM31.zero()} ** N_ORACLE_COLUMNS;
    columns[2] = common.q(10);
    columns[32] = common.q(11);
    columns[37] = common.q(12);
    columns[41] = common.q(13);
    const row = try Row.fromOracleColumns(&columns);
    try std.testing.expect(row.rd.addr.eql(common.q(10)));
    try std.testing.expect(row.cmp_result.eql(common.q(11)));
    try std.testing.expect(row.diff_markers[0].eql(common.q(12)));
    try std.testing.expect(row.diff_val.eql(common.q(13)));
}
