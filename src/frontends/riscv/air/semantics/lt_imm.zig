//! Exact pinned Stark-V SLTI/SLTIU semantics and lookup requests.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const common = @import("common.zig");

pub const N_ORACLE_COLUMNS: usize = 37;
pub const N_CONSTRAINTS: usize = 32;
pub const CURRENT_TRACE_COMPATIBLE = true;

pub const Row = struct {
    clk: QM31,
    pc: QM31,
    rd: common.Access,
    rs1: common.Access,
    cmp_result: QM31,
    rs1_msl_felt: QM31,
    imm_0: QM31,
    imm_1: QM31,
    imm_msb: QM31,
    is_slti: QM31,
    is_sltiu: QM31,
    diff_markers: [4]QM31,
    diff_val: QM31,
    destination: common.Destination,
    imm_msl_felt: QM31,

    pub fn active(self: Row) QM31 {
        return self.is_slti.add(self.is_sltiu);
    }

    pub fn fromOracleColumns(columns: []const QM31) !Row {
        if (columns.len != N_ORACLE_COLUMNS) return error.InvalidOracleTraceShape;
        return .{
            .clk = columns[0],
            .pc = columns[1],
            .rd = common.accessFromColumns(columns[2..12]),
            .rs1 = common.accessFromColumns(columns[12..22]),
            .cmp_result = columns[22],
            .rs1_msl_felt = columns[23],
            .imm_0 = columns[24],
            .imm_1 = columns[25],
            .imm_msb = columns[26],
            .is_slti = columns[27],
            .is_sltiu = columns[28],
            .diff_markers = columns[29..33].*,
            .diff_val = columns[33],
            .destination = common.destinationFromColumns(columns[34..36]),
            .imm_msl_felt = columns[36],
        };
    }
};

pub const Derived = struct {
    imm: QM31,
    sext_imm_1: QM31,
    sext_imm_2: QM31,
    expected_imm_msl: QM31,
    rs1_msl_gap: QM31,
    rs1_msl_shifted: QM31,
    imm_1_doubled: QM31,
    prefix_sum: QM31,
    cmp_sign: QM31,
};

pub fn derive(row: Row) Derived {
    const sext_2 = row.imm_msb.mul(common.q(255));
    var prefix = QM31.zero();
    for (row.diff_markers) |marker| prefix = prefix.add(marker);
    return .{
        .imm = row.imm_0.add(row.imm_1.mul(common.q(256))).add(row.imm_msb.mul(common.q(2048))),
        .sext_imm_1 = row.imm_1.add(row.imm_msb.mul(common.q(248))),
        .sext_imm_2 = sext_2,
        .expected_imm_msl = row.is_sltiu.mul(sext_2).sub(row.is_slti.mul(row.imm_msb)),
        .rs1_msl_gap = row.rs1.next[3].sub(row.rs1_msl_felt),
        .rs1_msl_shifted = row.rs1_msl_felt.add(row.is_slti.mul(common.q(128))),
        .imm_1_doubled = row.imm_1.mul(common.q(2)),
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
    out[n] = common.bit(row.is_slti);
    n += 1;
    out[n] = common.bit(row.is_sltiu);
    n += 1;

    out[n] = common.bit(row.imm_msb);
    n += 1;
    // Materializing the selected signed/unsigned top limb keeps the comparison
    // constraints cubic. Inlining this quadratic selector into the oriented
    // comparison would make the AIR quartic and require another blowup bit.
    out[n] = row.imm_msl_felt.sub(d.expected_imm_msl);
    n += 1;
    out[n] = d.rs1_msl_gap.mul(common.q(256).sub(d.rs1_msl_gap));
    n += 1;
    for (row.diff_markers) |marker| {
        out[n] = common.bit(marker);
        n += 1;
    }

    const lhs = [_]QM31{ row.rs1.next[0], row.rs1.next[1], row.rs1.next[2], row.rs1_msl_felt };
    const rhs = [_]QM31{ row.imm_0, d.sext_imm_1, d.sext_imm_2, row.imm_msl_felt };
    var more_significant = QM31.zero();
    var limb: usize = 4;
    while (limb > 0) {
        limb -= 1;
        const marker = row.diff_markers[limb];
        const oriented = d.cmp_sign.mul(rhs[limb].sub(lhs[limb]));
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
    out[n] = common.bit(row.cmp_result);
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
    // The source register is read-only: its emitted `next` limbs must equal
    // the consumed `previous` limbs. `rd` is pinned by the result link above.
    for (common.readOnlyAccessConstraints(row.rs1, row.active())) |constraint| {
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
    const d = derive(row);
    return .{
        .pc = row.pc,
        .opcode_id = row.is_slti.mul(common.q(11)).add(row.is_sltiu.mul(common.q(12))),
        .rd = row.rd.addr,
        .rs1 = row.rs1.addr,
        .operand = d.imm,
    };
}

pub const AccessLookups = struct { rd: common.AccessChain, rs1: common.AccessChain };

pub fn accessLookups(row: Row) AccessLookups {
    return .{
        .rd = common.registerAccessChain(row.rd, row.clk),
        .rs1 = common.registerAccessChain(row.rs1, row.clk),
    };
}

pub fn stateLookup(row: Row) common.RegistersStateChain {
    return common.registersStateChain(row.pc, row.clk);
}

pub fn immediateRangeLookup(row: Row) [3]QM31 {
    const d = derive(row);
    return .{ d.rs1_msl_shifted, row.imm_0, d.imm_1_doubled };
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
    rs1.previous[0] = QM31.one();
    return .{
        .clk = QM31.one(),
        .pc = common.q(0x1000),
        .rd = rd,
        .rs1 = rs1,
        .cmp_result = QM31.one(),
        .rs1_msl_felt = QM31.zero(),
        .imm_0 = common.q(2),
        .imm_1 = QM31.zero(),
        .imm_msb = QM31.zero(),
        .is_slti = QM31.zero(),
        .is_sltiu = QM31.one(),
        .diff_markers = .{ QM31.one(), QM31.zero(), QM31.zero(), QM31.zero() },
        .diff_val = QM31.one(),
        .destination = .{ .nonzero = QM31.one(), .inverse = QM31.one() },
        .imm_msl_felt = QM31.zero(),
    };
}

test "lt imm: exact unsigned comparison is accepted" {
    var row = honestUnsignedRow();
    std.mem.doNotOptimizeAway(&row);
    try std.testing.expect(evaluate(row).allZero());
    try std.testing.expect(programLookup(row).operand.eql(common.q(2)));
}

test "lt imm: forged result and malformed immediate are rejected" {
    var row = honestUnsignedRow();
    row.cmp_result = QM31.zero();
    try std.testing.expect(!evaluate(row).allZero());
    row = honestUnsignedRow();
    row.imm_msb = common.q(2);
    try std.testing.expect(!evaluate(row).allZero());
    row = honestUnsignedRow();
    row.imm_msl_felt = QM31.one();
    try std.testing.expect(!evaluate(row).allZero());
}

test "lt imm: read-only source access must emit the value it consumed" {
    var row = honestUnsignedRow();
    // The comparison runs over `next`, so swapping the consumed value is only
    // caught by the read-only binding.
    row.rs1.previous = .{ common.q(0xef), common.q(0xbe), common.q(0xad), common.q(0xde) };
    try std.testing.expect(!evaluate(row).allZero());

    // The destination write stays unbound to `previous`: rd.next is pinned by
    // the result link instead, so an honest changed rd value still accepts.
    row = honestUnsignedRow();
    row.rd.previous = .{ common.q(9), common.q(9), common.q(9), common.q(9) };
    try std.testing.expect(evaluate(row).allZero());
}

test "lt imm: adapter preserves exact immediate decomposition" {
    var columns = [_]QM31{QM31.zero()} ** N_ORACLE_COLUMNS;
    columns[22] = common.q(10);
    columns[24] = common.q(11);
    columns[25] = common.q(12);
    columns[26] = common.q(13);
    columns[33] = common.q(14);
    columns[36] = common.q(15);
    const row = try Row.fromOracleColumns(&columns);
    try std.testing.expect(row.cmp_result.eql(common.q(10)));
    try std.testing.expect(row.imm_0.eql(common.q(11)));
    try std.testing.expect(row.imm_1.eql(common.q(12)));
    try std.testing.expect(row.imm_msb.eql(common.q(13)));
    try std.testing.expect(row.diff_val.eql(common.q(14)));
    try std.testing.expect(row.imm_msl_felt.eql(common.q(15)));
}
