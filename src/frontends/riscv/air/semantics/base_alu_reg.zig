//! Exact direct semantics for ADD/SUB and lookup requests for bitwise R-type
//! instructions, expressed over the full committed family-column layout.
//!
//! Oracle: `stark-v` `crates/air/src/schema.rs`, `base_alu_reg`, pinned by
//! `conformance/upstream.md`.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const common = @import("common.zig");

pub const N_ORACLE_COLUMNS: usize = 43;
pub const N_CONSTRAINTS: usize = 21;

pub const Row = struct {
    clk: QM31,
    pc: QM31,
    rd: common.Access,
    rs1: common.Access,
    rs2: common.Access,
    is_add: QM31,
    is_sub: QM31,
    is_xor: QM31,
    is_or: QM31,
    is_and: QM31,
    result: [4]QM31,
    destination: common.Destination,

    pub fn fromOracleColumns(columns: []const QM31) !Row {
        if (columns.len != N_ORACLE_COLUMNS) return error.InvalidOracleTraceShape;
        return .{
            .clk = columns[0],
            .pc = columns[1],
            .rd = common.accessFromColumns(columns[2..12]),
            .rs1 = common.accessFromColumns(columns[12..22]),
            .rs2 = common.accessFromColumns(columns[22..32]),
            .is_add = columns[32],
            .is_sub = columns[33],
            .is_xor = columns[34],
            .is_or = columns[35],
            .is_and = columns[36],
            .result = columns[37..41].*,
            .destination = common.destinationFromColumns(columns[41..43]),
        };
    }

    pub fn active(self: Row) QM31 {
        return self.is_add.add(self.is_sub).add(self.is_xor).add(self.is_or).add(self.is_and);
    }
};

pub const Constraints = common.ConstraintSet(N_CONSTRAINTS);

/// Direct AIR constraints. The byte-range lookups documented in
/// `rangeCheckPairs` and the decoded program lookup returned by
/// `programLookup` must be wired alongside these constraints.
pub fn evaluate(row: Row) Constraints {
    var out: [N_CONSTRAINTS]QM31 = undefined;
    var i: usize = 0;

    out[i] = common.bit(row.active());
    i += 1;
    const flags = [_]QM31{ row.is_add, row.is_sub, row.is_xor, row.is_or, row.is_and };
    for (flags) |flag| {
        out[i] = common.bit(flag);
        i += 1;
    }
    var carry = QM31.zero();
    for (0..4) |limb| {
        const numerator = row.rs1.next[limb].add(row.rs2.next[limb]).add(carry).sub(row.result[limb]);
        carry = numerator.mul(common.INV_BYTE_RADIX);
        out[i] = common.selected(row.is_add, common.bit(carry));
        i += 1;
    }

    carry = QM31.zero();
    for (0..4) |limb| {
        const numerator = row.result[limb].add(row.rs2.next[limb]).add(carry).sub(row.rs1.next[limb]);
        carry = numerator.mul(common.INV_BYTE_RADIX);
        out[i] = common.selected(row.is_sub, common.bit(carry));
        i += 1;
    }
    for (common.destinationConstraints(row.rd.addr, row.destination)) |constraint| {
        out[i] = constraint;
        i += 1;
    }
    for (common.destinationResultConstraints(row.rd, row.result, row.destination)) |constraint| {
        out[i] = constraint;
        i += 1;
    }
    std.debug.assert(i == out.len);
    return .{ .values = out };
}

pub fn placementConstraint(row: Row, is_active: QM31) QM31 {
    return row.active().sub(is_active);
}

/// The upstream opcode ids are protocol constants, not Zig enum ordinals.
pub fn programLookup(row: Row) common.ProgramTuple {
    const opcode_id = row.is_add.mul(common.q(0))
        .add(row.is_sub.mul(common.q(1)))
        .add(row.is_xor.mul(common.q(5)))
        .add(row.is_or.mul(common.q(8)))
        .add(row.is_and.mul(common.q(9)));
    return .{
        .pc = row.pc,
        .opcode_id = opcode_id,
        .rd = row.rd.addr,
        .rs1 = row.rs1.addr,
        .operand = row.rs2.addr,
    };
}

/// Bitwise table requests. The caller multiplies their LogUp numerators by
/// `is_xor + is_or + is_and`; ADD/SUB rows therefore emit no bitwise entries.
pub fn bitwiseLookups(row: Row) [4]common.BitwiseTuple {
    const operation_id = row.is_xor.mul(common.q(2)).add(row.is_or);
    var tuples: [4]common.BitwiseTuple = undefined;
    for (&tuples, 0..) |*tuple, i| {
        tuple.* = .{
            .lhs = row.rs1.next[i],
            .rhs = row.rs2.next[i],
            .result = row.result[i],
            .operation_id = operation_id,
        };
    }
    return tuples;
}

pub fn bitwiseLookupEnabler(row: Row) QM31 {
    return row.is_xor.add(row.is_or).add(row.is_and);
}

/// Each pair is one `range_check_8_8` request.
pub fn rangeCheckPairs(row: Row) [6][2]QM31 {
    return .{
        .{ row.result[0], row.result[1] },
        .{ row.result[2], row.result[3] },
        .{ row.rs1.next[0], row.rs1.next[1] },
        .{ row.rs1.next[2], row.rs1.next[3] },
        .{ row.rs2.next[0], row.rs2.next[1] },
        .{ row.rs2.next[2], row.rs2.next[3] },
    };
}

pub const AccessLookups = struct {
    rd: common.AccessChain,
    rs1: common.AccessChain,
    rs2: common.AccessChain,
};

/// Register-file state-chain entries. All three accesses emit at this AIR
/// row's clock, matching the pinned Stark-V schema.
pub fn accessLookups(row: Row) AccessLookups {
    return .{
        .rd = common.registerAccessChain(row.rd, row.clk),
        .rs1 = common.registerAccessChain(row.rs1, row.clk),
        .rs2 = common.registerAccessChain(row.rs2, row.clk),
    };
}

fn zeroRow() Row {
    const zero_access = common.Access{
        .addr = QM31.zero(),
        .previous = .{QM31.zero()} ** 4,
        .previous_clock = QM31.zero(),
        .next = .{QM31.zero()} ** 4,
    };
    return .{
        .clk = QM31.zero(),
        .pc = QM31.zero(),
        .is_add = QM31.zero(),
        .is_sub = QM31.zero(),
        .is_xor = QM31.zero(),
        .is_or = QM31.zero(),
        .is_and = QM31.zero(),
        .result = .{QM31.zero()} ** 4,
        .destination = .{ .nonzero = QM31.zero(), .inverse = QM31.zero() },
        .rd = zero_access,
        .rs1 = zero_access,
        .rs2 = zero_access,
    };
}

test "base alu reg semantics: ADD accepts byte carry chain" {
    var row = zeroRow();
    row.pc = common.q(0x1000);
    row.rd.addr = QM31.one();
    row.destination = .{ .nonzero = QM31.one(), .inverse = QM31.one() };
    row.is_add = QM31.one();
    row.rs1.next = .{ common.q(255), common.q(255), common.q(0), common.q(0) };
    row.rs2.next = .{ common.q(1), common.q(0), common.q(0), common.q(0) };
    row.rd.next = .{ common.q(0), common.q(0), common.q(1), common.q(0) };
    row.result = row.rd.next;
    try std.testing.expect(evaluate(row).allZero());
}

test "base alu reg semantics: ADD rejects a forged result" {
    var row = zeroRow();
    row.pc = common.q(0x1000);
    row.rd.addr = QM31.one();
    row.destination = .{ .nonzero = QM31.one(), .inverse = QM31.one() };
    row.is_add = QM31.one();
    row.rs1.next[0] = common.q(7);
    row.rs2.next[0] = common.q(9);
    row.rd.next[0] = common.q(17);
    row.result[0] = common.q(17);
    try std.testing.expect(!evaluate(row).allZero());
}

test "base alu reg semantics: x0 discards arithmetic and bitwise results" {
    var row = zeroRow();
    row.pc = common.q(0x1000);
    row.is_add = QM31.one();
    row.rs1.next[0] = common.q(7);
    row.rs2.next[0] = common.q(9);
    row.result[0] = common.q(16);
    try std.testing.expect(evaluate(row).allZero());

    row.is_add = QM31.zero();
    row.is_xor = QM31.one();
    try std.testing.expect(bitwiseLookupEnabler(row).eql(QM31.one()));
}

test "base alu reg semantics: SUB accepts unsigned wraparound" {
    var row = zeroRow();
    row.pc = common.q(0x1000);
    row.rd.addr = QM31.one();
    row.destination = .{ .nonzero = QM31.one(), .inverse = QM31.one() };
    row.is_sub = QM31.one();
    row.rs1.next = .{QM31.zero()} ** 4;
    row.rs2.next[0] = common.q(1);
    row.rd.next = .{ common.q(255), common.q(255), common.q(255), common.q(255) };
    row.result = row.rd.next;
    try std.testing.expect(evaluate(row).allZero());
}

test "base alu reg semantics: decoded tuple uses pinned Stark-V ids" {
    var row = zeroRow();
    row.is_xor = QM31.one();
    const tuple = programLookup(row);
    try std.testing.expect(tuple.opcode_id.eql(common.q(5)));
}

test "base alu reg semantics: access lookups consume previous and emit at row clock" {
    var row = zeroRow();
    row.clk = common.q(19);
    row.rs1.addr = common.q(7);
    row.rs1.previous_clock = common.q(11);
    row.rs1.previous[0] = common.q(41);
    row.rs1.next[0] = common.q(42);

    const chain = accessLookups(row).rs1;
    try std.testing.expect(chain.previous.addr_space.isZero());
    try std.testing.expect(chain.previous.addr.eql(common.q(7)));
    try std.testing.expect(chain.previous.clock.eql(common.q(11)));
    try std.testing.expect(chain.previous.limbs[0].eql(common.q(41)));
    try std.testing.expect(chain.next.clock.eql(common.q(19)));
    try std.testing.expect(chain.next.limbs[0].eql(common.q(42)));
    try std.testing.expect(chain.clock_gap.eql(common.q(8)));
}

test "base alu reg semantics: oracle adapter preserves access-first layout" {
    var columns = [_]QM31{QM31.zero()} ** N_ORACLE_COLUMNS;
    columns[2] = common.q(1);
    columns[3] = common.q(2);
    columns[7] = common.q(3);
    columns[8] = common.q(4);
    columns[12] = common.q(5);
    columns[17] = common.q(6);
    columns[18] = common.q(7);
    columns[22] = common.q(8);
    columns[27] = common.q(9);
    columns[28] = common.q(10);
    columns[32] = common.q(11);

    const row = try Row.fromOracleColumns(&columns);
    try std.testing.expect(row.rd.addr.eql(common.q(1)));
    try std.testing.expect(row.rd.previous[0].eql(common.q(2)));
    try std.testing.expect(row.rd.previous_clock.eql(common.q(3)));
    try std.testing.expect(row.rd.next[0].eql(common.q(4)));
    try std.testing.expect(row.rs1.addr.eql(common.q(5)));
    try std.testing.expect(row.rs1.previous_clock.eql(common.q(6)));
    try std.testing.expect(row.rs1.next[0].eql(common.q(7)));
    try std.testing.expect(row.rs2.addr.eql(common.q(8)));
    try std.testing.expect(row.rs2.previous_clock.eql(common.q(9)));
    try std.testing.expect(row.rs2.next[0].eql(common.q(10)));
    try std.testing.expect(row.is_add.eql(common.q(11)));
}
