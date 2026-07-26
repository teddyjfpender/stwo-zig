//! Exact direct semantics for the base ALU immediate family.
//!
//! The committed trace carries Stark-V's exact 12-bit decomposition so byte
//! carries cannot alias through the M31 modulus.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const common = @import("common.zig");

pub const N_ORACLE_COLUMNS: usize = 35;
pub const N_CONSTRAINTS: usize = 21;

pub const Row = struct {
    clk: QM31,
    pc: QM31,
    rd: common.Access,
    rs1: common.Access,
    imm_0: QM31,
    imm_1: QM31,
    imm_msb: QM31,
    is_addi: QM31,
    is_xori: QM31,
    is_ori: QM31,
    is_andi: QM31,
    result: [4]QM31,
    destination: common.Destination,

    pub fn fromOracleColumns(columns: []const QM31) !Row {
        if (columns.len != N_ORACLE_COLUMNS) return error.InvalidOracleTraceShape;
        return .{
            .clk = columns[0],
            .pc = columns[1],
            .rd = common.accessFromColumns(columns[2..12]),
            .rs1 = common.accessFromColumns(columns[12..22]),
            .imm_0 = columns[22],
            .imm_1 = columns[23],
            .imm_msb = columns[24],
            .is_addi = columns[25],
            .is_xori = columns[26],
            .is_ori = columns[27],
            .is_andi = columns[28],
            .result = columns[29..33].*,
            .destination = common.destinationFromColumns(columns[33..35]),
        };
    }

    pub fn active(self: Row) QM31 {
        return self.is_addi.add(self.is_xori).add(self.is_ori).add(self.is_andi);
    }
};

pub const Constraints = common.ConstraintSet(N_CONSTRAINTS);

fn immediateLimbs(row: Row) [4]QM31 {
    // Sign extension of `[imm_0:8, imm_1:3, sign:1]` to four bytes.
    const limb_1 = row.imm_1.add(row.imm_msb.mul(common.q(248)));
    const fill = row.imm_msb.mul(common.q(255));
    return .{ row.imm_0, limb_1, fill, fill };
}

pub fn unsignedImmediate(row: Row) QM31 {
    return row.imm_0
        .add(row.imm_1.mul(common.q(1 << 8)))
        .add(row.imm_msb.mul(common.q(1 << 11)));
}

/// Exact direct constraints, conditional on the documented immediate and
/// register-limb range lookups.
pub fn evaluate(row: Row) Constraints {
    var out: [N_CONSTRAINTS]QM31 = undefined;
    var i: usize = 0;

    out[i] = common.bit(row.active());
    i += 1;
    const flags = [_]QM31{ row.is_addi, row.is_xori, row.is_ori, row.is_andi };
    for (flags) |flag| {
        out[i] = common.bit(flag);
        i += 1;
    }
    out[i] = common.bit(row.imm_msb);
    i += 1;
    const imm = immediateLimbs(row);
    var carry = QM31.zero();
    for (0..4) |limb| {
        const numerator = row.rs1.next[limb].add(imm[limb]).add(carry).sub(row.result[limb]);
        carry = numerator.mul(common.INV_BYTE_RADIX);
        out[i] = common.selected(row.is_addi, common.bit(carry));
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
    // rs1 is read-only: it must emit exactly the value it consumed.
    for (common.readOnlyAccessConstraints(row.rs1, row.active())) |constraint| {
        out[i] = constraint;
        i += 1;
    }
    std.debug.assert(i == out.len);
    return .{ .values = out };
}

pub fn placementConstraint(row: Row, is_active: QM31) QM31 {
    return row.active().sub(is_active);
}

pub fn programLookup(row: Row) common.ProgramTuple {
    const opcode_id = row.is_addi.mul(common.q(10))
        .add(row.is_xori.mul(common.q(13)))
        .add(row.is_ori.mul(common.q(14)))
        .add(row.is_andi.mul(common.q(15)));
    return .{
        .pc = row.pc,
        .opcode_id = opcode_id,
        .rd = row.rd.addr,
        .rs1 = row.rs1.addr,
        .operand = unsignedImmediate(row),
    };
}

pub fn bitwiseLookups(row: Row) [4]common.BitwiseTuple {
    const operation_id = row.is_xori.mul(common.q(2)).add(row.is_ori);
    const imm = immediateLimbs(row);
    var tuples: [4]common.BitwiseTuple = undefined;
    for (&tuples, 0..) |*tuple, i| {
        tuple.* = .{
            .lhs = row.rs1.next[i],
            .rhs = imm[i],
            .result = row.result[i],
            .operation_id = operation_id,
        };
    }
    return tuples;
}

pub fn bitwiseLookupEnabler(row: Row) QM31 {
    return row.is_xori.add(row.is_ori).add(row.is_andi);
}

/// Inputs for the upstream `range_check_8_11` immediate lookup. The second
/// coordinate is shifted by eight bits exactly as in the pinned schema.
pub fn immediateRangeLookup(row: Row) [2]QM31 {
    return .{ row.imm_0, row.imm_1.mul(common.q(1 << 8)) };
}

pub fn registerRangeCheckPairs(row: Row) [4][2]QM31 {
    return .{
        .{ row.result[0], row.result[1] },
        .{ row.result[2], row.result[3] },
        .{ row.rs1.next[0], row.rs1.next[1] },
        .{ row.rs1.next[2], row.rs1.next[3] },
    };
}

pub const AccessLookups = struct {
    rd: common.AccessChain,
    rs1: common.AccessChain,
};

pub fn accessLookups(row: Row) AccessLookups {
    return .{
        .rd = common.registerAccessChain(row.rd, row.clk),
        .rs1 = common.registerAccessChain(row.rs1, row.clk),
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
        .is_addi = QM31.zero(),
        .is_xori = QM31.zero(),
        .is_ori = QM31.zero(),
        .is_andi = QM31.zero(),
        .imm_0 = QM31.zero(),
        .imm_1 = QM31.zero(),
        .imm_msb = QM31.zero(),
        .result = .{QM31.zero()} ** 4,
        .destination = .{ .nonzero = QM31.zero(), .inverse = QM31.zero() },
        .rd = zero_access,
        .rs1 = zero_access,
    };
}

test "base alu imm semantics: exact ADDI accepts an honest row" {
    var row = zeroRow();
    row.pc = common.q(0x1000);
    row.rd.addr = QM31.one();
    row.destination = .{ .nonzero = QM31.one(), .inverse = QM31.one() };
    row.is_addi = QM31.one();
    row.imm_0 = common.q(1);
    row.rd.next[0] = common.q(1);
    row.result[0] = common.q(1);
    try std.testing.expect(evaluate(row).allZero());
}

test "base alu imm semantics: rs1 must emit the value it consumed" {
    var row = zeroRow();
    row.pc = common.q(0x1000);
    row.rd.addr = QM31.one();
    row.destination = .{ .nonzero = QM31.one(), .inverse = QM31.one() };
    row.is_addi = QM31.one();
    row.imm_0 = common.q(1);
    row.rs1.next[0] = common.q(41);
    row.rs1.previous = row.rs1.next;
    row.rd.next[0] = common.q(42);
    row.result[0] = common.q(42);
    try std.testing.expect(evaluate(row).allZero());

    // The addition runs on `next`; forging `previous` turns the source read
    // into an arbitrary register write and must be rejected.
    row.rs1.previous[0] = common.q(0xbe);
    try std.testing.expect(!evaluate(row).allZero());
}

test "base alu imm semantics: exact ADDI rejects known impossible witness" {
    var row = zeroRow();
    row.pc = common.q(0x1000);
    row.rd.addr = QM31.one();
    row.destination = .{ .nonzero = QM31.one(), .inverse = QM31.one() };
    row.is_addi = QM31.one();
    row.imm_0 = common.q(1);
    // The pre-existing prover test claimed ADDI x1,x1,1 while rs1 remained 0
    // and rd advanced to 2. The byte carry constraint must reject that row.
    row.rs1.next[0] = common.q(0);
    row.rd.next[0] = common.q(2);
    row.result[0] = common.q(2);
    try std.testing.expect(!evaluate(row).allZero());
}

test "base alu imm semantics: byte carries reject M31 word alias" {
    var row = zeroRow();
    row.pc = common.q(0x1000);
    row.rd.addr = QM31.one();
    row.destination = .{ .nonzero = QM31.one(), .inverse = QM31.one() };
    row.is_addi = QM31.one();
    // 0x7fffffff is the M31 modulus, so a single reconstructed word equation
    // would confuse this forged result with zero. Per-byte carries do not.
    row.rd.next = .{ common.q(255), common.q(255), common.q(255), common.q(127) };
    row.result = row.rd.next;
    try std.testing.expect(common.composeU32(row.rd.next).isZero());
    try std.testing.expect(!evaluate(row).allZero());
}

test "base alu imm semantics: x0 discards arithmetic and bitwise results" {
    var row = zeroRow();
    row.pc = common.q(0x1000);
    row.is_addi = QM31.one();
    row.imm_0 = common.q(1);
    row.result[0] = common.q(1);
    try std.testing.expect(evaluate(row).allZero());

    row.is_addi = QM31.zero();
    row.is_xori = QM31.one();
    try std.testing.expect(bitwiseLookupEnabler(row).eql(QM31.one()));
}

test "base alu imm semantics: negative immediate sign extends by bytes" {
    var row = zeroRow();
    row.pc = common.q(0x1000);
    row.rd.addr = QM31.one();
    row.destination = .{ .nonzero = QM31.one(), .inverse = QM31.one() };
    row.is_addi = QM31.one();
    row.imm_0 = common.q(255);
    row.imm_1 = common.q(7);
    row.imm_msb = QM31.one();
    row.rs1.next = .{QM31.zero()} ** 4;
    row.rd.next = .{ common.q(255), common.q(255), common.q(255), common.q(255) };
    row.result = row.rd.next;
    try std.testing.expect(evaluate(row).allZero());

    const tuple = programLookup(row);
    try std.testing.expect(tuple.opcode_id.eql(common.q(10)));
    try std.testing.expect(tuple.operand.eql(common.q(4095)));
}

test "base alu imm semantics: access lookups preserve register chain values" {
    var row = zeroRow();
    row.clk = common.q(23);
    row.rd.addr = common.q(3);
    row.rd.previous_clock = common.q(17);
    row.rd.previous[2] = common.q(90);
    row.rd.next[2] = common.q(91);

    const chain = accessLookups(row).rd;
    try std.testing.expect(chain.previous.addr.eql(common.q(3)));
    try std.testing.expect(chain.previous.clock.eql(common.q(17)));
    try std.testing.expect(chain.previous.limbs[2].eql(common.q(90)));
    try std.testing.expect(chain.next.clock.eql(common.q(23)));
    try std.testing.expect(chain.next.limbs[2].eql(common.q(91)));
    try std.testing.expect(chain.clock_gap.eql(common.q(6)));
}

test "base alu imm semantics: oracle adapter preserves access-first layout" {
    var columns = [_]QM31{QM31.zero()} ** N_ORACLE_COLUMNS;
    columns[2] = common.q(1);
    columns[3] = common.q(2);
    columns[7] = common.q(3);
    columns[8] = common.q(4);
    columns[12] = common.q(5);
    columns[13] = common.q(6);
    columns[17] = common.q(7);
    columns[18] = common.q(8);
    columns[22] = common.q(9);
    columns[25] = common.q(10);

    const row = try Row.fromOracleColumns(&columns);
    try std.testing.expect(row.rd.addr.eql(common.q(1)));
    try std.testing.expect(row.rd.previous[0].eql(common.q(2)));
    try std.testing.expect(row.rd.previous_clock.eql(common.q(3)));
    try std.testing.expect(row.rd.next[0].eql(common.q(4)));
    try std.testing.expect(row.rs1.addr.eql(common.q(5)));
    try std.testing.expect(row.rs1.previous[0].eql(common.q(6)));
    try std.testing.expect(row.rs1.previous_clock.eql(common.q(7)));
    try std.testing.expect(row.rs1.next[0].eql(common.q(8)));
    try std.testing.expect(row.imm_0.eql(common.q(9)));
    try std.testing.expect(row.is_addi.eql(common.q(10)));
}
