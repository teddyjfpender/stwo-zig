//! Exact pinned Stark-V `MUL` semantics and relation requests.
//!
//! The low-word product is enforced by four singleton `range_check_8_11`
//! lookups over the schoolbook carry chain. There is intentionally no direct
//! multiplication constraint: this is the degree-bounded upstream design.
//! Oracle: pinned `crates/air/src/schema.rs` and `runner/src/ops/muldiv.rs`.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const common = @import("common.zig");
const control = @import("control_common.zig");
const Opcode = @import("../program/opcode.zig").Opcode;

/// Exact generated `MulColumns` order at the pinned Stark-V revision.
pub const N_ORACLE_COLUMNS: usize = 39;
pub const N_CONSTRAINTS: usize = 16;
pub const LOOKUP_BATCH_SIZE: usize = 1;
pub const BITWISE_LOOKUP_COUNT: usize = 0;
pub const CURRENT_TRACE_COMPATIBLE = true;
pub const MISSING_CURRENT_WITNESS_COLUMNS = [_][]const u8{};

pub const Row = struct {
    enabler: QM31,
    clock: QM31,
    pc: QM31,
    rd: common.Access,
    rs1: common.Access,
    rs2: common.Access,
    result: [4]QM31,
    destination: common.Destination,

    pub fn fromOracleColumns(columns: []const QM31) !Row {
        if (columns.len != N_ORACLE_COLUMNS) return error.InvalidOracleTraceShape;
        return .{
            .enabler = columns[0],
            .clock = columns[1],
            .pc = columns[2],
            .rd = common.accessFromColumns(columns[3..13]),
            .rs1 = common.accessFromColumns(columns[13..23]),
            .rs2 = common.accessFromColumns(columns[23..33]),
            .result = columns[33..37].*,
            .destination = common.destinationFromColumns(columns[37..39]),
        };
    }
};

pub const Derived = struct {
    carries: [4]QM31,
};

pub fn derive(row: Row) Derived {
    @setEvalBranchQuota(100_000);
    const lhs = row.rs1.next;
    const rhs = row.rs2.next;
    const result = row.result;
    var carry: [4]QM31 = undefined;
    carry[0] = lhs[0].mul(rhs[0]).sub(result[0]).mul(common.INV_BYTE_RADIX);
    carry[1] = carry[0].add(lhs[1].mul(rhs[0])).add(lhs[0].mul(rhs[1]))
        .sub(result[1]).mul(common.INV_BYTE_RADIX);
    carry[2] = carry[1].add(lhs[2].mul(rhs[0])).add(lhs[1].mul(rhs[1]))
        .add(lhs[0].mul(rhs[2])).sub(result[2]).mul(common.INV_BYTE_RADIX);
    carry[3] = carry[2].add(lhs[3].mul(rhs[0])).add(lhs[2].mul(rhs[1]))
        .add(lhs[1].mul(rhs[2])).add(lhs[0].mul(rhs[3]))
        .sub(result[3]).mul(common.INV_BYTE_RADIX);
    return .{ .carries = carry };
}

pub const Constraints = common.ConstraintSet(N_CONSTRAINTS);

pub fn evaluate(row: Row) Constraints {
    var out: [N_CONSTRAINTS]QM31 = undefined;
    out[0] = row.enabler.mul(QM31.one().sub(row.enabler));
    @memcpy(out[1..4], &common.destinationConstraints(row.rd.addr, row.destination));
    @memcpy(
        out[4..8],
        &common.destinationResultConstraints(row.rd, row.result, row.destination),
    );
    // Source registers are read-only: the emitted `next` limbs must equal the
    // consumed `previous` limbs, otherwise the operand is a free prover choice
    // that is also written back onto the register bus.
    @memcpy(out[8..12], &common.readOnlyAccessConstraints(row.rs1, row.enabler));
    @memcpy(out[12..16], &common.readOnlyAccessConstraints(row.rs2, row.enabler));
    return .{ .values = out };
}

/// Binds the table-local enabler to the component placement selector.
pub fn placementConstraint(row: Row, is_active: QM31) QM31 {
    return row.enabler.sub(is_active);
}

pub fn programLookup(row: Row) common.ProgramTuple {
    return .{
        .pc = row.pc,
        .opcode_id = common.q(Opcode.mul.protocolId()),
        .rd = row.rd.addr,
        .rs1 = row.rs1.addr,
        .operand = row.rs2.addr,
    };
}

pub const Lookups = struct {
    /// Fields retain the exact `schema.rs` declaration order.
    program: control.Request(common.ProgramTuple),
    state: control.StateLookups,
    rs1: control.RegisterAccessLookups,
    rs2: control.RegisterAccessLookups,
    product_ranges: [4]control.Request(control.RangePairTuple),
    rd: control.RegisterAccessLookups,
};

pub fn lookups(row: Row) Lookups {
    const carries = derive(row).carries;
    var ranges: [4]control.Request(control.RangePairTuple) = undefined;
    for (&ranges, 0..) |*request, limb| {
        request.* = control.rangePairRequest(row.enabler, row.result[limb], carries[limb]);
    }
    return .{
        .program = control.programRequest(row.enabler, programLookup(row)),
        .state = control.stateLookups(
            row.pc,
            row.clock,
            row.pc.add(common.q(4)),
            row.enabler,
        ),
        .rs1 = control.registerAccessLookups(row.rs1, row.clock, row.enabler),
        .rs2 = control.registerAccessLookups(row.rs2, row.clock, row.enabler),
        .product_ranges = ranges,
        .rd = control.registerAccessLookups(row.rd, row.clock, row.enabler),
    };
}

fn zeroAccess() common.Access {
    return .{
        .addr = QM31.zero(),
        .previous = .{QM31.zero()} ** 4,
        .previous_clock = QM31.zero(),
        .next = .{QM31.zero()} ** 4,
    };
}

fn honestRow() Row {
    var rd = zeroAccess();
    rd.addr = common.q(3);
    rd.next = .{ common.q(1), QM31.zero(), QM31.zero(), QM31.zero() };
    var rs1 = zeroAccess();
    rs1.addr = common.q(1);
    rs1.next = .{common.q(255)} ** 4;
    rs1.previous = rs1.next;
    var rs2 = zeroAccess();
    rs2.addr = common.q(2);
    rs2.next = .{common.q(255)} ** 4;
    rs2.previous = rs2.next;
    return .{
        .enabler = QM31.one(),
        .clock = common.q(9),
        .pc = common.q(0x1000),
        .rd = rd,
        .rs1 = rs1,
        .rs2 = rs2,
        .result = rd.next,
        .destination = .{
            .nonzero = QM31.one(),
            .inverse = common.q(3).inv() catch unreachable,
        },
    };
}

test "mul: maximal operands produce exact bounded carry requests" {
    const row = honestRow();
    try std.testing.expect(evaluate(row).allZero());
    const requests = lookups(row);
    try std.testing.expect(requests.program.tuple.opcode_id.eql(common.q(37)));
    for (requests.product_ranges) |request| {
        const limb = try request.tuple.limb_0.tryIntoM31();
        const carry = try request.tuple.limb_1.tryIntoM31();
        try std.testing.expect(limb.toU32() < 256);
        try std.testing.expect(carry.toU32() < 2048);
        try std.testing.expect(request.numerator.eql(QM31.one().neg()));
    }
}

test "mul: forged low product is rejected by exact range request" {
    var row = honestRow();
    row.rs1.next = .{ QM31.one(), QM31.zero(), QM31.zero(), QM31.zero() };
    row.rs2.next = row.rs1.next;
    row.rd.next[0] = common.q(2);
    row.result[0] = common.q(2);
    const forged_carry = try derive(row).carries[0].tryIntoM31();
    try std.testing.expect(forged_carry.toU32() >= 2048);
}

test "mul: source register write-back forgery is rejected" {
    var forged_rs1 = honestRow();
    forged_rs1.rs1.previous = .{ common.q(5), QM31.zero(), QM31.zero(), QM31.zero() };
    try std.testing.expect(!evaluate(forged_rs1).allZero());

    var forged_rs2 = honestRow();
    forged_rs2.rs2.previous[3] = common.q(7);
    try std.testing.expect(!evaluate(forged_rs2).allZero());
}

test "mul: adapter starts with the generated enabler column" {
    var columns = [_]QM31{QM31.zero()} ** N_ORACLE_COLUMNS;
    columns[0] = common.q(1);
    columns[1] = common.q(2);
    columns[2] = common.q(3);
    columns[3] = common.q(4);
    columns[13] = common.q(5);
    columns[23] = common.q(6);
    const row = try Row.fromOracleColumns(&columns);
    try std.testing.expect(row.enabler.eql(common.q(1)));
    try std.testing.expect(row.clock.eql(common.q(2)));
    try std.testing.expect(row.rd.addr.eql(common.q(4)));
    try std.testing.expect(row.rs1.addr.eql(common.q(5)));
    try std.testing.expect(row.rs2.addr.eql(common.q(6)));
}
