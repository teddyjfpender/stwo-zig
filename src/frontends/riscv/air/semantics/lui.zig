//! Exact pinned Stark-V AIR semantics and lookup requests for LUI.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const common = @import("common.zig");
const control = @import("control_common.zig");
const Opcode = @import("../program/opcode.zig").Opcode;

pub const N_MAIN_COLUMNS: usize = 18;
pub const N_CONSTRAINTS: usize = 8;

pub const Row = struct {
    enabler: QM31,
    clock: QM31,
    pc: QM31,
    rd: common.Access,
    imm_0: QM31,
    imm_1: QM31,
    imm_2: QM31,
    destination: common.Destination,

    pub fn fromMainColumns(columns: []const QM31) !Row {
        if (columns.len != N_MAIN_COLUMNS) return error.InvalidMainTraceShape;
        return .{
            .enabler = columns[0],
            .clock = columns[1],
            .pc = columns[2],
            .rd = control.accessFromColumns(columns, 3),
            .imm_0 = columns[13],
            .imm_1 = columns[14],
            .imm_2 = columns[15],
            .destination = common.destinationFromColumns(columns[16..18]),
        };
    }
};

pub const Constraints = common.ConstraintSet(N_CONSTRAINTS);

pub fn evaluate(row: Row) Constraints {
    var out: [N_CONSTRAINTS]QM31 = undefined;
    out[0] = common.bit(row.enabler);
    @memcpy(out[1..4], &common.destinationConstraints(row.rd.addr, row.destination));
    @memcpy(
        out[4..8],
        &common.destinationResultConstraints(row.rd, resultLimbs(row), row.destination),
    );
    return .{ .values = out };
}

pub fn placementConstraint(row: Row, is_active: QM31) QM31 {
    return row.enabler.sub(is_active);
}

pub fn immediate(row: Row) QM31 {
    return row.imm_0
        .add(row.imm_1.mul(common.q(1 << 4)))
        .add(row.imm_2.mul(common.q(1 << 12)));
}

pub fn resultLimbs(row: Row) [4]QM31 {
    return .{ QM31.zero(), row.imm_0.mul(common.q(1 << 4)), row.imm_1, row.imm_2 };
}

pub fn programLookup(row: Row) common.ProgramTuple {
    return .{
        .pc = row.pc,
        .opcode_id = common.q(Opcode.lui.protocolId()),
        .rd = row.rd.addr,
        .rs1 = immediate(row),
        .operand = QM31.zero(),
    };
}

pub const RdLookups = struct {
    consume: control.Request(common.MemoryAccessTuple),
    emit: control.Request(common.MemoryAccessTuple),
    clock_gap: control.Request(control.Range20Tuple),
};

pub const Lookups = struct {
    program: control.Request(common.ProgramTuple),
    state: control.StateLookups,
    immediate_range: control.Request(control.RangeTripleTuple),
    rd: RdLookups,
};

pub fn lookups(row: Row) Lookups {
    const chain = common.registerAccessChain(row.rd, row.clock);
    return .{
        .program = control.programRequest(row.enabler, programLookup(row)),
        .state = control.stateLookups(
            row.pc,
            row.clock,
            row.pc.add(common.q(4)),
            row.enabler,
        ),
        .immediate_range = .{
            .numerator = row.enabler.neg(),
            .tuple = .{ .limb_0 = row.imm_1, .limb_1 = row.imm_2, .limb_2 = row.imm_0 },
        },
        .rd = .{
            .consume = .{ .numerator = row.enabler.neg(), .tuple = chain.previous },
            .emit = .{
                .numerator = row.enabler,
                .tuple = chain.next,
            },
            .clock_gap = control.range20Request(row.enabler, chain.clock_gap),
        },
    };
}

fn zeroRow() Row {
    return .{
        .enabler = QM31.zero(),
        .clock = QM31.zero(),
        .pc = QM31.zero(),
        .rd = .{
            .addr = QM31.zero(),
            .previous = .{QM31.zero()} ** 4,
            .previous_clock = QM31.zero(),
            .next = .{QM31.zero()} ** 4,
        },
        .imm_0 = QM31.zero(),
        .imm_1 = QM31.zero(),
        .imm_2 = QM31.zero(),
        .destination = .{ .nonzero = QM31.zero(), .inverse = QM31.zero() },
    };
}

test "lui: exact lookup writes the decomposed upper immediate" {
    var row = zeroRow();
    row.enabler = QM31.one();
    row.clock = common.q(8);
    row.pc = common.q(0x1000);
    row.rd.addr = common.q(7);
    row.destination = .{
        .nonzero = QM31.one(),
        .inverse = common.q(7).inv() catch unreachable,
    };
    row.imm_0 = common.q(0xc);
    row.imm_1 = common.q(0xab);
    row.imm_2 = common.q(0xde);
    row.rd.next = resultLimbs(row);
    try std.testing.expect(evaluate(row).allZero());

    const requests = lookups(row);
    try std.testing.expect(requests.program.tuple.opcode_id.eql(common.q(35)));
    try std.testing.expect(requests.program.tuple.rs1.eql(common.q(0xdeabc)));
    try std.testing.expect(requests.rd.emit.tuple.limbs[0].isZero());
    try std.testing.expect(requests.rd.emit.tuple.limbs[1].eql(common.q(0xc0)));
    try std.testing.expect(requests.rd.emit.tuple.limbs[2].eql(common.q(0xab)));
    try std.testing.expect(requests.rd.emit.tuple.limbs[3].eql(common.q(0xde)));
    try std.testing.expect(requests.immediate_range.tuple.limb_2.eql(common.q(0xc)));
}

test "lui: forged non-boolean enabler is rejected" {
    var row = zeroRow();
    row.enabler = common.q(2);
    try std.testing.expect(!evaluate(row).allZero());
}

test "lui: exact adapter has upstream enabler first" {
    var columns = [_]QM31{QM31.zero()} ** N_MAIN_COLUMNS;
    columns[0] = common.q(1);
    columns[3] = common.q(2);
    columns[8] = common.q(3);
    columns[9] = common.q(4);
    columns[13] = common.q(5);
    columns[15] = common.q(6);
    const row = try Row.fromMainColumns(&columns);
    try std.testing.expect(row.enabler.eql(common.q(1)));
    try std.testing.expect(row.rd.addr.eql(common.q(2)));
    try std.testing.expect(row.rd.previous_clock.eql(common.q(3)));
    try std.testing.expect(row.rd.next[0].eql(common.q(4)));
    try std.testing.expect(row.imm_0.eql(common.q(5)));
    try std.testing.expect(row.imm_2.eql(common.q(6)));
}
