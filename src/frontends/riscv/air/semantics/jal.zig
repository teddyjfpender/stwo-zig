//! Exact pinned Stark-V AIR semantics and lookup requests for JAL.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const common = @import("common.zig");
const control = @import("control_common.zig");
const Opcode = @import("../program/opcode.zig").Opcode;

pub const N_MAIN_COLUMNS: usize = 20;
pub const N_CONSTRAINTS: usize = 9;

pub const Row = struct {
    enabler: QM31,
    clock: QM31,
    pc: QM31,
    rd: common.Access,
    imm_felt: QM31,
    result: [4]QM31,
    destination: common.Destination,

    pub fn fromMainColumns(columns: []const QM31) !Row {
        if (columns.len != N_MAIN_COLUMNS) return error.InvalidMainTraceShape;
        return .{
            .enabler = columns[0],
            .clock = columns[1],
            .pc = columns[2],
            .rd = control.accessFromColumns(columns, 3),
            .imm_felt = columns[13],
            .result = columns[14..18].*,
            .destination = common.destinationFromColumns(columns[18..20]),
        };
    }
};

pub const Constraints = common.ConstraintSet(N_CONSTRAINTS);

pub fn evaluate(row: Row) Constraints {
    var out: [N_CONSTRAINTS]QM31 = undefined;
    out[0] = common.bit(row.enabler);
    out[1] = row.enabler.mul(
        common.composeU32(row.result).sub(row.pc.add(common.q(4))),
    );
    @memcpy(out[2..5], &common.destinationConstraints(row.rd.addr, row.destination));
    @memcpy(
        out[5..9],
        &common.destinationResultConstraints(row.rd, row.result, row.destination),
    );
    return .{ .values = out };
}

pub fn placementConstraint(row: Row, is_active: QM31) QM31 {
    return row.enabler.sub(is_active);
}

pub fn programLookup(row: Row) common.ProgramTuple {
    return .{
        .pc = row.pc,
        .opcode_id = common.q(Opcode.jal.protocolId()),
        .rd = row.rd.addr,
        .rs1 = row.imm_felt,
        .operand = QM31.zero(),
    };
}

pub const RdLookups = struct {
    /// The pinned schema currently contains the same predecessor request twice.
    /// Keeping both entries is required for byte-for-byte relation parity.
    consume: [2]control.Request(common.MemoryAccessTuple),
    emit: control.Request(common.MemoryAccessTuple),
    clock_gap: control.Request(control.Range20Tuple),
};

pub const RangeLookups = struct {
    middle_bytes: control.Request(control.RangePairTuple),
    m31_split: control.Request(control.RangePairTuple),
};

pub const Lookups = struct {
    program: control.Request(common.ProgramTuple),
    state: control.StateLookups,
    rd: RdLookups,
    ranges: RangeLookups,
};

pub fn lookups(row: Row) Lookups {
    const chain = common.registerAccessChain(row.rd, row.clock);
    const consume = control.Request(common.MemoryAccessTuple){
        .numerator = row.enabler.neg(),
        .tuple = chain.previous,
    };
    return .{
        .program = control.programRequest(row.enabler, programLookup(row)),
        .state = control.stateLookups(
            row.pc,
            row.clock,
            row.pc.add(row.imm_felt),
            row.enabler,
        ),
        .rd = .{
            .consume = .{ consume, consume },
            .emit = .{ .numerator = row.enabler, .tuple = chain.next },
            .clock_gap = control.range20Request(row.enabler, chain.clock_gap),
        },
        .ranges = .{
            .middle_bytes = control.rangePairRequest(
                row.enabler,
                row.result[1],
                row.result[2],
            ),
            .m31_split = control.rangePairRequest(
                row.enabler,
                row.result[0],
                row.result[3],
            ),
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
        .imm_felt = QM31.zero(),
        .result = .{QM31.zero()} ** 4,
        .destination = .{ .nonzero = QM31.zero(), .inverse = QM31.zero() },
    };
}

test "jal: honest jump binds link register and target" {
    var row = zeroRow();
    row.enabler = QM31.one();
    row.clock = common.q(12);
    row.pc = common.q(0x1000);
    row.imm_felt = common.q(24);
    row.rd.addr = QM31.one();
    row.rd.next = .{ common.q(4), common.q(0x10), QM31.zero(), QM31.zero() };
    row.result = row.rd.next;
    row.destination = .{ .nonzero = QM31.one(), .inverse = QM31.one() };
    try std.testing.expect(evaluate(row).allZero());

    const requests = lookups(row);
    try std.testing.expect(requests.program.tuple.opcode_id.eql(common.q(33)));
    try std.testing.expect(requests.program.tuple.rs1.eql(common.q(24)));
    try std.testing.expect(requests.state.emit.tuple.pc.eql(common.q(0x1018)));
    try std.testing.expect(requests.state.emit.tuple.clock.eql(common.q(13)));
}

test "jal: forged link register is rejected" {
    var row = zeroRow();
    row.enabler = QM31.one();
    row.pc = common.q(100);
    row.rd.addr = QM31.one();
    row.destination = .{ .nonzero = QM31.one(), .inverse = QM31.one() };
    row.rd.next[0] = common.q(105);
    row.result[0] = common.q(105);
    try std.testing.expect(!evaluate(row).allZero());
}

test "jal: lookup list preserves pinned duplicate predecessor request" {
    var row = zeroRow();
    row.enabler = QM31.one();
    row.rd.addr = common.q(4);
    row.rd.previous_clock = common.q(3);
    row.rd.previous[0] = common.q(9);
    const requests = lookups(row).rd;
    try std.testing.expect(requests.consume[0].tuple.addr.eql(requests.consume[1].tuple.addr));
    try std.testing.expect(requests.consume[0].tuple.clock.eql(requests.consume[1].tuple.clock));
    try std.testing.expect(requests.consume[0].tuple.limbs[0].eql(requests.consume[1].tuple.limbs[0]));
}

test "jal: exact adapter has upstream enabler first" {
    var columns = [_]QM31{QM31.zero()} ** N_MAIN_COLUMNS;
    columns[0] = common.q(1);
    columns[3] = common.q(2);
    columns[8] = common.q(3);
    columns[9] = common.q(4);
    columns[13] = common.q(5);
    const row = try Row.fromMainColumns(&columns);
    try std.testing.expect(row.enabler.eql(common.q(1)));
    try std.testing.expect(row.rd.addr.eql(common.q(2)));
    try std.testing.expect(row.rd.previous_clock.eql(common.q(3)));
    try std.testing.expect(row.rd.next[0].eql(common.q(4)));
    try std.testing.expect(row.imm_felt.eql(common.q(5)));
}
