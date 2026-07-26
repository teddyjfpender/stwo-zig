//! Sail-compatible base-I FENCE semantics for the single-hart zkVM profile.
//!
//! Sail treats every funct3=000 MISC-MEM encoding as FENCE, including
//! forward-compatible values of fm, pred/succ, rs1, and rd. The proof binds
//! those fields to the fetched word while retiring the instruction as a
//! state-only no-op.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const common = @import("common.zig");
const control = @import("control_common.zig");
const Opcode = @import("../program/opcode.zig").Opcode;

pub const N_MAIN_COLUMNS: usize = 6;
pub const N_CONSTRAINTS: usize = 1;
pub const CURRENT_TRACE_COMPATIBLE = true;

pub const Row = struct {
    enabler: QM31,
    clock: QM31,
    pc: QM31,
    rd: QM31,
    rs1: QM31,
    immediate: QM31,

    pub fn fromMainColumns(columns: []const QM31) !Row {
        if (columns.len != N_MAIN_COLUMNS) return error.InvalidMainTraceShape;
        return .{
            .enabler = columns[0],
            .clock = columns[1],
            .pc = columns[2],
            .rd = columns[3],
            .rs1 = columns[4],
            .immediate = columns[5],
        };
    }
};

pub const Constraints = common.ConstraintSet(N_CONSTRAINTS);

pub fn evaluate(row: Row) Constraints {
    return .{ .values = .{common.bit(row.enabler)} };
}

pub fn placementConstraint(row: Row, is_active: QM31) QM31 {
    return row.enabler.sub(is_active);
}

pub fn programLookup(row: Row) common.ProgramTuple {
    return .{
        .pc = row.pc,
        .opcode_id = common.q(Opcode.fence.protocolId()),
        .rd = row.rd,
        .rs1 = row.rs1,
        .operand = row.immediate,
    };
}

pub const Lookups = struct {
    program: control.Request(common.ProgramTuple),
    state: control.StateLookups,
};

pub fn lookups(row: Row) Lookups {
    return .{
        .program = control.programRequest(row.enabler, programLookup(row)),
        .state = control.stateLookups(
            row.pc,
            row.clock,
            row.pc.add(common.q(4)),
            row.enabler,
        ),
    };
}

fn zeroRow() Row {
    return .{
        .enabler = QM31.zero(),
        .clock = QM31.zero(),
        .pc = QM31.zero(),
        .rd = QM31.zero(),
        .rs1 = QM31.zero(),
        .immediate = QM31.zero(),
    };
}

test "fence: reserved fields remain word-bound while execution is a no-op" {
    var row = zeroRow();
    row.enabler = QM31.one();
    row.clock = common.q(7);
    row.pc = common.q(0x1000);
    row.rd = common.q(31);
    row.rs1 = common.q(17);
    row.immediate = common.q(0xf53);
    try std.testing.expect(evaluate(row).allZero());

    const requests = lookups(row);
    try std.testing.expect(requests.program.tuple.opcode_id.eql(common.q(45)));
    try std.testing.expect(requests.program.tuple.rd.eql(common.q(31)));
    try std.testing.expect(requests.program.tuple.rs1.eql(common.q(17)));
    try std.testing.expect(requests.program.tuple.operand.eql(common.q(0xf53)));
    try std.testing.expect(requests.state.emit.tuple.pc.eql(common.q(0x1004)));
    try std.testing.expect(requests.state.emit.tuple.clock.eql(common.q(8)));
}

test "fence: forged active selector is rejected" {
    var row = zeroRow();
    row.enabler = common.q(2);
    try std.testing.expect(!evaluate(row).allZero());
}

test "fence: exact adapter preserves every committed field" {
    const columns = [_]QM31{
        common.q(1),
        common.q(2),
        common.q(3),
        common.q(4),
        common.q(5),
        common.q(6),
    };
    const row = try Row.fromMainColumns(&columns);
    try std.testing.expect(row.enabler.eql(common.q(1)));
    try std.testing.expect(row.clock.eql(common.q(2)));
    try std.testing.expect(row.pc.eql(common.q(3)));
    try std.testing.expect(row.rd.eql(common.q(4)));
    try std.testing.expect(row.rs1.eql(common.q(5)));
    try std.testing.expect(row.immediate.eql(common.q(6)));
}
