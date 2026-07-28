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

pub fn Semantics(comptime S: type) type {
    return struct {
        const ops = common.Ops(S);
        const ctl = control.Ops(S);

        pub const N_MAIN_COLUMNS: usize = 6;
        pub const N_CONSTRAINTS: usize = 1;
        pub const CURRENT_TRACE_COMPATIBLE = true;

        pub const Row = struct {
            enabler: S,
            clock: S,
            pc: S,
            rd: S,
            rs1: S,
            immediate: S,

            pub fn fromMainColumns(columns: []const S) !Row {
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

        pub const Constraints = ops.ConstraintSet(N_CONSTRAINTS);

        pub fn evaluate(row: Row) Constraints {
            return .{ .values = .{ops.bit(row.enabler)} };
        }

        pub fn placementConstraint(row: Row, is_active: S) S {
            return row.enabler.sub(is_active);
        }

        pub fn programLookup(row: Row) ops.ProgramTuple {
            return .{
                .pc = row.pc,
                .opcode_id = ops.q(Opcode.fence.protocolId()),
                .rd = row.rd,
                .rs1 = row.rs1,
                .operand = row.immediate,
            };
        }

        pub const Lookups = struct {
            program: ctl.Request(ops.ProgramTuple),
            state: ctl.StateLookups,
        };

        pub fn lookups(row: Row) Lookups {
            return .{
                .program = ctl.programRequest(row.enabler, programLookup(row)),
                .state = ctl.stateLookups(
                    row.pc,
                    row.clock,
                    row.pc.add(ops.q(4)),
                    row.enabler,
                ),
            };
        }

        fn zeroRow() Row {
            return .{
                .enabler = S.zero(),
                .clock = S.zero(),
                .pc = S.zero(),
                .rd = S.zero(),
                .rs1 = S.zero(),
                .immediate = S.zero(),
            };
        }

        /// Family self-tests.  Wrapped in a function so only the shipped
        /// QM31 instantiation below compiles them: their bodies use field
        /// operations (`inv`, `eql`, `tryIntoM31`) that are deliberately
        /// absent from the scalar interface the extraction instantiates.
        fn selfTests() type {
            return struct {
                test "fence: reserved fields remain word-bound while execution is a no-op" {
                    var row = zeroRow();
                    row.enabler = S.one();
                    row.clock = ops.q(7);
                    row.pc = ops.q(0x1000);
                    row.rd = ops.q(31);
                    row.rs1 = ops.q(17);
                    row.immediate = ops.q(0xf53);
                    try std.testing.expect(evaluate(row).allZero());

                    const requests = lookups(row);
                    try std.testing.expect(requests.program.tuple.opcode_id.eql(ops.q(45)));
                    try std.testing.expect(requests.program.tuple.rd.eql(ops.q(31)));
                    try std.testing.expect(requests.program.tuple.rs1.eql(ops.q(17)));
                    try std.testing.expect(requests.program.tuple.operand.eql(ops.q(0xf53)));
                    try std.testing.expect(requests.state.emit.tuple.pc.eql(ops.q(0x1004)));
                    try std.testing.expect(requests.state.emit.tuple.clock.eql(ops.q(8)));
                }

                test "fence: forged active selector is rejected" {
                    var row = zeroRow();
                    row.enabler = ops.q(2);
                    try std.testing.expect(!evaluate(row).allZero());
                }

                test "fence: exact adapter preserves every committed field" {
                    const columns = [_]S{
                        ops.q(1),
                        ops.q(2),
                        ops.q(3),
                        ops.q(4),
                        ops.q(5),
                        ops.q(6),
                    };
                    const row = try Row.fromMainColumns(&columns);
                    try std.testing.expect(row.enabler.eql(ops.q(1)));
                    try std.testing.expect(row.clock.eql(ops.q(2)));
                    try std.testing.expect(row.pc.eql(ops.q(3)));
                    try std.testing.expect(row.rd.eql(ops.q(4)));
                    try std.testing.expect(row.rs1.eql(ops.q(5)));
                    try std.testing.expect(row.immediate.eql(ops.q(6)));
                }
            };
        }
    };
}

comptime {
    _ = Semantics(QM31).selfTests();
}
