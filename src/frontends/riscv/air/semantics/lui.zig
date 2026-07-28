//! Exact pinned Stark-V AIR semantics and lookup requests for LUI.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const common = @import("common.zig");
const control = @import("control_common.zig");
const Opcode = @import("../program/opcode.zig").Opcode;

pub fn Semantics(comptime S: type) type {
    return struct {
        const ops = common.Ops(S);
        const ctl = control.Ops(S);

        pub const N_MAIN_COLUMNS: usize = 18;
        pub const N_CONSTRAINTS: usize = 8;

        pub const Row = struct {
            enabler: S,
            clock: S,
            pc: S,
            rd: ops.Access,
            imm_0: S,
            imm_1: S,
            imm_2: S,
            destination: ops.Destination,

            pub fn fromMainColumns(columns: []const S) !Row {
                if (columns.len != N_MAIN_COLUMNS) return error.InvalidMainTraceShape;
                return .{
                    .enabler = columns[0],
                    .clock = columns[1],
                    .pc = columns[2],
                    .rd = ctl.accessFromColumns(columns, 3),
                    .imm_0 = columns[13],
                    .imm_1 = columns[14],
                    .imm_2 = columns[15],
                    .destination = ops.destinationFromColumns(columns[16..18]),
                };
            }
        };

        pub const Constraints = ops.ConstraintSet(N_CONSTRAINTS);

        pub fn evaluate(row: Row) Constraints {
            var out: [N_CONSTRAINTS]S = undefined;
            out[0] = ops.bit(row.enabler);
            @memcpy(out[1..4], &ops.destinationConstraints(row.rd.addr, row.destination));
            @memcpy(
                out[4..8],
                &ops.destinationResultConstraints(row.rd, resultLimbs(row), row.destination),
            );
            return .{ .values = out };
        }

        pub fn placementConstraint(row: Row, is_active: S) S {
            return row.enabler.sub(is_active);
        }

        pub fn immediate(row: Row) S {
            return row.imm_0
                .add(row.imm_1.mul(ops.q(1 << 4)))
                .add(row.imm_2.mul(ops.q(1 << 12)));
        }

        pub fn resultLimbs(row: Row) [4]S {
            return .{ S.zero(), row.imm_0.mul(ops.q(1 << 4)), row.imm_1, row.imm_2 };
        }

        pub fn programLookup(row: Row) ops.ProgramTuple {
            return .{
                .pc = row.pc,
                .opcode_id = ops.q(Opcode.lui.protocolId()),
                .rd = row.rd.addr,
                .rs1 = immediate(row),
                .operand = S.zero(),
            };
        }

        pub const RdLookups = struct {
            consume: ctl.Request(ops.MemoryAccessTuple),
            emit: ctl.Request(ops.MemoryAccessTuple),
            clock_gap: ctl.Request(ctl.Range20Tuple),
        };

        pub const Lookups = struct {
            program: ctl.Request(ops.ProgramTuple),
            state: ctl.StateLookups,
            immediate_range: ctl.Request(ctl.RangeTripleTuple),
            rd: RdLookups,
        };

        pub fn lookups(row: Row) Lookups {
            const chain = ops.registerAccessChain(row.rd, row.clock, .first);
            return .{
                .program = ctl.programRequest(row.enabler, programLookup(row)),
                .state = ctl.stateLookups(
                    row.pc,
                    row.clock,
                    row.pc.add(ops.q(4)),
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
                    .clock_gap = ctl.range20Request(row.enabler, chain.clock_gap),
                },
            };
        }

        fn zeroRow() Row {
            return .{
                .enabler = S.zero(),
                .clock = S.zero(),
                .pc = S.zero(),
                .rd = .{
                    .addr = S.zero(),
                    .previous = .{S.zero()} ** 4,
                    .previous_clock = S.zero(),
                    .next = .{S.zero()} ** 4,
                },
                .imm_0 = S.zero(),
                .imm_1 = S.zero(),
                .imm_2 = S.zero(),
                .destination = .{ .nonzero = S.zero(), .inverse = S.zero() },
            };
        }

        /// Family self-tests.  Wrapped in a function so only the shipped
        /// QM31 instantiation below compiles them: their bodies use field
        /// operations (`inv`, `eql`, `tryIntoM31`) that are deliberately
        /// absent from the scalar interface the extraction instantiates.
        fn selfTests() type {
            return struct {
                test "lui: exact lookup writes the decomposed upper immediate" {
                    var row = zeroRow();
                    row.enabler = S.one();
                    row.clock = ops.q(8);
                    row.pc = ops.q(0x1000);
                    row.rd.addr = ops.q(7);
                    row.destination = .{
                        .nonzero = S.one(),
                        .inverse = ops.q(7).inv() catch unreachable,
                    };
                    row.imm_0 = ops.q(0xc);
                    row.imm_1 = ops.q(0xab);
                    row.imm_2 = ops.q(0xde);
                    row.rd.next = resultLimbs(row);
                    try std.testing.expect(evaluate(row).allZero());

                    const requests = lookups(row);
                    try std.testing.expect(requests.program.tuple.opcode_id.eql(ops.q(35)));
                    try std.testing.expect(requests.program.tuple.rs1.eql(ops.q(0xdeabc)));
                    try std.testing.expect(requests.rd.emit.tuple.limbs[0].isZero());
                    try std.testing.expect(requests.rd.emit.tuple.limbs[1].eql(ops.q(0xc0)));
                    try std.testing.expect(requests.rd.emit.tuple.limbs[2].eql(ops.q(0xab)));
                    try std.testing.expect(requests.rd.emit.tuple.limbs[3].eql(ops.q(0xde)));
                    try std.testing.expect(requests.immediate_range.tuple.limb_2.eql(ops.q(0xc)));
                }

                test "lui: forged non-boolean enabler is rejected" {
                    var row = zeroRow();
                    row.enabler = ops.q(2);
                    try std.testing.expect(!evaluate(row).allZero());
                }

                test "lui: exact adapter has upstream enabler first" {
                    var columns = [_]S{S.zero()} ** N_MAIN_COLUMNS;
                    columns[0] = ops.q(1);
                    columns[3] = ops.q(2);
                    columns[8] = ops.q(3);
                    columns[9] = ops.q(4);
                    columns[13] = ops.q(5);
                    columns[15] = ops.q(6);
                    const row = try Row.fromMainColumns(&columns);
                    try std.testing.expect(row.enabler.eql(ops.q(1)));
                    try std.testing.expect(row.rd.addr.eql(ops.q(2)));
                    try std.testing.expect(row.rd.previous_clock.eql(ops.q(3)));
                    try std.testing.expect(row.rd.next[0].eql(ops.q(4)));
                    try std.testing.expect(row.imm_0.eql(ops.q(5)));
                    try std.testing.expect(row.imm_2.eql(ops.q(6)));
                }
            };
        }
    };
}

comptime {
    _ = Semantics(QM31).selfTests();
}
