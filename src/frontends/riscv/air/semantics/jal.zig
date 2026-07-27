//! Exact pinned Stark-V AIR semantics and lookup requests for JAL.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const common = @import("common.zig");
const control = @import("control_common.zig");
const Opcode = @import("../program/opcode.zig").Opcode;

pub fn Semantics(comptime S: type) type {
    return struct {
        const ops = common.Ops(S);
        const ctl = control.Ops(S);

        pub const N_MAIN_COLUMNS: usize = 20;
        pub const N_CONSTRAINTS: usize = 9;

        pub const Row = struct {
            enabler: S,
            clock: S,
            pc: S,
            rd: ops.Access,
            imm_felt: S,
            result: [4]S,
            destination: ops.Destination,

            pub fn fromMainColumns(columns: []const S) !Row {
                if (columns.len != N_MAIN_COLUMNS) return error.InvalidMainTraceShape;
                return .{
                    .enabler = columns[0],
                    .clock = columns[1],
                    .pc = columns[2],
                    .rd = ctl.accessFromColumns(columns, 3),
                    .imm_felt = columns[13],
                    .result = columns[14..18].*,
                    .destination = ops.destinationFromColumns(columns[18..20]),
                };
            }
        };

        pub const Constraints = ops.ConstraintSet(N_CONSTRAINTS);

        pub fn evaluate(row: Row) Constraints {
            var out: [N_CONSTRAINTS]S = undefined;
            out[0] = ops.bit(row.enabler);
            out[1] = row.enabler.mul(
                ops.composeU32(row.result).sub(row.pc.add(ops.q(4))),
            );
            @memcpy(out[2..5], &ops.destinationConstraints(row.rd.addr, row.destination));
            @memcpy(
                out[5..9],
                &ops.destinationResultConstraints(row.rd, row.result, row.destination),
            );
            return .{ .values = out };
        }

        pub fn placementConstraint(row: Row, is_active: S) S {
            return row.enabler.sub(is_active);
        }

        pub fn programLookup(row: Row) ops.ProgramTuple {
            return .{
                .pc = row.pc,
                .opcode_id = ops.q(Opcode.jal.protocolId()),
                .rd = row.rd.addr,
                .rs1 = row.imm_felt,
                .operand = S.zero(),
            };
        }

        pub const RdLookups = struct {
            /// The pinned schema currently contains the same predecessor request twice.
            /// Keeping both entries is required for byte-for-byte relation parity.
            consume: [2]ctl.Request(ops.MemoryAccessTuple),
            emit: ctl.Request(ops.MemoryAccessTuple),
            clock_gap: ctl.Request(ctl.Range20Tuple),
        };

        pub const RangeLookups = struct {
            middle_bytes: ctl.Request(ctl.RangePairTuple),
            m31_split: ctl.Request(ctl.RangePairTuple),
        };

        pub const Lookups = struct {
            program: ctl.Request(ops.ProgramTuple),
            state: ctl.StateLookups,
            rd: RdLookups,
            ranges: RangeLookups,
        };

        pub fn lookups(row: Row) Lookups {
            const chain = ops.registerAccessChain(row.rd, row.clock);
            const consume = ctl.Request(ops.MemoryAccessTuple){
                .numerator = row.enabler.neg(),
                .tuple = chain.previous,
            };
            return .{
                .program = ctl.programRequest(row.enabler, programLookup(row)),
                .state = ctl.stateLookups(
                    row.pc,
                    row.clock,
                    row.pc.add(row.imm_felt),
                    row.enabler,
                ),
                .rd = .{
                    .consume = .{ consume, consume },
                    .emit = .{ .numerator = row.enabler, .tuple = chain.next },
                    .clock_gap = ctl.range20Request(row.enabler, chain.clock_gap),
                },
                .ranges = .{
                    .middle_bytes = ctl.rangePairRequest(
                        row.enabler,
                        row.result[1],
                        row.result[2],
                    ),
                    .m31_split = ctl.rangePairRequest(
                        row.enabler,
                        row.result[0],
                        row.result[3],
                    ),
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
                .imm_felt = S.zero(),
                .result = .{S.zero()} ** 4,
                .destination = .{ .nonzero = S.zero(), .inverse = S.zero() },
            };
        }

        /// Family self-tests.  Wrapped in a function so only the shipped
        /// QM31 instantiation below compiles them: their bodies use field
        /// operations (`inv`, `eql`, `tryIntoM31`) that are deliberately
        /// absent from the scalar interface the extraction instantiates.
        fn selfTests() type {
            return struct {
                test "jal: honest jump binds link register and target" {
                    var row = zeroRow();
                    row.enabler = S.one();
                    row.clock = ops.q(12);
                    row.pc = ops.q(0x1000);
                    row.imm_felt = ops.q(24);
                    row.rd.addr = S.one();
                    row.rd.next = .{ ops.q(4), ops.q(0x10), S.zero(), S.zero() };
                    row.result = row.rd.next;
                    row.destination = .{ .nonzero = S.one(), .inverse = S.one() };
                    try std.testing.expect(evaluate(row).allZero());

                    const requests = lookups(row);
                    try std.testing.expect(requests.program.tuple.opcode_id.eql(ops.q(33)));
                    try std.testing.expect(requests.program.tuple.rs1.eql(ops.q(24)));
                    try std.testing.expect(requests.state.emit.tuple.pc.eql(ops.q(0x1018)));
                    try std.testing.expect(requests.state.emit.tuple.clock.eql(ops.q(13)));
                }

                test "jal: forged link register is rejected" {
                    var row = zeroRow();
                    row.enabler = S.one();
                    row.pc = ops.q(100);
                    row.rd.addr = S.one();
                    row.destination = .{ .nonzero = S.one(), .inverse = S.one() };
                    row.rd.next[0] = ops.q(105);
                    row.result[0] = ops.q(105);
                    try std.testing.expect(!evaluate(row).allZero());
                }

                test "jal: lookup list preserves pinned duplicate predecessor request" {
                    var row = zeroRow();
                    row.enabler = S.one();
                    row.rd.addr = ops.q(4);
                    row.rd.previous_clock = ops.q(3);
                    row.rd.previous[0] = ops.q(9);
                    const requests = lookups(row).rd;
                    try std.testing.expect(requests.consume[0].tuple.addr.eql(requests.consume[1].tuple.addr));
                    try std.testing.expect(requests.consume[0].tuple.clock.eql(requests.consume[1].tuple.clock));
                    try std.testing.expect(requests.consume[0].tuple.limbs[0].eql(requests.consume[1].tuple.limbs[0]));
                }

                test "jal: exact adapter has upstream enabler first" {
                    var columns = [_]S{S.zero()} ** N_MAIN_COLUMNS;
                    columns[0] = ops.q(1);
                    columns[3] = ops.q(2);
                    columns[8] = ops.q(3);
                    columns[9] = ops.q(4);
                    columns[13] = ops.q(5);
                    const row = try Row.fromMainColumns(&columns);
                    try std.testing.expect(row.enabler.eql(ops.q(1)));
                    try std.testing.expect(row.rd.addr.eql(ops.q(2)));
                    try std.testing.expect(row.rd.previous_clock.eql(ops.q(3)));
                    try std.testing.expect(row.rd.next[0].eql(ops.q(4)));
                    try std.testing.expect(row.imm_felt.eql(ops.q(5)));
                }
            };
        }
    };
}

comptime {
    _ = Semantics(QM31).selfTests();
}
