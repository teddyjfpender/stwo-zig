//! Exact pinned Stark-V SLL/SRL/SRA semantics and lookup requests.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const common = @import("common.zig");
const shift = @import("shift_common.zig");

pub fn Semantics(comptime S: type) type {
    return struct {
        const ops = common.Ops(S);
        const sh = shift.Semantics(S);

        pub const N_ORACLE_COLUMNS: usize = 60;
        pub const N_CONSTRAINTS: usize = sh.N_CONSTRAINTS + 4;
        pub const CURRENT_TRACE_COMPATIBLE = true;

        pub const Row = struct {
            clk: S,
            pc: S,
            rs2: ops.Access,
            semantic: sh.Row,

            /// Pinned `define_trace_tables!` committed-column order.
            pub fn fromOracleColumns(columns: []const S) !Row {
                if (columns.len != N_ORACLE_COLUMNS) return error.InvalidOracleTraceShape;
                const rd = ops.accessFromColumns(columns[2..12]);
                const rs1 = ops.accessFromColumns(columns[12..22]);
                const rs2 = ops.accessFromColumns(columns[22..32]);
                return .{
                    .clk = columns[0],
                    .pc = columns[1],
                    .rs2 = rs2,
                    .semantic = .{
                        .rd = rd,
                        .rs1 = rs1,
                        .rs1_sign = columns[32],
                        .is_sll = columns[33],
                        .is_srl = columns[34],
                        .is_sra = columns[35],
                        .bit_multiplier_left = columns[36],
                        .bit_multiplier_right = columns[37],
                        .bit_markers = columns[38..46].*,
                        .limb_markers = columns[46..50].*,
                        .carries = columns[50..54].*,
                        .result = columns[54..58].*,
                        .destination = ops.destinationFromColumns(columns[58..60]),
                    },
                };
            }
        };

        pub const Constraints = ops.ConstraintSet(N_CONSTRAINTS);

        pub fn evaluate(row: Row) Constraints {
            var out: [N_CONSTRAINTS]S = undefined;
            const core = sh.evaluate(row.semantic);
            @memcpy(out[0..sh.N_CONSTRAINTS], &core.values);
            // rs2 is read-only: it must emit exactly the value it consumed.
            @memcpy(
                out[sh.N_CONSTRAINTS..],
                &ops.readOnlyAccessConstraints(row.rs2, row.semantic.active()),
            );
            return .{ .values = out };
        }

        pub fn placementConstraint(row: Row, is_active: S) S {
            return row.semantic.active().sub(is_active);
        }

        pub fn programLookup(row: Row) ops.ProgramTuple {
            return .{
                .pc = row.pc,
                .opcode_id = row.semantic.is_sll.mul(ops.q(2))
                    .add(row.semantic.is_srl.mul(ops.q(6)))
                    .add(row.semantic.is_sra.mul(ops.q(7))),
                .rd = row.semantic.rd.addr,
                .rs1 = row.semantic.rs1.addr,
                .operand = row.rs2.addr,
            };
        }

        pub const AccessLookups = struct {
            rd: ops.AccessChain,
            rs1: ops.AccessChain,
            rs2: ops.AccessChain,
        };

        pub fn accessLookups(row: Row) AccessLookups {
            return .{
                .rd = ops.registerAccessChain(row.semantic.rd, row.clk),
                .rs1 = ops.registerAccessChain(row.semantic.rs1, row.clk),
                .rs2 = ops.registerAccessChain(row.rs2, row.clk),
            };
        }

        pub fn stateLookup(row: Row) ops.RegistersStateChain {
            return ops.registersStateChain(row.pc, row.clk);
        }

        pub fn shiftAmountRangeLookup(row: Row) S {
            const amount = sh.derive(row.semantic).shift_amount;
            return ops.q(7).sub(row.rs2.next[0].sub(amount).mul(ops.INV_32()));
        }

        pub const carryRangePairs = sh.carryRangePairs;
        pub const rdRangePairs = sh.rdRangePairs;
        pub const signRangeLookup = sh.signRangeLookup;

        fn zeroAccess() ops.Access {
            return .{
                .addr = S.zero(),
                .previous = .{S.zero()} ** 4,
                .previous_clock = S.zero(),
                .next = .{S.zero()} ** 4,
            };
        }

        fn sllByOneRow() Row {
            const rd = ops.Access{
                .addr = ops.q(1),
                .previous = .{S.zero()} ** 4,
                .previous_clock = S.zero(),
                .next = .{ ops.q(2), S.zero(), S.zero(), S.zero() },
            };
            var rs1 = zeroAccess();
            rs1.addr = ops.q(2);
            rs1.next[0] = S.one();
            rs1.previous = rs1.next;
            var rs2 = zeroAccess();
            rs2.addr = ops.q(3);
            rs2.next[0] = S.one();
            rs2.previous = rs2.next;
            return .{
                .clk = ops.q(1),
                .pc = ops.q(0x1000),
                .rs2 = rs2,
                .semantic = .{
                    .rd = rd,
                    .rs1 = rs1,
                    .rs1_sign = S.zero(),
                    .is_sll = S.one(),
                    .is_srl = S.zero(),
                    .is_sra = S.zero(),
                    .bit_multiplier_left = ops.q(2),
                    .bit_multiplier_right = S.zero(),
                    .bit_markers = .{ S.zero(), S.one(), S.zero(), S.zero(), S.zero(), S.zero(), S.zero(), S.zero() },
                    .limb_markers = .{ S.one(), S.zero(), S.zero(), S.zero() },
                    .carries = .{S.zero()} ** 4,
                    .result = .{ ops.q(2), S.zero(), S.zero(), S.zero() },
                    .destination = .{ .nonzero = S.one(), .inverse = S.one() },
                },
            };
        }

        /// Family self-tests.  Wrapped in a function so only the shipped
        /// QM31 instantiation below compiles them: their bodies use field
        /// operations (`inv`, `eql`, `tryIntoM31`) that are deliberately
        /// absent from the scalar interface the extraction instantiates.
        fn selfTests() type {
            return struct {
                test "shifts reg: exact SLL row and tuple are accepted" {
                    var row = sllByOneRow();
                    std.mem.doNotOptimizeAway(&row);
                    try std.testing.expect(evaluate(row).allZero());
                    try std.testing.expect(programLookup(row).opcode_id.eql(ops.q(2)));
                    try std.testing.expect(shiftAmountRangeLookup(row).eql(ops.q(7)));
                }

                test "shifts reg: forged output and non-hot markers are rejected" {
                    var row = sllByOneRow();
                    row.semantic.rd.next[0] = ops.q(3);
                    try std.testing.expect(!evaluate(row).allZero());

                    row = sllByOneRow();
                    row.semantic.bit_markers[2] = S.one();
                    try std.testing.expect(!evaluate(row).allZero());
                }

                test "shifts reg: read-only sources must emit the value they consumed" {
                    // The shift computes on `next`; a diverging `previous` would let the
                    // instruction double as an arbitrary register write.
                    var row = sllByOneRow();
                    row.semantic.rs1.previous[0] = ops.q(0xde);
                    try std.testing.expect(!evaluate(row).allZero());

                    row = sllByOneRow();
                    row.rs2.previous[0] = ops.q(0xad);
                    try std.testing.expect(!evaluate(row).allZero());
                }

                test "shifts reg: arithmetic right shift binds sign extension" {
                    var row = sllByOneRow();
                    row.semantic.is_sll = S.zero();
                    row.semantic.is_sra = S.one();
                    row.semantic.rs1_sign = S.one();
                    row.semantic.bit_multiplier_left = S.zero();
                    row.semantic.bit_multiplier_right = ops.q(2);
                    row.semantic.rs1.next = .{ S.zero(), S.zero(), S.zero(), ops.q(128) };
                    row.semantic.rs1.previous = row.semantic.rs1.next;
                    row.semantic.rd.next = .{ S.zero(), S.zero(), S.zero(), ops.q(192) };
                    row.semantic.result = row.semantic.rd.next;
                    try std.testing.expect(evaluate(row).allZero());

                    row.semantic.rs1_sign = S.zero();
                    try std.testing.expect(!evaluate(row).allZero());
                }

                test "shifts reg: adapter follows oracle access-first order" {
                    var columns = [_]S{S.zero()} ** N_ORACLE_COLUMNS;
                    columns[2] = ops.q(11);
                    columns[12] = ops.q(12);
                    columns[22] = ops.q(13);
                    columns[32] = ops.q(14);
                    columns[50] = ops.q(15);
                    const row = try Row.fromOracleColumns(&columns);
                    try std.testing.expect(row.semantic.rd.addr.eql(ops.q(11)));
                    try std.testing.expect(row.semantic.rs1.addr.eql(ops.q(12)));
                    try std.testing.expect(row.rs2.addr.eql(ops.q(13)));
                    try std.testing.expect(row.semantic.rs1_sign.eql(ops.q(14)));
                    try std.testing.expect(row.semantic.carries[0].eql(ops.q(15)));
                }
            };
        }
    };
}

comptime {
    _ = Semantics(QM31).selfTests();
}
