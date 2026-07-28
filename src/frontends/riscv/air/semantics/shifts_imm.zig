//! Exact pinned Stark-V SLLI/SRLI/SRAI semantics and lookup requests.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const common = @import("common.zig");
const shift = @import("shift_common.zig");

pub fn Semantics(comptime S: type) type {
    return struct {
        const ops = common.Ops(S);
        const sh = shift.Semantics(S);

        pub const N_ORACLE_COLUMNS: usize = 51;
        pub const N_CONSTRAINTS: usize = sh.N_CONSTRAINTS + 1;
        pub const CURRENT_TRACE_COMPATIBLE = true;

        pub const Row = struct {
            clk: S,
            pc: S,
            imm_truncated: S,
            semantic: sh.Row,

            pub fn fromOracleColumns(columns: []const S) !Row {
                if (columns.len != N_ORACLE_COLUMNS) return error.InvalidOracleTraceShape;
                const rd = ops.accessFromColumns(columns[2..12]);
                const rs1 = ops.accessFromColumns(columns[12..22]);
                return .{
                    .clk = columns[0],
                    .pc = columns[1],
                    .imm_truncated = columns[23],
                    .semantic = .{
                        .rd = rd,
                        .rs1 = rs1,
                        .rs1_sign = columns[22],
                        .is_sll = columns[24],
                        .is_srl = columns[25],
                        .is_sra = columns[26],
                        .bit_multiplier_left = columns[27],
                        .bit_multiplier_right = columns[28],
                        .bit_markers = columns[29..37].*,
                        .limb_markers = columns[37..41].*,
                        .carries = columns[41..45].*,
                        .result = columns[45..49].*,
                        .destination = ops.destinationFromColumns(columns[49..51]),
                    },
                };
            }
        };

        pub const Constraints = ops.ConstraintSet(N_CONSTRAINTS);

        pub fn evaluate(row: Row) Constraints {
            var out: [N_CONSTRAINTS]S = undefined;
            const core = sh.evaluate(row.semantic);
            @memcpy(out[0..sh.N_CONSTRAINTS], &core.values);
            out[sh.N_CONSTRAINTS] = row.imm_truncated.sub(sh.derive(row.semantic).shift_amount);
            return .{ .values = out };
        }

        pub fn placementConstraint(row: Row, is_active: S) S {
            return row.semantic.active().sub(is_active);
        }

        pub fn programLookup(row: Row) ops.ProgramTuple {
            return .{
                .pc = row.pc,
                .opcode_id = row.semantic.is_sll.mul(ops.q(16))
                    .add(row.semantic.is_srl.mul(ops.q(17)))
                    .add(row.semantic.is_sra.mul(ops.q(18))),
                .rd = row.semantic.rd.addr,
                .rs1 = row.semantic.rs1.addr,
                .operand = row.imm_truncated,
            };
        }

        pub const AccessLookups = struct {
            rd: ops.AccessChain,
            rs1: ops.AccessChain,
        };

        pub fn accessLookups(row: Row) AccessLookups {
            return .{
                .rd = ops.registerAccessChain(row.semantic.rd, row.clk, .second),
                .rs1 = ops.registerAccessChain(row.semantic.rs1, row.clk, .first),
            };
        }

        pub fn stateLookup(row: Row) ops.RegistersStateChain {
            return ops.registersStateChain(row.pc, row.clk);
        }

        pub const carryRangePairs = sh.carryRangePairs;
        pub const rdRangePairs = sh.rdRangePairs;
        pub const signRangeLookup = sh.signRangeLookup;

        fn slliByOneRow() Row {
            const rd = ops.Access{
                .addr = ops.q(1),
                .previous = .{S.zero()} ** 4,
                .previous_clock = S.zero(),
                .next = .{ ops.q(2), S.zero(), S.zero(), S.zero() },
            };
            const rs1 = ops.Access{
                .addr = ops.q(2),
                .previous = .{ S.one(), S.zero(), S.zero(), S.zero() },
                .previous_clock = S.zero(),
                .next = .{ S.one(), S.zero(), S.zero(), S.zero() },
            };
            return .{
                .clk = S.one(),
                .pc = ops.q(0x1000),
                .imm_truncated = S.one(),
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
                test "shifts imm: exact SLLI row is accepted" {
                    var row = slliByOneRow();
                    std.mem.doNotOptimizeAway(&row);
                    try std.testing.expect(evaluate(row).allZero());
                    try std.testing.expect(programLookup(row).opcode_id.eql(ops.q(16)));
                }

                test "shifts imm: immediate and carry forgeries are rejected" {
                    var row = slliByOneRow();
                    row.imm_truncated = ops.q(2);
                    try std.testing.expect(!evaluate(row).allZero());

                    row = slliByOneRow();
                    row.semantic.carries[0] = S.one();
                    try std.testing.expect(!evaluate(row).allZero());
                }

                test "shifts imm: rs1 must emit the value it consumed" {
                    // The shift computes on `next`; a diverging `previous` would let the
                    // instruction double as an arbitrary register write.
                    var row = slliByOneRow();
                    row.semantic.rs1.previous[0] = ops.q(0xef);
                    try std.testing.expect(!evaluate(row).allZero());
                }

                test "shifts imm: adapter uses oracle access-first order" {
                    var columns = [_]S{S.zero()} ** N_ORACLE_COLUMNS;
                    columns[2] = ops.q(11);
                    columns[12] = ops.q(12);
                    columns[22] = ops.q(13);
                    columns[23] = ops.q(14);
                    columns[41] = ops.q(15);
                    const row = try Row.fromOracleColumns(&columns);
                    try std.testing.expect(row.semantic.rd.addr.eql(ops.q(11)));
                    try std.testing.expect(row.semantic.rs1.addr.eql(ops.q(12)));
                    try std.testing.expect(row.semantic.rs1_sign.eql(ops.q(13)));
                    try std.testing.expect(row.imm_truncated.eql(ops.q(14)));
                    try std.testing.expect(row.semantic.carries[0].eql(ops.q(15)));
                }
            };
        }
    };
}

comptime {
    _ = Semantics(QM31).selfTests();
}
