//! Test-only oracle for the retired handwritten Stark-V SLT/SLTU AIR.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const common = @import("common.zig");

pub fn Semantics(comptime S: type) type {
    return struct {
        const ops = common.Ops(S);

        pub const N_ORACLE_COLUMNS: usize = 44;
        pub const N_CONSTRAINTS: usize = 35;
        pub const CURRENT_TRACE_COMPATIBLE = true;

        pub const Row = struct {
            clk: S,
            pc: S,
            rd: ops.Access,
            rs1: ops.Access,
            rs2: ops.Access,
            cmp_result: S,
            rs1_msl_felt: S,
            rs2_msl_felt: S,
            is_slt: S,
            is_sltu: S,
            diff_markers: [4]S,
            diff_val: S,
            destination: ops.Destination,

            pub fn active(self: Row) S {
                return self.is_slt.add(self.is_sltu);
            }

            pub fn fromOracleColumns(columns: []const S) !Row {
                if (columns.len != N_ORACLE_COLUMNS) return error.InvalidOracleTraceShape;
                return .{
                    .clk = columns[0],
                    .pc = columns[1],
                    .rd = ops.accessFromColumns(columns[2..12]),
                    .rs1 = ops.accessFromColumns(columns[12..22]),
                    .rs2 = ops.accessFromColumns(columns[22..32]),
                    .cmp_result = columns[32],
                    .rs1_msl_felt = columns[33],
                    .rs2_msl_felt = columns[34],
                    .is_slt = columns[35],
                    .is_sltu = columns[36],
                    .diff_markers = columns[37..41].*,
                    .diff_val = columns[41],
                    .destination = ops.destinationFromColumns(columns[42..44]),
                };
            }
        };

        pub const Derived = struct {
            rs1_msl_gap: S,
            rs2_msl_gap: S,
            rs1_msl_shifted: S,
            rs2_msl_shifted: S,
            prefix_sum: S,
            cmp_sign: S,
        };

        pub fn derive(row: Row) Derived {
            var prefix = S.zero();
            for (row.diff_markers) |marker| prefix = prefix.add(marker);
            return .{
                .rs1_msl_gap = row.rs1.next[3].sub(row.rs1_msl_felt),
                .rs2_msl_gap = row.rs2.next[3].sub(row.rs2_msl_felt),
                .rs1_msl_shifted = row.rs1_msl_felt.add(row.is_slt.mul(ops.q(128))),
                .rs2_msl_shifted = row.rs2_msl_felt.add(row.is_slt.mul(ops.q(128))),
                .prefix_sum = prefix,
                .cmp_sign = row.cmp_result.mul(ops.q(2)).sub(S.one()),
            };
        }

        pub const Constraints = ops.ConstraintSet(N_CONSTRAINTS);

        pub fn evaluate(row: Row) Constraints {
            var out: [N_CONSTRAINTS]S = undefined;
            var n: usize = 0;
            const d = derive(row);

            out[n] = ops.bit(row.active());
            n += 1;
            out[n] = ops.bit(row.is_slt);
            n += 1;
            out[n] = ops.bit(row.is_sltu);
            n += 1;

            out[n] = ops.bit(row.cmp_result);
            n += 1;
            for (row.diff_markers) |marker| {
                out[n] = ops.bit(marker);
                n += 1;
            }
            out[n] = d.rs1_msl_gap.mul(ops.q(256).sub(d.rs1_msl_gap));
            n += 1;
            out[n] = d.rs2_msl_gap.mul(ops.q(256).sub(d.rs2_msl_gap));
            n += 1;

            var more_significant = S.zero();
            var limb: usize = 4;
            while (limb > 0) {
                limb -= 1;
                const marker = row.diff_markers[limb];
                const lhs = if (limb == 3) row.rs1_msl_felt else row.rs1.next[limb];
                const rhs = if (limb == 3) row.rs2_msl_felt else row.rs2.next[limb];
                const oriented = d.cmp_sign.mul(rhs.sub(lhs));
                out[n] = S.one().sub(more_significant).sub(marker).mul(oriented);
                n += 1;
                out[n] = marker.mul(row.diff_val.sub(oriented));
                n += 1;
                more_significant = more_significant.add(marker);
            }
            out[n] = d.prefix_sum.mul(S.one().sub(d.prefix_sum));
            n += 1;
            out[n] = S.one().sub(d.prefix_sum).mul(row.cmp_result);
            n += 1;
            for (ops.destinationConstraints(row.rd.addr, row.destination)) |constraint| {
                out[n] = constraint;
                n += 1;
            }
            for (ops.destinationResultConstraints(
                row.rd,
                .{ row.cmp_result, S.zero(), S.zero(), S.zero() },
                row.destination,
            )) |constraint| {
                out[n] = constraint;
                n += 1;
            }
            // Source registers are read-only: their emitted `next` limbs must equal
            // the consumed `previous` limbs. `rd` is pinned by the result link above.
            for (ops.readOnlyAccessConstraints(row.rs1, row.active())) |constraint| {
                out[n] = constraint;
                n += 1;
            }
            for (ops.readOnlyAccessConstraints(row.rs2, row.active())) |constraint| {
                out[n] = constraint;
                n += 1;
            }
            std.debug.assert(n == out.len);
            return .{ .values = out };
        }

        pub fn placementConstraint(row: Row, is_active: S) S {
            return row.active().sub(is_active);
        }

        pub fn programLookup(row: Row) ops.ProgramTuple {
            return .{
                .pc = row.pc,
                .opcode_id = row.is_slt.mul(ops.q(3)).add(row.is_sltu.mul(ops.q(4))),
                .rd = row.rd.addr,
                .rs1 = row.rs1.addr,
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
                .rd = ops.registerAccessChain(row.rd, row.clk, .third),
                .rs1 = ops.registerAccessChain(row.rs1, row.clk, .first),
                .rs2 = ops.registerAccessChain(row.rs2, row.clk, .second),
            };
        }

        pub fn stateLookup(row: Row) ops.RegistersStateChain {
            return ops.registersStateChain(row.pc, row.clk);
        }

        pub fn mslRangeLookup(row: Row) [2]S {
            const d = derive(row);
            return .{ d.rs1_msl_shifted, d.rs2_msl_shifted };
        }

        pub const PositiveDiffLookup = struct { numerator: S, value: S };

        pub fn positiveDiffLookup(row: Row) PositiveDiffLookup {
            return .{ .numerator = derive(row).prefix_sum, .value = row.diff_val.sub(S.one()) };
        }

        fn zeroAccess() ops.Access {
            return .{
                .addr = S.zero(),
                .previous = .{S.zero()} ** 4,
                .previous_clock = S.zero(),
                .next = .{S.zero()} ** 4,
            };
        }

        fn honestUnsignedRow() Row {
            var rd = zeroAccess();
            rd.addr = S.one();
            rd.next[0] = S.one();
            var rs1 = zeroAccess();
            rs1.addr = ops.q(2);
            rs1.next[0] = S.one();
            rs1.previous[0] = S.one();
            var rs2 = zeroAccess();
            rs2.addr = ops.q(3);
            rs2.next[0] = ops.q(2);
            rs2.previous[0] = ops.q(2);
            return .{
                .clk = S.one(),
                .pc = ops.q(0x1000),
                .rd = rd,
                .rs1 = rs1,
                .rs2 = rs2,
                .cmp_result = S.one(),
                .rs1_msl_felt = S.zero(),
                .rs2_msl_felt = S.zero(),
                .is_slt = S.zero(),
                .is_sltu = S.one(),
                .diff_markers = .{ S.one(), S.zero(), S.zero(), S.zero() },
                .diff_val = S.one(),
                .destination = .{ .nonzero = S.one(), .inverse = S.one() },
            };
        }

        /// Family self-tests.  Wrapped in a function so only the shipped
        /// QM31 instantiation below compiles them: their bodies use field
        /// operations (`inv`, `eql`, `tryIntoM31`) that are deliberately
        /// absent from the scalar interface the extraction instantiates.
        fn selfTests() type {
            return struct {
                test "lt reg: exact unsigned comparison is accepted" {
                    var row = honestUnsignedRow();
                    std.mem.doNotOptimizeAway(&row);
                    try std.testing.expect(evaluate(row).allZero());
                    try std.testing.expect(programLookup(row).opcode_id.eql(ops.q(4)));
                    try std.testing.expect(accessLookups(row).rd.next.limbs[0].eql(S.one()));
                }

                test "lt reg: forged result and multiple diff markers are rejected" {
                    var row = honestUnsignedRow();
                    row.cmp_result = S.zero();
                    try std.testing.expect(!evaluate(row).allZero());
                    row = honestUnsignedRow();
                    row.diff_markers[1] = S.one();
                    try std.testing.expect(!evaluate(row).allZero());
                }

                test "lt reg: read-only source access must emit the value it consumed" {
                    var row = honestUnsignedRow();
                    // The comparison runs over `next`, so swapping the consumed value is only
                    // caught by the read-only binding.
                    row.rs1.previous = .{ ops.q(0xef), ops.q(0xbe), ops.q(0xad), ops.q(0xde) };
                    try std.testing.expect(!evaluate(row).allZero());

                    row = honestUnsignedRow();
                    row.rs2.previous[2] = ops.q(0x7f);
                    try std.testing.expect(!evaluate(row).allZero());

                    // The destination write stays unbound to `previous`: rd.next is pinned by
                    // the result link instead, so an honest changed rd value still accepts.
                    row = honestUnsignedRow();
                    row.rd.previous = .{ ops.q(9), ops.q(9), ops.q(9), ops.q(9) };
                    try std.testing.expect(evaluate(row).allZero());
                }

                test "lt reg: signed negative-to-zero comparison uses M31 limbs" {
                    var row = honestUnsignedRow();
                    row.is_slt = S.one();
                    row.is_sltu = S.zero();
                    row.rs1.next = .{ ops.q(255), ops.q(255), ops.q(255), ops.q(255) };
                    row.rs1.previous = row.rs1.next;
                    row.rs2.next = .{S.zero()} ** 4;
                    row.rs2.previous = row.rs2.next;
                    row.rs1_msl_felt = S.zero().sub(S.one());
                    row.rs2_msl_felt = S.zero();
                    row.diff_markers = .{ S.zero(), S.zero(), S.zero(), S.one() };
                    row.diff_val = S.one();
                    try std.testing.expect(evaluate(row).allZero());
                }

                test "lt reg: adapter preserves oracle witness order" {
                    var columns = [_]S{S.zero()} ** N_ORACLE_COLUMNS;
                    columns[2] = ops.q(10);
                    columns[32] = ops.q(11);
                    columns[37] = ops.q(12);
                    columns[41] = ops.q(13);
                    const row = try Row.fromOracleColumns(&columns);
                    try std.testing.expect(row.rd.addr.eql(ops.q(10)));
                    try std.testing.expect(row.cmp_result.eql(ops.q(11)));
                    try std.testing.expect(row.diff_markers[0].eql(ops.q(12)));
                    try std.testing.expect(row.diff_val.eql(ops.q(13)));
                }
            };
        }
    };
}

comptime {
    _ = Semantics(QM31).selfTests();
}
