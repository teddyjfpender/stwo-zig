//! Exact pinned Stark-V SLTI/SLTIU semantics and lookup requests.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const common = @import("common.zig");

pub fn Semantics(comptime S: type) type {
    return struct {
        const ops = common.Ops(S);

        pub const N_ORACLE_COLUMNS: usize = 37;
        pub const N_CONSTRAINTS: usize = 32;
        pub const CURRENT_TRACE_COMPATIBLE = true;

        pub const Row = struct {
            clk: S,
            pc: S,
            rd: ops.Access,
            rs1: ops.Access,
            cmp_result: S,
            rs1_msl_felt: S,
            imm_0: S,
            imm_1: S,
            imm_msb: S,
            is_slti: S,
            is_sltiu: S,
            diff_markers: [4]S,
            diff_val: S,
            destination: ops.Destination,
            imm_msl_felt: S,

            pub fn active(self: Row) S {
                return self.is_slti.add(self.is_sltiu);
            }

            pub fn fromOracleColumns(columns: []const S) !Row {
                if (columns.len != N_ORACLE_COLUMNS) return error.InvalidOracleTraceShape;
                return .{
                    .clk = columns[0],
                    .pc = columns[1],
                    .rd = ops.accessFromColumns(columns[2..12]),
                    .rs1 = ops.accessFromColumns(columns[12..22]),
                    .cmp_result = columns[22],
                    .rs1_msl_felt = columns[23],
                    .imm_0 = columns[24],
                    .imm_1 = columns[25],
                    .imm_msb = columns[26],
                    .is_slti = columns[27],
                    .is_sltiu = columns[28],
                    .diff_markers = columns[29..33].*,
                    .diff_val = columns[33],
                    .destination = ops.destinationFromColumns(columns[34..36]),
                    .imm_msl_felt = columns[36],
                };
            }
        };

        pub const Derived = struct {
            imm: S,
            sext_imm_1: S,
            sext_imm_2: S,
            expected_imm_msl: S,
            rs1_msl_gap: S,
            rs1_msl_shifted: S,
            imm_1_doubled: S,
            prefix_sum: S,
            cmp_sign: S,
        };

        pub fn derive(row: Row) Derived {
            const sext_2 = row.imm_msb.mul(ops.q(255));
            var prefix = S.zero();
            for (row.diff_markers) |marker| prefix = prefix.add(marker);
            return .{
                .imm = row.imm_0.add(row.imm_1.mul(ops.q(256))).add(row.imm_msb.mul(ops.q(2048))),
                .sext_imm_1 = row.imm_1.add(row.imm_msb.mul(ops.q(248))),
                .sext_imm_2 = sext_2,
                .expected_imm_msl = row.is_sltiu.mul(sext_2).sub(row.is_slti.mul(row.imm_msb)),
                .rs1_msl_gap = row.rs1.next[3].sub(row.rs1_msl_felt),
                .rs1_msl_shifted = row.rs1_msl_felt.add(row.is_slti.mul(ops.q(128))),
                .imm_1_doubled = row.imm_1.mul(ops.q(2)),
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
            out[n] = ops.bit(row.is_slti);
            n += 1;
            out[n] = ops.bit(row.is_sltiu);
            n += 1;

            out[n] = ops.bit(row.imm_msb);
            n += 1;
            // Materializing the selected signed/unsigned top limb keeps the comparison
            // constraints cubic. Inlining this quadratic selector into the oriented
            // comparison would make the AIR quartic and require another blowup bit.
            out[n] = row.imm_msl_felt.sub(d.expected_imm_msl);
            n += 1;
            out[n] = d.rs1_msl_gap.mul(ops.q(256).sub(d.rs1_msl_gap));
            n += 1;
            for (row.diff_markers) |marker| {
                out[n] = ops.bit(marker);
                n += 1;
            }

            const lhs = [_]S{ row.rs1.next[0], row.rs1.next[1], row.rs1.next[2], row.rs1_msl_felt };
            const rhs = [_]S{ row.imm_0, d.sext_imm_1, d.sext_imm_2, row.imm_msl_felt };
            var more_significant = S.zero();
            var limb: usize = 4;
            while (limb > 0) {
                limb -= 1;
                const marker = row.diff_markers[limb];
                const oriented = d.cmp_sign.mul(rhs[limb].sub(lhs[limb]));
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
            out[n] = ops.bit(row.cmp_result);
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
            // The source register is read-only: its emitted `next` limbs must equal
            // the consumed `previous` limbs. `rd` is pinned by the result link above.
            for (ops.readOnlyAccessConstraints(row.rs1, row.active())) |constraint| {
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
            const d = derive(row);
            return .{
                .pc = row.pc,
                .opcode_id = row.is_slti.mul(ops.q(11)).add(row.is_sltiu.mul(ops.q(12))),
                .rd = row.rd.addr,
                .rs1 = row.rs1.addr,
                .operand = d.imm,
            };
        }

        pub const AccessLookups = struct { rd: ops.AccessChain, rs1: ops.AccessChain };

        pub fn accessLookups(row: Row) AccessLookups {
            return .{
                .rd = ops.registerAccessChain(row.rd, row.clk),
                .rs1 = ops.registerAccessChain(row.rs1, row.clk),
            };
        }

        pub fn stateLookup(row: Row) ops.RegistersStateChain {
            return ops.registersStateChain(row.pc, row.clk);
        }

        pub fn immediateRangeLookup(row: Row) [3]S {
            const d = derive(row);
            return .{ d.rs1_msl_shifted, row.imm_0, d.imm_1_doubled };
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
            return .{
                .clk = S.one(),
                .pc = ops.q(0x1000),
                .rd = rd,
                .rs1 = rs1,
                .cmp_result = S.one(),
                .rs1_msl_felt = S.zero(),
                .imm_0 = ops.q(2),
                .imm_1 = S.zero(),
                .imm_msb = S.zero(),
                .is_slti = S.zero(),
                .is_sltiu = S.one(),
                .diff_markers = .{ S.one(), S.zero(), S.zero(), S.zero() },
                .diff_val = S.one(),
                .destination = .{ .nonzero = S.one(), .inverse = S.one() },
                .imm_msl_felt = S.zero(),
            };
        }

        /// Family self-tests.  Wrapped in a function so only the shipped
        /// QM31 instantiation below compiles them: their bodies use field
        /// operations (`inv`, `eql`, `tryIntoM31`) that are deliberately
        /// absent from the scalar interface the extraction instantiates.
        fn selfTests() type {
            return struct {
                test "lt imm: exact unsigned comparison is accepted" {
                    var row = honestUnsignedRow();
                    std.mem.doNotOptimizeAway(&row);
                    try std.testing.expect(evaluate(row).allZero());
                    try std.testing.expect(programLookup(row).operand.eql(ops.q(2)));
                }

                test "lt imm: forged result and malformed immediate are rejected" {
                    var row = honestUnsignedRow();
                    row.cmp_result = S.zero();
                    try std.testing.expect(!evaluate(row).allZero());
                    row = honestUnsignedRow();
                    row.imm_msb = ops.q(2);
                    try std.testing.expect(!evaluate(row).allZero());
                    row = honestUnsignedRow();
                    row.imm_msl_felt = S.one();
                    try std.testing.expect(!evaluate(row).allZero());
                }

                test "lt imm: read-only source access must emit the value it consumed" {
                    var row = honestUnsignedRow();
                    // The comparison runs over `next`, so swapping the consumed value is only
                    // caught by the read-only binding.
                    row.rs1.previous = .{ ops.q(0xef), ops.q(0xbe), ops.q(0xad), ops.q(0xde) };
                    try std.testing.expect(!evaluate(row).allZero());

                    // The destination write stays unbound to `previous`: rd.next is pinned by
                    // the result link instead, so an honest changed rd value still accepts.
                    row = honestUnsignedRow();
                    row.rd.previous = .{ ops.q(9), ops.q(9), ops.q(9), ops.q(9) };
                    try std.testing.expect(evaluate(row).allZero());
                }

                test "lt imm: adapter preserves exact immediate decomposition" {
                    var columns = [_]S{S.zero()} ** N_ORACLE_COLUMNS;
                    columns[22] = ops.q(10);
                    columns[24] = ops.q(11);
                    columns[25] = ops.q(12);
                    columns[26] = ops.q(13);
                    columns[33] = ops.q(14);
                    columns[36] = ops.q(15);
                    const row = try Row.fromOracleColumns(&columns);
                    try std.testing.expect(row.cmp_result.eql(ops.q(10)));
                    try std.testing.expect(row.imm_0.eql(ops.q(11)));
                    try std.testing.expect(row.imm_1.eql(ops.q(12)));
                    try std.testing.expect(row.imm_msb.eql(ops.q(13)));
                    try std.testing.expect(row.diff_val.eql(ops.q(14)));
                    try std.testing.expect(row.imm_msl_felt.eql(ops.q(15)));
                }
            };
        }
    };
}

comptime {
    _ = Semantics(QM31).selfTests();
}
