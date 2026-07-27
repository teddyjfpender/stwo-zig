//! Shared pinned Stark-V shift equations.
//!
//! The hot-one markers and per-byte carries are protocol witnesses. They are
//! not interchangeable with a binary shift amount or a whole-word result.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const common = @import("common.zig");

pub fn Semantics(comptime S: type) type {
    return struct {
        const ops = common.Ops(S);

        pub const N_CONSTRAINTS: usize = 65;

        pub const Row = struct {
            rd: ops.Access,
            rs1: ops.Access,
            rs1_sign: S,
            is_sll: S,
            is_srl: S,
            is_sra: S,
            bit_multiplier_left: S,
            bit_multiplier_right: S,
            bit_markers: [8]S,
            limb_markers: [4]S,
            carries: [4]S,
            result: [4]S,
            destination: ops.Destination,

            pub fn active(self: Row) S {
                return self.is_sll.add(self.is_srl).add(self.is_sra);
            }
        };

        pub const Derived = struct {
            right_shift: S,
            bit_multiplier: S,
            bit_shift: S,
            limb_shift: S,
            shift_amount: S,
            bit_marker_sum: S,
            limb_marker_sum: S,
        };

        pub fn derive(row: Row) Derived {
            var bit_multiplier = S.zero();
            var bit_shift = S.zero();
            var bit_marker_sum = S.zero();
            for (row.bit_markers, 0..) |marker, i| {
                bit_multiplier = bit_multiplier.add(marker.mul(ops.q(@as(u64, 1) << @intCast(i))));
                bit_shift = bit_shift.add(marker.mul(ops.q(i)));
                bit_marker_sum = bit_marker_sum.add(marker);
            }
            var limb_shift = S.zero();
            var limb_marker_sum = S.zero();
            for (row.limb_markers, 0..) |marker, i| {
                limb_shift = limb_shift.add(marker.mul(ops.q(i)));
                limb_marker_sum = limb_marker_sum.add(marker);
            }
            return .{
                .right_shift = row.is_srl.add(row.is_sra),
                .bit_multiplier = bit_multiplier,
                .bit_shift = bit_shift,
                .limb_shift = limb_shift,
                .shift_amount = limb_shift.mul(ops.q(8)).add(bit_shift),
                .bit_marker_sum = bit_marker_sum,
                .limb_marker_sum = limb_marker_sum,
            };
        }

        pub const Constraints = ops.ConstraintSet(N_CONSTRAINTS);

        /// Exact Section 3/4 shift constraints from the pinned schema. Immediate
        /// shifts add `imm_truncated == shift_amount` in their family module.
        pub fn evaluate(row: Row) Constraints {
            @setEvalBranchQuota(100_000);
            var out: [N_CONSTRAINTS]S = undefined;
            var n: usize = 0;
            const d = derive(row);
            const enabler = row.active();

            out[n] = ops.bit(enabler);
            n += 1;
            for ([_]S{ row.is_sll, row.is_srl, row.is_sra }) |flag| {
                out[n] = ops.bit(flag);
                n += 1;
            }

            out[n] = ops.bit(row.rs1_sign);
            n += 1;
            // Logical and left shifts always zero-fill. Arithmetic right shifts are
            // the only instructions allowed to carry a sign witness.
            out[n] = S.one().sub(row.is_sra).mul(row.rs1_sign);
            n += 1;
            for (row.bit_markers) |marker| {
                out[n] = ops.bit(marker);
                n += 1;
            }
            for (row.limb_markers) |marker| {
                out[n] = ops.bit(marker);
                n += 1;
            }
            out[n] = d.bit_marker_sum.sub(enabler);
            n += 1;
            out[n] = d.limb_marker_sum.sub(enabler);
            n += 1;
            out[n] = row.bit_multiplier_left.sub(row.is_sll.mul(d.bit_multiplier));
            n += 1;
            out[n] = row.bit_multiplier_right.sub(d.right_shift.mul(d.bit_multiplier));
            n += 1;

            // Left shifts by 8*i+b, with byte carries flowing toward higher limbs.
            for (0..4) |i| {
                const marker = row.limb_markers[i];
                for (0..4) |j| {
                    if (j < i) {
                        out[n] = row.is_sll.mul(marker).mul(row.result[j]);
                    } else if (j == i) {
                        out[n] = row.is_sll.mul(marker).mul(
                            row.result[j].add(ops.BYTE_RADIX().mul(row.carries[0])),
                        ).sub(marker.mul(row.rs1.next[0]).mul(row.bit_multiplier_left));
                    } else {
                        const k = j - i;
                        const carry_term = row.carries[k - 1].sub(ops.BYTE_RADIX().mul(row.carries[k]));
                        out[n] = row.is_sll.mul(marker).mul(row.result[j].sub(carry_term))
                            .sub(marker.mul(row.rs1.next[k]).mul(row.bit_multiplier_left));
                    }
                    n += 1;
                }
            }

            // Right shifts by 8*i+b, with arithmetic sign fill where SRA is active.
            for (0..4) |i| {
                const marker = row.limb_markers[i];
                for (0..4) |j| {
                    const input = i + j;
                    if (input < 3) {
                        out[n] = marker.mul(
                            row.carries[input + 1].mul(d.right_shift).mul(ops.BYTE_RADIX())
                                .add(d.right_shift.mul(row.rs1.next[input].sub(row.carries[input])))
                                .sub(row.result[j].mul(row.bit_multiplier_right)),
                        );
                    } else if (input == 3) {
                        out[n] = marker.mul(
                            row.rs1_sign.mul(row.bit_multiplier_right.sub(S.one())).mul(ops.BYTE_RADIX())
                                .add(d.right_shift.mul(row.rs1.next[3].sub(row.carries[3])))
                                .sub(row.result[j].mul(row.bit_multiplier_right)),
                        );
                    } else {
                        out[n] = d.right_shift.mul(marker).mul(
                            row.result[j].sub(row.rs1_sign.mul(ops.q(255))),
                        );
                    }
                    n += 1;
                }
            }
            for (ops.destinationConstraints(row.rd.addr, row.destination)) |constraint| {
                out[n] = constraint;
                n += 1;
            }
            for (ops.destinationResultConstraints(row.rd, row.result, row.destination)) |constraint| {
                out[n] = constraint;
                n += 1;
            }
            // rs1 is read-only: it must emit exactly the value it consumed.
            for (ops.readOnlyAccessConstraints(row.rs1, enabler)) |constraint| {
                out[n] = constraint;
                n += 1;
            }
            std.debug.assert(n == out.len);
            return .{ .values = out };
        }

        /// Each tuple proves both ends of one honest carry window in the
        /// existing byte-pair table: `carry_i` is non-negative and
        /// `(bit_multiplier - 1) - carry_i` is non-negative.  Together they
        /// bind every carry to `[0, bit_multiplier)` on an active row.
        pub fn carryRangePairs(row: Row) [4][2]S {
            const enabler = row.active();
            const upper = derive(row).bit_multiplier.sub(enabler);
            return .{
                .{ row.carries[0], upper.sub(row.carries[0]) },
                .{ row.carries[1], upper.sub(row.carries[1]) },
                .{ row.carries[2], upper.sub(row.carries[2]) },
                .{ row.carries[3], upper.sub(row.carries[3]) },
            };
        }

        pub fn rdRangePairs(row: Row) [2][2]S {
            return .{
                .{ row.result[0], row.result[1] },
                .{ row.result[2], row.result[3] },
            };
        }

        /// `range_check_m31` constrains the second limb to seven bits. Together with
        /// boolean `rs1_sign`, this proves it is exactly bit 31 of the operand.
        pub fn signRangeLookup(row: Row) [2]S {
            return .{
                S.zero(),
                row.rs1.next[3].sub(row.rs1_sign.mul(ops.q(128))),
            };
        }

        /// Family self-tests.  Wrapped in a function so only the shipped
        /// QM31 instantiation below compiles them: their bodies use field
        /// operations (`inv`, `eql`, `tryIntoM31`) that are deliberately
        /// absent from the scalar interface the extraction instantiates.
        fn selfTests() type {
            return struct {
                test "shift common: logical right shift cannot choose arithmetic sign fill" {
                    const rd = ops.Access{
                        .addr = ops.q(3),
                        .previous = .{S.zero()} ** 4,
                        .previous_clock = S.zero(),
                        .next = .{ ops.q(0x22), ops.q(0x33), ops.q(0x44), ops.q(0xff) },
                    };
                    var rs1 = rd;
                    rs1.addr = S.one();
                    rs1.next = .{ ops.q(0x11), ops.q(0x22), ops.q(0x33), ops.q(0x44) };
                    const row = Row{
                        .rd = rd,
                        .rs1 = rs1,
                        .rs1_sign = S.one(),
                        .is_sll = S.zero(),
                        .is_srl = S.one(),
                        .is_sra = S.zero(),
                        .bit_multiplier_left = S.zero(),
                        .bit_multiplier_right = S.one(),
                        .bit_markers = .{ S.one(), S.zero(), S.zero(), S.zero(), S.zero(), S.zero(), S.zero(), S.zero() },
                        .limb_markers = .{ S.zero(), S.one(), S.zero(), S.zero() },
                        .carries = .{S.zero()} ** 4,
                        .result = rd.next,
                        .destination = .{
                            .nonzero = S.one(),
                            .inverse = ops.q(3).inv() catch unreachable,
                        },
                    };
                    try std.testing.expect(!evaluate(row).allZero());
                }

                test "shift common: arithmetic sign range binds operand bit 31" {
                    const table = @import("../lookups/tables/schema.zig");
                    var row = Row{
                        .rd = .{
                            .addr = ops.q(3),
                            .previous = .{S.zero()} ** 4,
                            .previous_clock = S.zero(),
                            .next = .{ S.zero(), S.zero(), S.zero(), ops.q(0x44) },
                        },
                        .rs1 = .{
                            .addr = S.one(),
                            .previous = .{ S.zero(), S.zero(), S.zero(), ops.q(0x44) },
                            .previous_clock = S.zero(),
                            .next = .{ S.zero(), S.zero(), S.zero(), ops.q(0x44) },
                        },
                        .rs1_sign = S.zero(),
                        .is_sll = S.zero(),
                        .is_srl = S.zero(),
                        .is_sra = S.one(),
                        .bit_multiplier_left = S.zero(),
                        .bit_multiplier_right = S.one(),
                        .bit_markers = .{ S.one(), S.zero(), S.zero(), S.zero(), S.zero(), S.zero(), S.zero(), S.zero() },
                        .limb_markers = .{ S.one(), S.zero(), S.zero(), S.zero() },
                        .carries = .{S.zero()} ** 4,
                        .result = .{ S.zero(), S.zero(), S.zero(), ops.q(0x44) },
                        .destination = .{
                            .nonzero = S.one(),
                            .inverse = ops.q(3).inv() catch unreachable,
                        },
                    };
                    _ = try table.indexSecure(.range_check_m31, &signRangeLookup(row));

                    row.rs1_sign = S.one();
                    try std.testing.expect(evaluate(row).allZero());
                    try std.testing.expectError(
                        error.ValueOutOfRange,
                        table.indexSecure(.range_check_m31, &signRangeLookup(row)),
                    );

                    // rs1 is read-only: the shift computes on `next`, so a diverging
                    // `previous` is an arbitrary register write and must be rejected.
                    row.rs1.previous[3] = ops.q(0x99);
                    try std.testing.expect(!evaluate(row).allZero());
                }
            };
        }
    };
}

comptime {
    _ = Semantics(QM31).selfTests();
}
