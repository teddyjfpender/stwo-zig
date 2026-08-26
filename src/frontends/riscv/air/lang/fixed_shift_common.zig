//! Allocation-free executable form of the shared RV32 shift equations.
//!
//! Register and immediate shift authorities authenticate the same typed shift
//! core, then retain this fixed scalar program. Keeping the 65 common roots in
//! one executable module prevents the two production families from acquiring
//! independent hot-path transcriptions.

const std = @import("std");
const common = @import("../semantics/common.zig");

pub const CONSTRAINT_COUNT: usize = 65;

pub fn Evaluator(comptime S: type) type {
    return struct {
        const ops = common.Ops(S);

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

            pub inline fn active(self: Row) S {
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

        pub const DirectConstraints = struct {
            values: [CONSTRAINT_COUNT]S,

            pub fn allZero(self: @This()) bool {
                for (self.values) |value| if (!value.isZero()) return false;
                return true;
            }
        };

        pub fn derive(row: Row) Derived {
            var bit_multiplier = S.zero();
            var bit_shift = S.zero();
            var bit_marker_sum = S.zero();
            for (row.bit_markers, 0..) |marker, index| {
                bit_multiplier = bit_multiplier.add(
                    marker.mul(ops.q(@as(u64, 1) << @intCast(index))),
                );
                bit_shift = bit_shift.add(marker.mul(ops.q(index)));
                bit_marker_sum = bit_marker_sum.add(marker);
            }
            var limb_shift = S.zero();
            var limb_marker_sum = S.zero();
            for (row.limb_markers, 0..) |marker, index| {
                limb_shift = limb_shift.add(marker.mul(ops.q(index)));
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

        /// Keep the 65-root kernel out of forced-inline call chains. ReleaseFast
        /// can still inline it when profitable, but forcing this large body
        /// into every family facade increases instruction-cache pressure and
        /// register spills on the all-coordinate production workload.
        pub fn evaluate(row: Row) DirectConstraints {
            @setEvalBranchQuota(100_000);
            var out: [CONSTRAINT_COUNT]S = undefined;
            var index: usize = 0;
            const derived = derive(row);
            const active = row.active();

            out[index] = ops.bit(active);
            index += 1;
            for ([_]S{ row.is_sll, row.is_srl, row.is_sra }) |flag| {
                out[index] = ops.bit(flag);
                index += 1;
            }
            out[index] = ops.bit(row.rs1_sign);
            index += 1;
            out[index] = S.one().sub(row.is_sra).mul(row.rs1_sign);
            index += 1;
            for (row.bit_markers) |marker| {
                out[index] = ops.bit(marker);
                index += 1;
            }
            for (row.limb_markers) |marker| {
                out[index] = ops.bit(marker);
                index += 1;
            }
            out[index] = derived.bit_marker_sum.sub(active);
            index += 1;
            out[index] = derived.limb_marker_sum.sub(active);
            index += 1;
            out[index] = row.bit_multiplier_left.sub(
                row.is_sll.mul(derived.bit_multiplier),
            );
            index += 1;
            out[index] = row.bit_multiplier_right.sub(
                derived.right_shift.mul(derived.bit_multiplier),
            );
            index += 1;

            for (0..4) |limb_shift| {
                const marker = row.limb_markers[limb_shift];
                for (0..4) |result_limb| {
                    if (result_limb < limb_shift) {
                        out[index] = row.is_sll.mul(marker).mul(row.result[result_limb]);
                    } else if (result_limb == limb_shift) {
                        out[index] = row.is_sll.mul(marker).mul(
                            row.result[result_limb].add(
                                ops.BYTE_RADIX().mul(row.carries[0]),
                            ),
                        ).sub(
                            marker.mul(row.rs1.next[0]).mul(row.bit_multiplier_left),
                        );
                    } else {
                        const source_limb = result_limb - limb_shift;
                        const carry_term = row.carries[source_limb - 1].sub(
                            ops.BYTE_RADIX().mul(row.carries[source_limb]),
                        );
                        out[index] = row.is_sll.mul(marker).mul(
                            row.result[result_limb].sub(carry_term),
                        ).sub(
                            marker.mul(row.rs1.next[source_limb]).mul(
                                row.bit_multiplier_left,
                            ),
                        );
                    }
                    index += 1;
                }
            }

            for (0..4) |limb_shift| {
                const marker = row.limb_markers[limb_shift];
                for (0..4) |result_limb| {
                    const source_limb = limb_shift + result_limb;
                    if (source_limb < 3) {
                        out[index] = marker.mul(
                            row.carries[source_limb + 1].mul(derived.right_shift)
                                .mul(ops.BYTE_RADIX())
                                .add(derived.right_shift.mul(
                                    row.rs1.next[source_limb].sub(
                                        row.carries[source_limb],
                                    ),
                                ))
                                .sub(row.result[result_limb].mul(
                                row.bit_multiplier_right,
                            )),
                        );
                    } else if (source_limb == 3) {
                        out[index] = marker.mul(
                            row.rs1_sign.mul(row.bit_multiplier_right.sub(S.one()))
                                .mul(ops.BYTE_RADIX())
                                .add(derived.right_shift.mul(
                                    row.rs1.next[3].sub(row.carries[3]),
                                ))
                                .sub(row.result[result_limb].mul(
                                row.bit_multiplier_right,
                            )),
                        );
                    } else {
                        out[index] = derived.right_shift.mul(marker).mul(
                            row.result[result_limb].sub(
                                row.rs1_sign.mul(ops.q(255)),
                            ),
                        );
                    }
                    index += 1;
                }
            }
            for (ops.destinationConstraints(row.rd.addr, row.destination)) |root| {
                out[index] = root;
                index += 1;
            }
            for (ops.destinationResultConstraints(
                row.rd,
                row.result,
                row.destination,
            )) |root| {
                out[index] = root;
                index += 1;
            }
            for (ops.readOnlyAccessConstraints(row.rs1, active)) |root| {
                out[index] = root;
                index += 1;
            }
            std.debug.assert(index == out.len);
            return .{ .values = out };
        }

        pub inline fn carryRangePairs(row: Row) [4][2]S {
            const active = row.active();
            const upper = derive(row).bit_multiplier.sub(active);
            return .{
                .{ row.carries[0], upper.sub(row.carries[0]) },
                .{ row.carries[1], upper.sub(row.carries[1]) },
                .{ row.carries[2], upper.sub(row.carries[2]) },
                .{ row.carries[3], upper.sub(row.carries[3]) },
            };
        }

        pub inline fn resultRangePairs(row: Row) [2][2]S {
            return .{
                .{ row.result[0], row.result[1] },
                .{ row.result[2], row.result[3] },
            };
        }

        pub inline fn signRange(row: Row) [2]S {
            return .{
                S.zero(),
                row.rs1.next[3].sub(row.rs1_sign.mul(ops.q(128))),
            };
        }
    };
}

comptime {
    if (CONSTRAINT_COUNT != 65)
        @compileError("fixed shift common root geometry drifted");
}
