//! Shared pinned Stark-V shift equations.
//!
//! The hot-one markers and per-byte carries are protocol witnesses. They are
//! not interchangeable with a binary shift amount or a whole-word result.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const common = @import("common.zig");

pub const N_CONSTRAINTS: usize = 61;

pub const Row = struct {
    rd: common.Access,
    rs1: common.Access,
    rs1_sign: QM31,
    is_sll: QM31,
    is_srl: QM31,
    is_sra: QM31,
    bit_multiplier_left: QM31,
    bit_multiplier_right: QM31,
    bit_markers: [8]QM31,
    limb_markers: [4]QM31,
    carries: [4]QM31,
    result: [4]QM31,
    destination: common.Destination,

    pub fn active(self: Row) QM31 {
        return self.is_sll.add(self.is_srl).add(self.is_sra);
    }
};

pub const Derived = struct {
    right_shift: QM31,
    bit_multiplier: QM31,
    bit_shift: QM31,
    limb_shift: QM31,
    shift_amount: QM31,
    bit_marker_sum: QM31,
    limb_marker_sum: QM31,
};

pub fn derive(row: Row) Derived {
    var bit_multiplier = QM31.zero();
    var bit_shift = QM31.zero();
    var bit_marker_sum = QM31.zero();
    for (row.bit_markers, 0..) |marker, i| {
        bit_multiplier = bit_multiplier.add(marker.mul(common.q(@as(u64, 1) << @intCast(i))));
        bit_shift = bit_shift.add(marker.mul(common.q(i)));
        bit_marker_sum = bit_marker_sum.add(marker);
    }
    var limb_shift = QM31.zero();
    var limb_marker_sum = QM31.zero();
    for (row.limb_markers, 0..) |marker, i| {
        limb_shift = limb_shift.add(marker.mul(common.q(i)));
        limb_marker_sum = limb_marker_sum.add(marker);
    }
    return .{
        .right_shift = row.is_srl.add(row.is_sra),
        .bit_multiplier = bit_multiplier,
        .bit_shift = bit_shift,
        .limb_shift = limb_shift,
        .shift_amount = limb_shift.mul(common.q(8)).add(bit_shift),
        .bit_marker_sum = bit_marker_sum,
        .limb_marker_sum = limb_marker_sum,
    };
}

pub const Constraints = common.ConstraintSet(N_CONSTRAINTS);

/// Exact Section 3/4 shift constraints from the pinned schema. Immediate
/// shifts add `imm_truncated == shift_amount` in their family module.
pub fn evaluate(row: Row) Constraints {
    @setEvalBranchQuota(100_000);
    var out: [N_CONSTRAINTS]QM31 = undefined;
    var n: usize = 0;
    const d = derive(row);
    const enabler = row.active();

    out[n] = common.bit(enabler);
    n += 1;
    for ([_]QM31{ row.is_sll, row.is_srl, row.is_sra }) |flag| {
        out[n] = common.bit(flag);
        n += 1;
    }

    out[n] = common.bit(row.rs1_sign);
    n += 1;
    // Logical and left shifts always zero-fill. Arithmetic right shifts are
    // the only instructions allowed to carry a sign witness.
    out[n] = QM31.one().sub(row.is_sra).mul(row.rs1_sign);
    n += 1;
    for (row.bit_markers) |marker| {
        out[n] = common.bit(marker);
        n += 1;
    }
    for (row.limb_markers) |marker| {
        out[n] = common.bit(marker);
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
                    row.result[j].add(common.BYTE_RADIX.mul(row.carries[0])),
                ).sub(marker.mul(row.rs1.next[0]).mul(row.bit_multiplier_left));
            } else {
                const k = j - i;
                const carry_term = row.carries[k - 1].sub(common.BYTE_RADIX.mul(row.carries[k]));
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
                    row.carries[input + 1].mul(d.right_shift).mul(common.BYTE_RADIX)
                        .add(d.right_shift.mul(row.rs1.next[input].sub(row.carries[input])))
                        .sub(row.result[j].mul(row.bit_multiplier_right)),
                );
            } else if (input == 3) {
                out[n] = marker.mul(
                    row.rs1_sign.mul(row.bit_multiplier_right.sub(QM31.one())).mul(common.BYTE_RADIX)
                        .add(d.right_shift.mul(row.rs1.next[3].sub(row.carries[3])))
                        .sub(row.result[j].mul(row.bit_multiplier_right)),
                );
            } else {
                out[n] = d.right_shift.mul(marker).mul(
                    row.result[j].sub(row.rs1_sign.mul(common.q(255))),
                );
            }
            n += 1;
        }
    }
    for (common.destinationConstraints(row.rd.addr, row.destination)) |constraint| {
        out[n] = constraint;
        n += 1;
    }
    for (common.destinationResultConstraints(row.rd, row.result, row.destination)) |constraint| {
        out[n] = constraint;
        n += 1;
    }
    std.debug.assert(n == out.len);
    return .{ .values = out };
}

pub fn carryRangePairs(row: Row) [2][2]QM31 {
    const enabler = row.active();
    const upper = derive(row).bit_multiplier.sub(enabler);
    return .{
        .{ upper.sub(row.carries[0]), upper.sub(row.carries[1]) },
        .{ upper.sub(row.carries[2]), upper.sub(row.carries[3]) },
    };
}

pub fn rdRangePairs(row: Row) [2][2]QM31 {
    return .{
        .{ row.result[0], row.result[1] },
        .{ row.result[2], row.result[3] },
    };
}

/// `range_check_m31` constrains the second limb to seven bits. Together with
/// boolean `rs1_sign`, this proves it is exactly bit 31 of the operand.
pub fn signRangeLookup(row: Row) [2]QM31 {
    return .{
        QM31.zero(),
        row.rs1.next[3].sub(row.rs1_sign.mul(common.q(128))),
    };
}

test "shift common: logical right shift cannot choose arithmetic sign fill" {
    const rd = common.Access{
        .addr = common.q(3),
        .previous = .{QM31.zero()} ** 4,
        .previous_clock = QM31.zero(),
        .next = .{ common.q(0x22), common.q(0x33), common.q(0x44), common.q(0xff) },
    };
    var rs1 = rd;
    rs1.addr = QM31.one();
    rs1.next = .{ common.q(0x11), common.q(0x22), common.q(0x33), common.q(0x44) };
    const row = Row{
        .rd = rd,
        .rs1 = rs1,
        .rs1_sign = QM31.one(),
        .is_sll = QM31.zero(),
        .is_srl = QM31.one(),
        .is_sra = QM31.zero(),
        .bit_multiplier_left = QM31.zero(),
        .bit_multiplier_right = QM31.one(),
        .bit_markers = .{ QM31.one(), QM31.zero(), QM31.zero(), QM31.zero(), QM31.zero(), QM31.zero(), QM31.zero(), QM31.zero() },
        .limb_markers = .{ QM31.zero(), QM31.one(), QM31.zero(), QM31.zero() },
        .carries = .{QM31.zero()} ** 4,
        .result = rd.next,
        .destination = .{
            .nonzero = QM31.one(),
            .inverse = common.q(3).inv() catch unreachable,
        },
    };
    try std.testing.expect(!evaluate(row).allZero());
}

test "shift common: arithmetic sign range binds operand bit 31" {
    const table = @import("../lookups/tables/schema.zig");
    var row = Row{
        .rd = .{
            .addr = common.q(3),
            .previous = .{QM31.zero()} ** 4,
            .previous_clock = QM31.zero(),
            .next = .{ QM31.zero(), QM31.zero(), QM31.zero(), common.q(0x44) },
        },
        .rs1 = .{
            .addr = QM31.one(),
            .previous = .{QM31.zero()} ** 4,
            .previous_clock = QM31.zero(),
            .next = .{ QM31.zero(), QM31.zero(), QM31.zero(), common.q(0x44) },
        },
        .rs1_sign = QM31.zero(),
        .is_sll = QM31.zero(),
        .is_srl = QM31.zero(),
        .is_sra = QM31.one(),
        .bit_multiplier_left = QM31.zero(),
        .bit_multiplier_right = QM31.one(),
        .bit_markers = .{ QM31.one(), QM31.zero(), QM31.zero(), QM31.zero(), QM31.zero(), QM31.zero(), QM31.zero(), QM31.zero() },
        .limb_markers = .{ QM31.one(), QM31.zero(), QM31.zero(), QM31.zero() },
        .carries = .{QM31.zero()} ** 4,
        .result = .{ QM31.zero(), QM31.zero(), QM31.zero(), common.q(0x44) },
        .destination = .{
            .nonzero = QM31.one(),
            .inverse = common.q(3).inv() catch unreachable,
        },
    };
    _ = try table.indexSecure(.range_check_m31, &signRangeLookup(row));

    row.rs1_sign = QM31.one();
    try std.testing.expect(evaluate(row).allZero());
    try std.testing.expectError(
        error.ValueOutOfRange,
        table.indexSecure(.range_check_m31, &signRangeLookup(row)),
    );
}
