//! Canonical native witness rows for the typed V3 leaf-link arithmetic AIR.
//! These rows are only meaningful when a future wrapper authenticates every
//! source and local-statement relation consumed by the AIR definition.
const std = @import("std");
const core = @import("stwo_core");
const air = @import("ethereum_leaf_link_arithmetic_v1.zig");
const segment_v2 = @import("../segment_statement_v2.zig");
const M31 = core.fields.m31.M31;
const Row = air.Row;
const Kind = air.Kind;
const ROOT = air.ROOT;
const ROOT_LOW = air.ROOT_LOW;
const ROOT_HIGH = air.ROOT_HIGH;
const ROOT_BYTES = air.ROOT_BYTES;
const ROOT_DOUBLED_HIGH = air.ROOT_DOUBLED_HIGH;
const ROOT_GAP_INVERSE = air.ROOT_GAP_INVERSE;
const PRESENCE = air.PRESENCE;
const TAG = air.TAG;
const START = air.START;
const END = air.END;
const COUNT = air.COUNT;
const CARRY = air.CARRY;
const POSITION_BYTES = air.POSITION_BYTES;
const ACTIVE = air.ACTIVE;
const ROOT_MASK = air.ROOT_MASK;
const COMPLETION_MASK = air.COMPLETION_MASK;
const POSITION_MASK = air.POSITION_MASK;
const SIDE = air.SIDE;

pub fn logicalRow(kind: Kind, root_value: u32, presence: bool, start: u64, count: u32) !Row {
    var row: Row = @splat(M31.zero());
    row[ACTIVE] = M31.one();
    switch (kind) {
        .entry_root, .exit_root => {
            if (root_value >= core.fields.m31.Modulus) return error.NonCanonicalContinuationRoot;
            row[ROOT_MASK] = M31.one();
            row[SIDE] = M31.fromCanonical(@intFromBool(kind == .exit_root));
            row[ROOT] = M31.fromCanonical(root_value);
            const low = root_value & 0xffff;
            const high = root_value >> 16;
            row[ROOT_LOW] = M31.fromCanonical(low);
            row[ROOT_HIGH] = M31.fromCanonical(high);
            row[ROOT_BYTES] = M31.fromCanonical(low & 255);
            row[ROOT_BYTES + 1] = M31.fromCanonical(low >> 8);
            row[ROOT_BYTES + 2] = M31.fromCanonical(high & 255);
            row[ROOT_BYTES + 3] = M31.fromCanonical(high >> 8);
            row[ROOT_DOUBLED_HIGH] = M31.fromCanonical(2 * (high >> 8));
            const gap = (65535 - low) + (32767 - high);
            row[ROOT_GAP_INVERSE] = try M31.fromCanonical(gap).inv();
        },
        .completion => {
            row[COMPLETION_MASK] = M31.one();
            row[PRESENCE] = M31.fromCanonical(@intFromBool(presence));
            row[TAG] = M31.fromCanonical(@intFromEnum(segment_v2.Tag.completion_absent) + @as(u32, @intFromBool(presence)));
        },
        .position => {
            const end = std.math.add(u64, start, count) catch return error.GlobalCycleOverflow;
            row[POSITION_MASK] = M31.one();
            var carry: u32 = 0;
            for (0..4) |i| {
                const shift: u6 = @intCast(16 * i);
                const start_limb: u32 = @intCast((start >> shift) & 0xffff);
                const end_limb: u32 = @intCast((end >> shift) & 0xffff);
                const count_limb: u32 = if (i < 2) @intCast((count >> @as(u5, @intCast(16 * i))) & 0xffff) else 0;
                row[START + i] = M31.fromCanonical(start_limb);
                row[END + i] = M31.fromCanonical(end_limb);
                row[POSITION_BYTES + 2 * i] = M31.fromCanonical(start_limb & 255);
                row[POSITION_BYTES + 2 * i + 1] = M31.fromCanonical(start_limb >> 8);
                row[POSITION_BYTES + 8 + 2 * i] = M31.fromCanonical(end_limb & 255);
                row[POSITION_BYTES + 8 + 2 * i + 1] = M31.fromCanonical(end_limb >> 8);
                carry = (start_limb + count_limb + carry) >> 16;
                if (i < 3) row[CARRY + i] = M31.fromCanonical(carry);
                if (i < 2) {
                    row[COUNT + i] = M31.fromCanonical(count_limb);
                    row[POSITION_BYTES + 16 + 2 * i] = M31.fromCanonical(count_limb & 255);
                    row[POSITION_BYTES + 16 + 2 * i + 1] = M31.fromCanonical(count_limb >> 8);
                }
            }
            std.debug.assert(carry == 0);
        },
    }
    return row;
}
