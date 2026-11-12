//! Canonical verifier-owned control row and its logical AIR encoding.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const control = @import("control.zig");
const ProofKind = @import("proof_kind.zig").ProofKind;
const COLUMN_COUNT = control.PREPROCESSED_COLUMN_COUNT;

pub const Row = struct {
    segment_mask: u32,
    binary_mask: u32,
    verifier_id: u32,
    sequence: u32,
    tag: u32,
    args: [4]u32,
    terminal_mask: u32,

    pub fn values(self: Row) [COLUMN_COUNT]M31 {
        return .{
            M31.fromU64(self.segment_mask),
            M31.fromU64(self.binary_mask),
            M31.fromU64(self.verifier_id),
            M31.fromU64(self.sequence),
            M31.fromU64(self.tag),
            M31.fromU64(self.args[0]),
            M31.fromU64(self.args[1]),
            M31.fromU64(self.args[2]),
            M31.fromU64(self.args[3]),
            M31.fromU64(self.terminal_mask),
        };
    }
};

pub fn logicalRow(row: Row, kind: ProofKind) [control.LOGICAL_INPUT_COUNT]M31 {
    const values = row.values();
    const selectors = kind.selectors();
    return values ++ .{ selectors[0], selectors[1] };
}

test "R-012 framework control row encoding preserves every column and proof-kind selector" {
    const row: Row = .{
        .segment_mask = 0,
        .binary_mask = 1,
        .verifier_id = 2,
        .sequence = 3,
        .tag = 4,
        .args = .{ 5, 6, 7, 8 },
        .terminal_mask = 9,
    };
    const values = row.values();
    for (values, 0..) |value, i| try std.testing.expectEqual(M31.fromU64(i), value);
    inline for (.{ ProofKind.segment_leaf, ProofKind.binary_node, ProofKind.empty_leaf }) |kind| {
        const encoded = logicalRow(row, kind);
        try std.testing.expectEqualSlices(M31, &values, encoded[0..COLUMN_COUNT]);
        try std.testing.expectEqual(M31.fromU64(@intFromBool(kind == .segment_leaf)), encoded[10]);
        try std.testing.expectEqual(M31.fromU64(@intFromBool(kind == .binary_node)), encoded[11]);
    }
}
