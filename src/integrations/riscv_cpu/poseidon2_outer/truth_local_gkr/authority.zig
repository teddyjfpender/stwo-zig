//! Opt-in truth-local-GKR shape authority. Existing profiles/rosters continue
//! to use classic interactions; this module grants no production admission.
const std = @import("std");
const core = @import("stwo_core");
const R = @import("../../word16_global_execution/services/roster.zig");
const Legacy = @import("../../word16_global_execution/services/gkr_local/truth_role.zig");
const Roles = @import("../../word16_global_execution/services/gkr_local/truth_components.zig");
const Frame = @import("../../word16_global_execution/services/gkr_local/truth_frame.zig");
const Classic = @import("../../word16_global_execution/services/gkr_local/truth_classic.zig");
const B = @import("../../word16_global_execution/services/gkr_local/binding.zig");
pub const production_admission_open = false;
pub const security_qualified = false;
pub const DOMAIN = "op-pure-p2-truth-local-gkr/v1";
pub const Shape = struct {
    original: Legacy.Shape,
    pub fn instance(self: Shape) Frame.Instance {
        return self.original.instance();
    }
    pub fn widths(self: Shape) [3]usize {
        const old = self.original.widths();
        return .{ old[0], old[1], B.INTERACTION_COLUMNS + old[2] - self.original.localWidth() };
    }
    pub fn globalWidth(self: Shape) usize {
        return self.widths()[2] - B.INTERACTION_COLUMNS;
    }
    pub fn constraints(self: Shape) usize {
        return self.original.nConstraints() - Classic.residualCount(self.instance()) + B.CONSTRAINTS;
    }
    pub fn shifts(self: Shape, tree: usize, column: usize) []const i32 {
        if (tree != 2) return self.original.shifts(tree, column);
        if (column < 8) return &.{ 0, 2 };
        if (column < 16 or column >= self.widths()[2] - 8) return &.{ 0, -1 };
        return &.{0};
    }
};
pub fn shapes(truth: R.Truth) ![3]Shape {
    if (truth != .keccak and truth != .secp) return error.UnsupportedLocalGkrTruth;
    const source = try Roles.shapesForDeclaration(@import("../../word16_global_execution/services/wire.zig").TruthDeclaration.from(truth));
    var out: [3]Shape = undefined;
    for (source, &out) |old, *value| value.* = .{ .original = old };
    try validate(out);
    return out;
}
pub fn validate(values: [3]Shape) !void {
    const first = values[0].original;
    if (first.kind == .keccak) {
        if (values[1].original.kind != .chi or values[2].original.kind != .xor5 or values[1].original.log_size != first.keccak_policy.tableLog(.chi) or values[2].original.log_size != first.keccak_policy.tableLog(.xor5)) return error.InvalidLocalGkrTruthShape;
    } else if (first.kind != .product or values[1].original.kind != .linear or values[2].original.kind != .bytes) return error.InvalidLocalGkrTruthShape;
    if (first.kind == .keccak) {
        for (values) |shape| if (shape.original.keccak_policy != first.keccak_policy) return error.InvalidLocalGkrTruthShape;
    } else if (values[1].original.byte_policy != first.byte_policy or values[2].original.log_size != 8) return error.InvalidLocalGkrTruthShape;
    var positive_mass: u64 = 0;
    for (values, 0..) |shape, i| {
        const instance = shape.instance();
        _ = try instance.variables();
        if ((i < 2 and first.kind != .keccak) or (i == 0 and first.kind == .keccak)) positive_mass = try std.math.add(u64, positive_mass, try std.math.mul(u64, try instance.rows(), instance.queries));
    }
    // Positive queries include padded secp reads. Table multiplicities are one
    // field count per source-owned distinct table value; no free list of poles.
    if (positive_mass >= core.fields.m31.Modulus) return error.TruthGkrMassExceeded;
}
pub const Cost = struct {
    old_widths: [3]usize = @splat(0),
    new_widths: [3]usize = @splat(0),
    old_cells: u64 = 0,
    new_cells: u64 = 0,
    old_samples: usize = 0,
    new_samples: usize = 0,
    padded_facts: u64 = 0,
};
pub fn cost(values: [3]Shape) !Cost {
    try validate(values);
    var out: Cost = .{};
    for (values) |shape| {
        const rows = try shape.instance().rows();
        out.padded_facts += try shape.instance().facts();
        const old = shape.original.widths();
        const next = shape.widths();
        for (0..3) |tree| {
            out.old_widths[tree] += old[tree];
            out.new_widths[tree] += next[tree];
            out.old_cells += rows * old[tree];
            out.new_cells += rows * next[tree];
            for (0..old[tree]) |c| out.old_samples += shape.original.shifts(tree, c).len;
            for (0..next[tree]) |c| out.new_samples += shape.shifts(tree, c).len;
        }
    }
    return out;
}
test "OP truth local GKR shape removes local interaction width and preserves source masks" {
    const a = std.testing.allocator;
    var setup = try @import("../../word16_global_execution/keccak/shared/roster.zig").TruthSetup.init(a, 13);
    defer setup.deinit();
    const s = try shapes(.{ .keccak = .{ .setup = &setup, .first_id = 1, .calls = 338 } });
    const c = try cost(s);
    try std.testing.expectEqual([3]usize{ 46, 1925, 5368 }, c.old_widths);
    try std.testing.expectEqual([3]usize{ 46, 1925, 256 }, c.new_widths);
    try std.testing.expectEqual(@as(u64, 59949056), c.old_cells);
    try std.testing.expectEqual(@as(u64, 18071552), c.new_cells);
    try std.testing.expectEqual(@as(u64, 16786432), c.padded_facts);
    try std.testing.expectEqual(@as(usize, 13774), c.old_samples);
    try std.testing.expectEqual(@as(usize, 8686), c.new_samples);
    try std.testing.expectEqualSlices(i32, &.{ 0, 2 }, s[0].shifts(2, 0));
    try std.testing.expectEqualSlices(i32, &.{ 0, -1 }, s[0].shifts(2, 8));
}
