//! Hash-independent owned inputs for the canonical recursive DEEP circuit.
//! The caller admits the profile and capture provenance; this checks geometry
//! and encoding, not Merkle authentication or proof validity.
const std = @import("std");
const core = @import("stwo_core");
const deep = @import("air/pcs_deep_circuit.zig");
const layouts = @import("sample_point_layout.zig");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
pub const Owned = struct {
    arena: std.heap.ArenaAllocator,
    inputs: deep.Witness,
    pub fn deinit(self: *Owned) void {
        self.arena.deinit();
        self.* = undefined;
    }
    pub fn init(backing: std.mem.Allocator, profile: deep.Profile, capture: anytype) !Owned {
        try profile.validate();
        const fail = error.InvalidPcsArithmeticCapture;
        if (capture.column_log_sizes.len != profile.trees.len or capture.sampled_points.len != profile.trees.len or
            capture.sampled_values.len != try profile.sampleCount() or capture.queries.raw.len != profile.query_count or
            capture.deep_answers.len != profile.query_count or capture.queried_values.len != try std.math.mul(usize, try profile.columnCount(), profile.query_count)) return fail;
        try field(capture.oods_seed);
        try field(capture.deep_randomness);
        const current = core.circle.secureFieldPointFromRandomSeedChecked(capture.oods_seed) catch return fail;
        const mask_log = profile.lifting_log_size - profile.log_blowup_factor;
        const step = core.poly.circle.canonic.CanonicCoset.new(mask_log).step();
        const previous = current.sub(.{ .x = QM31.fromBase(step.x), .y = QM31.fromBase(step.y) });
        var cursor: usize = 0;
        for (profile.trees, capture.column_log_sizes, capture.sampled_points) |tree, logs, columns| {
            if (!std.mem.eql(u32, tree.column_log_sizes, logs) or columns.len != logs.len) return fail;
            for (columns) |points| {
                const layout = layouts.classifyColumn(points, current, previous) catch return fail;
                if (layout != profile.sample_layouts[cursor]) return fail;
                cursor += 1;
            }
        }
        for (capture.sampled_values) |value| try field(value);
        for (capture.deep_answers) |value| try field(value);
        for (capture.queried_values) |value| if (value.v >= core.fields.m31.Modulus) return fail;
        for (capture.queries.raw) |position| if (position >= @as(usize, 1) << @intCast(profile.lifting_log_size)) return fail;
        var arena = std.heap.ArenaAllocator.init(backing);
        errdefer arena.deinit();
        const a = arena.allocator();
        const raw = try a.alloc(M31, profile.query_count);
        for (capture.queries.raw, raw) |position, *out| out.* = M31.fromCanonical(@intCast(position));
        return .{ .arena = arena, .inputs = .{
            .active = true,
            .sampled_values = try a.dupe(QM31, capture.sampled_values),
            .queried_values = try a.dupe(M31, capture.queried_values),
            .oods_seed = capture.oods_seed,
            .deep_randomness = capture.deep_randomness,
            .raw_queries = raw,
            .answers = try a.dupe(QM31, capture.deep_answers),
        } };
    }
};
fn field(value: QM31) !void {
    for (value.toM31Array()) |coordinate| if (coordinate.v >= core.fields.m31.Modulus) return error.InvalidPcsArithmeticCapture;
}
