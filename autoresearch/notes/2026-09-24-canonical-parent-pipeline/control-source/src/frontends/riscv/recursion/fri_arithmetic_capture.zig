//! Hash-independent owned inputs for the canonical recursive FRI circuit.
//! Capture provenance and the profile are admitted by the caller. This conversion
//! checks arithmetic shape/routing; it does not authenticate Merkle roots itself.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("air/fri_verifier_circuit.zig");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
pub const Owned = struct {
    arena: std.heap.ArenaAllocator,
    inputs: circuit.Witness,
    pub fn deinit(self: *Owned) void {
        self.arena.deinit();
        self.* = undefined;
    }
    pub fn init(backing: std.mem.Allocator, profile: circuit.Profile, capture: anytype) !Owned {
        try profile.validate();
        const fail = error.InvalidFriArithmeticCapture;
        const layers = capture.fri.layers;
        const n: usize = profile.query_count;
        if (capture.queries.raw.len != n or capture.deep_answers.len != n or
            layers.len != profile.fold_widths.len or capture.last_layer_coefficients.len != try profile.lastLayerCoefficientCount()) return fail;
        var arena = std.heap.ArenaAllocator.init(backing);
        errdefer arena.deinit();
        const a = arena.allocator();
        const raw = try a.alloc(M31, n);
        const last = try a.alloc(M31, n);
        for (capture.queries.raw, raw) |position, *out| {
            if (position >= @as(usize, 1) << @intCast(profile.lifting_log_size)) return fail;
            out.* = M31.fromCanonical(@intCast(position));
        }
        const values = try a.alloc([]const QM31, layers.len);
        const positions = try a.alloc([]const M31, layers.len);
        const offsets = try a.alloc([]const M31, layers.len);
        const alphas = try a.alloc(QM31, layers.len);
        var consumed: u32 = 0;
        for (layers, profile.fold_widths, 0..) |layer, width, l| {
            const step = std.math.log2_int(u32, width);
            if (layer.fold_width != width or layer.fold_step != step or layer.query_count != n or
                layer.positions.len != n or layer.values.len != (std.math.mul(usize, n, width) catch return fail) or
                layer.path_depth != profile.lifting_log_size - consumed - step) return fail;
            const p = try a.alloc(M31, n);
            const o = try a.alloc(M31, n);
            for (layer.positions, capture.queries.raw, p, o) |position, original, *position_out, *offset_out| {
                if (position != original >> @intCast(consumed)) return fail;
                position_out.* = M31.fromCanonical(@intCast(position));
                offset_out.* = M31.fromCanonical(@intCast(position & (width - 1)));
            }
            positions[l] = p;
            offsets[l] = o;
            values[l] = try copyFields(a, layer.values);
            try validateField(layer.folding_alpha);
            alphas[l] = layer.folding_alpha;
            consumed += step;
        }
        for (capture.queries.raw, last) |position, *out| out.* = M31.fromCanonical(@intCast(position >> @intCast(consumed)));
        const deep = try copyFields(a, capture.deep_answers);
        const coefficients = try copyFields(a, capture.last_layer_coefficients);
        return .{ .arena = arena, .inputs = .{ .active = true, .deep_answers = deep, .authenticated_values = values, .fri_alphas = alphas, .raw_queries = raw, .fri_positions = positions, .fri_offsets = offsets, .last_layer_positions = last, .last_layer_coefficients = coefficients } };
    }
};
fn validateField(value: QM31) !void {
    for (value.toM31Array()) |coordinate| if (coordinate.v >= core.fields.m31.Modulus) return error.InvalidFriArithmeticCapture;
}
fn copyFields(a: std.mem.Allocator, values: []const QM31) ![]QM31 {
    for (values) |value| try validateField(value);
    return a.dupe(QM31, values);
}
