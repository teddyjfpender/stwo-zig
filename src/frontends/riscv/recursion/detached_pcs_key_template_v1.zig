//! Proof-free FRI/PCS graph template for an independently admitted detached
//! child key. It carries only fixed geometry and inactive circuit evaluations.
const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const fri = @import("air/fri_verifier_circuit.zig");
const pcs = @import("air/pcs_deep_circuit.zig");
const fri_merkle = @import("air/fri_merkle_leaf_witness.zig");
const key_shape = @import("detached_pcs_key_shape_v1.zig");
const key_geometry = @import("detached_pcs_key_geometry_v1.zig");
const TREE_COUNT = @import("recursion_air_composition_capture_layout_v3.zig").TREE_COUNT;

pub const TemplateV1 = struct {
    allocator: std.mem.Allocator,
    geometry: key_geometry.GeometryV1,
    circuit: fri.Circuit,
    pcs_circuit: pcs.Prepared,
    trace_tree_heights: []u32,
    column_log_sizes: [][]const u32,
    fri_layer_profiles: []fri_merkle.LayerProfile,
    fold_widths: []u32,

    pub fn pcsGraph(self: *const TemplateV1) @import("air/composition_circuit.zig").CircuitGraph {
        return self.pcs_circuit.graph();
    }

    pub fn friGraph(self: *const TemplateV1) @import("air/composition_circuit.zig").CircuitGraph {
        return self.circuit.graph();
    }

    pub fn init(allocator: std.mem.Allocator, key: anytype) !TemplateV1 {
        var geometry = try key_geometry.GeometryV1.init(allocator, key);
        errdefer geometry.deinit();
        const shape = try key_shape.scheduleShape(allocator, key);
        if (shape.query_count != geometry.query_count or
            shape.tree_heights[TREE_COUNT - 1] != geometry.lifting_log_size)
            return error.KeyPcsGeometryMismatch;
        const trace_tree_heights = try allocator.dupe(u32, &shape.tree_heights);
        errdefer allocator.free(trace_tree_heights);
        const column_log_sizes = try allocator.alloc([]const u32, TREE_COUNT);
        errdefer allocator.free(column_log_sizes);
        for (geometry.column_logs, column_log_sizes) |logs, *destination|
            destination.* = logs;
        const fri_layer_profiles = try allocator.alloc(fri_merkle.LayerProfile, shape.fri.count);
        errdefer allocator.free(fri_layer_profiles);
        const fold_widths = try allocator.alloc(u32, shape.fri.count);
        errdefer allocator.free(fold_widths);
        for (shape.fri.active(), fri_layer_profiles, fold_widths) |round, *layer, *width| {
            layer.* = .{ .width = round.fold_width, .tree_height = round.merkle_tree_height };
            width.* = round.fold_width;
        }
        const fri_profile = fri.Profile{
            .lifting_log_size = geometry.lifting_log_size,
            .log_blowup_factor = geometry.blowup,
            .log_last_layer_degree_bound = key.pcs_config.fri_config.log_last_layer_degree_bound,
            .fold_widths = fold_widths,
            .query_count = geometry.query_count,
        };
        try fri_profile.validate();
        var circuit = try fri.build(allocator, fri_profile);
        errdefer circuit.deinit();
        var pcs_circuit = try geometry.buildPcsCircuit(allocator);
        errdefer pcs_circuit.deinit();
        return .{
            .allocator = allocator,
            .geometry = geometry,
            .circuit = circuit,
            .pcs_circuit = pcs_circuit,
            .trace_tree_heights = trace_tree_heights,
            .column_log_sizes = column_log_sizes,
            .fri_layer_profiles = fri_layer_profiles,
            .fold_widths = fold_widths,
        };
    }

    pub fn deinit(self: *TemplateV1) void {
        self.pcs_circuit.deinit();
        self.circuit.deinit();
        self.allocator.free(self.fold_widths);
        self.allocator.free(self.fri_layer_profiles);
        self.allocator.free(self.column_log_sizes);
        self.allocator.free(self.trace_tree_heights);
        self.geometry.deinit();
        self.* = undefined;
    }

    pub fn evaluateInactive(self: *const TemplateV1) !fri.Evaluation {
        const query_count: usize = self.geometry.query_count;
        const layer_count = self.fold_widths.len;
        const coefficient_count = try self.circuit.profile().lastLayerCoefficientCount();
        var qm31_count = std.math.add(usize, query_count, layer_count) catch return error.KeyPcsGeometryMismatch;
        qm31_count = std.math.add(usize, qm31_count, coefficient_count) catch return error.KeyPcsGeometryMismatch;
        for (self.fold_widths) |width| {
            const values = std.math.mul(usize, query_count, width) catch return error.KeyPcsGeometryMismatch;
            qm31_count = std.math.add(usize, qm31_count, values) catch return error.KeyPcsGeometryMismatch;
        }
        const m31_count = std.math.mul(usize, query_count, 2 + 2 * layer_count) catch return error.KeyPcsGeometryMismatch;
        const zero_qm31 = try self.allocator.alloc(QM31, qm31_count);
        defer self.allocator.free(zero_qm31);
        @memset(zero_qm31, QM31.zero());
        const zero_m31 = try self.allocator.alloc(M31, m31_count);
        defer self.allocator.free(zero_m31);
        @memset(zero_m31, M31.zero());

        var authenticated: [fri.MAX_FRI_LAYERS][]const QM31 = undefined;
        var positions: [fri.MAX_FRI_LAYERS][]const M31 = undefined;
        var offsets: [fri.MAX_FRI_LAYERS][]const M31 = undefined;
        var q_cursor: usize = 0;
        const deep_answers = take(QM31, zero_qm31, &q_cursor, query_count);
        for (self.fold_widths, 0..) |width, index|
            authenticated[index] = take(QM31, zero_qm31, &q_cursor, query_count * width);
        const alphas = take(QM31, zero_qm31, &q_cursor, layer_count);
        const coefficients = take(QM31, zero_qm31, &q_cursor, coefficient_count);
        std.debug.assert(q_cursor == zero_qm31.len);

        var m_cursor: usize = 0;
        const raw_queries = take(M31, zero_m31, &m_cursor, query_count);
        for (0..layer_count) |index| {
            positions[index] = take(M31, zero_m31, &m_cursor, query_count);
            offsets[index] = take(M31, zero_m31, &m_cursor, query_count);
        }
        const last_positions = take(M31, zero_m31, &m_cursor, query_count);
        std.debug.assert(m_cursor == zero_m31.len);
        return self.circuit.evaluate(self.allocator, .{
            .active = false,
            .deep_answers = deep_answers,
            .authenticated_values = authenticated[0..layer_count],
            .fri_alphas = alphas,
            .raw_queries = raw_queries,
            .fri_positions = positions[0..layer_count],
            .fri_offsets = offsets[0..layer_count],
            .last_layer_positions = last_positions,
            .last_layer_coefficients = coefficients,
        });
    }

    pub fn evaluatePcsInactive(self: *const TemplateV1) !pcs.Evaluation {
        return self.pcs_circuit.evaluateInactive(self.allocator);
    }
};

fn take(comptime T: type, storage: []const T, cursor: *usize, count: usize) []const T {
    const result = storage[cursor.*..][0..count];
    cursor.* += count;
    return result;
}
