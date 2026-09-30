//! Circuit AIR admission and placement plan for the shared resident CUDA
//! constraint evaluator. The pinned circuit catalogue selects every kernel;
//! proof-specific geometry and literal parameters never select executable
//! code. This is the same heterogeneous-domain topology used by Cairo CUDA.
const std = @import("std");
const circuit = @import("stwo_circuit_frontend");
const circuit_cpu = @import("stwo_circuit_cpu_integration");
const cairo_cuda = @import("stwo_cairo_cuda_integration");
const eval = cairo_cuda.executor.eval.topology;
const parametric = cairo_cuda.parametric_eval;
const air_aot = @import("air_aot.zig");

pub const Placement = struct {
    component_index: u32,
    part_index: u32,
    cache_key: u64,
    kernel_name: [:0]u8,
    constant_offset: u32,
    constant_count: u32,
};

pub const Plan = struct {
    allocator: std.mem.Allocator,
    topology: eval.Topology,
    placements: []Placement,
    constants: []u32,
    denominator_inverses: []u32,
    preprocessed_logs: []u32,

    pub fn init(
        allocator: std.mem.Allocator,
        layout: *const circuit.common.preprocessed.ColumnLayout,
        bound: *const circuit_cpu.air.Bundle,
        catalog: *const air_aot.Catalog,
    ) !Plan {
        try catalog.admitBound(bound);
        const preprocessed_logs = try allocator.alloc(u32, layout.entries.len);
        errdefer allocator.free(preprocessed_logs);
        for (layout.entries, preprocessed_logs) |entry, *log| log.* = entry.log_size;
        var topology = try eval.Topology.deriveCanonical(allocator, bound.*, preprocessed_logs);
        errdefer topology.deinit();
        if (topology.components.len != circuit.common.component_list.N_COMPONENTS or
            topology.placements.len != catalog.occurrences.len)
            return error.CircuitCompositionPlacementMismatch;

        var constant_count: usize = 0;
        var denominator_count: usize = 0;
        for (bound.components) |component| {
            denominator_count = try checkedAdd(denominator_count, component.denominator_inverses.len);
            for (component.parts) |part|
                constant_count = try checkedAdd(constant_count, try parametric.constantWordCount(part.program));
        }
        if (constant_count == 0 or denominator_count != topology.summary.denominator_words)
            return error.CircuitCompositionPlacementMismatch;
        const constants = try allocator.alloc(u32, constant_count);
        errdefer allocator.free(constants);
        const denominators = try allocator.alloc(u32, denominator_count);
        errdefer allocator.free(denominators);
        const placements = try allocator.alloc(Placement, topology.placements.len);
        var initialized: usize = 0;
        errdefer {
            for (placements[0..initialized]) |placement| allocator.free(placement.kernel_name);
            allocator.free(placements);
        }

        var constant_cursor: usize = 0;
        var denominator_cursor: usize = 0;
        var placement_cursor: usize = 0;
        for (bound.components, 0..) |component, component_index| {
            @memcpy(denominators[denominator_cursor..][0..component.denominator_inverses.len], component.denominator_inverses);
            denominator_cursor += component.denominator_inverses.len;
            for (component.parts, 0..) |part, part_index| {
                const occurrence = catalog.occurrences[placement_cursor];
                const topology_placement = topology.placements[placement_cursor];
                if (occurrence.component_index != component_index or
                    occurrence.part_index != part_index or
                    topology_placement.component_index != component_index or
                    topology_placement.part_index != part_index or
                    occurrence.body_index >= catalog.bodies.len)
                    return error.CircuitCompositionPlacementMismatch;
                const body = catalog.bodies[occurrence.body_index];
                const count = try parametric.constantWordCount(part.program);
                if (count != body.constant_count or body.cache_key == 0)
                    return error.CircuitCompositionPlacementMismatch;
                try parametric.writeConstants(part.program, constants[constant_cursor..][0..count]);
                placements[placement_cursor] = .{
                    .component_index = @intCast(component_index),
                    .part_index = @intCast(part_index),
                    .cache_key = body.cache_key,
                    .kernel_name = try allocator.dupeZ(u8, body.kernel_name),
                    .constant_offset = std.math.cast(u32, constant_cursor) orelse return error.CircuitCompositionSizeOverflow,
                    .constant_count = std.math.cast(u32, count) orelse return error.CircuitCompositionSizeOverflow,
                };
                initialized += 1;
                placement_cursor += 1;
                constant_cursor += count;
            }
        }
        if (placement_cursor != placements.len or constant_cursor != constants.len or denominator_cursor != denominators.len)
            return error.CircuitCompositionPlacementMismatch;
        return .{
            .allocator = allocator,
            .topology = topology,
            .placements = placements,
            .constants = constants,
            .denominator_inverses = denominators,
            .preprocessed_logs = preprocessed_logs,
        };
    }

    pub fn deinit(self: *Plan) void {
        for (self.placements) |placement| self.allocator.free(placement.kernel_name);
        self.allocator.free(self.placements);
        self.allocator.free(self.constants);
        self.allocator.free(self.denominator_inverses);
        self.allocator.free(self.preprocessed_logs);
        self.topology.deinit();
        self.* = undefined;
    }
};

fn checkedAdd(a: usize, b: usize) !usize {
    return std.math.add(usize, a, b) catch error.CircuitCompositionSizeOverflow;
}

test "resident circuit composition admits pinned AOT and all eleven source domains" {
    const allocator = std.testing.allocator;
    const encoded = try std.fs.cwd().readFileAlloc(allocator, circuit_cpu.air.bundle_path, 16 << 20);
    defer allocator.free(encoded);
    var template = try circuit_cpu.air.parse(allocator, encoded);
    defer template.deinit();
    var catalog = try air_aot.build(allocator, encoded);
    defer catalog.deinit();
    const layout = try circuit.common.preprocessed.ColumnLayout.fromComponentSizes(circuit_cpu.air.recorded_sizes);
    var bound = try circuit_cpu.air.bind(allocator, &template, try circuit.common.component_list.circuitComponentLogSizes(&layout), &layout);
    defer bound.deinit();
    var plan = try Plan.init(allocator, &layout, &bound, &catalog);
    defer plan.deinit();
    try std.testing.expectEqual(@as(usize, 11), plan.topology.components.len);
    try std.testing.expectEqual(catalog.occurrences.len, plan.placements.len);
    try std.testing.expect(plan.topology.wide_trace_offsets);
    try std.testing.expect(plan.topology.summary.accumulator_words > 0);
    for (plan.topology.components, bound.components) |component, source| {
        try std.testing.expectEqual(source.trace_log_size, component.trace_log_size);
        try std.testing.expectEqual(source.evaluation_log_size, component.evaluation_log_size);
        try std.testing.expectEqual(source.ext_sources.len, component.extended_parameter_count);
    }
    for (plan.placements) |placement| {
        try std.testing.expect(placement.cache_key != 0);
        try std.testing.expect(placement.kernel_name.len != 0);
    }
}
