//! Circuit recursion proof cardinalities in the shared one-read SWPC envelope.
//! The shape is taken from the authenticated circuit geometry, not Cairo's
//! compact-proof protocol. In particular FRI uses the circuit's fold step.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const shared = @import("stwo_native_cuda_integration").common.proof_bundle;
const geometry_module = @import("geometry.zig");
const oods_module = @import("resident_oods.zig");
const decommit_module = @import("resident_decommit.zig");

pub const Layout = struct {
    sampled_values: usize,
    fri_roots: usize,
    final_coefficients: usize,
    query_count: u32,
    query_pow_bits: u32,
    blowup: u32,
    fold_step: u32,
    max_log_degree_bound: u32,

    pub fn init(
        geometry: *const geometry_module.Geometry,
        oods: *const oods_module.Plan,
        config: core.pcs.config_v2.PcsConfigV2,
    ) !Layout {
        if (geometry.fri_layers.len == 0 or
            geometry.fri_layers.len > 64 or
            oods.offsets.len == 0 or
            config.fri_config.n_queries == 0 or
            config.fri_config.fold_step == 0)
            return error.InvalidCircuitTerminalGeometry;
        return .{
            .sampled_values = oods.offsets.len,
            .fri_roots = geometry.fri_layers.len,
            .final_coefficients = try shared.pow2(config.fri_config.log_last_layer_degree_bound),
            .query_count = config.fri_config.n_queries,
            .query_pow_bits = config.fri_config.pow_bits,
            .blowup = config.fri_config.log_blowup_factor,
            .fold_step = config.fri_config.fold_step,
            .max_log_degree_bound = geometry.composition_evaluation_log,
        };
    }
};

pub const Decommit = struct { capacity_words: usize };

const Descriptor = struct {
    pub fn sectionLengths(logical: Layout, decommit: Decommit) ![shared.section_count]usize {
        if (logical.sampled_values == 0 or logical.fri_roots == 0 or
            logical.final_coefficients == 0 or decommit.capacity_words == 0)
            return error.InvalidCircuitTerminalGeometry;
        return .{
            try shared.add(4 * 8, try shared.mul(circuit.common.component_list.N_COMPONENTS, 4)),
            try shared.mul(logical.sampled_values, 4),
            try shared.mul(logical.fri_roots, 8),
            try shared.mul(logical.final_coefficients, 4),
            4, // Interaction PoW nonce followed by FRI/query PoW nonce.
            decommit.capacity_words,
        };
    }

    pub fn fixedHeader(logical: Layout, _: Decommit, total_words: usize) ![shared.fixed_header_words]u32 {
        return .{
            shared.magic,
            shared.version,
            try shared.u32Count(total_words),
            shared.section_count,
            4,
            circuit.common.component_list.N_COMPONENTS,
            try shared.u32Count(try shared.mul(logical.sampled_values, 4)),
            try shared.u32Count(logical.fri_roots),
            try shared.u32Count(logical.final_coefficients),
            logical.query_count,
            logical.query_pow_bits,
            circuit.common.component_list.INTERACTION_POW_BITS,
            logical.max_log_degree_bound,
            logical.blowup,
            logical.fold_step,
            std.math.maxInt(u32), // Final-layer degree verdict is device-written.
        };
    }
};

pub const Bundle = shared.BundleFor(Layout, Decommit, Descriptor);

pub fn init(
    allocator: std.mem.Allocator,
    geometry: *const geometry_module.Geometry,
    oods: *const oods_module.Plan,
    decommit: *const decommit_module.Plan,
    config: core.pcs.config_v2.PcsConfigV2,
) !Bundle {
    return Bundle.init(allocator, try Layout.init(geometry, oods, config), .{
        .capacity_words = decommit.topology.assembly_capacity_words,
    });
}

test "resident circuit terminal bundle has four roots, eleven claims and two nonces" {
    const allocator = std.testing.allocator;
    const cpu = @import("stwo_circuit_cpu_integration");
    const air = @import("air_aot.zig");
    const encoded = try std.fs.cwd().readFileAlloc(allocator, cpu.air.bundle_path, 16 << 20);
    defer allocator.free(encoded);
    var template = try cpu.air.parse(allocator, encoded);
    defer template.deinit();
    var catalog = try air.build(allocator, encoded);
    defer catalog.deinit();
    const column_layout = try circuit.common.preprocessed.ColumnLayout.fromComponentSizes(cpu.air.recorded_sizes);
    var bound = try cpu.air.bind(allocator, &template, try circuit.common.component_list.circuitComponentLogSizes(&column_layout), &column_layout);
    defer bound.deinit();
    const fri = try core.pcs.config_v2.FriConfigV2.init(26, 0, 1, 70, 4);
    const config = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(fri, column_layout.traceLogSize());
    var geometry = try geometry_module.Geometry.init(allocator, &column_layout, &bound, &catalog, config);
    defer geometry.deinit();
    var oods = try oods_module.Plan.init(allocator, &bound, &geometry, fri.log_blowup_factor);
    defer oods.deinit();
    var decommit = try decommit_module.Plan.init(allocator, &geometry, config);
    defer decommit.deinit();
    var bundle = try init(allocator, &geometry, &oods, &decommit, config);
    defer bundle.deinit(allocator);
    try bundle.validate(decommit.topology.assembly_capacity_words);
    try std.testing.expectEqual(@as(usize, 4 * 8 + circuit.common.component_list.N_COMPONENTS * 4), bundle.section(.trace_commitments).words);
    try std.testing.expectEqual(oods.offsets.len * 4, bundle.section(.sampled_values).words);
    try std.testing.expectEqual(geometry.fri_layers.len * 8, bundle.section(.fri_commitments).words);
    try std.testing.expectEqual(@as(usize, 4), bundle.section(.proof_of_work).words);
    try std.testing.expectEqual(@as(u32, 4), bundle.static_header[14]);
}
