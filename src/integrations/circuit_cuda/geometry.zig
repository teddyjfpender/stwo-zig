//! Exact circuit PCS shape shared by the resident CUDA proof controllers.
//! This is independent of witness values and of the channel profile. The
//! transcript chooses its channel separately; both profiles commit the same
//! four lifted trees and use the same FRI layer geometry.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const circuit_cpu = @import("stwo_circuit_cpu_integration");
const air_aot = @import("air_aot.zig");

const component_list = circuit.common.component_list;
const preprocessed = circuit.common.preprocessed;
const PcsConfigV2 = core.pcs.config_v2.PcsConfigV2;
const FriGeometry = core.fri.geometry.FriGeometry;

pub const TreeRole = enum(u8) { preprocessed, main, interaction, composition };

pub const Tree = struct {
    role: TreeRole,
    column_logs: []u32,
    lifted_log: u32,
};

pub const FriLayer = struct {
    evaluation_log: u32,
    fold_step: u32,
    cumulative_fold: u32,
    leaf_log: u32,
};

pub const Geometry = struct {
    allocator: std.mem.Allocator,
    trees: [4]Tree,
    fri_layers: []FriLayer,
    composition_evaluation_log: u32,
    fri_input_log: u32,
    identity: [32]u8,

    pub fn init(
        allocator: std.mem.Allocator,
        layout: *const preprocessed.ColumnLayout,
        bound: *const circuit_cpu.air.Bundle,
        catalog: *const air_aot.Catalog,
        pcs_config: PcsConfigV2,
    ) !Geometry {
        try catalog.admitBound(bound);
        const expected = try component_list.circuitComponentLogSizes(layout);
        const component_logs = expected.toArray();
        if (bound.components.len != component_logs.len)
            return error.InvalidCircuitGeometry;
        for (bound.components, component_logs, component_list.COMPONENT_NAMES) |component, log, name| {
            if (component.trace_log_size != log or
                !std.mem.eql(u8, component.label, name))
                return error.InvalidCircuitGeometry;
        }

        var trees: [4]Tree = undefined;
        var owned: usize = 0;
        errdefer for (trees[0..owned]) |tree| allocator.free(tree.column_logs);
        const blowup = pcs_config.fri_config.log_blowup_factor;
        const preprocessed_logs = try allocator.alloc(u32, layout.entries.len);
        for (layout.entries, preprocessed_logs) |entry, *out| out.* = entry.log_size;
        trees[0] = try treeFor(allocator, .preprocessed, preprocessed_logs, pcs_config, blowup);
        owned += 1;

        inline for (.{
            .{ TreeRole.main, circuit.witness.trace.traceWidths() },
            .{ TreeRole.interaction, circuit.witness.trace.interactionWidths() },
        }, 1..) |spec, tree_index| {
            var count: usize = 0;
            for (spec[1]) |width| count = try std.math.add(usize, count, width);
            const logs = try allocator.alloc(u32, count);
            var cursor: usize = 0;
            for (component_logs, spec[1]) |log, width| {
                @memset(logs[cursor..][0..width], log);
                cursor += width;
            }
            trees[tree_index] = try treeFor(allocator, spec[0], logs, pcs_config, blowup);
            owned += 1;
        }
        const composition_log = try bound.verifierMaxLogDegreeBound();
        const split = core.verifier_types.COMPOSITION_LOG_SPLIT;
        if (composition_log <= split) return error.InvalidCircuitGeometry;
        const composition_logs = try allocator.alloc(u32, 4 << @intCast(split));
        @memset(composition_logs, composition_log - split);
        trees[3] = try treeFor(allocator, .composition, composition_logs, pcs_config, blowup);
        owned += 1;

        const fri_input_log = try pcs_config.finalLiftingLogSize(trees[0].lifted_log, true, composition_log - split);
        const final_log = try std.math.add(u32, pcs_config.fri_config.log_last_layer_degree_bound, blowup);
        if (final_log >= fri_input_log) return error.InvalidCircuitGeometry;
        const fold_step = pcs_config.fri_config.fold_step;
        const round_count = std.math.divCeil(u32, fri_input_log - final_log, fold_step) catch return error.InvalidCircuitGeometry;
        const fri = FriGeometry.initRuntime(fri_input_log, .{
            .round_count = round_count,
            .fold_step = fold_step,
            .final_log = final_log,
            .packed_log = core.fri.LOG_PACKED_LEAF_SIZE,
        }) catch return error.InvalidCircuitGeometry;
        const fri_layers = try allocator.alloc(FriLayer, fri.roundCount());
        errdefer allocator.free(fri_layers);
        for (fri_layers, 0..) |*layer, index| layer.* = .{
            .evaluation_log = try fri.evaluationLog(index),
            .fold_step = try fri.roundFold(index),
            .cumulative_fold = try fri.cumulativeFold(index),
            .leaf_log = try fri.leafLog(index),
        };

        return .{
            .allocator = allocator,
            .trees = trees,
            .fri_layers = fri_layers,
            .composition_evaluation_log = composition_log,
            .fri_input_log = fri_input_log,
            .identity = geometryIdentity(layout, catalog, trees, fri_layers, pcs_config),
        };
    }

    pub fn deinit(self: *Geometry) void {
        for (self.trees) |tree| self.allocator.free(tree.column_logs);
        self.allocator.free(self.fri_layers);
        self.* = undefined;
    }
};

fn treeFor(allocator: std.mem.Allocator, role: TreeRole, logs: []u32, config: PcsConfigV2, blowup: u32) !Tree {
    errdefer allocator.free(logs);
    const extended = try allocator.alloc(u32, logs.len);
    defer allocator.free(extended);
    for (logs, extended) |log, *out| out.* = try std.math.add(u32, log, blowup);
    const lifted = try config.treeHeight(@intFromEnum(role), extended);
    return .{ .role = role, .column_logs = logs, .lifted_log = lifted };
}

fn geometryIdentity(layout: *const preprocessed.ColumnLayout, catalog: *const air_aot.Catalog, trees: [4]Tree, layers: []const FriLayer, pcs: PcsConfigV2) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/circuit-cuda/resident-geometry/v1\x00");
    hash.update(air_aot.bundle_sha256);
    for (layout.entries) |entry| {
        hash.update(entry.id);
        hashInt(&hash, entry.log_size);
    }
    for (catalog.occurrences) |occurrence| {
        const body = catalog.bodies[occurrence.body_index];
        hash.update(&body.normalized_program_identity);
        hashInt(&hash, occurrence.component_index);
        hashInt(&hash, occurrence.part_index);
    }
    for (trees) |tree| {
        hashInt(&hash, @intFromEnum(tree.role));
        hashInt(&hash, tree.lifted_log);
        for (tree.column_logs) |log| hashInt(&hash, log);
    }
    for (layers) |layer| {
        hashInt(&hash, layer.evaluation_log);
        hashInt(&hash, layer.fold_step);
        hashInt(&hash, layer.cumulative_fold);
        hashInt(&hash, layer.leaf_log);
    }
    inline for (.{ pcs.fri_config.pow_bits, pcs.fri_config.log_blowup_factor, pcs.fri_config.log_last_layer_degree_bound, pcs.fri_config.n_queries, pcs.fri_config.fold_step, pcs.trace_lifting_log_size, pcs.preprocessed_lifting_log_size }) |value| hashInt(&hash, value);
    return hash.finalResult();
}

fn hashInt(hash: *std.crypto.hash.sha2.Sha256, value: u32) void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, value, .little);
    hash.update(&bytes);
}

test "circuit CUDA resident geometry follows both registry sizes and lifted PCS" {
    const allocator = std.testing.allocator;
    const encoded = try std.fs.cwd().readFileAlloc(allocator, circuit_cpu.air.bundle_path, 16 << 20);
    defer allocator.free(encoded);
    var template = try circuit_cpu.air.parse(allocator, encoded);
    defer template.deinit();
    var catalog = try air_aot.build(allocator, encoded);
    defer catalog.deinit();
    const fri = try core.pcs.config_v2.FriConfigV2.init(26, 0, 1, 70, 4);
    for ([_]circuit.common.finalize.ComponentSizes{
        circuit_cpu.air.recorded_sizes,
        .{ .eq = 1 << 16, .qm31_ops = 1 << 19, .m31_to_u32 = 1 << 17, .triple_xor = 1 << 16, .blake_g_gate = 1 << 19 },
    }) |sizes| {
        const layout = try preprocessed.ColumnLayout.fromComponentSizes(sizes);
        var bound = try circuit_cpu.air.bind(allocator, &template, try component_list.circuitComponentLogSizes(&layout), &layout);
        defer bound.deinit();
        const config = PcsConfigV2.fromFriAndTraceSize(fri, layout.traceLogSize());
        var geometry = try Geometry.init(allocator, &layout, &bound, &catalog, config);
        defer geometry.deinit();
        try std.testing.expectEqual(@as(usize, preprocessed.N_PREPROCESSED_COLUMNS), geometry.trees[0].column_logs.len);
        try std.testing.expectEqual(config.trace_lifting_log_size, geometry.trees[0].lifted_log);
        try std.testing.expectEqual(config.trace_lifting_log_size, geometry.trees[3].lifted_log);
        try std.testing.expectEqual(@as(usize, 8), geometry.trees[3].column_logs.len);
        try std.testing.expectEqual(geometry.fri_input_log, geometry.fri_layers[0].evaluation_log);
        try std.testing.expectEqual(@as(u32, fri.log_last_layer_degree_bound + fri.log_blowup_factor), geometry.fri_layers[geometry.fri_layers.len - 1].evaluation_log - geometry.fri_layers[geometry.fri_layers.len - 1].fold_step);
    }
}

test "circuit CUDA tree and FRI geometry matches the pinned Rust R7 proofs" {
    const allocator = std.testing.allocator;
    const encoded = try std.fs.cwd().readFileAlloc(allocator, circuit_cpu.air.bundle_path, 16 << 20);
    defer allocator.free(encoded);
    var template = try circuit_cpu.air.parse(allocator, encoded);
    defer template.deinit();
    var catalog = try air_aot.build(allocator, encoded);
    defer catalog.deinit();
    for ([_][]const u8{ "vectors/circuit/r7/prove_small.json", "vectors/circuit/r7/prove_profiles.json" }, 0..) |path, fixture_index| {
        const fixture_bytes = try std.fs.cwd().readFileAlloc(allocator, path, 8 << 20);
        defer allocator.free(fixture_bytes);
        var parsed = try std.json.parseFromSlice(std.json.Value, allocator, fixture_bytes, .{});
        defer parsed.deinit();
        const body = try jsonField(parsed.value, "body");
        if (fixture_index == 0) {
            const proofs = (try jsonField(body, "proofs")).array.items;
            try std.testing.expectEqual(@as(usize, 6), proofs.len);
            for (proofs) |proof| try expectRustProofGeometry(allocator, &template, &catalog, proof);
        } else {
            const profiles = (try jsonField(body, "profiles")).array.items;
            try std.testing.expectEqual(@as(usize, 2), profiles.len);
            for (profiles) |profile| {
                const proofs = (try jsonField(profile, "proofs")).array.items;
                try std.testing.expectEqual(@as(usize, 2), proofs.len);
                for (proofs) |proof| try expectRustProofGeometry(allocator, &template, &catalog, proof);
            }
        }
    }
}

fn expectRustProofGeometry(allocator: std.mem.Allocator, template: *const circuit_cpu.air.Bundle, catalog: *const air_aot.Catalog, proof: std.json.Value) !void {
    const pairs = (try jsonField(proof, "component_log_sizes")).array.items;
    if (pairs.len != component_list.N_COMPONENTS) return error.InvalidCircuitFixture;
    const sizes = circuit.common.finalize.ComponentSizes{
        .eq = try jsonSize(pairs[0]),
        .qm31_ops = try jsonSize(pairs[1]),
        .triple_xor = try jsonSize(pairs[2]),
        .m31_to_u32 = try jsonSize(pairs[3]),
        .blake_g_gate = try jsonSize(pairs[4]),
    };
    const layout = try preprocessed.ColumnLayout.fromComponentSizes(sizes);
    var bound = try circuit_cpu.air.bind(allocator, template, try component_list.circuitComponentLogSizes(&layout), &layout);
    defer bound.deinit();
    const config_json = try jsonField(proof, "pcs_config");
    const fri_json = try jsonField(config_json, "fri_config");
    const config = PcsConfigV2{
        .fri_config = try core.pcs.config_v2.FriConfigV2.init(
            try jsonU32(try jsonField(fri_json, "pow_bits")),
            try jsonU32(try jsonField(fri_json, "log_last_layer_degree_bound")),
            try jsonU32(try jsonField(fri_json, "log_blowup_factor")),
            try jsonU32(try jsonField(fri_json, "n_queries")),
            try jsonU32(try jsonField(fri_json, "fold_step")),
        ),
        .trace_lifting_log_size = try jsonU32(try jsonField(config_json, "trace_lifting_log_size")),
        .preprocessed_lifting_log_size = try jsonU32(try jsonField(config_json, "preprocessed_lifting_log_size")),
    };
    var geometry = try Geometry.init(allocator, &layout, &bound, catalog, config);
    defer geometry.deinit();
    try std.testing.expectEqual(config.preprocessed_lifting_log_size, geometry.trees[0].lifted_log);
    try std.testing.expectEqual(config.trace_lifting_log_size, geometry.trees[1].lifted_log);
    try std.testing.expectEqual(config.trace_lifting_log_size, geometry.trees[2].lifted_log);
    try std.testing.expectEqual(config.trace_lifting_log_size, geometry.trees[3].lifted_log);
    const expected_fri = try jsonField(proof, "fri");
    try std.testing.expectEqual(@as(usize, 1) + (try jsonField(expected_fri, "inner_layer_roots")).array.items.len, geometry.fri_layers.len);
    const fixture_groups = [_][]const u8{ "preprocessed_columns", "base_columns", "interaction_columns" };
    for (fixture_groups, 0..) |key, tree_index| {
        const groups = (try jsonField(proof, key)).array.items;
        var column_index: usize = 0;
        for (groups) |group| for ((try jsonField(group, "columns")).array.items) |column| {
            if (column_index >= geometry.trees[tree_index].column_logs.len) return error.InvalidCircuitFixture;
            const fixture_log = try jsonU32(try jsonField(column, "log_size"));
            try std.testing.expectEqual(geometry.trees[tree_index].column_logs[column_index] + config.fri_config.log_blowup_factor, fixture_log);
            column_index += 1;
        };
        try std.testing.expectEqual(geometry.trees[tree_index].column_logs.len, column_index);
    }
}

fn jsonField(value: std.json.Value, key: []const u8) !std.json.Value {
    if (value != .object) return error.InvalidCircuitFixture;
    return value.object.get(key) orelse error.InvalidCircuitFixture;
}

fn jsonU32(value: std.json.Value) !u32 {
    if (value != .integer or value.integer < 0) return error.InvalidCircuitFixture;
    return std.math.cast(u32, value.integer) orelse error.InvalidCircuitFixture;
}

fn jsonSize(pair: std.json.Value) !usize {
    if (pair != .array or pair.array.items.len != 2) return error.InvalidCircuitFixture;
    const log = try jsonU32(pair.array.items[1]);
    if (log >= @bitSizeOf(usize)) return error.InvalidCircuitFixture;
    return @as(usize, 1) << @intCast(log);
}
