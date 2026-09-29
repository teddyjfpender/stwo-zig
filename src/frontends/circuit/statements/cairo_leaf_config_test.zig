//! The leaf `ProofConfig` against `vectors/circuit/r6/cairo_statement.json`
//! (`leaf_configs`, emitted by upstream `ProofConfig::new` and
//! `ProofInfo::total_bytes` for the checked-in canonical_small registry).

const std = @import("std");
const core = @import("stwo_core");
const leaf_config = @import("cairo_leaf_config.zig");
const projection_mod = @import("../air_eval/projection.zig");
const cairo_components = @import("../air_eval/cairo_components.zig");
const proof = @import("../stark_verifier/proof.zig");

const FriConfigV2 = core.pcs.config_v2.FriConfigV2;

fn int(value: std.json.Value) u32 {
    return @intCast(value.integer);
}

test "cairo leaf config: ProofConfig and proof size match upstream for every registry leaf" {
    const allocator = std.testing.allocator;
    const bytes = try std.fs.cwd().readFileAlloc(allocator, "vectors/circuit/r6/cairo_statement.json", 4 * 1024 * 1024);
    defer allocator.free(bytes);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{});
    defer parsed.deinit();
    const body = parsed.value.object.get("body").?.object;
    try std.testing.expectEqual(int(body.get("constants").?.object.get("interaction_pow_bits").?), core.cairo_air_layout.interaction_pow_bits);

    const projection_bytes = try std.fs.cwd().readFileAlloc(allocator, "vectors/circuit/official/compiled_air_constraints_v1.bin", 64 * 1024 * 1024);
    defer allocator.free(projection_bytes);
    var projection = try projection_mod.parse(allocator, projection_bytes);
    defer projection.deinit();
    var table = try cairo_components.build(allocator, &projection);
    defer table.deinit();

    const records = body.get("leaf_configs").?.array.items;
    try std.testing.expect(records.len > 0);
    for (records) |item| {
        const record = item.object;
        const variant = std.meta.stringToEnum(core.cairo_air_layout.Variant, record.get("variant").?.string).?;
        const fri = try FriConfigV2.init(
            int(record.get("pow_bits").?),
            int(record.get("log_last_layer_degree_bound").?),
            int(record.get("log_blowup_factor").?),
            int(record.get("n_queries").?),
            int(record.get("fold_step").?),
        );
        var config = try leaf_config.leafVerifierConfig(allocator, &table, variant, fri, int(record.get("trace_log_size").?));
        defer config.deinit(allocator);

        const shapes = record.get("component_shapes").?.array.items;
        try std.testing.expectEqual(shapes.len, config.n_enabled_components);
        try std.testing.expectEqual(shapes.len, config.proof_config.component_shapes.len);
        for (shapes, config.proof_config.component_shapes) |want, got| {
            try std.testing.expectEqual(int(want.array.items[0]), got.trace_columns);
            try std.testing.expectEqual(int(want.array.items[1]), got.interaction_columns);
        }
        const columns = config.proof_config.nColumnsPerTrace();
        for (record.get("n_columns_per_trace").?.array.items, columns) |want, got| try std.testing.expectEqual(int(want), got);
        try std.testing.expectEqual(int(record.get("log_trace_size").?), config.proof_config.log_trace_size);
        try std.testing.expectEqual(int(record.get("n_interaction_pow_bits").?), config.proof_config.n_interaction_pow_bits);
        const total = proof.ProofInfo.fromConfig(config.proof_config).totalBytes();
        try std.testing.expectEqual(int(record.get("proof_total_bytes").?), total);
    }
}
