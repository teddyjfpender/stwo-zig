//! Machine-readable, source-bound Cairo CUDA geometry receipt.
const std = @import("std");
const stwo = @import("stwo");
const source = stwo.integrations.cairo_cuda.canonical_source;
const controller_bundle = stwo.integrations.cairo_cuda.executor.ingress.controller_bundle;

const ComponentBytes = struct {
    main: u64 = 0,
    interaction: u64 = 0,
};

pub fn writeJsonReport(
    allocator: std.mem.Allocator,
    path: []const u8,
    assets: *const source.Assets,
    prepared: *const source.Prepared,
    controllers: *const controller_bundle.Prepared,
    registry_sha: ?[32]u8,
) !void {
    const program = prepared.request.proof_program;
    var partial_ec: ComponentBytes = .{};
    var ec_op: ComponentBytes = .{};
    var tree_main_words: u64 = 0;
    var tree_interaction_words: u64 = 0;
    for (program.commitments) |tree| {
        const columns = program.trace_columns[tree.first_column .. tree.first_column + tree.column_count];
        for (columns) |column| {
            if (column.log_rows >= 63) return error.InvalidTraceLog;
            const words: u64 = @as(u64, 1) << @intCast(column.log_rows);
            if (tree.role == .main) tree_main_words = try std.math.add(u64, tree_main_words, words);
            if (tree.role == .interaction) tree_interaction_words = try std.math.add(u64, tree_interaction_words, words);
            if (column.component >= prepared.composition.components.len) continue;
            const label = prepared.composition.components[column.component].label;
            const selected: ?*ComponentBytes = if (std.mem.eql(u8, label, "partial_ec_mul_window_bits_18"))
                &partial_ec
            else if (std.mem.eql(u8, label, "ec_op_builtin"))
                &ec_op
            else
                null;
            if (selected) |bytes| {
                const count = try std.math.mul(u64, words, 4);
                if (tree.role == .main) bytes.main = try std.math.add(u64, bytes.main, count);
                if (tree.role == .interaction) bytes.interaction = try std.math.add(u64, bytes.interaction, count);
            }
        }
    }

    var pedersen_distinct: ?u32 = null;
    var pedersen_partial_rows: ?u32 = null;
    for (prepared.claim.components, prepared.geometry.extents) |component, extent| {
        if (std.mem.eql(u8, component.name, "pedersen_aggregator_window_bits_18"))
            pedersen_distinct = extent.distinct_rows;
        if (std.mem.eql(u8, component.name, "partial_ec_mul_window_bits_18"))
            pedersen_partial_rows = extent.padded_rows;
    }
    var partial_lookup_bytes: u64 = 0;
    for (prepared.request.proof.components, prepared.composition.components) |planned, component| {
        if (!std.mem.eql(u8, planned.name, "partial_ec_mul_window_bits_18")) continue;
        const witness = prepared.witnesses.find(planned.name) orelse return error.MissingWitnessProgram;
        if (component.trace_log_size >= 63) return error.InvalidTraceLog;
        partial_lookup_bytes = try std.math.mul(u64, try std.math.mul(u64, @as(u64, 1) << @intCast(component.trace_log_size), witness.program.n_lookup_words), 4);
    }
    const input_hex = std.fmt.bytesToHex(prepared.input_file_sha256, .lower);
    const witness_hex = std.fmt.bytesToHex(assets.witness_sha, .lower);
    const fixed_hex = std.fmt.bytesToHex(assets.fixed_sha, .lower);
    const relation_hex = std.fmt.bytesToHex(assets.relation_sha, .lower);
    const program_hex = std.fmt.bytesToHex(program.program_digest, .lower);
    var registry_hex: [64]u8 = undefined;
    const registry_text: ?[]const u8 = if (registry_sha) |digest| blk: {
        registry_hex = std.fmt.bytesToHex(digest, .lower);
        break :blk &registry_hex;
    } else null;
    const report = .{
        .schema = "stwo.cairo-trace-geometry.v1",
        .pie = std.fs.path.stem(path),
        .input_sha256 = &input_hex,
        .registry_sha256 = registry_text,
        .witness_sha256 = &witness_hex,
        .fixed_sha256 = &fixed_hex,
        .relation_sha256 = &relation_hex,
        .proof_program_sha256 = &program_hex,
        .variant = @tagName(prepared.variant),
        .allocated_bytes = try std.math.mul(u64, controllers.resident.combined_arena.total_words, 4),
        .peak_live_bytes = try std.math.mul(u64, prepared.request.resident.summary.peak_live_words, 4),
        .request_arena_bytes = prepared.request.resident.summary.allocatedResidentBytes(),
        .main_trace_words = tree_main_words,
        .interaction_trace_words = tree_interaction_words,
        .pedersen_distinct_keys = pedersen_distinct,
        .pedersen_partial_padded_rows = pedersen_partial_rows,
        .pedersen_partial_lookup_bytes = partial_lookup_bytes,
        .pedersen_partial_main_coefficient_bytes = partial_ec.main,
        .pedersen_partial_interaction_coefficient_bytes = partial_ec.interaction,
        .ec_op_main_coefficient_bytes = ec_op.main,
        .ec_op_interaction_coefficient_bytes = ec_op.interaction,
    };
    const encoded = try std.json.Stringify.valueAlloc(allocator, report, .{});
    defer allocator.free(encoded);
    try std.fs.File.stdout().writeAll(encoded);
    try std.fs.File.stdout().writeAll("\n");
}
