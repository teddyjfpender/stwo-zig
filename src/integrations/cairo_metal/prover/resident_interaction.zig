//! Zero-source-copy LogUp over lookup feeds retained in a Metal arena.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const relation_recipe = @import("../../../backends/metal/recipes/relation.zig");
const shared_runtime = @import("../../../backends/metal/shared_runtime.zig");
const interaction_executor =
    @import("../../../frontends/cairo/witness/interaction_executor.zig");
const interaction_trace =
    @import("../../../frontends/cairo/witness/interaction_trace.zig");
const resident_lookup = @import("resident_lookup.zig");

pub fn execute(
    allocator: std.mem.Allocator,
    request: interaction_executor.Request,
    storage: *resident_lookup.Storage,
) !interaction_executor.MaterializedTrace {
    const started = try std.time.Instant.now();
    const column_count =
        request.descriptors.len / interaction_trace.descriptor_words;
    if (request.source.layout() != .lookup_words or
        request.source.rows() != storage.rows or
        column_count != storage.interaction_columns)
        return error.InvalidResidentLookupGeometry;

    try writeSecureSlice(
        &storage.arena,
        storage.alpha_powers,
        request.alpha_powers,
    );
    try writeSecure(&storage.arena, storage.z, request.z);
    const instance = relation_recipe.RelationInstanceBindings{
        .rows = @intCast(storage.rows),
        .real_rows = @intCast(request.source.realRows()),
        .source_offset_rows = request.source.sourceOffsetRows(),
        .sources = &.{storage.source},
        .descriptors = request.descriptors,
        .outputs = storage.outputs,
        .claimed_sum = storage.claimed_sum,
    };
    var lease = try shared_runtime.acquireExisting();
    defer lease.deinit();
    var recipe = try relation_recipe.RelationRecipe.init(
        allocator,
        lease.runtime,
        &storage.arena,
        &.{instance},
        storage.alpha_powers,
        storage.z,
        storage.scan_scratch,
    );
    defer recipe.deinit();
    try recipe.execute();
    const executed = try std.time.Instant.now();

    const values = try allocator.alloc(
        QM31,
        try std.math.mul(usize, column_count, storage.rows),
    );
    errdefer allocator.free(values);
    for (0..column_count) |column| {
        const a = try resident_lookup.bindingWords(
            &storage.arena,
            storage.outputs[column * 4],
        );
        const b = try resident_lookup.bindingWords(
            &storage.arena,
            storage.outputs[column * 4 + 1],
        );
        const c = try resident_lookup.bindingWords(
            &storage.arena,
            storage.outputs[column * 4 + 2],
        );
        const d = try resident_lookup.bindingWords(
            &storage.arena,
            storage.outputs[column * 4 + 3],
        );
        for (0..storage.rows) |row|
            values[column * storage.rows + row] =
                QM31.fromU32Unchecked(a[row], b[row], c[row], d[row]);
    }
    const claimed_words = try resident_lookup.bindingWords(
        &storage.arena,
        storage.claimed_sum,
    );
    const claimed_sum = QM31.fromU32Unchecked(
        claimed_words[0],
        claimed_words[1],
        claimed_words[2],
        claimed_words[3],
    );
    const final_row = try interaction_trace.circleScanRow(
        storage.rows,
        storage.rows - 1,
    );
    if (!values[(column_count - 1) * storage.rows + final_row]
        .eql(QM31.zero()))
        return error.InvalidInteractionSum;

    if (std.posix.getenv("STWO_CAIRO_METAL_LOGUP_DIAGNOSTICS") != null) {
        const finished = try std.time.Instant.now();
        std.debug.print(
            "cairo_metal_logup resident=true rows={} columns={} " ++
                "gpu_ms={d:.3} gather_ms={d:.3} total_ms={d:.3}\n",
            .{
                storage.rows,
                column_count,
                recipe.accumulated_gpu_ms,
                elapsedMs(executed, finished),
                elapsedMs(started, finished),
            },
        );
    }
    return .{
        .allocator = allocator,
        .values = values,
        .row_count = storage.rows,
        .column_count = column_count,
        .claimed_sum = claimed_sum,
    };
}

fn writeSecure(
    arena: anytype,
    binding: @import("../../../backends/metal/arena_plan.zig").Binding,
    value: QM31,
) !void {
    const destination = try resident_lookup.bindingWords(arena, binding);
    if (destination.len != 4) return error.InvalidBindingSize;
    const coordinates = value.toM31Array();
    inline for (0..4) |coordinate|
        destination[coordinate] = coordinates[coordinate].v;
}

fn writeSecureSlice(
    arena: anytype,
    binding: @import("../../../backends/metal/arena_plan.zig").Binding,
    values: []const QM31,
) !void {
    const destination = try resident_lookup.bindingWords(arena, binding);
    if (destination.len != values.len * 4)
        return error.InvalidBindingSize;
    for (values, 0..) |value, index| {
        const coordinates = value.toM31Array();
        inline for (0..4) |coordinate|
            destination[index * 4 + coordinate] = coordinates[coordinate].v;
    }
}

fn elapsedMs(start: std.time.Instant, end: std.time.Instant) f64 {
    return @as(f64, @floatFromInt(end.since(start))) / std.time.ns_per_ms;
}
