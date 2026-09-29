//! Zero-source-copy LogUp over lookup feeds retained in a Metal arena.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const M31 = @import("stwo_core").fields.m31.M31;
const relation_recipe = @import("stwo_metal_backend").recipes.relation;
const shared_runtime = @import("stwo_metal_backend").shared_runtime;
const interaction_executor =
    @import("stwo_cairo_frontend").witness.interaction_executor;
const interaction_trace =
    @import("stwo_cairo_frontend").witness.interaction_trace;
const resident_lookup = @import("resident_lookup.zig");

pub fn execute(
    allocator: std.mem.Allocator,
    request: interaction_executor.Request,
    storage: *resident_lookup.Storage,
) !interaction_executor.MaterializedTrace {
    const execution = try executeRecipe(allocator, request, storage);
    const column_count = storage.interaction_columns;
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
    if (std.posix.getenv("STWO_CAIRO_METAL_LOGUP_DIAGNOSTICS") != null) {
        const finished = try std.time.Instant.now();
        std.debug.print(
            "cairo_metal_logup resident=true rows={} columns={} " ++
                "gpu_ms={d:.3} gather_ms={d:.3} total_ms={d:.3}\n",
            .{
                storage.rows,
                column_count,
                execution.gpu_ms,
                elapsedMs(execution.executed, finished),
                elapsedMs(execution.started, finished),
            },
        );
    }
    return .{
        .allocator = allocator,
        .values = values,
        .row_count = storage.rows,
        .column_count = column_count,
        .claimed_sum = execution.claimed_sum,
    };
}

const Execution = struct {
    claimed_sum: QM31,
    started: std.time.Instant,
    executed: std.time.Instant,
    gpu_ms: f64,
};

fn executeRecipe(
    allocator: std.mem.Allocator,
    request: interaction_executor.Request,
    storage: *resident_lookup.Storage,
) !Execution {
    const started = try std.time.Instant.now();
    const column_count =
        request.descriptors.len / interaction_trace.descriptor_words;
    if (request.source.layout() != .lookup_words or
        request.source.rows() != storage.rows or
        column_count != storage.interaction_columns)
        return error.InvalidResidentLookupGeometry;

    // Diagnostic placement experiment: CPU faults one word per destination
    // page before submission, rather than asking the device to instantiate
    // untouched shared pages. The kernel still writes every coordinate.
    if (std.posix.getenv("STWO_CAIRO_METAL_PREFAULT_LOGUP_OUTPUTS")) |value| {
        if (std.mem.eql(u8, value, "1")) {
            const stride = @max(@as(usize, 1), std.heap.pageSize() / @sizeOf(u32));
            for (storage.outputs) |output| {
                const words = try resident_lookup.bindingWords(&storage.arena, output);
                var row: usize = 0;
                while (row < words.len) : (row += stride) {
                    const word: *volatile u32 = &words[row];
                    word.* = 0;
                }
                if (words.len != 0) {
                    const last: *volatile u32 = &words[words.len - 1];
                    last.* = 0;
                }
            }
        }
    }

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
    for (0..4) |coordinate| {
        const final_plane = try resident_lookup.bindingWords(
            &storage.arena,
            storage.outputs[(column_count - 1) * 4 + coordinate],
        );
        if (final_plane[final_row] != 0) return error.InvalidInteractionSum;
    }

    return .{
        .claimed_sum = claimed_sum,
        .started = started,
        .executed = executed,
        .gpu_ms = recipe.accumulated_gpu_ms,
    };
}

/// Copy canonical device coordinate planes once, without an intermediate
/// secure-field trace. Destination geometry is checked before any GPU work.
pub fn executeCoordinates(
    allocator: std.mem.Allocator,
    request: interaction_executor.Request,
    storage: *resident_lookup.Storage,
    planes: []const []M31,
) !QM31 {
    if (planes.len != storage.interaction_columns * 4)
        return error.InvalidInteractionGeometry;
    for (planes) |plane| if (plane.len != storage.rows)
        return error.InvalidInteractionGeometry;
    const execution = try executeRecipe(allocator, request, storage);
    for (planes, storage.outputs) |plane, output| {
        const source = try resident_lookup.bindingWords(&storage.arena, output);
        @memcpy(std.mem.sliceAsBytes(plane), std.mem.sliceAsBytes(source));
    }
    if (std.posix.getenv("STWO_CAIRO_METAL_LOGUP_DIAGNOSTICS") != null) {
        const finished = try std.time.Instant.now();
        std.debug.print(
            "cairo_metal_logup resident=true coordinates=true rows={} columns={} " ++
                "gpu_ms={d:.3} copy_ms={d:.3} total_ms={d:.3}\n",
            .{
                storage.rows,                            storage.interaction_columns,            execution.gpu_ms,
                elapsedMs(execution.executed, finished), elapsedMs(execution.started, finished),
            },
        );
    }
    return execution.claimed_sum;
}

fn writeSecure(
    arena: anytype,
    binding: @import("stwo_metal_backend").arena_plan.Binding,
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
    binding: @import("stwo_metal_backend").arena_plan.Binding,
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
