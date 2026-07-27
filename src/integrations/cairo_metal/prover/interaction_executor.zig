//! General Cairo LogUp execution on authenticated resident Metal kernels.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const arena_plan = @import("../../../backends/metal/arena_plan.zig");
const relation_recipe = @import("../../../backends/metal/recipes/relation.zig");
const shared_runtime = @import("../../../backends/metal/shared_runtime.zig");
const interaction_executor = @import("../../../frontends/cairo/witness/interaction_executor.zig");
const interaction_trace = @import("../../../frontends/cairo/witness/interaction_trace.zig");

pub fn executor() interaction_executor.Executor {
    return .{ .execute_fn = execute };
}

fn execute(
    _: ?*anyopaque,
    allocator: std.mem.Allocator,
    request: interaction_executor.Request,
) !interaction_executor.MaterializedTrace {
    const diagnostics = std.posix.getenv(
        "STWO_CAIRO_METAL_LOGUP_DIAGNOSTICS",
    ) != null;
    const started = if (diagnostics) try std.time.Instant.now() else undefined;
    try validateRequest(request);
    var projection = try Projection.init(allocator, request);
    defer projection.deinit();
    const rows = request.source.rows();
    const column_count =
        request.descriptors.len / interaction_trace.descriptor_words;

    var lease = try shared_runtime.acquireExisting();
    defer lease.deinit();

    var layout = Layout.init();
    const source_binding_count: usize =
        if (request.source.layout() == .lookup_words)
            1
        else
            request.source.physicalColumnCount();
    const sources = try allocator.alloc(
        arena_plan.Binding,
        source_binding_count,
    );
    defer allocator.free(sources);
    if (request.source.layout() == .lookup_words) {
        const source_words = std.math.mul(
            usize,
            projection.lookup_columns.len,
            rows,
        ) catch return error.AllocationSizeOverflow;
        sources[0] = try layout.add(
            std.math.mul(u64, source_words, @sizeOf(u32)) catch
                return error.AllocationSizeOverflow,
        );
    } else {
        for (sources) |*source|
            source.* = try layout.add(
                std.math.mul(u64, rows, @sizeOf(u32)) catch
                    return error.AllocationSizeOverflow,
            );
    }

    const output_count = std.math.mul(
        usize,
        column_count,
        4,
    ) catch return error.AllocationSizeOverflow;
    const outputs = try allocator.alloc(arena_plan.Binding, output_count);
    defer allocator.free(outputs);
    for (outputs) |*output|
        output.* = try layout.add(
            std.math.mul(u64, rows, @sizeOf(u32)) catch
                return error.AllocationSizeOverflow,
        );
    const claimed_sum = try layout.add(4 * @sizeOf(u32));
    const alpha_powers = try layout.add(
        std.math.mul(u64, request.alpha_powers.len, 4 * @sizeOf(u32)) catch
            return error.AllocationSizeOverflow,
    );
    const z = try layout.add(4 * @sizeOf(u32));
    const blocks = std.math.divCeil(usize, rows, 256) catch
        return error.AllocationSizeOverflow;
    const scan_scratch = try layout.add(
        std.math.mul(u64, blocks, 4 * @sizeOf(u32)) catch
            return error.AllocationSizeOverflow,
    );

    var arena = try arena_plan.ResidentArena.initByteLength(
        lease.runtime,
        layout.byte_length,
    );
    defer arena.deinit();
    const copy_started =
        if (diagnostics) try std.time.Instant.now() else undefined;
    try copySources(
        &arena,
        sources,
        request.source,
        projection.lookup_columns,
    );
    try writeSecureSlice(&arena, alpha_powers, request.alpha_powers);
    try writeSecure(&arena, z, request.z);
    const copy_finished =
        if (diagnostics) try std.time.Instant.now() else undefined;

    const instance = relation_recipe.RelationInstanceBindings{
        .rows = @intCast(rows),
        .real_rows = @intCast(request.source.realRows()),
        .source_offset_rows = request.source.sourceOffsetRows(),
        .sources = sources,
        .descriptors = projection.descriptors,
        .outputs = outputs,
        .claimed_sum = claimed_sum,
    };
    var recipe = try relation_recipe.RelationRecipe.init(
        allocator,
        lease.runtime,
        &arena,
        &.{instance},
        alpha_powers,
        z,
        scan_scratch,
    );
    defer recipe.deinit();
    const prepare_finished =
        if (diagnostics) try std.time.Instant.now() else undefined;
    try recipe.execute();
    const execute_finished =
        if (diagnostics) try std.time.Instant.now() else undefined;

    const result_values = try allocator.alloc(
        QM31,
        std.math.mul(usize, column_count, rows) catch
            return error.AllocationSizeOverflow,
    );
    errdefer allocator.free(result_values);
    for (0..column_count) |column| {
        const a = try words(&arena, outputs[column * 4]);
        const b = try words(&arena, outputs[column * 4 + 1]);
        const c = try words(&arena, outputs[column * 4 + 2]);
        const d = try words(&arena, outputs[column * 4 + 3]);
        for (0..rows) |row| {
            result_values[column * rows + row] =
                QM31.fromU32Unchecked(a[row], b[row], c[row], d[row]);
        }
    }
    const claimed_words = try words(&arena, claimed_sum);
    const result_claimed_sum = QM31.fromU32Unchecked(
        claimed_words[0],
        claimed_words[1],
        claimed_words[2],
        claimed_words[3],
    );
    const final_row = try interaction_trace.circleScanRow(rows, rows - 1);
    if (!result_values[
        (column_count - 1) * rows + final_row
    ].eql(QM31.zero())) return error.InvalidInteractionSum;
    if (diagnostics) {
        const finished = try std.time.Instant.now();
        std.debug.print(
            "cairo_metal_logup rows={} columns={} sources={} arena_bytes={} " ++
                "setup_ms={d:.3} copy_ms={d:.3} prepare_ms={d:.3} " ++
                "execute_ms={d:.3} gpu_ms={d:.3} gather_ms={d:.3} total_ms={d:.3}\n",
            .{
                rows,
                column_count,
                if (request.source.layout() == .lookup_words)
                    projection.lookup_columns.len
                else
                    request.source.physicalColumnCount(),
                layout.byte_length,
                elapsedMs(started, copy_started),
                elapsedMs(copy_started, copy_finished),
                elapsedMs(copy_finished, prepare_finished),
                elapsedMs(prepare_finished, execute_finished),
                recipe.accumulated_gpu_ms,
                elapsedMs(execute_finished, finished),
                elapsedMs(started, finished),
            },
        );
    }

    return .{
        .allocator = allocator,
        .values = result_values,
        .row_count = rows,
        .column_count = column_count,
        .claimed_sum = result_claimed_sum,
    };
}

const Projection = struct {
    allocator: std.mem.Allocator,
    descriptors: []const u32,
    owned_descriptors: ?[]u32 = null,
    lookup_columns: []const u32 = &.{},
    owned_lookup_columns: ?[]u32 = null,

    fn init(
        allocator: std.mem.Allocator,
        request: interaction_executor.Request,
    ) !Projection {
        if (request.source.layout() != .lookup_words)
            return .{
                .allocator = allocator,
                .descriptors = request.descriptors,
            };
        const descriptors = try allocator.dupe(u32, request.descriptors);
        errdefer allocator.free(descriptors);
        var columns = std.ArrayList(u32).empty;
        defer columns.deinit(allocator);
        try columns.append(allocator, std.math.maxInt(u32));

        var descriptor_index: usize = 0;
        while (descriptor_index < descriptors.len) : (descriptor_index += interaction_trace.descriptor_words) {
            const descriptor = descriptors[descriptor_index..][0..interaction_trace.descriptor_words];
            for (0..descriptor[0]) |use_index| {
                const use = descriptor[1 + use_index * interaction_trace.use_words ..][0..interaction_trace.use_words];
                const original = request.descriptors[descriptor_index + 1 +
                    use_index * interaction_trace.use_words ..][0..interaction_trace.use_words];
                if (original[2] > 1) {
                    const first_column: u32 = @intCast(columns.items.len);
                    for (1..original[2]) |word|
                        try columns.append(
                            allocator,
                            std.math.add(
                                u32,
                                original[1],
                                @intCast(word),
                            ) catch return error.AllocationSizeOverflow,
                        );
                    use[1] = first_column - 1;
                } else {
                    use[1] = 0;
                }
                if (original[4] == 2) {
                    use[5] = try projectedColumn(
                        allocator,
                        &columns,
                        original[5],
                    );
                }
            }
        }
        const owned_columns = try columns.toOwnedSlice(allocator);
        return .{
            .allocator = allocator,
            .descriptors = descriptors,
            .owned_descriptors = descriptors,
            .lookup_columns = owned_columns,
            .owned_lookup_columns = owned_columns,
        };
    }

    fn deinit(self: *Projection) void {
        if (self.owned_descriptors) |descriptors|
            self.allocator.free(descriptors);
        if (self.owned_lookup_columns) |columns|
            self.allocator.free(columns);
        self.* = undefined;
    }
};

fn projectedColumn(
    allocator: std.mem.Allocator,
    columns: *std.ArrayList(u32),
    original: u32,
) !u32 {
    for (columns.items, 0..) |candidate, index|
        if (candidate == original) return @intCast(index);
    const index: u32 = @intCast(columns.items.len);
    try columns.append(allocator, original);
    return index;
}

fn elapsedMs(start: std.time.Instant, end: std.time.Instant) f64 {
    return @as(f64, @floatFromInt(end.since(start))) /
        std.time.ns_per_ms;
}

fn validateRequest(request: interaction_executor.Request) !void {
    if (request.descriptors.len == 0 or
        request.descriptors.len % interaction_trace.descriptor_words != 0 or
        request.source.rows() == 0 or
        !std.math.isPowerOfTwo(request.source.rows()) or
        request.source.rows() > std.math.maxInt(u32) or
        request.source.realRows() > request.source.rows())
        return error.InvalidDescriptor;
    var descriptor_index: usize = 0;
    while (descriptor_index < request.descriptors.len) : (descriptor_index += interaction_trace.descriptor_words) {
        const descriptor = request.descriptors[descriptor_index..][0..interaction_trace.descriptor_words];
        if (descriptor[0] < 1 or descriptor[0] > 2)
            return error.InvalidDescriptor;
        for (0..descriptor[0]) |use_index| {
            const use = descriptor[1 + use_index * interaction_trace.use_words ..][0..interaction_trace.use_words];
            try request.source.validateUse(use, request.alpha_powers.len);
        }
    }
}

fn copySources(
    arena: *arena_plan.ResidentArena,
    sources: []const arena_plan.Binding,
    source: interaction_trace.SourceView,
    lookup_columns: []const u32,
) !void {
    const rows = source.rows();
    if (source.layout() == .lookup_words) {
        if (sources.len != 1 or lookup_columns.len == 0)
            return error.InvalidBindingSize;
        const destination = try words(arena, sources[0]);
        @memset(destination[0..rows], 0);
        for (lookup_columns[1..], 1..) |column, destination_column|
            try source.copyPhysicalColumn(
                column,
                destination[destination_column * rows ..][0..rows],
            );
        return;
    }
    if (sources.len != source.physicalColumnCount())
        return error.InvalidBindingSize;
    for (sources, 0..) |binding, column|
        try source.copyPhysicalColumn(
            column,
            try words(arena, binding),
        );
}

const Layout = struct {
    byte_length: u64 = 0,
    next_id: u32 = 1,

    fn init() Layout {
        return .{};
    }

    fn add(self: *Layout, size_bytes: u64) !arena_plan.Binding {
        if (size_bytes == 0) return error.InvalidBindingSize;
        const offset = std.mem.alignForward(u64, self.byte_length, 16);
        self.byte_length = std.math.add(u64, offset, size_bytes) catch
            return error.AllocationSizeOverflow;
        const binding = arena_plan.Binding{
            .logical_id = self.next_id,
            .slot = self.next_id,
            .offset_bytes = offset,
            .size_bytes = size_bytes,
            .materialization = .resident,
            .occupied = [_]u64{0} ** (arena_plan.max_ticks / 64),
        };
        self.next_id += 1;
        return binding;
    }
};

fn words(
    arena: *arena_plan.ResidentArena,
    binding: arena_plan.Binding,
) ![]u32 {
    const aligned: []align(4) u8 = @alignCast(try arena.bytes(binding));
    return std.mem.bytesAsSlice(u32, aligned);
}

fn writeSecure(
    arena: *arena_plan.ResidentArena,
    binding: arena_plan.Binding,
    value: QM31,
) !void {
    const destination = try words(arena, binding);
    if (destination.len != 4) return error.InvalidBindingSize;
    const coordinates = value.toM31Array();
    inline for (0..4) |coordinate|
        destination[coordinate] = coordinates[coordinate].v;
}

fn writeSecureSlice(
    arena: *arena_plan.ResidentArena,
    binding: arena_plan.Binding,
    values: []const QM31,
) !void {
    const destination = try words(arena, binding);
    if (destination.len != values.len * 4) return error.InvalidBindingSize;
    for (values, 0..) |value, index| {
        const coordinates = value.toM31Array();
        inline for (0..4) |coordinate|
            destination[index * 4 + coordinate] = coordinates[coordinate].v;
    }
}

test "Metal relation source export preserves canonical physical columns" {
    const source_words = [_]u32{
        3,  5,  7,  9,
        11, 13, 17, 19,
        2,  0,  4,  6,
    };
    const source = try interaction_trace.SourceView.lookupWords(
        try interaction_trace.LookupColumns.init(&source_words, 4),
        3,
    );
    try std.testing.expectEqual(@as(usize, 3), source.physicalColumnCount());
    try std.testing.expectEqual(@as(usize, 3), source.realRows());
    var copied: [4]u32 = undefined;
    try source.copyPhysicalColumn(1, &copied);
    try std.testing.expectEqualSlices(u32, source_words[4..8], &copied);
}
