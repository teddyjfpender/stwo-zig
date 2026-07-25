//! Fixed-table and memory-table ingress mapper boundary.

const std = @import("std");
const adapter = @import(
    "../../../../frontends/cairo/adapter/mod.zig",
);
const proof_plan = @import(
    "../../../../frontends/cairo/proof_plan.zig",
);
const composition = @import(
    "../../../../frontends/cairo/witness/composition_bundle.zig",
);
const fixed_bundle = @import(
    "../../../../frontends/cairo/witness/fixed_table_bundle.zig",
);
const execution_tables = @import(
    "../../../../frontends/cairo/witness/execution_tables.zig",
);
const common = @import(
    "../../../../backends/cuda/runtime/stages/common.zig",
);
const fixed_plan = @import("../../base_writer_plan/fixed_tables.zig");
const memory_plan = @import("../../base_writer_plan/memory.zig");
const request_compiler = @import("../../request_compiler.zig");
const resident_plan = @import("../resident_plan.zig");
const trace_commit = @import("../trace_commit.zig");
const trace_writer = @import("../trace_writer_controller.zig");
const multiplicity_feeds = @import("multiplicity_feeds.zig");
const writer_views = @import("writer_views.zig");

pub const Bound = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    bindings: []trace_writer.Binding,
    execution_tables: [37]common.Words,

    pub fn deinit(self: *Bound) void {
        self.arena.deinit();
        self.allocator.free(self.bindings);
        self.* = undefined;
    }
};

pub fn prepare(
    allocator: std.mem.Allocator,
    session: anytype,
    uploader: anytype,
    provider: anytype,
    request: *const request_compiler.PreparedRequest,
    proof: *const proof_plan.CairoProofPlan,
    components: composition.Bundle,
    fixed: fixed_bundle.Bundle,
    input: *const adapter.ProverInput,
    preprocessed: *const trace_commit.Bound,
    feeds: multiplicity_feeds.Bound,
    views: writer_views.Registry,
    memory_sources: common.Words,
) !Bound {
    if (proof.components.len != components.components.len)
        return error.InvalidBaseTableInventory;

    var fixed_tables = try fixed_plan.compile(
        allocator,
        components,
        fixed,
    );
    defer fixed_tables.deinit();
    var memory_tables = try memory_plan.compile(
        allocator,
        components,
        input,
    );
    defer memory_tables.deinit();

    const binding_count = try std.math.add(
        usize,
        fixed_tables.entries.len,
        memory_tables.entries.len,
    );
    const bindings = try allocator.alloc(trace_writer.Binding, binding_count);
    errdefer allocator.free(bindings);
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const owned = arena.allocator();

    const fixed_storage = try exactSlot(
        provider,
        &request.resident,
        .fixed_writer_tables,
    );
    _ = try exactSlot(
        provider,
        &request.resident,
        .memory_writer_tables,
    );

    var binding_cursor: usize = 0;
    var fixed_cursor: usize = 0;
    for (fixed_tables.entries) |entry| {
        const scheduled = request.trace_dispatch.find(
            entry.name,
            entry.instance,
        ) orelse return error.MissingBaseTableSchedule;
        const view = views.find(entry.component_index) orelse
            return error.MissingBaseTableView;
        if (view.trace_columns.len != entry.trace_output_count)
            return error.InvalidBaseTableView;

        const sources = try owned.alloc(
            trace_writer.FixedSource,
            entry.source_column_count,
        );
        for (entry.preprocessed_sources, sources) |identity, *source| {
            const ordinal = findIdentity(
                fixed.preprocessed_identities,
                identity,
            ) orelse return error.MissingPreprocessedColumn;
            const resident = try preprocessed.preprocessedBaseEvaluation(
                ordinal,
            );
            if (resident.len != entry.row_count)
                return error.InvalidPreprocessedColumnExtent;
            source.* = .{ .identity = identity, .resident = resident };
        }
        const multiplicities = try splitColumns(
            owned,
            feeds.destination(entry.name) orelse
                return error.MissingMultiplicityDestination,
            entry.multiplicity_column_count,
            entry.row_count,
        );
        const lookup_outputs = try splitColumns(
            owned,
            view.lookup_words,
            entry.lookup_output_count,
            entry.row_count,
        );
        const buffers = try fixedBuffers(
            fixed_storage,
            &fixed_cursor,
            entry,
        );
        const dependencies = try dependencyCapabilities(
            owned,
            scheduled.dependencies,
            views,
        );
        const prepared = trace_writer.prepareFixed(
            allocator,
            session,
            entry,
            scheduled.*,
            .{
                .sources = sources,
                .multiplicity_columns = multiplicities,
                .trace_outputs = view.trace_columns,
                .lookup_outputs = lookup_outputs,
                .buffers = buffers,
            },
            dependencies,
        ) catch |err| {
            std.debug.print(
                "cairo-cuda fixed writer {s} failed: {s}\n",
                .{ entry.name, @errorName(err) },
            );
            return err;
        };
        bindings[binding_cursor] = .{
            .component_index = entry.component_index,
            .catalog_identity = entry.identity,
            .body = .{ .fixed = prepared },
        };
        binding_cursor += 1;
    }
    if (fixed_cursor != fixed_storage.len)
        return error.InvalidFixedTableStorageExtent;

    var execution: [37]common.Words = undefined;
    var execution_cursor: usize = 0;
    var source_cursor: usize = 0;
    for (memory_tables.entries) |entry| {
        const scheduled = request.trace_dispatch.find(
            entry.name,
            entry.instance,
        ) orelse return error.MissingBaseTableSchedule;
        const view = views.find(entry.component_index) orelse
            return error.MissingBaseTableView;
        if (view.trace_columns.len != entry.output_column_count)
            return error.InvalidBaseTableView;
        const source_columns: usize = switch (entry.kind) {
            .address_to_id => 1,
            .id_to_big, .id_to_small => entry.limb_count,
        };
        const source_rows = try memorySourceRows(entry);
        const source_words = try std.math.mul(
            usize,
            source_columns,
            source_rows,
        );
        const source_end = try std.math.add(
            usize,
            source_cursor,
            source_words,
        );
        if (source_end > memory_sources.len or
            execution_cursor + source_columns > execution.len)
        {
            return error.InvalidMemorySourceExtent;
        }
        const execution_columns = try splitColumns(
            owned,
            try memory_sources.sub(source_cursor, source_words),
            @intCast(source_columns),
            @intCast(source_rows),
        );
        try uploadMemorySources(
            allocator,
            uploader,
            input,
            entry,
            execution_columns,
        );
        @memcpy(
            execution[execution_cursor..][0..source_columns],
            execution_columns,
        );
        execution_cursor += source_columns;
        source_cursor = source_end;
        const writer_columns = switch (entry.kind) {
            .address_to_id => blk: {
                const result = try owned.alloc(common.Words, 1);
                result[0] = try execution_columns[0].sub(
                    entry.source_value_offset,
                    entry.source_value_count,
                );
                break :blk result;
            },
            .id_to_big, .id_to_small => execution_columns,
        };

        const multiplicity_name = switch (entry.kind) {
            .address_to_id => "memory_address_to_id",
            .id_to_big => "memory_id_to_big",
            .id_to_small => "memory_id_to_big#small",
        };
        const multiplicities = feeds.destination(multiplicity_name) orelse
            return error.MissingMultiplicityDestination;
        const dependencies = try dependencyCapabilities(
            owned,
            scheduled.dependencies,
            views,
        );
        const body: trace_writer.Body = switch (entry.kind) {
            .address_to_id => .{ .memory_address = trace_writer.prepareMemoryAddress(
                session,
                entry,
                scheduled.*,
                .{
                    .resident = writer_columns[0],
                    .value_offset = entry.source_value_offset,
                    .words_per_value = entry.source_words_per_value,
                },
                .{
                    .address_ids = writer_columns[0],
                    .multiplicities = multiplicities,
                    .outputs = view.trace_columns,
                },
                dependencies,
            ) catch |err| {
                std.debug.print(
                    "cairo-cuda memory writer {s} failed: {s}\n",
                    .{ entry.name, @errorName(err) },
                );
                return err;
            } },
            .id_to_big, .id_to_small => blk: {
                if (multiplicities.len != entry.row_count)
                    return error.InvalidMultiplicityExtent;
                const prepared = trace_writer.prepareMemoryValue(
                    session,
                    entry,
                    scheduled.*,
                    entry.source_value_offset,
                    .{
                        .sources = writer_columns,
                        .multiplicities = multiplicities,
                        .outputs = view.trace_columns,
                    },
                    dependencies,
                ) catch |err| {
                    std.debug.print(
                        "cairo-cuda memory writer {s} failed: {s}\n",
                        .{ entry.name, @errorName(err) },
                    );
                    return err;
                };
                break :blk switch (entry.kind) {
                    .id_to_big => .{ .memory_value_big = prepared },
                    .id_to_small => .{ .memory_value_small = prepared },
                    else => unreachable,
                };
            },
        };
        bindings[binding_cursor] = .{
            .component_index = entry.component_index,
            .catalog_identity = entry.identity,
            .body = body,
        };
        binding_cursor += 1;
    }
    if (binding_cursor != bindings.len or
        source_cursor != memory_sources.len or
        execution_cursor != execution.len)
    {
        return error.InvalidBaseTableInventory;
    }
    return .{
        .allocator = allocator,
        .arena = arena,
        .bindings = bindings,
        .execution_tables = execution,
    };
}

fn fixedBuffers(
    storage: common.Words,
    cursor: *usize,
    entry: fixed_plan.Entry,
) !@import(
    "../../../../backends/cuda/runtime/stages/cairo_base/fixed_tables.zig",
).Buffers {
    return .{
        .source_pointer_table = if (entry.source_column_count == 0)
            .{ .address = 0, .len = 0, .owner = 0 }
        else
            try takePointerTable(
                storage,
                cursor,
                entry.source_column_count,
            ),
        .multiplicity_pointer_table = try takePointerTable(
            storage,
            cursor,
            entry.multiplicity_column_count,
        ),
        .trace_multiplicity_columns = try take(
            storage,
            cursor,
            entry.trace_output_count,
        ),
        .trace_output_pointer_table = try takePointerTable(
            storage,
            cursor,
            entry.trace_output_count,
        ),
        .lookup_descriptors = try take(
            storage,
            cursor,
            @as(usize, entry.lookup_output_count) * 4,
        ),
        .lookup_output_pointer_table = try takePointerTable(
            storage,
            cursor,
            entry.lookup_output_count,
        ),
    };
}

fn takePointerTable(
    storage: common.Words,
    cursor: *usize,
    count: u32,
) !common.Words {
    const pointer_words = @sizeOf(usize) / @sizeOf(u32);
    cursor.* = std.mem.alignForward(usize, cursor.*, pointer_words);
    if (cursor.* > storage.len) return error.InvalidBaseTableInventory;
    return take(
        storage,
        cursor,
        try std.math.mul(usize, count, pointer_words),
    );
}

fn uploadMemorySources(
    allocator: std.mem.Allocator,
    uploader: anytype,
    input: *const adapter.ProverInput,
    entry: memory_plan.Entry,
    columns: []const common.Words,
) !void {
    if (columns.len == 0) return error.InvalidMemorySourceExtent;
    const staging = try allocator.alloc(u32, columns[0].len);
    defer allocator.free(staging);
    for (columns, 0..) |column, limb| {
        for (staging, 0..) |*value, row| {
            const source_index = switch (entry.kind) {
                .address_to_id => row,
                .id_to_big, .id_to_small => @as(usize, entry.source_value_offset) + row,
            };
            value.* = switch (entry.kind) {
                .address_to_id => input.memory.address_to_id[source_index].raw,
                .id_to_big => execution_tables.limb(
                    input,
                    execution_tables.MEMORY_VALUE_TABLE,
                    @import(
                        "../../../../frontends/cairo/common/memory.zig",
                    ).EncodedMemoryValueId.f252(@intCast(source_index)).raw,
                    @intCast(limb),
                ),
                .id_to_small => execution_tables.limb(
                    input,
                    execution_tables.MEMORY_VALUE_TABLE,
                    @import(
                        "../../../../frontends/cairo/common/memory.zig",
                    ).EncodedMemoryValueId.small(
                        @intCast(source_index),
                    ).raw,
                    @intCast(limb),
                ),
            };
        }
        try uploader.uploadSlice(u32, column, staging);
    }
}

fn memorySourceRows(entry: memory_plan.Entry) !usize {
    const rows = switch (entry.kind) {
        .address_to_id => std.math.add(
            u32,
            entry.source_value_offset,
            entry.source_value_count,
        ) catch return error.InvalidMemorySourceExtent,
        .id_to_big, .id_to_small => entry.source_value_count,
    };
    return rows;
}

fn splitColumns(
    allocator: std.mem.Allocator,
    storage: common.Words,
    count: u32,
    rows: u32,
) ![]common.Words {
    const expected = try std.math.mul(usize, count, rows);
    if (storage.len != expected) return error.InvalidBaseTableView;
    const columns = try allocator.alloc(common.Words, count);
    for (columns, 0..) |*column, index| {
        column.* = try storage.sub(index * @as(usize, rows), rows);
    }
    return columns;
}

fn findIdentity(
    identities: []const []u8,
    target: []const u8,
) ?u32 {
    for (identities, 0..) |identity, index| {
        if (std.mem.eql(u8, identity, target)) return @intCast(index);
    }
    return null;
}

fn dependencyCapabilities(
    allocator: std.mem.Allocator,
    dependencies: []const @import("../trace_schedule.zig").Dependency,
    views: writer_views.Registry,
) ![]trace_writer.DependencyCapability {
    const capabilities = try allocator.alloc(
        trace_writer.DependencyCapability,
        dependencies.len,
    );
    for (dependencies, capabilities) |dependency, *capability| {
        const producer = views.find(
            dependency.producer_component_index,
        ) orelse return error.MissingBaseTableDependency;
        const required: usize = switch (dependency.kind) {
            .producer_words => try std.math.add(
                usize,
                dependency.word_base,
                try std.math.mul(
                    usize,
                    dependency.words_per_instance,
                    dependency.instances,
                ),
            ),
            .capacity => dependency.instances,
            .native_ec_workspace => return error.InvalidBaseTableDependency,
        };
        if (required == 0 or producer.sub_words.len < required)
            return error.InvalidBaseTableDependency;
        capability.* = .{
            .dependency = dependency,
            .resident = try producer.sub_words.sub(0, required),
        };
    }
    return capabilities;
}

fn exactSlot(
    provider: anytype,
    plan: *const resident_plan.Plan,
    kind: resident_plan.SlotKind,
) !common.Words {
    const descriptor = plan.slot(kind, 0) orelse
        return error.MissingResidentSlot;
    const resident = try provider.slot(descriptor.id);
    if (resident.len != descriptor.words)
        return error.InvalidResidentSlotExtent;
    return resident;
}

fn take(
    storage: common.Words,
    cursor: *usize,
    words: usize,
) !common.Words {
    const output = try storage.sub(cursor.*, words);
    cursor.* = try std.math.add(usize, cursor.*, words);
    return output;
}

test "fixed buffers align pointer tables after odd scalar metadata" {
    const entry = fixed_plan.Entry{
        .component_index = 0,
        .fixed_ordinal = 0,
        .graph_hash = 0,
        .name = "odd_trace_outputs",
        .instance = 0,
        .log_size = 4,
        .row_count = 16,
        .source_column_count = 0,
        .multiplicity_column_count = 1,
        .trace_output_count = 1,
        .lookup_output_count = 1,
        .preprocessed_sources = &.{},
        .trace_multiplicity_columns = &.{0},
        .lookup_descriptors = &.{ 0, 0, 0, 0 },
        .identity = [_]u8{0} ** 32,
    };
    const storage = common.Words{
        .address = 0x1000,
        .len = 12,
        .owner = 7,
        .generation = 11,
    };
    var cursor: usize = 0;
    const buffers = try fixedBuffers(storage, &cursor, entry);
    try std.testing.expectEqual(@as(usize, 12), cursor);
    try std.testing.expectEqual(@as(usize, 0x1000), buffers.multiplicity_pointer_table.address);
    try std.testing.expectEqual(@as(usize, 0x1008), buffers.trace_multiplicity_columns.address);
    try std.testing.expectEqual(@as(usize, 0x1010), buffers.trace_output_pointer_table.address);
    try std.testing.expectEqual(@as(usize, 0x1018), buffers.lookup_descriptors.address);
    try std.testing.expectEqual(@as(usize, 0x1028), buffers.lookup_output_pointer_table.address);
}
