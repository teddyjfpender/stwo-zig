//! Resident device binding for one authenticated Cairo relation plan.
//!
//! Callers supply only semantic base/lookup sources produced by the trace
//! writer. Every pointer table, descriptor mirror, interaction output, claim,
//! denominator, challenge, and scratch view is derived from the resident plan.

const std = @import("std");
const proof_ir = @import("stwo_backend_contracts").proof_program;
const field = @import("stwo_cuda_backend").abi.field;
const relation_abi = @import("stwo_cuda_backend").abi.stages.relation;
const relation_stage = @import("stwo_cuda_backend").runtime.stages.relation;
const common = @import("stwo_cuda_backend").runtime.stages.common;
const relation_adapter = @import("../../relation_adapter.zig");
const resident_plan = @import("../resident_plan.zig");
const trace_schedule = @import("../trace_schedule.zig");
const writer_views = @import("writer_views.zig");

const pointer_words = @sizeOf(usize) / @sizeOf(u32);

comptime {
    std.debug.assert(pointer_words == 2);
}

pub const production_ready = true;

/// Semantic writer output for one canonical Cairo component.
///
/// `lookup_words` is one column-major slab with
/// `rows * relation.lookup_word_columns` words. Non-lookup relations consume
/// `base_columns` directly and require one exact row-sized view per source.
pub const ComponentSources = struct {
    component_index: u32,
    base_columns: []const common.Words,
    lookup_words: ?common.Words = null,
};

/// Owned host registry of device views. The views alias the proof arena; only
/// the small host-side slice tables are allocated here.
pub const SourceRegistry = struct {
    allocator: std.mem.Allocator,
    sources: []ComponentSources,
    base_columns: []common.Words,

    pub fn deinit(self: *SourceRegistry) void {
        self.allocator.free(self.base_columns);
        self.allocator.free(self.sources);
        self.* = undefined;
    }
};

/// Partitions retained lookup slabs in canonical component order and resolves
/// every non-lookup relation against its authenticated main-writer output.
///
/// A composite member still uses its own schedule ordinal: its root owns the
/// launch, but the main commitment owns a distinct writer-output span for the
/// member's columns.
pub fn buildSourceRegistry(
    allocator: std.mem.Allocator,
    relations: *const relation_adapter.Plan,
    schedule: trace_schedule.Schedule,
    views: writer_views.Registry,
    main_commit: anytype,
) !SourceRegistry {
    if (relations.instances.len != schedule.entries.len)
        return error.InvalidRelationSourceCount;
    var base_count: usize = 0;
    for (relations.instances) |instance| {
        if (instance.layout != .lookup_words)
            base_count = try add(base_count, instance.source_pointer_count);
    }
    const sources = try allocator.alloc(
        ComponentSources,
        relations.instances.len,
    );
    errdefer allocator.free(sources);
    const base_columns = try allocator.alloc(common.Words, base_count);
    errdefer allocator.free(base_columns);

    var base_cursor: usize = 0;
    for (relations.instances, sources) |instance, *source| {
        const ordinal = try scheduleOrdinal(
            schedule,
            instance.component_index,
        );
        if (instance.layout == .lookup_words) {
            const words = try mul(
                instance.geometry.rows,
                instance.lookup_word_columns,
            );
            const view = views.find(instance.component_index) orelse {
                std.debug.print(
                    "cairo-cuda relation lookup view missing " ++
                        "component={s} index={d} ordinal={d}\n",
                    .{
                        instance.component,
                        instance.component_index,
                        ordinal,
                    },
                );
                return error.MissingRelationLookupSource;
            };
            if (words != view.lookup_words.len) {
                std.debug.print(
                    "cairo-cuda relation lookup extent component={s} " ++
                        "index={d} ordinal={d} expected_words={d} " ++
                        "available_words={d}\n",
                    .{
                        instance.component,
                        instance.component_index,
                        ordinal,
                        words,
                        view.lookup_words.len,
                    },
                );
                return error.InvalidRelationSourceExtent;
            }
            source.* = .{
                .component_index = instance.component_index,
                .base_columns = &.{},
                .lookup_words = try view.lookup_words.sub(0, words),
            };
            continue;
        }

        const matrix = try main_commit.writerOutput(ordinal);
        if (matrix.column_stride_words == 0 or
            matrix.storage.len % matrix.column_stride_words != 0 or
            matrix.storage.len / matrix.column_stride_words !=
                instance.source_pointer_count or
            matrix.column_stride_words != instance.geometry.rows)
        {
            std.debug.print(
                "cairo-cuda relation source {s}#{} component={} " ++
                    "layout={s} source_count={} matrix_words={} " ++
                    "matrix_stride={} relation_rows={}\n",
                .{
                    instance.component,
                    instance.component_instance,
                    instance.component_index,
                    @tagName(instance.layout),
                    instance.source_pointer_count,
                    matrix.storage.len,
                    matrix.column_stride_words,
                    instance.geometry.rows,
                },
            );
            return error.InvalidRelationSourceExtent;
        }
        const end = try add(base_cursor, instance.source_pointer_count);
        const columns = base_columns[base_cursor..end];
        for (columns, 0..) |*column, index| {
            column.* = try matrix.storage.sub(
                try mul(index, matrix.column_stride_words),
                matrix.column_stride_words,
            );
        }
        source.* = .{
            .component_index = instance.component_index,
            .base_columns = columns,
        };
        base_cursor = end;
    }
    if (base_cursor != base_columns.len)
        return error.InvalidRelationSourceExtent;
    return .{
        .allocator = allocator,
        .sources = sources,
        .base_columns = base_columns,
    };
}

pub const Bound = struct {
    allocator: std.mem.Allocator,
    prepared: *relation_stage.PreparedPlan,
    topology_identity: proof_ir.Digest,

    pub fn deinit(self: *Bound) void {
        relation_stage.deinit(self.allocator, self.prepared);
        self.* = undefined;
    }

    pub fn runtime(self: *const Bound) *const relation_stage.PreparedPlan {
        return self.prepared;
    }
};

/// Compiles and uploads the complete device graph during ingress.
///
/// `uploader` must expose `uploadSlice(T, destination, host_values)`.
/// `provider` must expose `slot(id)` and routes request/process residency from
/// the authenticated slot inventory.
pub fn prepareAndUpload(
    allocator: std.mem.Allocator,
    uploader: anytype,
    provider: anytype,
    plan: *const resident_plan.Plan,
    program: proof_ir.ProofProgram,
    relations: *const relation_adapter.Plan,
    sources: []const ComponentSources,
) !Bound {
    if (!std.mem.eql(
        u8,
        &plan.program_identity,
        &program.program_digest,
    )) return error.RelationResidentIdentityMismatch;
    try validateSources(relations, sources);

    const instance_count = relations.instances.len;
    const table_words = try mul(instance_count, pointer_words);
    const top = try exactSlot(
        provider,
        plan,
        .relation_top_level_tables,
        0,
    );
    if (top.len != try mul(table_words, 5))
        return error.InvalidRelationResidentExtent;
    const buffers = relation_stage.DeviceBuffers{
        .drawn_z_alpha = try (try exactSlot(
            provider,
            plan,
            .relation_challenges,
            0,
        )).cast(field.SecureField),
        .alpha_powers = try (try exactSlot(
            provider,
            plan,
            .relation_alpha_powers,
            0,
        )).cast(field.SecureField),
        .z = try (try exactSlot(
            provider,
            plan,
            .relation_z,
            0,
        )).cast(field.SecureField),
        .source_tables = try top.sub(0, table_words),
        .descriptors = try top.sub(table_words, table_words),
        .output_tables = try top.sub(table_words * 2, table_words),
        .denominator_slabs = try top.sub(table_words * 3, table_words),
        .geometry = try (try exactSlot(
            provider,
            plan,
            .relation_geometry,
            0,
        )).cast(relation_abi.Geometry),
        .claimed_sums = try top.sub(table_words * 4, table_words),
        .reduction_partials = try exactSlot(
            provider,
            plan,
            .relation_reduction_scratch,
            0,
        ),
        .scan_block_sums = try exactSlot(
            provider,
            plan,
            .relation_scan_scratch,
            0,
        ),
    };

    const nested_sources = try exactSlot(
        provider,
        plan,
        .relation_source_pointer_tables,
        0,
    );
    const descriptor_storage = try exactSlot(
        provider,
        plan,
        .relation_descriptors,
        0,
    );
    const nested_outputs = try exactSlot(
        provider,
        plan,
        .relation_output_graph,
        0,
    );
    const denominator_storage = try (try exactSlot(
        provider,
        plan,
        .relation_denominators,
        0,
    )).cast(field.SecureField);
    const claimed_sums = try (try exactSlot(
        provider,
        plan,
        .relation_claimed_sums,
        0,
    )).cast(field.SecureField);
    if (claimed_sums.len != instance_count)
        return error.InvalidRelationResidentExtent;

    const source_count = try totalSources(relations);
    const output_count = try totalOutputs(relations);
    const source_views = try allocator.alloc(common.Words, source_count);
    defer allocator.free(source_views);
    const output_views = try allocator.alloc(common.Words, output_count);
    defer allocator.free(output_views);
    try bindInteractionOutputs(
        output_views,
        provider,
        plan,
        program,
        relations,
    );

    const device = try allocator.alloc(
        relation_adapter.DeviceInstanceBinding,
        instance_count,
    );
    defer allocator.free(device);
    var source_cursor: usize = 0;
    var source_table_cursor: usize = 0;
    var descriptor_cursor: usize = 0;
    var output_cursor: usize = 0;
    var output_table_cursor: usize = 0;
    var denominator_cursor: usize = 0;
    for (relations.instances, device, 0..) |instance, *binding, index| {
        const source_end = try add(
            source_cursor,
            instance.source_pointer_count,
        );
        const instance_sources = source_views[source_cursor..source_end];
        try bindSources(
            instance,
            try uniqueSources(sources, instance.component_index),
            instance_sources,
        );
        const source_table_words = try mul(
            instance.source_pointer_count,
            pointer_words,
        );
        const source_table_end = try add(
            source_table_cursor,
            source_table_words,
        );
        const descriptor_words = try mul(
            instance.geometry.columns,
            relation_abi.descriptor_words,
        );
        const descriptor_end = try add(
            descriptor_cursor,
            descriptor_words,
        );
        const coordinates = try mul(instance.geometry.columns, 4);
        const output_end = try add(output_cursor, coordinates);
        const output_table_words = try mul(coordinates, pointer_words);
        const output_table_end = try add(
            output_table_cursor,
            output_table_words,
        );
        const denominator_values = try mul(
            instance.geometry.rows,
            instance.geometry.columns,
        );
        const denominator_end = try add(
            denominator_cursor,
            denominator_values,
        );
        binding.* = .{
            .source_pointer_table = try nested_sources.sub(
                source_table_cursor,
                source_table_words,
            ),
            .source_columns = instance_sources,
            .descriptor_storage = try descriptor_storage.sub(
                descriptor_cursor,
                descriptor_words,
            ),
            .output_pointer_table = try nested_outputs.sub(
                output_table_cursor,
                output_table_words,
            ),
            .output_coordinates = output_views[output_cursor..output_end],
            .denominator_slab = try denominator_storage.sub(
                denominator_cursor,
                denominator_values,
            ),
            .claimed_sum = try claimed_sums.sub(
                index,
                1,
            ),
        };
        source_cursor = source_end;
        source_table_cursor = source_table_end;
        descriptor_cursor = descriptor_end;
        output_cursor = output_end;
        output_table_cursor = output_table_end;
        denominator_cursor = denominator_end;
    }
    if (source_cursor != source_views.len or
        source_table_cursor != nested_sources.len or
        descriptor_cursor != descriptor_storage.len or
        output_cursor != output_views.len or
        output_table_cursor != nested_outputs.len or
        denominator_cursor != denominator_storage.len)
    {
        return error.InvalidRelationResidentExtent;
    }
    const prepared = try relations.prepareAndUpload(
        allocator,
        uploader,
        buffers,
        device,
    );
    return .{
        .allocator = allocator,
        .prepared = prepared,
        .topology_identity = relations.topology_identity,
    };
}

fn bindSources(
    instance: relation_adapter.Instance,
    supplied: ComponentSources,
    destination: []common.Words,
) !void {
    if (instance.layout == .lookup_words) {
        const lookup = supplied.lookup_words orelse
            return error.MissingRelationLookupSource;
        if (destination.len != 1 or
            lookup.len != try mul(
                instance.geometry.rows,
                instance.lookup_word_columns,
            ))
        {
            return error.InvalidRelationSourceExtent;
        }
        destination[0] = lookup;
        return;
    }
    if (supplied.lookup_words != null or
        supplied.base_columns.len != destination.len)
    {
        return error.InvalidRelationSourceExtent;
    }
    for (supplied.base_columns, destination) |source, *bound| {
        if (source.len != instance.geometry.rows)
            return error.InvalidRelationSourceExtent;
        bound.* = source;
    }
}

fn bindInteractionOutputs(
    destination: []common.Words,
    provider: anytype,
    plan: *const resident_plan.Plan,
    program: proof_ir.ProofProgram,
    relations: *const relation_adapter.Plan,
) !void {
    const ordinal = try commitmentOrdinal(program, .interaction);
    const tree = program.commitments[ordinal];
    const storage = try exactSlot(
        provider,
        plan,
        .trace_coefficients,
        @intCast(ordinal),
    );
    var cursor: usize = 0;
    for (relations.instances) |instance| {
        const expected = try mul(instance.geometry.columns, 4);
        var offset: usize = 0;
        var count: usize = 0;
        for (program.trace_columns[tree.first_column..][0..tree.column_count]) |column| {
            const words = try pow2(column.log_rows);
            if (instance.component_index == column.component) {
                if (words != instance.geometry.rows)
                    return error.InvalidRelationOutputExtent;
                if (cursor >= destination.len)
                    return error.InvalidRelationOutputExtent;
                destination[cursor] = try storage.sub(offset, words);
                cursor += 1;
                count += 1;
            }
            offset = try add(offset, words);
        }
        if (offset != storage.len or count != expected)
            return error.InvalidRelationOutputExtent;
    }
    if (cursor != destination.len)
        return error.InvalidRelationOutputExtent;
}

fn validateSources(
    relations: *const relation_adapter.Plan,
    sources: []const ComponentSources,
) !void {
    if (sources.len != relations.instances.len)
        return error.InvalidRelationSourceCount;
    for (relations.instances) |instance|
        _ = try uniqueSources(sources, instance.component_index);
}

fn uniqueSources(
    sources: []const ComponentSources,
    component_index: u32,
) !ComponentSources {
    var found: ?ComponentSources = null;
    for (sources) |source| {
        if (source.component_index != component_index) continue;
        if (found != null) return error.DuplicateRelationSources;
        found = source;
    }
    return found orelse error.MissingRelationSources;
}

fn totalSources(relations: *const relation_adapter.Plan) !usize {
    var total: usize = 0;
    for (relations.instances) |instance|
        total = try add(total, instance.source_pointer_count);
    return total;
}

fn totalOutputs(relations: *const relation_adapter.Plan) !usize {
    var total: usize = 0;
    for (relations.instances) |instance|
        total = try add(total, try mul(instance.geometry.columns, 4));
    return total;
}

fn commitmentOrdinal(
    program: proof_ir.ProofProgram,
    role: proof_ir.CommitmentRole,
) !usize {
    var result: ?usize = null;
    for (program.commitments, 0..) |tree, ordinal| {
        if (tree.role != role) continue;
        if (result != null) return error.DuplicateCommitmentRole;
        result = ordinal;
    }
    return result orelse error.MissingCommitmentRole;
}

fn scheduleOrdinal(
    schedule: trace_schedule.Schedule,
    component_index: u32,
) !u32 {
    var result: ?u32 = null;
    for (schedule.entries) |entry| {
        if (entry.component_index != component_index) continue;
        if (result != null) return error.DuplicateRelationScheduleEntry;
        result = entry.canonical_ordinal;
    }
    return result orelse error.MissingRelationScheduleEntry;
}

fn exactSlot(
    provider: anytype,
    plan: *const resident_plan.Plan,
    kind: resident_plan.SlotKind,
    ordinal: u32,
) !common.Words {
    const descriptor = plan.slot(kind, ordinal) orelse
        return error.MissingRelationResidentSlot;
    const result = try provider.slot(descriptor.id);
    if (result.len != descriptor.words)
        return error.InvalidRelationResidentExtent;
    return result;
}

fn pow2(log_rows: u32) !usize {
    if (log_rows >= @bitSizeOf(usize))
        return error.InvalidRelationOutputExtent;
    return @as(usize, 1) << @intCast(log_rows);
}

fn add(left: anytype, right: anytype) !usize {
    const lhs = std.math.cast(usize, left) orelse
        return error.RelationBindingOverflow;
    const rhs = std.math.cast(usize, right) orelse
        return error.RelationBindingOverflow;
    return std.math.add(usize, lhs, rhs) catch
        error.RelationBindingOverflow;
}

fn mul(left: anytype, right: anytype) !usize {
    const lhs = std.math.cast(usize, left) orelse
        return error.RelationBindingOverflow;
    const rhs = std.math.cast(usize, right) orelse
        return error.RelationBindingOverflow;
    return std.math.mul(usize, lhs, rhs) catch
        error.RelationBindingOverflow;
}

test "relation binding rejects a program before touching device providers" {
    const Provider = struct {
        pub fn slot(_: @This(), _: u32) !common.Words {
            return error.UnexpectedDeviceAccess;
        }
    };
    const Uploader = struct {
        pub fn uploadSlice(
            _: *@This(),
            comptime T: type,
            _: anytype,
            _: []const T,
        ) !void {
            return error.UnexpectedDeviceAccess;
        }
    };
    var plan: resident_plan.Plan = undefined;
    plan.program_identity = [_]u8{1} ** 32;
    var program: proof_ir.ProofProgram = undefined;
    program.program_digest = [_]u8{2} ** 32;
    var relations: relation_adapter.Plan = undefined;
    var uploader = Uploader{};
    try std.testing.expectError(
        error.RelationResidentIdentityMismatch,
        prepareAndUpload(
            std.testing.allocator,
            &uploader,
            Provider{},
            &plan,
            program,
            &relations,
            &.{},
        ),
    );
}

test "source registry rejects cardinality before touching resident views" {
    const MainCommit = struct {
        pub fn writerOutput(
            _: @This(),
            _: u32,
        ) !common.WordMatrix {
            return error.UnexpectedDeviceAccess;
        }
    };
    var relations: relation_adapter.Plan = undefined;
    relations.instances = &.{};
    var entries: [1]trace_schedule.Entry = undefined;
    var schedule: trace_schedule.Schedule = undefined;
    schedule.entries = &entries;
    try std.testing.expectError(
        error.InvalidRelationSourceCount,
        buildSourceRegistry(
            std.testing.allocator,
            &relations,
            schedule,
            .{ .components = &.{} },
            MainCommit{},
        ),
    );
}
