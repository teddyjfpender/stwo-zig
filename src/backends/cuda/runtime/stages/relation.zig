//! Checked execution of an immutable, arena-backed relation graph.

const std = @import("std");
const abi = @import("../../abi/stages/relation.zig");
const column = @import("../column.zig");
const common = @import("common.zig");
const field = @import("../../abi/field.zig");
const layout = @import("resident_layout.zig");
const runtime_error = @import("../error.zig");
const residency = @import("relation/residency.zig");
const telemetry = @import("../telemetry.zig");

pub const Native = OpsFor(abi);
pub const TraceCommitNative = OpsForAt(abi, .trace_commit);
pub const ColumnDescriptor = abi.ColumnDescriptor;
pub const Geometry = abi.Geometry;
pub const MultiplicityKind = abi.MultiplicityKind;
pub const TupleKind = abi.TupleKind;
pub const UseDescriptor = abi.UseDescriptor;
pub const Geometries = column.DeviceSlice(Geometry);

pub const launch_count = 9;
const pointer_words = @sizeOf(usize) / @sizeOf(u32);
const default_stage = telemetry.Stage.constraint_evaluation;

comptime {
    // The imported CUDA pointer-table ABI stores each 64-bit device address
    // as two u32 words. A 32-bit host cannot bind this product safely.
    std.debug.assert(pointer_words == 2);
}

/// Host-owned topology compiled from one immutable `ProofProgram`.
///
/// The corresponding device geometry and pointer tables are uploaded once by
/// the plan compiler. Request execution only launches this fixed schedule.
pub const Topology = struct {
    geometry: []const Geometry,
    max_alpha_powers: u32,
    total_pair_blocks: u32,
    total_inverse_blocks: u32,
    total_chain_blocks: u32,
    total_row_blocks: u32,
    /// Optional frontend-owned identity for the exact relation topology.
    /// Native static frontends retain the zero identity because their trusted
    /// ingress already uploads compile-time descriptors and pointer tables.
    topology_identity: [32]u8 = [_]u8{0} ** 32,

    pub fn validate(self: Topology) runtime_error.Error!void {
        if (self.geometry.len == 0 or self.max_alpha_powers == 0 or
            self.total_pair_blocks == 0 or self.total_inverse_blocks == 0 or
            self.total_chain_blocks == 0 or self.total_row_blocks == 0)
        {
            return error.InvalidKernelDescriptor;
        }
        const signed_limit: u32 = @intCast(std.math.maxInt(i32));
        const quarter_limit = std.math.maxInt(u32) / 4;
        if (self.geometry.len > quarter_limit or
            self.total_pair_blocks > signed_limit or
            self.total_inverse_blocks > signed_limit or
            self.total_chain_blocks > signed_limit or
            self.total_row_blocks > quarter_limit)
        {
            return error.InvalidKernelDescriptor;
        }
        var pair_first: u32 = 0;
        var inverse_first: u32 = 0;
        var row_first: u32 = 0;
        for (self.geometry) |geometry| {
            const values = try checkedMul(geometry.rows, geometry.columns);
            const row_blocks = blocks(geometry.rows, abi.launch_block);
            const pair_blocks = try checkedMul(
                row_blocks,
                geometry.columns,
            );
            const inverse_blocks = blocks(
                values,
                abi.inverse_block_values,
            );
            if (geometry.rows == 0 or
                geometry.rows >= 0x7fff_ffff or
                !std.math.isPowerOfTwo(geometry.rows) or
                geometry.columns == 0 or geometry.real_rows > geometry.rows or
                values > signed_limit or
                geometry.pair_first != pair_first or
                geometry.inverse_first != inverse_first or
                geometry.row_first != row_first or
                geometry.row_blocks != row_blocks or
                geometry.pair_blocks != pair_blocks or
                geometry.inverse_blocks != inverse_blocks or
                geometry.inverse_rows != inverseRows(geometry.rows))
            {
                return error.InvalidKernelDescriptor;
            }
            pair_first = try checkedAdd(pair_first, geometry.pair_blocks);
            inverse_first = try checkedAdd(
                inverse_first,
                geometry.inverse_blocks,
            );
            row_first = try checkedAdd(row_first, geometry.row_blocks);
        }
        if (pair_first != self.total_pair_blocks or
            inverse_first != self.total_inverse_blocks or
            row_first != self.total_chain_blocks or
            row_first != self.total_row_blocks)
        {
            return error.InvalidKernelDescriptor;
        }
        _ = try self.scratchWords();
    }

    pub fn instanceCount(self: Topology) runtime_error.Error!u32 {
        return common.count(self.geometry.len);
    }

    pub fn scratchWords(self: Topology) runtime_error.Error!u32 {
        return checkedMul(self.total_row_blocks, 4);
    }
};

/// Top-level device tables and scratch populated during proof ingress.
pub const DeviceBuffers = struct {
    drawn_z_alpha: common.SecureFields,
    alpha_powers: common.SecureFields,
    z: common.SecureFields,
    source_tables: common.Words,
    descriptors: common.Words,
    output_tables: common.Words,
    denominator_slabs: common.Words,
    geometry: Geometries,
    claimed_sums: common.Words,
    reduction_partials: common.Words,
    scan_block_sums: common.Words,
};

/// One instance's complete nested device graph. The plan compiler uploads all
/// pointer tables and descriptor/geometry mirrors from these exact values.
pub const InstanceBinding = struct {
    source_pointer_table: common.Words,
    source_columns: []const common.Words,
    /// Exact words reachable through each source pointer. An empty slice is
    /// reserved for trusted static frontends whose sources are one column each.
    source_word_extents: []const u32 = &.{},
    lookup_word_columns: u32 = 0,
    descriptor_storage: common.Words,
    descriptors: []const ColumnDescriptor,
    output_pointer_table: common.Words,
    output_coordinates: []const common.Words,
    denominator_slab: common.SecureFields,
    claimed_sum: common.SecureFields,
};

pub const PrepareOptions = struct {
    topology: Topology,
    buffers: DeviceBuffers,
    instances: []const InstanceBinding,
};

/// Opaque after ingress: callers cannot substitute raw pointer tables at the
/// execution boundary.
pub const PreparedPlan = opaque {};

const OwnedInstance = struct {
    source_pointer_table: common.Words,
    source_columns: []common.Words,
    source_word_extents: []u32,
    lookup_word_columns: u32,
    descriptor_storage: common.Words,
    descriptors: []ColumnDescriptor,
    output_pointer_table: common.Words,
    output_coordinates: []common.Words,
    denominator_slab: common.SecureFields,
    claimed_sum: common.SecureFields,
};

const PlanState = struct {
    topology: Topology,
    geometry: []Geometry,
    buffers: DeviceBuffers,
    instances: []OwnedInstance,
};

pub const PrepareError = std.mem.Allocator.Error || runtime_error.Error;

pub fn prepare(
    allocator: std.mem.Allocator,
    options: PrepareOptions,
) PrepareError!*PreparedPlan {
    try validatePreparedInput(allocator, options);
    const state = try allocator.create(PlanState);
    errdefer allocator.destroy(state);
    const geometry = try allocator.dupe(Geometry, options.topology.geometry);
    errdefer allocator.free(geometry);
    const instances = try allocator.alloc(
        OwnedInstance,
        options.instances.len,
    );
    var initialized: usize = 0;
    errdefer {
        for (instances[0..initialized]) |*instance|
            deinitInstance(allocator, instance);
        allocator.free(instances);
    }
    for (options.instances, instances) |source, *destination| {
        destination.* = try copyInstance(allocator, source);
        initialized += 1;
    }
    state.* = .{
        .topology = .{
            .geometry = geometry,
            .max_alpha_powers = options.topology.max_alpha_powers,
            .total_pair_blocks = options.topology.total_pair_blocks,
            .total_inverse_blocks = options.topology.total_inverse_blocks,
            .total_chain_blocks = options.topology.total_chain_blocks,
            .total_row_blocks = options.topology.total_row_blocks,
            .topology_identity = options.topology.topology_identity,
        },
        .geometry = geometry,
        .buffers = options.buffers,
        .instances = instances,
    };
    return @ptrCast(state);
}

pub fn deinit(allocator: std.mem.Allocator, prepared: *PreparedPlan) void {
    const state = planState(prepared);
    for (state.instances) |*instance| deinitInstance(allocator, instance);
    allocator.free(state.instances);
    allocator.free(state.geometry);
    allocator.destroy(state);
}

pub fn topologyIdentity(prepared: *const PreparedPlan) [32]u8 {
    return planStateConst(prepared).topology.topology_identity;
}

/// Proves that the Fiat-Shamir relation elements are written into the exact
/// destination consumed by this opaque relation plan.
pub fn validateTranscriptChallenge(
    prepared: *const PreparedPlan,
    drawn_z_alpha: common.SecureFields,
) runtime_error.Error!void {
    const state = planStateConst(prepared);
    if (!sameView(
        try state.buffers.drawn_z_alpha.cast(u32),
        try drawn_z_alpha.cast(u32),
    )) return error.InvalidKernelDescriptor;
}

/// Read-only canonical relation claims produced by this plan. The returned
/// span is suitable for one device-to-device copy into the transcript/proof
/// claim slot; callers cannot substitute a host claim.
pub fn transcriptClaims(
    prepared: *const PreparedPlan,
) runtime_error.Error!common.Words {
    const state = planStateConst(prepared);
    if (state.instances.len == 0) return error.InvalidKernelDescriptor;
    const first = try state.instances[0].claimed_sum.cast(u32);
    const claim_words = try checkedMul(
        @intCast(state.instances.len),
        4,
    );
    for (state.instances, 0..) |instance, index| {
        if (instance.claimed_sum.len != 1)
            return error.InvalidKernelDescriptor;
        const words = try instance.claimed_sum.cast(u32);
        const expected_address = std.math.add(
            usize,
            first.address,
            std.math.mul(
                usize,
                index,
                4 * @sizeOf(u32),
            ) catch return error.SizeOverflow,
        ) catch return error.SizeOverflow;
        if (words.address != expected_address or
            words.len != 4 or
            words.owner != first.owner or
            words.generation != first.generation)
        {
            return error.InvalidKernelDescriptor;
        }
    }
    return .{
        .address = first.address,
        .len = claim_words,
        .owner = first.owner,
        .generation = first.generation,
    };
}

pub fn OpsFor(comptime Api: type) type {
    return OpsForAt(Api, default_stage);
}

fn sameView(left: common.Words, right: common.Words) bool {
    return left.address == right.address and
        left.len == right.len and
        left.owner == right.owner and
        left.generation == right.generation;
}

/// Cairo draws relation challenges and commits the interaction tree inside
/// `trace_commit`; native AIRs historically run their relation stage during
/// `constraint_evaluation`. The launch body is identical, but stage ownership
/// must remain explicit for transcript ordering and telemetry.
pub fn OpsForAt(
    comptime Api: type,
    comptime stage: telemetry.Stage,
) type {
    return struct {
        pub fn execute(
            session: anytype,
            prepared: *const PreparedPlan,
        ) runtime_error.Error!void {
            try common.requireStage(session, stage);
            const state = planStateConst(prepared);
            const topology = state.topology;
            const buffers = state.buffers;
            const instance_count = try topology.instanceCount();
            const scratch_words = try topology.scratchWords();
            try validateResidentPlan(session, state);

            const drawn = try layout.resident(
                session,
                field.SecureField,
                buffers.drawn_z_alpha,
                2,
            );
            const alphas = try layout.resident(
                session,
                field.SecureField,
                buffers.alpha_powers,
                topology.max_alpha_powers,
            );
            const z = try layout.resident(
                session,
                field.SecureField,
                buffers.z,
                1,
            );
            const sources = try layout.resident(
                session,
                u32,
                buffers.source_tables,
                pointerTableWords(instance_count),
            );
            const descriptors = try layout.resident(
                session,
                u32,
                buffers.descriptors,
                pointerTableWords(instance_count),
            );
            const outputs = try layout.resident(
                session,
                u32,
                buffers.output_tables,
                pointerTableWords(instance_count),
            );
            const denominators = try layout.resident(
                session,
                u32,
                buffers.denominator_slabs,
                pointerTableWords(instance_count),
            );
            const geometry = try layout.resident(
                session,
                Geometry,
                buffers.geometry,
                instance_count,
            );
            const sums = try layout.resident(
                session,
                u32,
                buffers.claimed_sums,
                pointerTableWords(instance_count),
            );
            const partials = try layout.resident(
                session,
                u32,
                buffers.reduction_partials,
                scratch_words,
            );
            const scan = try layout.resident(
                session,
                u32,
                buffers.scan_block_sums,
                scratch_words,
            );
            const immutable_ranges = [_]layout.DeviceRange{
                drawn.range,
                sources.range,
                descriptors.range,
                outputs.range,
                denominators.range,
                geometry.range,
                sums.range,
            };
            const mutable_ranges = [_]layout.DeviceRange{
                alphas.range,
                z.range,
                partials.range,
                scan.range,
            };
            try layout.requireDisjoint(&mutable_ranges, &immutable_ranges);
            try layout.requireDisjoint(&mutable_ranges, &.{});

            var status = Api.stwo_relation_expand_challenges_on(
                drawn.pointer,
                alphas.pointer,
                topology.max_alpha_powers,
                @ptrCast(z.pointer),
                session.context.stream,
            );
            try common.record(session, stage, status);

            status = Api.stwo_relation_pairs_global_on(
                sources.pointer,
                descriptors.pointer,
                outputs.pointer,
                denominators.pointer,
                geometry.pointer,
                instance_count,
                topology.total_pair_blocks,
                alphas.pointer,
                topology.max_alpha_powers,
                @ptrCast(z.pointer),
                session.context.stream,
            );
            try common.record(session, stage, status);

            status = Api.stwo_relation_fraction_chain_global_on(
                outputs.pointer,
                denominators.pointer,
                geometry.pointer,
                instance_count,
                topology.total_inverse_blocks,
                topology.total_chain_blocks,
                session.context.stream,
            );
            try common.recordMany(session, stage, status, 2);

            status = Api.stwo_relation_tail_global_on(
                outputs.pointer,
                sums.pointer,
                geometry.pointer,
                instance_count,
                topology.total_row_blocks,
                partials.pointer,
                topology.total_row_blocks,
                scan.pointer,
                scratch_words,
                session.context.stream,
            );
            try common.recordMany(session, stage, status, 5);
        }
    };
}

fn validatePreparedInput(
    allocator: std.mem.Allocator,
    options: PrepareOptions,
) PrepareError!void {
    try options.topology.validate();
    try validateBufferLengths(options.topology, options.buffers);
    try residency.validatePointerTableAlignment(options.buffers);
    if (options.instances.len != options.topology.geometry.len)
        return error.InvalidKernelDescriptor;

    const identity = residency.DeviceIdentity.from(
        options.buffers.drawn_z_alpha,
    );
    var reads: std.ArrayList(layout.DeviceRange) = .empty;
    defer reads.deinit(allocator);
    var writes: std.ArrayList(layout.DeviceRange) = .empty;
    defer writes.deinit(allocator);
    try retainTopLevelRanges(
        allocator,
        &reads,
        &writes,
        identity,
        options.topology,
        options.buffers,
    );
    for (
        options.instances,
        options.topology.geometry,
    ) |instance, geometry| {
        try retainInstanceRanges(
            allocator,
            &reads,
            &writes,
            identity,
            geometry,
            options.topology.max_alpha_powers,
            instance,
        );
    }
    try layout.requireDisjoint(writes.items, reads.items);
    try layout.requireDisjoint(writes.items, &.{});
}

fn retainTopLevelRanges(
    allocator: std.mem.Allocator,
    reads: *std.ArrayList(layout.DeviceRange),
    writes: *std.ArrayList(layout.DeviceRange),
    identity: residency.DeviceIdentity,
    topology: Topology,
    buffers: DeviceBuffers,
) PrepareError!void {
    const instances = try topology.instanceCount();
    const table_words = pointerTableWords(instances);
    const scratch_words = try topology.scratchWords();
    inline for (.{
        .{ field.SecureField, buffers.drawn_z_alpha, 2, @alignOf(field.SecureField) },
        .{ u32, buffers.source_tables, table_words, @alignOf(usize) },
        .{ u32, buffers.descriptors, table_words, @alignOf(usize) },
        .{ u32, buffers.output_tables, table_words, @alignOf(usize) },
        .{ u32, buffers.denominator_slabs, table_words, @alignOf(usize) },
        .{ Geometry, buffers.geometry, instances, @alignOf(Geometry) },
        .{ u32, buffers.claimed_sums, table_words, @alignOf(usize) },
    }) |entry| {
        try reads.append(
            allocator,
            try residency.checkedRange(
                entry[0],
                entry[1],
                entry[2],
                entry[3],
                identity,
            ),
        );
    }
    inline for (.{
        .{
            field.SecureField,
            buffers.alpha_powers,
            topology.max_alpha_powers,
            @alignOf(field.SecureField),
        },
        .{ field.SecureField, buffers.z, 1, @alignOf(field.SecureField) },
        .{ u32, buffers.reduction_partials, scratch_words, @alignOf(u32) },
        .{ u32, buffers.scan_block_sums, scratch_words, @alignOf(u32) },
    }) |entry| {
        try writes.append(
            allocator,
            try residency.checkedRange(
                entry[0],
                entry[1],
                entry[2],
                entry[3],
                identity,
            ),
        );
    }
}

fn retainInstanceRanges(
    allocator: std.mem.Allocator,
    reads: *std.ArrayList(layout.DeviceRange),
    writes: *std.ArrayList(layout.DeviceRange),
    identity: residency.DeviceIdentity,
    geometry: Geometry,
    alpha_powers: u32,
    instance: InstanceBinding,
) PrepareError!void {
    const source_count = std.math.cast(
        u32,
        instance.source_columns.len,
    ) orelse return error.SizeOverflow;
    const output_count = try checkedMul(geometry.columns, 4);
    const descriptor_words = try checkedMul(
        geometry.columns,
        abi.descriptor_words,
    );
    const denominator_values = try checkedMul(
        geometry.rows,
        geometry.columns,
    );
    if ((instance.source_word_extents.len != 0 and
        instance.source_word_extents.len != instance.source_columns.len) or
        instance.descriptors.len != geometry.columns or
        instance.output_coordinates.len != output_count or
        instance.source_pointer_table.len !=
            pointerTableWords(source_count) or
        instance.output_pointer_table.len !=
            pointerTableWords(output_count) or
        instance.descriptor_storage.len != descriptor_words or
        instance.denominator_slab.len != denominator_values or
        instance.claimed_sum.len != 1)
    {
        return error.InvalidKernelDescriptor;
    }
    const bounds = abi.SourceBounds{
        .source_pointer_count = source_count,
        .lookup_word_columns = instance.lookup_word_columns,
        .max_alpha_powers = alpha_powers,
    };
    for (instance.descriptors) |descriptor| try descriptor.validate(bounds);

    inline for (.{
        instance.source_pointer_table,
        instance.output_pointer_table,
    }) |table| {
        try reads.append(
            allocator,
            try residency.checkedRange(
                u32,
                table,
                table.len,
                @alignOf(usize),
                identity,
            ),
        );
    }
    try reads.append(
        allocator,
        try residency.checkedRange(
            u32,
            instance.descriptor_storage,
            descriptor_words,
            @alignOf(ColumnDescriptor),
            identity,
        ),
    );
    for (instance.source_columns, 0..) |source, source_index| {
        const extent = try sourceWordExtent(
            instance.source_word_extents,
            source_index,
            geometry.rows,
        );
        try reads.append(
            allocator,
            try residency.checkedRange(
                u32,
                source,
                extent,
                @alignOf(u32),
                identity,
            ),
        );
    }
    for (instance.output_coordinates) |output| {
        try writes.append(
            allocator,
            try residency.checkedRange(
                u32,
                output,
                geometry.rows,
                @alignOf(u32),
                identity,
            ),
        );
    }
    try writes.append(
        allocator,
        try residency.checkedRange(
            field.SecureField,
            instance.denominator_slab,
            denominator_values,
            @alignOf(field.SecureField),
            identity,
        ),
    );
    try writes.append(
        allocator,
        try residency.checkedRange(
            field.SecureField,
            instance.claimed_sum,
            1,
            @alignOf(field.SecureField),
            identity,
        ),
    );
}

fn validateResidentPlan(
    session: anytype,
    state: *const PlanState,
) runtime_error.Error!void {
    try state.topology.validate();
    try validateBufferLengths(state.topology, state.buffers);
    for (
        state.instances,
        state.topology.geometry,
    ) |instance, geometry| {
        _ = try session.context.deviceSlicePointer(
            u32,
            instance.source_pointer_table,
            instance.source_pointer_table.len,
        );
        _ = try session.context.deviceSlicePointer(
            u32,
            instance.descriptor_storage,
            instance.descriptor_storage.len,
        );
        _ = try session.context.deviceSlicePointer(
            u32,
            instance.output_pointer_table,
            instance.output_pointer_table.len,
        );
        for (instance.source_columns, 0..) |source, source_index| {
            _ = try session.context.deviceSlicePointer(
                u32,
                source,
                try sourceWordExtent(
                    instance.source_word_extents,
                    source_index,
                    geometry.rows,
                ),
            );
        }
        for (instance.output_coordinates) |output| {
            _ = try session.context.deviceSlicePointer(
                u32,
                output,
                geometry.rows,
            );
        }
        _ = try session.context.deviceSlicePointer(
            field.SecureField,
            instance.denominator_slab,
            try checkedMul(geometry.rows, geometry.columns),
        );
        _ = try session.context.deviceSlicePointer(
            field.SecureField,
            instance.claimed_sum,
            1,
        );
    }
}

fn copyInstance(
    allocator: std.mem.Allocator,
    source: InstanceBinding,
) std.mem.Allocator.Error!OwnedInstance {
    const source_columns = try allocator.dupe(
        common.Words,
        source.source_columns,
    );
    errdefer allocator.free(source_columns);
    const source_word_extents = try allocator.dupe(
        u32,
        source.source_word_extents,
    );
    errdefer allocator.free(source_word_extents);
    const descriptors = try allocator.dupe(
        ColumnDescriptor,
        source.descriptors,
    );
    errdefer allocator.free(descriptors);
    const output_coordinates = try allocator.dupe(
        common.Words,
        source.output_coordinates,
    );
    return .{
        .source_pointer_table = source.source_pointer_table,
        .source_columns = source_columns,
        .source_word_extents = source_word_extents,
        .lookup_word_columns = source.lookup_word_columns,
        .descriptor_storage = source.descriptor_storage,
        .descriptors = descriptors,
        .output_pointer_table = source.output_pointer_table,
        .output_coordinates = output_coordinates,
        .denominator_slab = source.denominator_slab,
        .claimed_sum = source.claimed_sum,
    };
}

fn deinitInstance(
    allocator: std.mem.Allocator,
    instance: *OwnedInstance,
) void {
    allocator.free(instance.source_columns);
    allocator.free(instance.source_word_extents);
    allocator.free(instance.descriptors);
    allocator.free(instance.output_coordinates);
    instance.* = undefined;
}

fn planState(prepared: *PreparedPlan) *PlanState {
    return @ptrCast(@alignCast(prepared));
}

fn planStateConst(prepared: *const PreparedPlan) *const PlanState {
    return @ptrCast(@alignCast(prepared));
}

fn validateBufferLengths(
    topology: Topology,
    buffers: DeviceBuffers,
) runtime_error.Error!void {
    const instances = try topology.instanceCount();
    const table_words = pointerTableWords(instances);
    if (buffers.drawn_z_alpha.len != 2 or
        buffers.alpha_powers.len != topology.max_alpha_powers or
        buffers.z.len != 1 or
        buffers.source_tables.len != table_words or
        buffers.descriptors.len != table_words or
        buffers.output_tables.len != table_words or
        buffers.denominator_slabs.len != table_words or
        buffers.geometry.len != instances or
        buffers.claimed_sums.len != table_words or
        buffers.reduction_partials.len < try topology.scratchWords() or
        buffers.scan_block_sums.len < try topology.scratchWords())
    {
        return error.InvalidKernelDescriptor;
    }
}

fn pointerTableWords(count: u32) usize {
    return @as(usize, count) * pointer_words;
}

fn sourceWordExtent(
    extents: []const u32,
    index: usize,
    rows: u32,
) runtime_error.Error!u32 {
    if (extents.len == 0) return rows;
    if (index >= extents.len or extents[index] < rows)
        return error.InvalidKernelDescriptor;
    return extents[index];
}

fn blocks(values: u32, block_size: u32) u32 {
    return values / block_size + @intFromBool(values % block_size != 0);
}

fn checkedAdd(left: u32, right: u32) runtime_error.Error!u32 {
    return std.math.add(u32, left, right) catch error.SizeOverflow;
}

fn checkedMul(left: u32, right: u32) runtime_error.Error!u32 {
    return std.math.mul(u32, left, right) catch error.SizeOverflow;
}

fn inverseRows(rows: u32) u32 {
    std.debug.assert(rows != 0 and std.math.isPowerOfTwo(rows));
    const log_rows = std.math.log2_int(u32, rows);
    return if (log_rows == 0) 1 else @as(u32, 1) << @intCast(31 - log_rows);
}
