//! Exact resident completion of precomputed paired LogUp fractions.
//!
//! Specialized AIR kernels own numerator/denominator construction. This stage
//! exclusively owns batch inversion, fraction accumulation, claimed sums,
//! claim subtraction, and the canonical circle-order prefix scan.

const std = @import("std");
const abi = @import("../../abi/stages/relation.zig");
const column = @import("../column.zig");
const common = @import("common.zig");
const field = @import("../../abi/field.zig");
const layout = @import("resident_layout.zig");
const relation = @import("relation.zig");
const runtime_error = @import("../error.zig");
const telemetry = @import("../telemetry.zig");

pub const Native = OpsFor(abi);
pub const Geometry = abi.Geometry;
pub const Geometries = column.DeviceSlice(Geometry);
pub const Topology = relation.Topology;

const pointer_words = @sizeOf(usize) / @sizeOf(u32);
const stage = telemetry.Stage.constraint_evaluation;

comptime {
    std.debug.assert(pointer_words == 2);
}

pub const DeviceBuffers = struct {
    output_tables: common.Words,
    denominator_slabs: common.Words,
    geometry: Geometries,
    claimed_sums: common.Words,
    reduction_partials: common.Words,
    scan_block_sums: common.Words,
};

pub const InstanceBinding = struct {
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

pub const PreparedPlan = opaque {};

const OwnedInstance = struct {
    output_pointer_table: common.Words,
    output_coordinates: []common.Words,
    denominator_slab: common.SecureFields,
    claimed_sum: common.SecureFields,
};

const State = struct {
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
    try validateOptions(allocator, options);
    const state = try allocator.create(State);
    errdefer allocator.destroy(state);
    const geometry = try allocator.dupe(Geometry, options.topology.geometry);
    errdefer allocator.free(geometry);
    const instances = try allocator.alloc(OwnedInstance, options.instances.len);
    var initialized: usize = 0;
    errdefer {
        for (instances[0..initialized]) |instance|
            allocator.free(instance.output_coordinates);
        allocator.free(instances);
    }
    for (options.instances, instances) |source, *destination| {
        destination.* = .{
            .output_pointer_table = source.output_pointer_table,
            .output_coordinates = try allocator.dupe(
                common.Words,
                source.output_coordinates,
            ),
            .denominator_slab = source.denominator_slab,
            .claimed_sum = source.claimed_sum,
        };
        initialized += 1;
    }
    state.* = .{
        .topology = copyTopology(options.topology, geometry),
        .geometry = geometry,
        .buffers = options.buffers,
        .instances = instances,
    };
    return @ptrCast(state);
}

pub fn deinit(allocator: std.mem.Allocator, prepared: *PreparedPlan) void {
    const state = planState(prepared);
    for (state.instances) |instance|
        allocator.free(instance.output_coordinates);
    allocator.free(state.instances);
    allocator.free(state.geometry);
    allocator.destroy(state);
}

pub fn OpsFor(comptime Api: type) type {
    return struct {
        pub fn execute(
            session: anytype,
            prepared: *const PreparedPlan,
        ) runtime_error.Error!void {
            try common.requireStage(session, stage);
            const state = planStateConst(prepared);
            try validateResident(session, state);
            const instance_count = try state.topology.instanceCount();
            const scratch_words = try state.topology.scratchWords();
            const outputs = try layout.resident(
                session,
                u32,
                state.buffers.output_tables,
                tableWords(instance_count),
            );
            const denominators = try layout.resident(
                session,
                u32,
                state.buffers.denominator_slabs,
                tableWords(instance_count),
            );
            const geometry = try layout.resident(
                session,
                Geometry,
                state.buffers.geometry,
                instance_count,
            );
            const sums = try layout.resident(
                session,
                u32,
                state.buffers.claimed_sums,
                tableWords(instance_count),
            );
            const partials = try layout.resident(
                session,
                u32,
                state.buffers.reduction_partials,
                scratch_words,
            );
            const scan = try layout.resident(
                session,
                u32,
                state.buffers.scan_block_sums,
                scratch_words,
            );
            const immutable = [_]layout.DeviceRange{
                outputs.range,
                denominators.range,
                geometry.range,
                sums.range,
            };
            const mutable = [_]layout.DeviceRange{
                partials.range,
                scan.range,
            };
            try layout.requireDisjoint(&mutable, &immutable);

            var status = Api.stwo_relation_fraction_chain_global_on(
                outputs.pointer,
                denominators.pointer,
                geometry.pointer,
                instance_count,
                state.topology.total_inverse_blocks,
                state.topology.total_chain_blocks,
                session.context.stream,
            );
            try common.recordMany(session, stage, status, 2);
            status = Api.stwo_relation_tail_global_on(
                outputs.pointer,
                sums.pointer,
                geometry.pointer,
                instance_count,
                state.topology.total_row_blocks,
                partials.pointer,
                state.topology.total_row_blocks,
                scan.pointer,
                scratch_words,
                session.context.stream,
            );
            try common.recordMany(session, stage, status, 5);
        }
    };
}

fn validateOptions(
    allocator: std.mem.Allocator,
    options: PrepareOptions,
) PrepareError!void {
    try options.topology.validate();
    const count = try options.topology.instanceCount();
    if (options.instances.len != count)
        return error.InvalidKernelDescriptor;
    try validateBufferLengths(options.topology, options.buffers);
    var reads: std.ArrayList(layout.DeviceRange) = .empty;
    defer reads.deinit(allocator);
    var writes: std.ArrayList(layout.DeviceRange) = .empty;
    defer writes.deinit(allocator);
    const table_count = tableWords(count);
    inline for (.{
        .{ options.buffers.output_tables, table_count, @alignOf(usize) },
        .{ options.buffers.denominator_slabs, table_count, @alignOf(usize) },
        .{ options.buffers.claimed_sums, table_count, @alignOf(usize) },
    }) |entry| {
        if (entry[0].address % entry[2] != 0)
            return error.InvalidKernelDescriptor;
        try reads.append(
            allocator,
            try layout.elementRange(entry[0].address, entry[1], @sizeOf(u32)),
        );
    }
    try reads.append(
        allocator,
        try layout.elementRange(
            options.buffers.geometry.address,
            count,
            @sizeOf(Geometry),
        ),
    );
    const scratch = try options.topology.scratchWords();
    try writes.append(
        allocator,
        try layout.elementRange(
            options.buffers.reduction_partials.address,
            scratch,
            @sizeOf(u32),
        ),
    );
    try writes.append(
        allocator,
        try layout.elementRange(
            options.buffers.scan_block_sums.address,
            scratch,
            @sizeOf(u32),
        ),
    );
    for (options.instances, options.topology.geometry) |instance, geometry| {
        const coordinate_count = try checkedMul(geometry.columns, 4);
        const denominator_count = try checkedMul(geometry.rows, geometry.columns);
        if (instance.output_coordinates.len != coordinate_count or
            instance.output_pointer_table.len != tableWords(coordinate_count) or
            instance.denominator_slab.len != denominator_count or
            instance.claimed_sum.len != 1)
        {
            return error.InvalidKernelDescriptor;
        }
        try reads.append(
            allocator,
            try layout.elementRange(
                instance.output_pointer_table.address,
                instance.output_pointer_table.len,
                @sizeOf(u32),
            ),
        );
        for (instance.output_coordinates) |output| {
            try writes.append(
                allocator,
                try layout.elementRange(
                    output.address,
                    geometry.rows,
                    @sizeOf(u32),
                ),
            );
        }
        try writes.append(
            allocator,
            try layout.elementRange(
                instance.denominator_slab.address,
                denominator_count,
                @sizeOf(field.SecureField),
            ),
        );
        try writes.append(
            allocator,
            try layout.elementRange(
                instance.claimed_sum.address,
                1,
                @sizeOf(field.SecureField),
            ),
        );
    }
    try layout.requireDisjoint(writes.items, reads.items);
}

fn validateBufferLengths(
    topology: Topology,
    buffers: DeviceBuffers,
) runtime_error.Error!void {
    const count = try topology.instanceCount();
    const tables = tableWords(count);
    const scratch = try topology.scratchWords();
    if (buffers.output_tables.len != tables or
        buffers.denominator_slabs.len != tables or
        buffers.geometry.len != count or
        buffers.claimed_sums.len != tables or
        buffers.reduction_partials.len != scratch or
        buffers.scan_block_sums.len != scratch or
        buffers.output_tables.address % @alignOf(usize) != 0 or
        buffers.denominator_slabs.address % @alignOf(usize) != 0 or
        buffers.claimed_sums.address % @alignOf(usize) != 0)
    {
        return error.InvalidKernelDescriptor;
    }
}

fn validateResident(session: anytype, state: *const State) runtime_error.Error!void {
    try state.topology.validate();
    try validateBufferLengths(state.topology, state.buffers);
    for (state.instances, state.topology.geometry) |instance, geometry| {
        _ = try session.context.deviceSlicePointer(
            u32,
            instance.output_pointer_table,
            instance.output_pointer_table.len,
        );
        for (instance.output_coordinates) |output| {
            _ = try session.context.deviceSlicePointer(u32, output, geometry.rows);
        }
        _ = try session.context.deviceSlicePointer(
            field.SecureField,
            instance.denominator_slab,
            instance.denominator_slab.len,
        );
        _ = try session.context.deviceSlicePointer(
            field.SecureField,
            instance.claimed_sum,
            1,
        );
    }
}

fn copyTopology(source: Topology, geometry: []Geometry) Topology {
    return .{
        .geometry = geometry,
        .max_alpha_powers = source.max_alpha_powers,
        .total_pair_blocks = source.total_pair_blocks,
        .total_inverse_blocks = source.total_inverse_blocks,
        .total_chain_blocks = source.total_chain_blocks,
        .total_row_blocks = source.total_row_blocks,
    };
}

fn planState(prepared: *PreparedPlan) *State {
    return @ptrCast(@alignCast(prepared));
}

fn planStateConst(prepared: *const PreparedPlan) *const State {
    return @ptrCast(@alignCast(prepared));
}

fn tableWords(count: u32) u32 {
    return count * pointer_words;
}

fn checkedMul(left: u32, right: u32) runtime_error.Error!u32 {
    return std.math.mul(u32, left, right) catch error.SizeOverflow;
}

test "completion preparation rejects incomplete output graphs" {
    const geometry = [_]Geometry{.{
        .pair_first = 0,
        .pair_blocks = 4,
        .inverse_first = 0,
        .inverse_blocks = 1,
        .row_first = 0,
        .row_blocks = 4,
        .rows = 1024,
        .columns = 1,
        .real_rows = 1024,
        .source_offset_rows = 0,
        .inverse_rows = 1 << 21,
    }};
    const topology = Topology{
        .geometry = &geometry,
        .max_alpha_powers = 1,
        .total_pair_blocks = 4,
        .total_inverse_blocks = 1,
        .total_chain_blocks = 4,
        .total_row_blocks = 4,
    };
    const words = common.Words{
        .address = 0x1000,
        .len = 2,
        .owner = 7,
        .generation = 11,
    };
    const instance = InstanceBinding{
        .output_pointer_table = words,
        .output_coordinates = &.{},
        .denominator_slab = .{
            .address = 0x2000,
            .len = 1024,
            .owner = 7,
            .generation = 11,
        },
        .claimed_sum = .{
            .address = 0x3000,
            .len = 1,
            .owner = 7,
            .generation = 11,
        },
    };
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        prepare(std.testing.allocator, .{
            .topology = topology,
            .buffers = .{
                .output_tables = words,
                .denominator_slabs = words,
                .geometry = .{
                    .address = 0x4000,
                    .len = 1,
                    .owner = 7,
                    .generation = 11,
                },
                .claimed_sums = words,
                .reduction_partials = .{
                    .address = 0x5000,
                    .len = 16,
                    .owner = 7,
                    .generation = 11,
                },
                .scan_block_sums = .{
                    .address = 0x6000,
                    .len = 16,
                    .owner = 7,
                    .generation = 11,
                },
            },
            .instances = &.{instance},
        }),
    );
}
