//! Checked execution of an immutable, arena-backed relation graph.

const std = @import("std");
const abi = @import("../../abi/stages/relation.zig");
const column = @import("../column.zig");
const common = @import("common.zig");
const field = @import("../../abi/field.zig");
const layout = @import("resident_layout.zig");
const runtime_error = @import("../error.zig");
const telemetry = @import("../telemetry.zig");

pub const Native = OpsFor(abi);
pub const ColumnDescriptor = abi.ColumnDescriptor;
pub const Geometry = abi.Geometry;
pub const MultiplicityKind = abi.MultiplicityKind;
pub const TupleKind = abi.TupleKind;
pub const UseDescriptor = abi.UseDescriptor;
pub const Geometries = column.DeviceSlice(Geometry);

pub const launch_count = 9;
const pointer_words = @sizeOf(usize) / @sizeOf(u32);
const stage = telemetry.Stage.constraint_evaluation;

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

    pub fn validate(self: Topology) runtime_error.Error!void {
        if (self.geometry.len == 0 or self.max_alpha_powers == 0 or
            self.total_pair_blocks == 0 or self.total_inverse_blocks == 0 or
            self.total_chain_blocks == 0 or self.total_row_blocks == 0)
        {
            return error.InvalidKernelDescriptor;
        }
        var pair_first: u32 = 0;
        var inverse_first: u32 = 0;
        var row_first: u32 = 0;
        for (self.geometry) |geometry| {
            const row_blocks = blocks(geometry.rows, abi.launch_block);
            const pair_blocks = try checkedMul(
                row_blocks,
                geometry.columns,
            );
            const inverse_blocks = blocks(
                try checkedMul(geometry.rows, geometry.columns),
                abi.inverse_block_values,
            );
            if (geometry.rows == 0 or
                !std.math.isPowerOfTwo(geometry.rows) or
                geometry.columns == 0 or geometry.real_rows > geometry.rows or
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
    }

    pub fn instanceCount(self: Topology) runtime_error.Error!u32 {
        return common.count(self.geometry.len);
    }
};

/// Device-resident pointer tables and scratch owned by one compiled plan.
pub const Buffers = struct {
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

pub fn OpsFor(comptime Api: type) type {
    return struct {
        pub fn execute(
            session: anytype,
            topology: Topology,
            buffers: Buffers,
        ) runtime_error.Error!void {
            try common.requireStage(session, stage);
            try topology.validate();
            const instance_count = try topology.instanceCount();
            try validateBufferLengths(topology, buffers);

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
                topology.total_row_blocks * 4,
            );
            const scan = try layout.resident(
                session,
                u32,
                buffers.scan_block_sums,
                topology.total_row_blocks * 4,
            );
            const immutable_ranges = [_]layout.DeviceRange{
                drawn.range,
                sources.range,
                descriptors.range,
                geometry.range,
            };
            const mutable_ranges = [_]layout.DeviceRange{
                alphas.range,
                z.range,
                outputs.range,
                denominators.range,
                sums.range,
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
                topology.total_row_blocks * 4,
                session.context.stream,
            );
            try common.recordMany(session, stage, status, 5);
        }
    };
}

fn validateBufferLengths(
    topology: Topology,
    buffers: Buffers,
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
        buffers.reduction_partials.len < topology.total_row_blocks * 4 or
        buffers.scan_block_sums.len < topology.total_row_blocks * 4)
    {
        return error.InvalidKernelDescriptor;
    }
}

fn pointerTableWords(count: u32) usize {
    return @as(usize, count) * pointer_words;
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

test "relation topology admits one exact Plonk-shaped graph" {
    const geometry = [_]Geometry{.{
        .pair_first = 0,
        .pair_blocks = 512,
        .inverse_first = 0,
        .inverse_blocks = 128,
        .row_first = 0,
        .row_blocks = 256,
        .rows = 1 << 16,
        .columns = 2,
        .real_rows = 1 << 16,
        .source_offset_rows = 0,
        .inverse_rows = 1 << 15,
    }};
    const topology = Topology{
        .geometry = &geometry,
        .max_alpha_powers = 2,
        .total_pair_blocks = 512,
        .total_inverse_blocks = 128,
        .total_chain_blocks = 256,
        .total_row_blocks = 256,
    };
    try topology.validate();
}

test "relation topology rejects cumulative offset drift" {
    const geometry = [_]Geometry{.{
        .pair_first = 1,
        .pair_blocks = 2,
        .inverse_first = 0,
        .inverse_blocks = 1,
        .row_first = 0,
        .row_blocks = 1,
        .rows = 16,
        .columns = 2,
        .real_rows = 16,
        .source_offset_rows = 0,
        .inverse_rows = 1,
    }};
    const topology = Topology{
        .geometry = &geometry,
        .max_alpha_powers = 2,
        .total_pair_blocks = 2,
        .total_inverse_blocks = 1,
        .total_chain_blocks = 1,
        .total_row_blocks = 1,
    };
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        topology.validate(),
    );
}

test "relation topology rejects an inexact M31 row inverse" {
    const geometry = [_]Geometry{.{
        .pair_first = 0,
        .pair_blocks = 2,
        .inverse_first = 0,
        .inverse_blocks = 1,
        .row_first = 0,
        .row_blocks = 1,
        .rows = 16,
        .columns = 2,
        .real_rows = 16,
        .source_offset_rows = 0,
        .inverse_rows = 1,
    }};
    const topology = Topology{
        .geometry = &geometry,
        .max_alpha_powers = 2,
        .total_pair_blocks = 2,
        .total_inverse_blocks = 1,
        .total_chain_blocks = 1,
        .total_row_blocks = 1,
    };
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        topology.validate(),
    );
}
