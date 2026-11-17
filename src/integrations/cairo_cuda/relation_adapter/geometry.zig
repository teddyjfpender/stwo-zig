//! Canonical Cairo relation topology identity and checked geometry arithmetic.
const std = @import("std");
const relation_abi = @import("stwo_cuda_backend").abi.stages.relation;
const owner_api = @import("../relation_adapter.zig");
const Plan = owner_api.Plan;
const Error = owner_api.Error;

pub fn topologyIdentity(graph_hash: u64, plan: *const Plan) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/cairo/cuda/relation-topology/v1\x00");
    hashInt(&hash, u64, graph_hash);
    hashInt(&hash, u64, plan.instances.len);
    hashInt(&hash, u32, plan.max_alpha_powers);
    hashInt(&hash, u32, plan.total_pair_blocks);
    hashInt(&hash, u32, plan.total_inverse_blocks);
    hashInt(&hash, u32, plan.total_row_blocks);
    for (plan.instances) |instance| {
        hashInt(&hash, u32, instance.component_index);
        hashInt(&hash, u32, instance.component_instance);
        hashInt(&hash, u32, instance.relation_component_index);
        hashInt(&hash, u32, instance.relation_trace_index);
        hashInt(&hash, u64, instance.component.len);
        hash.update(instance.component);
        hashInt(&hash, u32, @intFromEnum(instance.part));
        hashInt(&hash, u32, @intFromEnum(instance.layout));
        hashInt(&hash, u32, instance.source_pointer_count);
        hashInt(&hash, u32, instance.lookup_word_columns);
        inline for (std.meta.fields(relation_abi.Geometry)) |field| {
            hashInt(
                &hash,
                u32,
                @field(instance.geometry, field.name),
            );
        }
        hashInt(&hash, u64, instance.descriptors.len);
        for (instance.descriptors) |descriptor| {
            hashInt(&hash, u32, descriptor.arity);
            hashUse(&hash, descriptor.first);
            hashUse(&hash, descriptor.second);
            hashInt(&hash, u32, descriptor.reserved);
        }
    }
    return hash.finalResult();
}

fn hashUse(
    hash: *std.crypto.hash.sha2.Sha256,
    use: relation_abi.UseDescriptor,
) void {
    inline for (std.meta.fields(relation_abi.UseDescriptor)) |field|
        hashInt(hash, u32, @field(use, field.name));
}

fn hashInt(
    hash: *std.crypto.hash.sha2.Sha256,
    comptime T: type,
    value: T,
) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}

pub fn inverseRows(rows: u32) u32 {
    std.debug.assert(rows != 0 and std.math.isPowerOfTwo(rows));
    const log_rows = std.math.log2_int(u32, rows);
    return if (log_rows == 0)
        1
    else
        @as(u32, 1) << @intCast(31 - log_rows);
}

pub fn blocks(values: u32, block_size: u32) u32 {
    return values / block_size + @intFromBool(values % block_size != 0);
}

pub fn checkedAddU32(left: anytype, right: anytype) !u32 {
    const lhs = std.math.cast(u32, left) orelse return Error.GeometryOverflow;
    const rhs = std.math.cast(u32, right) orelse return Error.GeometryOverflow;
    return std.math.add(u32, lhs, rhs) catch Error.GeometryOverflow;
}

pub fn checkedMulU32(left: anytype, right: anytype) !u32 {
    const lhs = std.math.cast(u32, left) orelse return Error.GeometryOverflow;
    const rhs = std.math.cast(u32, right) orelse return Error.GeometryOverflow;
    return std.math.mul(u32, lhs, rhs) catch Error.GeometryOverflow;
}

pub fn checkedMulUsize(left: anytype, right: anytype) !usize {
    const lhs = std.math.cast(usize, left) orelse
        return Error.GeometryOverflow;
    const rhs = std.math.cast(usize, right) orelse
        return Error.GeometryOverflow;
    return std.math.mul(usize, lhs, rhs) catch Error.GeometryOverflow;
}

pub fn checkedAddU64(left: anytype, right: anytype) !u64 {
    const lhs = std.math.cast(u64, left) orelse return Error.GeometryOverflow;
    const rhs = std.math.cast(u64, right) orelse return Error.GeometryOverflow;
    return std.math.add(u64, lhs, rhs) catch Error.GeometryOverflow;
}

pub fn checkedMulU64(left: anytype, right: anytype) !u64 {
    const lhs = std.math.cast(u64, left) orelse return Error.GeometryOverflow;
    const rhs = std.math.cast(u64, right) orelse return Error.GeometryOverflow;
    return std.math.mul(u64, lhs, rhs) catch Error.GeometryOverflow;
}
