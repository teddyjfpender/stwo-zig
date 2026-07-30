//! Canonical host-to-device ingress for the Cairo CUDA relation graph.

const std = @import("std");
const relation_abi = @import("stwo_cuda_backend").abi.stages.relation;
const relation_stage = @import("stwo_cuda_backend").runtime.stages.relation;

const pointer_words = @sizeOf(usize) / @sizeOf(u32);

comptime {
    std.debug.assert(pointer_words == 2);
}

pub fn sourceWordExtents(instance: anytype, destination: []u32) !void {
    if (destination.len != instance.source_pointer_count)
        return error.InvalidPreparedInputShape;
    @memset(destination, instance.geometry.rows);
    if (instance.layout == .lookup_words) {
        if (destination.len != 1 or instance.lookup_word_columns == 0)
            return error.InvalidPreparedInputShape;
        destination[0] = try checkedMulU32(
            instance.geometry.rows,
            instance.lookup_word_columns,
        );
    }
}

pub fn uploadCanonical(
    allocator: std.mem.Allocator,
    uploader: anytype,
    plan: anytype,
    buffers: relation_stage.DeviceBuffers,
    device: anytype,
) !void {
    const instance_count = std.math.cast(u32, plan.instances.len) orelse
        return error.GeometryOverflow;
    const top_words = try checkedMulUsize(instance_count, pointer_words);
    const top_storage = try allocator.alloc(
        u32,
        try checkedMulUsize(top_words, 5),
    );
    defer allocator.free(top_storage);
    const source_top = top_storage[0..top_words];
    const descriptor_top = top_storage[top_words .. top_words * 2];
    const output_top = top_storage[top_words * 2 .. top_words * 3];
    const denominator_top = top_storage[top_words * 3 .. top_words * 4];
    const claimed_top = top_storage[top_words * 4 .. top_words * 5];

    var nested_source_words: usize = 0;
    var nested_output_words: usize = 0;
    for (plan.instances) |instance| {
        nested_source_words = try checkedAddUsize(
            nested_source_words,
            try checkedMulUsize(instance.source_pointer_count, pointer_words),
        );
        nested_output_words = try checkedAddUsize(
            nested_output_words,
            try checkedMulUsize(
                try checkedMulU32(instance.geometry.columns, 4),
                pointer_words,
            ),
        );
    }
    const nested_source = try allocator.alloc(u32, nested_source_words);
    defer allocator.free(nested_source);
    const nested_output = try allocator.alloc(u32, nested_output_words);
    defer allocator.free(nested_output);

    var source_cursor: usize = 0;
    var output_cursor: usize = 0;
    for (plan.instances, device, 0..) |instance, resident, index| {
        const source_end = try checkedAddUsize(
            source_cursor,
            try checkedMulUsize(instance.source_pointer_count, pointer_words),
        );
        const source_words = nested_source[source_cursor..source_end];
        try encodePointerTable(source_words, resident.source_columns);
        try uploader.uploadSlice(
            u32,
            resident.source_pointer_table,
            source_words,
        );

        const descriptor_destination = try resident.descriptor_storage.cast(
            relation_abi.ColumnDescriptor,
        );
        try uploader.uploadSlice(
            relation_abi.ColumnDescriptor,
            descriptor_destination,
            instance.descriptors,
        );

        const output_count = try checkedMulU32(instance.geometry.columns, 4);
        const output_end = try checkedAddUsize(
            output_cursor,
            try checkedMulUsize(output_count, pointer_words),
        );
        const output_words = nested_output[output_cursor..output_end];
        try encodePointerTable(output_words, resident.output_coordinates);
        try uploader.uploadSlice(
            u32,
            resident.output_pointer_table,
            output_words,
        );

        const first = index * pointer_words;
        try encodePointer(
            source_top[first .. first + pointer_words],
            resident.source_pointer_table.address,
        );
        try encodePointer(
            descriptor_top[first .. first + pointer_words],
            resident.descriptor_storage.address,
        );
        try encodePointer(
            output_top[first .. first + pointer_words],
            resident.output_pointer_table.address,
        );
        try encodePointer(
            denominator_top[first .. first + pointer_words],
            resident.denominator_slab.address,
        );
        try encodePointer(
            claimed_top[first .. first + pointer_words],
            resident.claimed_sum.address,
        );
        source_cursor = source_end;
        output_cursor = output_end;
    }
    std.debug.assert(source_cursor == nested_source.len);
    std.debug.assert(output_cursor == nested_output.len);

    try uploader.uploadSlice(u32, buffers.source_tables, source_top);
    try uploader.uploadSlice(u32, buffers.descriptors, descriptor_top);
    try uploader.uploadSlice(u32, buffers.output_tables, output_top);
    try uploader.uploadSlice(u32, buffers.denominator_slabs, denominator_top);
    try uploader.uploadSlice(u32, buffers.claimed_sums, claimed_top);
    try uploader.uploadSlice(
        relation_abi.Geometry,
        buffers.geometry,
        plan.geometry,
    );
}

fn encodePointerTable(destination: []u32, slices: anytype) !void {
    if (destination.len != try checkedMulUsize(slices.len, pointer_words))
        return error.InvalidPreparedInputShape;
    for (slices, 0..) |slice, index| {
        const first = index * pointer_words;
        try encodePointer(
            destination[first .. first + pointer_words],
            slice.address,
        );
    }
}

fn encodePointer(destination: []u32, address: usize) !void {
    if (destination.len != pointer_words or address == 0)
        return error.InvalidPreparedInputShape;
    destination[0] = @truncate(address);
    destination[1] = @truncate(address >> 32);
}

fn checkedAddUsize(left: anytype, right: anytype) !usize {
    const lhs = std.math.cast(usize, left) orelse
        return error.GeometryOverflow;
    const rhs = std.math.cast(usize, right) orelse
        return error.GeometryOverflow;
    return std.math.add(usize, lhs, rhs) catch error.GeometryOverflow;
}

fn checkedMulU32(left: anytype, right: anytype) !u32 {
    const lhs = std.math.cast(u32, left) orelse
        return error.GeometryOverflow;
    const rhs = std.math.cast(u32, right) orelse
        return error.GeometryOverflow;
    return std.math.mul(u32, lhs, rhs) catch error.GeometryOverflow;
}

fn checkedMulUsize(left: anytype, right: anytype) !usize {
    const lhs = std.math.cast(usize, left) orelse
        return error.GeometryOverflow;
    const rhs = std.math.cast(usize, right) orelse
        return error.GeometryOverflow;
    return std.math.mul(usize, lhs, rhs) catch error.GeometryOverflow;
}
