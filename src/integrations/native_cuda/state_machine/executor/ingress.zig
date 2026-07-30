//! Canonical ingress for the exact State Machine v2 relation graph.

const std = @import("std");
const field = @import("stwo_cuda_backend").abi.field;
const relation_abi = @import("stwo_cuda_backend").abi.stages.relation;
const canonical = @import("../canonical_ingress.zig");
const plan_mod = @import("../plan.zig");
const relation_mod = @import("../relation.zig");
const slots = @import("../slots.zig");
const shared = @import("../../common/native_ingress.zig").ExecutorFor(
    @import("../geometry.zig"),
    plan_mod,
    canonical,
    slots,
);

pub fn run(
    transaction: anytype,
    prepared: *const plan_mod.PreparedPlan,
    pack: *const canonical.Pack,
    views: anytype,
) !void {
    try shared.run(transaction, prepared, pack, &views.base);
    try transaction.upload(
        u32,
        slots.empty_preprocessed_root,
        &pack.empty_preprocessed_root,
    );
    try transaction.upload(
        u32,
        slots.transcript_statement_words,
        &pack.transcript_statement_words,
    );
    try transaction.upload(
        u32,
        slots.constraint_denominator_inverses,
        &pack.circle.composition_denominator_inverses,
    );
    try uploadRelationGraph(transaction, prepared, views);
}

fn uploadRelationGraph(
    transaction: anytype,
    prepared: *const plan_mod.PreparedPlan,
    views: anytype,
) !void {
    const relation = &views.relation;
    const plan = try relation_mod.Plan.init(
        prepared.logical.geometry.statement.log_n_rows,
    );
    var source_table: [
        relation_mod.instance_count *
            relation_mod.source_pointer_count * 2
    ]u32 = undefined;
    var output_table: [
        relation_mod.instance_count *
            relation_mod.output_coordinates_per_instance * 2
    ]u32 = undefined;
    var source_tables: [relation_mod.instance_count * 2]u32 =
        undefined;
    var descriptor_tables: [relation_mod.instance_count * 2]u32 =
        undefined;
    var output_tables: [relation_mod.instance_count * 2]u32 =
        undefined;
    var denominator_tables: [relation_mod.instance_count * 2]u32 =
        undefined;
    var claimed_sum_tables: [relation_mod.instance_count * 2]u32 =
        undefined;
    for (&relation.instances, 0..) |*instance, index| {
        try encodePointerTable(
            source_table[index * relation_mod.source_pointer_count * 2 ..][0 .. relation_mod.source_pointer_count * 2],
            &instance.source_columns,
        );
        try encodePointerTable(
            output_table[index * relation_mod.output_coordinates_per_instance * 2 ..][0 .. relation_mod.output_coordinates_per_instance * 2],
            &instance.output_coordinates,
        );
        try encodeAddress(
            source_tables[index * 2 ..][0..2],
            instance.source_pointer_table.address,
        );
        try encodeAddress(
            descriptor_tables[index * 2 ..][0..2],
            instance.descriptor_storage.address,
        );
        try encodeAddress(
            output_tables[index * 2 ..][0..2],
            instance.output_pointer_table.address,
        );
        try encodeAddress(
            denominator_tables[index * 2 ..][0..2],
            instance.denominator_slab.address,
        );
        try encodeAddress(
            claimed_sum_tables[index * 2 ..][0..2],
            instance.claimed_sum.address,
        );
    }
    const descriptors = [_]relation_abi.ColumnDescriptor{
        relation_mod.x_descriptors[0],
        relation_mod.y_descriptors[0],
    };

    try transaction.upload(
        u32,
        slots.relation_source_pointer_table,
        &source_table,
    );
    try transaction.upload(
        relation_abi.ColumnDescriptor,
        slots.relation_descriptors,
        &descriptors,
    );
    try transaction.upload(
        u32,
        slots.relation_output_pointer_table,
        &output_table,
    );
    try transaction.upload(
        relation_abi.Geometry,
        slots.relation_geometry,
        &plan.geometry,
    );
    try transaction.upload(
        u32,
        slots.relation_source_tables,
        &source_tables,
    );
    try transaction.upload(
        u32,
        slots.relation_descriptor_tables,
        &descriptor_tables,
    );
    try transaction.upload(
        u32,
        slots.relation_output_tables,
        &output_tables,
    );
    try transaction.upload(
        u32,
        slots.relation_denominator_tables,
        &denominator_tables,
    );
    try transaction.upload(
        u32,
        slots.relation_claimed_sum_tables,
        &claimed_sum_tables,
    );
}

fn pointerTable(
    values: anytype,
) ![values.len * (@sizeOf(usize) / @sizeOf(u32))]u32 {
    var result: [
        values.len * (@sizeOf(usize) / @sizeOf(u32))
    ]u32 = undefined;
    try encodePointerTable(&result, values);
    return result;
}

fn encodePointerTable(
    destination: []u32,
    values: anytype,
) !void {
    if (destination.len != values.len * 2)
        return error.InvalidKernelDescriptor;
    for (values, 0..) |value, index| {
        try encodeAddress(
            destination[index * 2 ..][0..2],
            value.address,
        );
    }
}

fn encodeAddress(
    destination: []u32,
    address: usize,
) !void {
    if (destination.len != 2)
        return error.InvalidKernelDescriptor;
    const encoded = try pointerWords(address);
    @memcpy(destination, &encoded);
}

fn pointerWords(
    address: usize,
) ![@sizeOf(usize) / @sizeOf(u32)]u32 {
    comptime std.debug.assert(@sizeOf(usize) == @sizeOf(u64));
    var bytes: [@sizeOf(u64)]u8 = undefined;
    std.mem.writeInt(u64, &bytes, @intCast(address), .little);
    var result: [2]u32 = undefined;
    inline for (0..2) |index| {
        const first = index * @sizeOf(u32);
        result[index] = std.mem.readInt(
            u32,
            bytes[first..][0..@sizeOf(u32)],
            .little,
        );
    }
    return result;
}

test "pointer tables retain exact 64-bit device addresses" {
    const Slice = @import("stwo_cuda_backend").runtime.column.DeviceSlice(u32);
    const values = [_]Slice{
        .{ .address = 0x1122_3344_5566_7788, .len = 1, .owner = 7 },
        .{ .address = 0x8877_6655_4433_2211, .len = 1, .owner = 7 },
    };
    const encoded = try pointerTable(&values);
    try std.testing.expectEqualSlices(
        u32,
        &.{ 0x5566_7788, 0x1122_3344, 0x4433_2211, 0x8877_6655 },
        &encoded,
    );
    _ = field.SecureField;
}
