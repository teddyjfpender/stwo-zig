//! Canonical ingress for the exact resident Plonk/LogUp pointer graph.

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
    const geometry = plan.geometry;
    const source_table = try pointerTable(&relation.source_columns);
    const output_table = try pointerTable(&relation.output_coordinates);

    try transaction.upload(
        u32,
        slots.relation_source_pointer_table,
        &source_table,
    );
    try transaction.upload(
        relation_abi.ColumnDescriptor,
        slots.relation_descriptors,
        &relation_mod.descriptors,
    );
    try transaction.upload(
        u32,
        slots.relation_output_pointer_table,
        &output_table,
    );
    try transaction.upload(
        relation_abi.Geometry,
        slots.relation_geometry,
        &geometry,
    );
    try uploadSinglePointer(
        transaction,
        slots.relation_source_tables,
        relation.source_pointer_table.address,
    );
    try uploadSinglePointer(
        transaction,
        slots.relation_descriptor_tables,
        relation.descriptor_storage.address,
    );
    try uploadSinglePointer(
        transaction,
        slots.relation_output_tables,
        relation.output_pointer_table.address,
    );
    try uploadSinglePointer(
        transaction,
        slots.relation_denominator_tables,
        relation.denominator_slab.address,
    );
    try uploadSinglePointer(
        transaction,
        slots.relation_claimed_sum_tables,
        relation.claimed_sum.address,
    );
}

fn pointerTable(values: anytype) ![
    values.len * (@sizeOf(usize) / @sizeOf(u32))
]u32 {
    var result: [
        values.len * (@sizeOf(usize) / @sizeOf(u32))
    ]u32 = undefined;
    for (values, 0..) |value, index| {
        const encoded = try pointerWords(value.address);
        const first = index * encoded.len;
        result[first..][0..encoded.len].* = encoded;
    }
    return result;
}

fn uploadSinglePointer(
    transaction: anytype,
    id: slots.SlotId,
    address: usize,
) !void {
    const encoded = try pointerWords(address);
    try transaction.upload(u32, id, &encoded);
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
