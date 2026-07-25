//! One-time upload of the exact Blake interaction pointer graph.

const std = @import("std");
const completion_bindings = @import("completion_bindings.zig");
const completion_plan = @import("completion_plan.zig");
const facades = @import("facades.zig");
const interaction_plan = @import("interaction_plan.zig");
const slots = @import("slots.zig");

const pointer_words = @sizeOf(usize) / @sizeOf(u32);

pub fn upload(
    transaction: anytype,
    invocation: facades.Invocation,
) !void {
    try validateInvocation(invocation);
    const bound = try completion_bindings.bind(
        transaction,
        invocation.geometry,
        invocation.views,
    );
    const instances = try bound.instances();
    const output_coordinates = try pointerTable(
        &bound.output_coordinates,
    );
    var output_tables: [instances.len]usize = undefined;
    var denominators: [instances.len]usize = undefined;
    var claims: [instances.len]usize = undefined;
    for (instances, 0..) |instance, index| {
        output_tables[index] = instance.output_pointer_table.address;
        denominators[index] = instance.denominator_slab.address;
        claims[index] = instance.claimed_sum.address;
    }
    const output_table_pointers = try addressTable(&output_tables);
    const denominator_pointers = try addressTable(&denominators);
    const claim_pointers = try addressTable(&claims);
    const interaction = try interaction_plan.Plan.init(
        invocation.geometry,
        invocation.views,
    );
    const completion = try completion_plan.Plan.init(interaction);

    try transaction.upload(
        u32,
        slots.interaction_output_pointer_table,
        &output_coordinates,
    );
    try transaction.upload(
        u32,
        slots.interaction_output_tables,
        &output_table_pointers,
    );
    try transaction.upload(
        u32,
        slots.interaction_denominator_tables,
        &denominator_pointers,
    );
    try transaction.upload(
        u32,
        slots.interaction_claim_tables,
        &claim_pointers,
    );
    try transaction.upload(
        @import(
            "../../../../backends/cuda/abi/stages/relation.zig",
        ).Geometry,
        slots.interaction_geometry,
        &completion.geometry,
    );
}

fn validateInvocation(invocation: facades.Invocation) !void {
    if (invocation.interaction_slot != slots.interaction_evaluations or
        invocation.interaction_denominators_slot !=
            slots.interaction_denominators or
        invocation.interaction_batch_prefix_slot !=
            slots.interaction_batch_prefix or
        invocation.statement1_claims_slot != slots.statement1_claims)
    {
        return error.InvalidKernelDescriptor;
    }
    try invocation.views.validate(invocation.geometry);
}

fn pointerTable(values: anytype) ![
    values.len * pointer_words
]u32 {
    var addresses: [values.len]usize = undefined;
    for (values, 0..) |value, index| addresses[index] = value.address;
    return addressTable(&addresses);
}

fn addressTable(addresses: anytype) ![
    addresses.len * pointer_words
]u32 {
    var result: [addresses.len * pointer_words]u32 = undefined;
    for (addresses, 0..) |address, index| {
        const encoded = try pointerWords(address);
        result[index * pointer_words ..][0..pointer_words].* = encoded;
    }
    return result;
}

fn pointerWords(address: usize) ![pointer_words]u32 {
    comptime std.debug.assert(@sizeOf(usize) == @sizeOf(u64));
    var bytes: [@sizeOf(u64)]u8 = undefined;
    std.mem.writeInt(u64, &bytes, @intCast(address), .little);
    var result: [pointer_words]u32 = undefined;
    inline for (0..pointer_words) |index| {
        const first = index * @sizeOf(u32);
        result[index] = std.mem.readInt(
            u32,
            bytes[first..][0..@sizeOf(u32)],
            .little,
        );
    }
    return result;
}

test "exact interaction pointer encoding retains 64-bit addresses" {
    const encoded = try addressTable(
        &[_]usize{ 0x1122_3344_5566_7788, 0x8877_6655_4433_2211 },
    );
    try std.testing.expectEqualSlices(
        u32,
        &.{ 0x5566_7788, 0x1122_3344, 0x4433_2211, 0x8877_6655 },
        &encoded,
    );
}
