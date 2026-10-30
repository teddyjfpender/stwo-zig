const std = @import("std");
const D = @import("../block_v8_endpoint_source_descriptor_v1.zig").Descriptor;
const Shape = @import("../../air/statement.zig").Blake3ExecutionStatement;
fn shape() Shape {
    var out = std.mem.zeroes(Shape);
    out.initializeDescriptorStorage();
    out.n_components = 1;
    out.component_descs[0] = .{ .family = .load_store, .log_size = 1, .n_rows = 1, .n_columns = @intCast(@import("../../runner/trace.zig").nColumnsForFamily(.load_store)) };
    out.n_infra = 1;
    out.infra_descs[0] = .{ .kind = .clock_update, .log_size = 1, .n_rows = 1, .n_columns = @import("../../air/clock_update_interaction.zig").N_MAIN_COLUMNS };
    out.total_steps = 1;
    out.public_data.clock = 1;
    out.public_data.program_root = .{ .bytes = @splat(1) };
    out.public_data.completion = @import("../../air/public_data.zig").Completion.canonicalSelfLoop(0);
    out.public_data.io_entries.input_words = &.{};
    out.public_data.io_entries.output_words = &.{};
    return out;
}
test "endpoint descriptor binds complete layout frame policy counts and all first roots" {
    const a = std.testing.allocator;
    var s = shape();
    const frame = @import("../../air/block/memory_event.zig").Frame{ .clock_frame = .leaf_local, .global_first_cycle = 1, .cycle_count = 1 };
    const policy = @import("../block_v8_ram_endpoint_kernel_v1.zig").Policy{ .source_ordinal = 0, .max_local_clock = 3 };
    const roots = [4][32]u8{ @splat(2), @splat(3), @splat(4), @splat(5) };
    const expected = try D.derive(a, &s, .rv32im_zkvm_ethereum_sha_v1, frame, policy, 1, roots);
    try expected.require(try D.derive(a, &s, .rv32im_zkvm_ethereum_sha_v1, frame, policy, 1, roots));
    try std.testing.expectEqual(@as(u32, 4), (try expected.entry()).root_count);
    var later = frame;
    later.global_first_cycle += 1;
    const moved = try D.derive(a, &s, .rv32im_zkvm_ethereum_sha_v1, later, policy, 1, roots);
    try std.testing.expectError(error.UntrustedEndpointSourceDescriptor, moved.require(expected));
    var changed = roots;
    changed[1][0] ^= 1;
    const other_main = try D.derive(a, &s, .rv32im_zkvm_ethereum_sha_v1, frame, policy, 1, changed);
    try std.testing.expect(!std.meta.eql(other_main.scope.native_identity, expected.scope.native_identity));
    changed = roots;
    changed[0][0] ^= 1;
    const other_fixed = try D.derive(a, &s, .rv32im_zkvm_ethereum_sha_v1, frame, policy, 1, changed);
    try std.testing.expect(!std.meta.eql(other_fixed.scope.native_identity, expected.scope.native_identity));
    for (2..4) |tree| {
        changed = roots;
        changed[tree][0] ^= 1;
        const other_private = try D.derive(a, &s, .rv32im_zkvm_ethereum_sha_v1, frame, policy, 1, changed);
        try std.testing.expect(!std.meta.eql(other_private.scope.native_identity, expected.scope.native_identity));
    }
    const empty = try D.derive(a, &s, .rv32im_zkvm_ethereum_sha_v1, frame, policy, 0, roots);
    try std.testing.expectError(error.UntrustedEndpointSourceDescriptor, empty.require(expected));
    try std.testing.expectError(error.InvalidEndpointSourceRoots, D.derive(a, &s, .rv32im_zkvm_ethereum_sha_v1, frame, policy, 1, @splat(@splat(0))));
    later.cycle_count = 2;
    try std.testing.expectError(error.InvalidEndpointSourceFrame, D.derive(a, &s, .rv32im_zkvm_ethereum_sha_v1, later, policy, 1, roots));
}
