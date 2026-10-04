//! Scoped dense sorted-memory regression; execution/ROM entries are placeholders.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const fixture = @import("../block_v5_caller_memory_fixture_v1.zig");
const receiver = @import("../block_v5_word_memory_receiver_v1.zig");
const seal = @import("../block_v5_source_seal_v1.zig");
const Transition = @import("../../air/block/memory_transition.zig").Transition;

test "block-v5 packed dense 103 events freshly verifies cached range fractions and bus terms" {
    const a = std.testing.allocator;
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    var events: [103]Transition = undefined;
    for (&events, 0..) |*event, index| event.* = .{
        .space = 1,
        .address = 0x2000 + 4 * @as(u32, @intCast(index)),
        .clock = (@as(u64, 1) << 48) + index + 1,
        .before = 0,
        .after = 0x12345678 + @as(u32, @intCast(index)),
    };
    var memory = try fixture.Fixture.init(a, &events, @splat(0), @splat(0), @import("block_v5_initial_source_test.zig").layout, config);
    defer memory.deinit();
    // Log8 has 256 rows * 25 logical rational terms. Range denominators now
    // come from the shared sealed cache; only eight bus terms need per-row
    // inversion. Previously an inferred u11 chunk count wrapped 6400 to 256,
    // leaving the second after-value limb at row7 uninverted.
    try std.testing.expectEqual(@as(u32, 8), memory.first.claims[0].log_size);
    var counts: [seal.family_count]u32 = @splat(0);
    inline for ([_]seal.Family{ .program, .execution, .execution_sidecar, .program_request, .memory, .memory_range }) |family| counts[@intFromEnum(family) - 1] = 1;
    const pins = seal.Pins{
        .job_id = @splat(1),
        .source_image_digest = @splat(2),
        .native_template_id = @splat(3),
        .program_root = @splat(4),
        .program_plan_digest = @splat(5),
        .memory_plan_digest = memory.first.plan_digest,
        .initial_source_plan_digest = try memory.endpoint_pins.initial.digest(),
        .expected_final_rw_root = memory.endpoint_pins.expected_final_rw_root,
        .rw_endpoint_plan_digest = try memory.endpoint_pins.digest(),
        .register_endpoint_plan_digest = try memory.register_pins.digest(),
        .config = config,
        .counts = counts,
    };
    const entries = [_]seal.Entry{
        .{ .family = .program, .index = 0, .instance_id = @splat(6), .roots = .{ @splat(7), @splat(8) } },
        .{ .family = .execution, .index = 0, .instance_id = @splat(9), .roots = .{ @splat(10), @splat(11) } },
        .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(12), .roots = .{ @splat(13), @splat(14) } },
        .{ .family = .program_request, .index = 0, .instance_id = @splat(15), .roots = .{ @splat(16), @splat(17) } },
        memory.first.memoryEntry(0),
        memory.first.rangeEntry(0),
    };
    const sealed = try seal.seal(pins, &entries);
    var capture = fixture.Capture{};
    defer capture.deinit(a);
    try memory.prove(&capture, pins, &entries, sealed);
    var wrong = memory.pins(pins, &entries, sealed);
    wrong.source.expected_final_rw_root[0] ^= 1;
    try std.testing.expectError(error.UntrustedV5EndpointPlan, receiver.verify(Cpu, a, wrong, &.{}, memory.files(), capture.loader(), sealed));
    try std.testing.expect(capture.sorted != null and capture.range != null);
    const fresh = try receiver.verify(Cpu, a, memory.pins(pins, &entries, sealed), &.{}, memory.files(), capture.loader(), sealed);
    try std.testing.expectEqual(@as(u64, 103), fresh.event_count);
    try std.testing.expectEqual(@as(u64, 103), fresh.first_touch_count);
    try std.testing.expectEqual(@as(u64, 103), fresh.endpoint_count);
    // Ten current limbs per row, plus three key-gap limbs on
    // every row after the first. No clocks or words are narrowed.
    try std.testing.expectEqual(@as(u64, 1336), fresh.range_count);
    try std.testing.expectEqual(@as(u32, 1), fresh.memory_instances);
    try std.testing.expectEqual(@as(u32, 1), fresh.range_shards);
    try std.testing.expect(fresh.register_endpoints_verified);
    try std.testing.expectEqual(@as(u64, 0), fresh.register_endpoint_count);
    try std.testing.expectEqualSlices(u8, &memory.endpoint_pins.expected_final_rw_root, &fresh.final_rw_root);
    try std.testing.expect(!fresh.transition_sum.isZero());
    try std.testing.expect(capture.sorted == null and capture.range == null);
}
