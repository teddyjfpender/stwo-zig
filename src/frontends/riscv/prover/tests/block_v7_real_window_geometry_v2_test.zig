const std = @import("std");
const C = @import("../block_v7_real_window_capture_v1.zig");
const Window = @import("../block_v7_real_window_policy_v2.zig");
const Base = @import("../block_v6_partitioned_native_components_v1.zig");
const Layout = @import("../block_v7_native_relation_layout_v1.zig");
const Fused = @import("../block_v5_native_projection_fused_proof_v2.zig");
test "actual retained native window reports independently derived composition geometry" {
    const path = std.posix.getenv("STWO_REAL_WINDOW_V2_ELF") orelse return error.SkipZigTest;
    const a = std.testing.allocator;
    const elf = try std.fs.cwd().readFileAlloc(a, path, 32 << 20);
    defer a.free(elf);
    var expected: C.Digest = undefined;
    _ = try std.fmt.hexToBytes(&expected, "ef68fdca9e627a4969e64aa97119f52f2d9c9d6b6e8d5cbbeb541fb93dab0688");
    try std.testing.expectEqualDeep(expected, C.sha(elf));
    const bytes = try std.fs.cwd().readFileAlloc(a, std.posix.getenv("STWO_REAL_WINDOW_V2_INCOMING") orelse return error.MissingSnapshot, 64 << 20);
    defer a.free(bytes);
    var incoming_pin: C.Digest = undefined;
    _ = try std.fmt.hexToBytes(&incoming_pin, std.posix.getenv("STWO_REAL_WINDOW_V2_INCOMING_SHA256") orelse return error.MissingPin);
    var incoming = try C.Snapshot.decode(a, bytes, incoming_pin, .{});
    defer incoming.deinit(a);
    var session = try @import("../../runner/mod.zig").EthereumShaExecutionSession.init(a, elf, .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local, .stop_on_halt_flag = true, .require_current_output_accesses = false });
    defer session.deinit();
    const loaded = try @import("../block_v7_initial_intervals_v1.zig").loadAddresses(a, elf, .{});
    defer a.free(loaded);
    try Window.validateSnapshot(incoming, &session.memory, loaded, session.elf_info.memory_layout, .{});
    const addresses = try a.alloc(u32, incoming.words.len);
    defer a.free(addresses);
    for (addresses, incoming.words) |*address, word| address.* = word.address;
    try session.memory.prepareAlignedWordWrites(addresses);
    for (incoming.words) |word| session.memory.writeU32AssumePrepared(word.address, word.value);
    session.cpu = incoming.cpu;
    var segment = try session.startSegment(16384);
    defer segment.deinit();
    var io = try @import("../blake3_segment_public.zig").Owned.init(a, &segment.base);
    defer io.deinit();
    io.data.program_root = .{ .bytes = @splat(1) }; // Geometry only; this is not proof authority.
    io.data.initial_rw_root = null;
    io.data.final_rw_root = null;
    io.data.io_entries.input_len = 0;
    io.data.io_entries.input_words = &.{};
    io.data.io_entries.output_len = 0;
    io.data.io_entries.output_words = &.{};
    const external = try @import("../block_v5_cpu_execution_source_v1.zig").externalCount(&segment);
    const owner = try @import("../blake3_execution_trace.zig").Owner.initWithExternal(a, &segment.base.execution_trace, io.data, &segment.base.state_chain_tracker, external);
    defer owner.deinit();
    try owner.sealNativeOnly();
    var layout = try Layout.Layout.init(a, &owner.statement, external, 1);
    defer layout.deinit();
    const base = try Base.Owner.init(a, &owner.statement, external);
    defer base.deinit();
    const split = Fused.compositionSplit(layout.slots);
    try std.testing.expectEqual(@as(u32, 3), split);
    try std.testing.expectEqual(@as(usize, 14), base.provers.len);
    var high_degree: usize = 0;
    for (layout.slots) |slot| if (slot.degree > 4) {
        high_degree += 1;
    };
    try std.testing.expectEqual(@as(usize, 2), high_degree);
    // The formerly rejected q1-to-q3 geometry must use a real polynomial
    // extension on the producer and the matching verifier degree bound.
    const Relocate = @import("../block_v6_joint_components_v1.zig");
    for (base.provers, base.verifiers) |prover, verifier| {
        const p = try Relocate.Relocated(true).init(prover, true, true, split);
        const v = try Relocate.Relocated(false).init(verifier, true, true, split);
        try std.testing.expectEqual(prover.intrinsicMaxConstraintLogDegreeBound() + 2, p.inner.maxConstraintLogDegreeBound());
        try std.testing.expectEqual(p.inner.maxConstraintLogDegreeBound(), v.inner.maxConstraintLogDegreeBound());
        try std.testing.expectEqual(split, p.compositionLogSplit());
    }
    std.debug.print("REAL_WINDOW_GEOMETRY target_split={d} native_components={d}\n", .{ split, base.provers.len });
    for (base.provers, 0..) |component, i| {
        std.debug.print("REAL_WINDOW_COMPONENT index={d} split={d} intrinsic_bound={d} effective_bound={d} override={any}\n", .{ i, component.compositionLogSplit(), component.intrinsicMaxConstraintLogDegreeBound(), component.maxConstraintLogDegreeBound(), component.composition_geometry_override_v1 });
    }
    for (layout.slots, 0..) |slot, i| if (slot.degree > 4) {
        std.debug.print("REAL_WINDOW_HIGH_DEGREE slot={d} degree={d} kind={any}\n", .{ i, slot.degree, slot.kind });
    };
}
