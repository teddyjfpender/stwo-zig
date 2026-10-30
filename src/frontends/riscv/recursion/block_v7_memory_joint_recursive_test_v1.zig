const std = @import("std");
const Profile = @import("block_v7_memory_joint_fixed_profile_v1.zig");
test "v7 joint memory independent profile lifecycle codegen" {
    inline for (.{ &Profile.Owned.derive, &Profile.Owned.validateAgainst, &Profile.Owned.deinit, &Profile.Owned.sampleCount, &Profile.Owned.publicCount }) |f| std.mem.doNotOptimizeAway(f);
}
test "v7 joint memory original capture and transcript codegen" {
    inline for (.{ &@import("../prover/block_v7_memory_joint_proof_v1.zig").For(@import("stwo_cpu_backend").CpuBackend).verifyAndCapture, &@import("block_v7_memory_joint_fixed_transcript_v1.zig").derive, &@import("air/block_v7_memory_joint_transcript_v1.zig").planReplay }) |f| std.mem.doNotOptimizeAway(f);
}
test "v7 joint memory complete independent fixed roster codegen" {
    std.mem.doNotOptimizeAway(&@import("block_v7_memory_joint_fixed_roster_v1.zig").Owned.derive);
}
test "v7 joint memory dedicated live parent adapter codegen" {
    std.mem.doNotOptimizeAway(&@import("block_v7_memory_joint_preparation_v1.zig").prepare);
}
test "v7 joint memory detached parent verifier codegen" {
    std.mem.doNotOptimizeAway(&@import("block_v7_memory_joint_receiver_v1.zig").verify);
}
comptime {
    _ = @import("air/block_v7_epoch_transcript_test_v1.zig");
}

test "v7 joint profile rejects mutable scalar geometry aliases" {
    const core = @import("stwo_core");
    const a = std.testing.allocator;
    const elf = blk: {
        var bytes = @import("../runner/guest_precompile/test_elf.zig").buildReleaseProgram(1, &.{0x0000006f}, 64, .rv32im_zkvm_v1);
        const table = std.mem.readInt(u32, bytes[264..268], .little);
        // The tiny generic fixture overlaps private input with initial data;
        // select the same disjoint ABI regions as the genuine memory gate.
        for ([4]usize{ 2, 3, 7, 8 }, [4]u32{ 0x100100, 64, 0x100180, 0x100190 }) |index, value|
            std.mem.writeInt(u32, bytes[table + (index + 1) * 16 + 4 ..][0..4], value, .little);
        break :blk bytes;
    };
    var initialized = try @import("../prover/block_v7_initial_intervals_v1.zig").Owned.derive(a, &elf, @import("../prover/block_v5_initial_sources_v1.zig").sha256(&elf), .rv32im_zkvm_v1, .{});
    defer initialized.deinit();
    var image = try @import("../prover/block_v7_program_image_v1.zig").Owned.init(a, &elf, &initialized, .{});
    defer image.deinit();
    const policy = @import("../prover/block_v7_execution_policy_v1.zig").Policy{ .initialized = &initialized, .program_root = image.root.bytes, .terminal = .{ .final_cycle = 1, .halt_address = initialized.info.halt_flag, .length_address = initialized.info.output_len, .data_address = initialized.info.output_data, .output_end = initialized.info.output_end, .output = ([1]u8{0} ** 32) ++ .{1} ++ ([1]u8{0} ** 10) }, .config = @import("blake3_execution_parent_protocol.zig").Profile.diagnostic_q8_pow0.config() };
    const event = @import("../air/block/memory_transition.zig").Transition{ .space = 1, .address = initialized.info.halt_flag, .clock = 1, .before = 0, .after = 1 };
    const geometry = @import("../prover/block_v5_ram_lanes_protocol_v1.zig").Claim{ .first_event = 0, .total_events = 1, .events = 1, .row_log = 1, .first = event, .last = event, .preceding = null };
    var layout = try @import("../prover/block_v7_memory_joint_layout_v1.zig").Layout.init(a, &.{geometry}, 1, .{});
    defer layout.deinit();
    const roots = [2][32]u8{ @splat(2), @splat(3) };
    const pin = try @import("../prover/block_v7_memory_joint_protocol_v1.zig").entry(policy, &layout, roots);
    const E = @import("../prover/block_v7_execution_epoch_v1.zig");
    var counts: E.Counts = @splat(0);
    counts[@intFromEnum(E.Family.memory_joint)] = 1;
    const epoch = try E.Epoch.init(try policy.digest(), policy.config, counts, &.{pin}, 1);
    // Shape-only public proposal, never a claimed successful memory proof.
    const claim = @import("../prover/block_v7_memory_joint_air_v1.zig").RamClaim{ .geometry = geometry, .sums = @splat(core.fields.qm31.QM31.zero()) };
    const p = try Profile.Owned.derive(a, .{ .policy = policy, .epoch = epoch, .roster = &.{pin}, .roots = roots, .interval_log = 1, .claims = .{ .ram = &.{claim}, .interval = @splat(core.fields.qm31.QM31.zero()), .range16 = @splat(core.fields.qm31.QM31.zero()), .terminal = @splat(core.fields.qm31.QM31.zero()) } }, .{});
    defer p.deinit();
    p.config.pow_bits += 1;
    try std.testing.expectError(error.UntrustedJointFixedProfile, p.validate());
    p.config.pow_bits -= 1;
    inline for (.{ "max_log", "mask_log", "lifting_log", "composition_log", "split" }) |field| {
        @field(p, field) += 1;
        try std.testing.expectError(error.UntrustedJointFixedProfile, p.validate());
        @field(p, field) -= 1;
    }
    inline for (.{ "mask_log", "composition_log", "split" }) |field| {
        @field(p.shape, field) += 1;
        try std.testing.expectError(error.UntrustedJointFixedProfile, p.validate());
        @field(p.shape, field) -= 1;
    }
    try p.validate();
}
