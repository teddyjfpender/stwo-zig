//! Production path: real pure-register ELF, two windows, independent policy,
//! staged native proofs and genuine exact recursion, detached fresh reception.
const std = @import("std");
const Driver = @import("block_v5_cpu_driver_v1.zig");
const Runner = @import("block_v4_cpu_runner_source.zig");
const Profile = @import("../recursion/blake3_execution_parent_protocol.zig").Profile;
const fixture = @import("../runner/guest_precompile/test_elf.zig");
const preflight = @import("blake3_execution_preflight.zig");
const profile = @import("../isa/execution_profile.zig").ExecutionProfile.rv32im_zkvm_ethereum_sha_v1;

test "block-v5 pure register complete detached bundle uses zero RW proofs" {
    const a = std.testing.allocator;
    // x0 is read and targeted as a destination. The real AIR must preserve
    // zero while proving x5/x6 chains across the independently pinned windows.
    const instructions = [_]u32{ 0x00700293, 0x00328313, 0x005302b3, 0x00128013, 0x00000013, 0x0000006f };
    const elf = fixture.buildReleaseProgram(instructions.len, &instructions, 64, profile);
    const config = Profile.diagnostic_q8_pow0.config();
    const planned = try preflight.runEthereumForProfile(profile, a, &elf, &.{}, &.{}, 3);
    const schedule = try @import("../runner/balanced_schedule.zig").Schedule.initExactWithTerminalSuffix(planned.last.cycle, 3, planned.required_terminal_cycles);
    const job = try @import("../recursion/blake3_block_execution_span_v3.zig").initJobFromEndpoints(config, planned.first, planned.last, schedule.segments, planned.first.machine.rw_memory);
    const pins = Runner.Pins{ .elf_sha256 = Runner.sha256(&elf), .input_sha256 = Runner.sha256(&.{}), .oracle_sha256 = Runner.sha256(&.{}), .program_root = planned.first.program, .initial_rw_root = planned.first.machine.rw_memory, .expected_job = job };
    var source = try Runner.Source.initFromPlan(a, &elf, &.{}, &.{}, 3, config, pins, planned);
    defer source.deinit();
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    var options = @import("block_v5_cpu_product_options_v1.zig").options(.diagnostic_q8_pow0, 2, 1);
    options.collection.ordinary.register_custody_mode = 1;
    options.collection.caller.register_custody_mode = 1;
    const result = try Driver.run(a, temporary.dir, &source, .{ .runner_pins = pins, .job_id = @splat(67), .expected_final_rw_root = planned.last.machine.rw_memory.bytes }, options);
    try std.testing.expectEqual(@as(u64, 0), result.verified.memory_events);
    try std.testing.expectEqual(@as(u64, 0), result.verified.byte_requests);
    try std.testing.expectEqual(@as(u32, 2), result.verified.execution_count);
    try std.testing.expectEqual(.verified, result.verified.exact_recursive_forest);
    try std.testing.expect(source.first_complete and !source.second_complete);
    try std.testing.expect(result.witness_file_bytes > 0);
    // Untouched nonzero RW leaves from the ELF remain in both full images.
    try std.testing.expectEqualSlices(u8, &planned.first.machine.rw_memory.bytes, &planned.last.machine.rw_memory.bytes);
    const Metadata = @import("block_v5_cpu_receiver_policy_file_v1.zig");
    const policy = try Metadata.read(a, temporary.dir, result.receiver_policy_sha256, .{ .job_id = @splat(67), .source_image_digest = try (@import("block_v5_cpu_driver_admission_v1.zig").InputPolicy{ .runner_pins = pins, .job_id = @splat(67), .expected_final_rw_root = planned.last.machine.rw_memory.bytes }).sourceImageDigest(), .program_root = pins.program_root.bytes, .initial_rw_root = pins.initial_rw_root.bytes, .final_rw_root = planned.last.machine.rw_memory.bytes, .config = config }, options.metadata);
    defer policy.deinit();
    try std.testing.expectEqual(@as(usize, 0), policy.globals().memory.memory.instanceCount());
    try std.testing.expectEqual(@as(usize, 0), policy.globals().memory.memory.rangeRoots().len);
    try std.testing.expectEqual(@as(u32, 1), policy.globals().tables.seal.register_custody_mode);
    try std.testing.expect(policy.globals().tables.register_windows != null);
    try @import("block_v5_register_projection_test_helper.zig").qualify(a, temporary.dir, policy.globals(), result.bundle_manifest_sha256, options.store, 0);
    var changed = policy.globals();
    switch (changed.memory.memory) {
        .word => |*pin| pin.expected_total_events = 1,
        .lanes => |*pin| pin.expected_total_events = 1,
    }
    try std.testing.expectError(error.UntrustedV5GlobalPins, changed.validate());
    changed = policy.globals();
    const wrong_windows = try a.dupe(@import("block_v5_register_windows_v1.zig").Window, changed.tables.register_windows.?.windows);
    defer a.free(wrong_windows);
    wrong_windows[0].final_clocks[5] += 1;
    changed.tables.register_windows.?.windows = wrong_windows;
    try std.testing.expectError(error.UntrustedV5RegisterWindowPlan, changed.validate());
}
