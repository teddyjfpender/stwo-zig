//! Real small ELF and callers through the complete block-v5 collection pass.
const std = @import("std");
const Collect = @import("prover/block_v5_cpu_collect_impl_v1.zig");
const Source = @import("prover/block_v4_cpu_runner_source.zig");
const Profile = @import("recursion/blake3_execution_parent_protocol.zig").Profile;
const profile = @import("isa/execution_profile.zig").ExecutionProfile.rv32im_zkvm_ethereum_sha_v1;
const fixture = @import("runner/guest_precompile/test_elf.zig");
const preflight = @import("prover/blake3_execution_preflight.zig");

test "block-v5 complete first-pass collection profile q8" {
    const a = std.testing.allocator;
    const selected = Profile.diagnostic_q8_pow0;
    const distinct = std.process.hasEnvVarConstant("STWO_BLOCK_PROFILE_DISTINCT_STORES");
    const small = std.process.hasEnvVarConstant("STWO_BLOCK_PROFILE_4K_STORES");
    const quarter_million = std.process.hasEnvVarConstant("STWO_BLOCK_PROFILE_256K_STORES");
    const large = std.process.hasEnvVarConstant("STWO_BLOCK_PROFILE_64K_STORES");
    const requested_stores: u64 = if (quarter_million) 262_144 else if (large) 65_536 else if (small) 4_096 else 16_384;
    const prefix = [_]u32{
        0x001002b7,                                            0x10028293,                                  0x08028313,
        @import("isa/sha256_compression_v1.zig").encode(5, 6), @import("isa/custom0.zig").encodeKeccakf(5), @import("isa/sha256_compression_v1.zig").encode(5, 6),
        0x00100137, // Place the store base in writable RAM before the repeated stores.
    };
    const suffix = [_]u32{
        0x00100137, 0x00100193, 0x00312223,
        0x00312423, 0x00312023, 0x0000006f,
    };
    // A finite loop keeps the ELF small while producing real sorted-RAM events.
    const loop = [_]u32{
        0x000043b7, // LUI x7, 4: 16,384 iterations.
        0x00312223, // SW x3, 4(x2).
        0x00000013, // NOP for repeated-address arm; ADDI x2, x2, 4 for distinct arm.
        0xfff38393, // ADDI x7, x7, -1.
        0xfe039ae3, // BNE x7, x0, -12.
    };
    var instructions = prefix ++ loop ++ suffix;
    if (quarter_million) {
        instructions[prefix.len] = 0x000403b7; // LUI x7, 64: 262,144 iterations.
    } else if (large) {
        instructions[prefix.len] = 0x000103b7; // LUI x7, 16: 65,536 iterations.
    } else if (small) {
        instructions[prefix.len] = 0x000013b7; // LUI x7, 1: 4,096 iterations.
    }
    if (distinct) instructions[prefix.len + 2] = 0x00410113;
    const elf = fixture.buildReleaseProgram(instructions.len, &instructions, 256, profile);
    const oracle = [_]u8{1};
    const config = selected.config();
    const planned = try preflight.runEthereumForProfile(profile, a, &elf, &.{}, &oracle, 2048);
    const schedule = try @import("runner/balanced_schedule.zig").Schedule.initExactWithTerminalSuffix(planned.last.cycle, 2048, planned.required_terminal_cycles);
    const job = try @import("recursion/blake3_block_execution_span_v3.zig").initJobFromEndpoints(config, planned.first, planned.last, schedule.segments, planned.first.machine.rw_memory);
    const pins = Source.Pins{ .elf_sha256 = Source.sha256(&elf), .input_sha256 = Source.sha256(&.{}), .oracle_sha256 = Source.sha256(&oracle), .initial_rw_root = planned.first.machine.rw_memory, .program_root = planned.first.program, .expected_job = job };
    var source = try Source.Source.initFromPlan(a, &elf, &.{}, &oracle, 2048, config, pins, planned);
    defer source.deinit();
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    var options = @import("prover/block_v5_cpu_product_options_v1.zig").options(selected, @intCast(schedule.segments), 2);
    options.collection.globals.maximum_memory_log = 16;
    const collected = try Collect.ForCapacity(false).collect(a, temporary.dir, &source, .{ .runner_pins = pins, .job_id = @splat(91), .expected_final_rw_root = planned.last.machine.rw_memory.bytes }, config, options.collection);
    defer collected.deinit();
    try std.testing.expect(source.first_complete and !source.second_complete);
    try std.testing.expectEqual(schedule.segments, collected.planning.records.items.len);
    try std.testing.expect(collected.replay.spooler.event_count > requested_stores);
    try std.testing.expect(collected.globals.memory.instanceCount() > 0);
    var first_touches = try collected.replay.firstTouches();
    defer first_touches.deinit();
    var first_touch_count: u64 = 0;
    while (try first_touches.next()) |_| first_touch_count += 1;
    std.debug.print("BLOCK_V5_PROFILE_DISTINCT stores={d} distinct={any} first_touches={d}\n", .{ requested_stores, distinct, first_touch_count });
}
