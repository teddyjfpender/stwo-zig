//! A real ELF with initial setup, SHA/Keccak callers and terminal output.
//! No captured proof fixture, callback-only receiver or placeholder plan.
const std = @import("std");
const Driver = @import("../block_v5_cpu_driver_v1.zig");
const Source = @import("../block_v4_cpu_runner_source.zig");
const Profile = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile;
const profile = @import("../../isa/execution_profile.zig").ExecutionProfile.rv32im_zkvm_ethereum_sha_v1;
const fixture = @import("../../runner/guest_precompile/test_elf.zig");
const preflight = @import("../blake3_execution_preflight.zig");

pub fn runFixture(a: std.mem.Allocator, comptime selected: Profile) !void {
    const caller_words = [_]u32{
        @import("../../isa/sha256_compression_v1.zig").encode(5, 6),
        @import("../../isa/custom0.zig").encodeKeccakf(5),
        @import("../../isa/sha256_compression_v1.zig").encode(5, 6),
    };
    const setup_words = [_]u32{ 0x001002b7, 0x10028293, 0x08028313 };
    const prefix = if (selected == .diagnostic_q8_pow0) setup_words ++ caller_words else setup_words ++ [_]u32{0x00000013} ** 3 ++ caller_words ++ [_]u32{0x00000013} ** 3;
    const instructions = prefix ++ [_]u32{
        0x00100137, 0x00100193, 0x00312223, 0x00312423, 0x00312023, 0x0000006f,
    };
    const elf = fixture.buildReleaseProgram(instructions.len, &instructions, 256, profile);
    const oracle = [_]u8{1};
    const config = selected.config();
    const planned = try preflight.runEthereumForProfile(profile, a, &elf, &.{}, &oracle, 6);
    const schedule = try @import("../../runner/balanced_schedule.zig").Schedule.initExactWithTerminalSuffix(planned.last.cycle, 6, planned.required_terminal_cycles);
    const job = try @import("../../recursion/blake3_block_execution_span_v3.zig").initJobFromEndpoints(config, planned.first, planned.last, schedule.segments, planned.first.machine.rw_memory);
    const pins = Source.Pins{ .elf_sha256 = Source.sha256(&elf), .input_sha256 = Source.sha256(&.{}), .oracle_sha256 = Source.sha256(&oracle), .initial_rw_root = planned.first.machine.rw_memory, .program_root = planned.first.program, .expected_job = job };
    var source = try Source.Source.initFromPlan(a, &elf, &.{}, &oracle, 6, config, pins, planned);
    defer source.deinit();
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    var options = @import("../block_v5_cpu_product_options_v1.zig").options(selected, 3, 2);
    options.collection.globals.maximum_memory_log = 10;
    const result = try Driver.run(a, temporary.dir, &source, .{ .runner_pins = pins, .job_id = @splat(91), .expected_final_rw_root = planned.last.machine.rw_memory.bytes }, options);
    try std.testing.expectEqual(@as(u32, if (selected == .diagnostic_q8_pow0) 2 else 3), result.verified.execution_count);
    try std.testing.expectEqual(.verified, result.verified.exact_recursive_forest);
    try std.testing.expect(result.proof_files > 10);
    try std.testing.expect(source.first_complete and !source.second_complete);
    try std.testing.expect(result.witness_file_bytes > 0);
    std.debug.print("BLOCK_V5_CPU_COMPLETE verified=true profile={s} segments={d} memory_events={d} proof_files={d} collection_ms={d} proving_ms={d} forest_ms={d} verify_ms={d}\n", .{ @tagName(selected), result.verified.execution_count, result.verified.memory_events, result.proof_files, result.collection_ns / std.time.ns_per_ms, result.proving_ns / std.time.ns_per_ms, result.forest_ns / std.time.ns_per_ms, result.verification_ns / std.time.ns_per_ms });
}
test "block-v5 CPU assembled mixed multi-segment complete bundle q8" {
    try runFixture(std.testing.allocator, .diagnostic_q8_pow0);
}
test "block-v5 CPU assembled mixed multi-segment complete bundle canonical q70 pow26" {
    try runFixture(std.testing.allocator, .csp_q70_pow26);
}
