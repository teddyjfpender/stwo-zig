//! Same real register/RAM/caller guest through both complete detached bundles.
//! The forest alone remains open; all global base proofs are freshly verified.
const std = @import("std");
const Driver = @import("../block_v5_cpu_driver_v1.zig");
const Source = @import("../block_v4_cpu_runner_source.zig");
const Profile = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile;
const Metadata = @import("../block_v5_cpu_receiver_policy_file_v1.zig");
const profile = @import("../../isa/execution_profile.zig").ExecutionProfile.rv32im_zkvm_ethereum_sha_v1;

test "block-v6 register custody complete comparison diagnostic q8" {
    try compare(.diagnostic_q8_pow0);
}
test "block-v6 register custody complete comparison canonical q70 pow26" {
    try compare(.csp_q70_pow26);
}

fn compare(selected: Profile) !void {
    const a = std.testing.allocator;
    const iterations = if (std.posix.getenv("STWO_REGISTER_COMPARE_ITERATIONS")) |raw| try std.fmt.parseInt(u32, raw, 10) else 4096;
    if (iterations < 4096 or iterations > 65536 or iterations % 4096 != 0) return error.InvalidRegisterComparisonSize;
    const prefix = [_]u32{
        0x001002b7,                                                  0x10028293,                                        0x08028313,
        @import("../../isa/sha256_compression_v1.zig").encode(5, 6), @import("../../isa/custom0.zig").encodeKeccakf(5), @import("../../isa/sha256_compression_v1.zig").encode(5, 6),
        0x00100137, // x2 = writable RAM base.
        0x00000193, // x3 = 0.
    };
    var instructions = prefix ++ [_]u32{
        0x000013b7, // LUI x7, iterations / 4096.
        0x00118193, // ADDI x3, x3, 1.
        0x02312023, // SW x3, 32(x2).
        0x02012203, // LW x4, 32(x2).
        0xfff38393, // ADDI x7, x7, -1.
        0xfe0398e3, // BNE x7, x0, -16.
        0x00100137,
        0x00100193,
        0x00312223,
        0x00312423,
        0x00312023,
        0x0000006f,
    };
    instructions[prefix.len] = (iterations & 0xfffff000) | (7 << 7) | 0x37;
    const elf = @import("../../runner/guest_precompile/test_elf.zig").buildReleaseProgram(instructions.len, &instructions, 256, profile);
    const oracle = [_]u8{1};
    const config = selected.config();
    const maximum = 3 * iterations;
    var preflight_timer = try std.time.Timer.start();
    const planned = try @import("../blake3_execution_preflight.zig").runEthereumForProfile(profile, a, &elf, &.{}, &oracle, maximum);
    const preflight_ns = preflight_timer.read();
    const schedule = try @import("../../runner/balanced_schedule.zig").Schedule.initExactWithTerminalSuffix(planned.last.cycle, maximum, planned.required_terminal_cycles);
    try std.testing.expectEqual(@as(u32, 2), schedule.segments);
    const job = try @import("../../recursion/blake3_block_execution_span_v3.zig").initJobFromEndpoints(config, planned.first, planned.last, schedule.segments, planned.first.machine.rw_memory);
    const pins = Source.Pins{ .elf_sha256 = Source.sha256(&elf), .input_sha256 = Source.sha256(&.{}), .oracle_sha256 = Source.sha256(&oracle), .initial_rw_root = planned.first.machine.rw_memory, .program_root = planned.first.program, .expected_job = job };
    var events: [2]u64 = undefined;
    for (0..2) |mode| {
        var source = try Source.Source.initFromPlan(a, &elf, &.{}, &oracle, maximum, config, pins, planned);
        defer source.deinit();
        var temporary = std.testing.tmpDir(.{});
        defer temporary.cleanup();
        var options = @import("../block_v5_cpu_product_options_v1.zig").options(selected, schedule.segments, 8);
        options.collection.ordinary.register_custody_mode = @intCast(mode);
        options.collection.caller.register_custody_mode = @intCast(mode);
        options.collection.globals.maximum_memory_log = 20;
        const input = @import("../block_v5_cpu_driver_admission_v1.zig").InputPolicy{ .runner_pins = pins, .job_id = @splat(113), .expected_final_rw_root = planned.last.machine.rw_memory.bytes };
        std.debug.print("BLOCK_V6_REGISTER_BEGIN profile={s} mode={d} iterations={d} cycles={d} segments={d} preflight_ns={d}\n", .{ @tagName(selected), mode, iterations, planned.last.cycle, schedule.segments, preflight_ns });
        var timer = try std.time.Timer.start();
        const result = try Driver.run(a, temporary.dir, &source, input, options);
        const wall_ns = timer.read();
        try std.testing.expectEqual(.verified, result.verified.exact_recursive_forest);
        try std.testing.expectEqual(schedule.segments, result.verified.execution_count);
        try std.testing.expectEqualDeep(planned.first.machine.rw_memory.bytes, result.verified.initial_rw_root);
        try std.testing.expectEqualDeep(planned.last.machine.rw_memory.bytes, result.verified.final_rw_root);
        events[mode] = result.verified.memory_events;
        const identity = Metadata.Identity{ .job_id = input.job_id, .source_image_digest = try input.sourceImageDigest(), .program_root = pins.program_root.bytes, .initial_rw_root = pins.initial_rw_root.bytes, .final_rw_root = planned.last.machine.rw_memory.bytes, .config = config };
        const metadata = try Metadata.read(a, temporary.dir, result.receiver_policy_sha256, identity, options.metadata);
        defer metadata.deinit();
        const globals = metadata.globals();
        _ = try globals.validate();
        try std.testing.expectEqual(mode, globals.tables.seal.register_custody_mode);
        try std.testing.expectEqual(mode == 1, globals.tables.register_windows != null);
        var memory_cells: u64 = 0;
        switch (globals.memory.memory) {
            .word => |word| {
                const Spec = @import("../block_v5_word_memory_component_v1.zig").Spec;
                for (word.claims) |claim| memory_cells += (@as(u64, 1) << @intCast(claim.log_size)) * (Spec.FIXED_COUNT + Spec.MAIN_COUNT + Spec.INTERACTION_COUNT);
            },
            .lanes => |lanes| {
                const Spec = @import("../block_v5_ram_lanes_component_v1.zig").Spec;
                for (lanes.pins) |instance| memory_cells += (@as(u64, 1) << @intCast(instance.claim.row_log)) * (Spec.FIXED_COUNT + Spec.MAIN_COUNT + Spec.INTERACTION_COUNT);
            },
        }
        if (mode == 1) try @import("block_v6_register_custody_negative_test_support.zig").qualify(a, temporary.dir, globals, result.bundle_manifest_sha256, options.store);
        if (mode == 1 and std.process.hasEnvVarConstant("STWO_COMPLETE_NATIVE_BATCH"))
            try @import("block_v6_complete_native_batch_test_support.zig").qualify(a, temporary.dir, globals, result.bundle_manifest_sha256, options.store, &.{}, selected);
        std.debug.print("BLOCK_V6_REGISTER_COMPLETE verified=true profile={s} mode={d} iterations={d} cycles={d} segments={d} events={d} byte_requests={d} memory_instances={d} memory_cells={d} base_files={d} collection_ns={d} proving_ns={d} forest_ns={d} verification_ns={d} wall_ns={d} memory_range_ns={d} lookup_ns={d} caller_ns={d} rom_ns={d} charged_peak_bytes={d} witness_file_bytes={d} proof_file_bytes={d} initial_rw={s} final_rw={s} complete_bundle=true standalone_root=false\n", .{ @tagName(selected), mode, iterations, planned.last.cycle, result.verified.execution_count, result.verified.memory_events, result.verified.byte_requests, globals.memory.memory.instanceCount(), memory_cells, result.proof_files, result.collection_ns, result.proving_ns, result.forest_ns, result.verification_ns, wall_ns, result.family_proving_ns.memory_and_range, result.family_proving_ns.lookup, result.family_proving_ns.caller, result.family_proving_ns.rom, result.aggregate_heap_peak_bytes, result.witness_file_bytes, result.proof_file_bytes, std.fmt.bytesToHex(result.verified.initial_rw_root, .lower), std.fmt.bytesToHex(result.verified.final_rw_root, .lower) });
    }
    try std.testing.expect(events[0] > events[1]);
    try std.testing.expect(events[1] >= 2 * iterations);
    std.debug.print("BLOCK_V6_REGISTER_MATCHED profile={s} cycles={d} mode0_events={d} mode1_events={d} same_elf_input_endpoints=true complete_bundles=true\n", .{ @tagName(selected), planned.last.cycle, events[0], events[1] });
}
