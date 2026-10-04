//! Real two-pass root/admission parity without producing new STARK proofs.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const driver = @import("../block_v5_cpu_driver_admission_v1.zig");
const physical = @import("../block_v5_cpu_native_root_proposal_v1.zig");
const native = @import("../blake3_execution_trace.zig");
const NativeV3 = @import("../block_v5_native_execution_proof_v3.zig");
const public = @import("../blake3_segment_public.zig");
const source_mod = @import("../block_v4_cpu_runner_source.zig");
const rom_mod = @import("../../air/program/blake3_commitment.zig");
const selected_profile = @import("../../isa/execution_profile.zig").ExecutionProfile.rv32im_zkvm_ethereum_sha_v1;

test "block-v5 CPU two-pass physical roots late bind real source census and match native replay" {
    const a = std.testing.allocator;
    var instructions: [20]u32 = @splat(0x00000013);
    instructions[0] = 0x00100137;
    instructions[1] = 0x00100193;
    instructions[13] = 0x00312223;
    instructions[14] = 0x00312423;
    instructions[17] = 0x00312023;
    instructions[18] = 0x0000006f;
    instructions[19] = @import("../../isa/sha256_compression_v1.zig").encode(5, 6);
    const elf = @import("../../runner/guest_precompile/test_elf.zig").buildReleaseProgram(instructions.len, &instructions, 0, selected_profile);
    const oracle = [_]u8{1};
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    const planned = try @import("../blake3_execution_preflight.zig").runEthereumForProfile(selected_profile, a, &elf, &.{}, &oracle, 6);
    const schedule = try @import("../../runner/balanced_schedule.zig").Schedule.initExactWithTerminalSuffix(planned.last.cycle, 6, planned.required_terminal_cycles);
    const job = try @import("../../recursion/blake3_block_execution_span_v3.zig").initJobFromEndpoints(config, planned.first, planned.last, schedule.segments, planned.first.machine.rw_memory);
    const source_pins = source_mod.Pins{ .elf_sha256 = hash(&elf), .input_sha256 = hash(&.{}), .oracle_sha256 = hash(&oracle), .initial_rw_root = planned.first.machine.rw_memory, .program_root = planned.first.program, .expected_job = job };
    var source = try source_mod.Source.init(a, &elf, &.{}, &oracle, 6, config, source_pins);
    defer source.deinit();
    const policy = driver.InputPolicy{ .runner_pins = source_pins, .job_id = @splat(1), .expected_final_rw_root = planned.last.machine.rw_memory.bytes };
    const limits = driver.Limits{ .max_executions = 3, .max_rom_words = 1024, .max_metadata_bytes = 8 * 1024 * 1024, .max_source_bytes = 1024 * 1024, .lookup_request_limit = 1000000 };
    var changed_policy = policy;
    changed_policy.runner_pins.oracle_sha256[0] ^= 1;
    try std.testing.expectError(error.UntrustedV5DriverSource, changed_policy.requireSource(&source, limits));
    changed_policy = policy;
    changed_policy.expected_final_rw_root[0] ^= 1;
    try std.testing.expectError(error.UntrustedV5DriverSource, changed_policy.requireSource(&source, limits));
    var small = limits;
    small.max_executions = 1;
    try std.testing.expectError(error.V5DriverSourceResourceLimit, policy.requireSource(&source, small));
    var planning: ?driver.Planning = null;
    defer if (planning) |*owned| owned.deinit();
    {
        var reader = try source.openPass(.first);
        defer reader.deinit();
        while (try reader.next()) |owned_segment| {
            var segment = owned_segment;
            defer segment.deinit();
            var io = try public.Owned.init(a, &segment.base);
            defer io.deinit();
            var rom = try rom_mod.buildDeclared(a, @as(@import("../../air/program/commitment.zig").DeclaredDecodeAuthority, .{ .profile = selected_profile }), .{segment.base.execution_trace.rows.items}, segment.base.rw_memory.program_words, @import("../commitment_program_witness.zig").completionFetch(io.data.completion));
            defer rom.deinit();
            try std.testing.expectEqualDeep(source_pins.program_root, rom.root);
            if (planning == null) planning = try driver.Planning.initFromSource(a, &source, policy, rom.leaves, config, limits);
            io.data.program_root = rom.root;
            const owner = try native.Owner.init(a, &segment.base.execution_trace, io.data, &segment.base.state_chain_tracker);
            defer owner.deinit();
            try owner.sealNativeOnly();
            var proposed = try physical.ForBackend(Cpu).collect(a, owner, config, selected_profile, segment.base.segment_index, segment.base.global_first_cycle, .{ .max_public_words = 1024, .max_metadata_bytes = 1024 * 1024 });
            var owns_proposed = true;
            defer if (owns_proposed) proposed.deinit();
            const fetches = try a.alloc(driver.Fetch, rom.rows.len);
            defer a.free(fetches);
            for (fetches, rom.rows) |*fetch, row| fetch.* = .{ .address = row.addr, .multiplicity = row.multiplicity };
            const demand = try @import("../block_v5_native_lookup_plan_v1.zig").nativeDemand(&owner.statement, 0);
            try planning.?.append(&proposed, fetches, &.{}, demand);
            owns_proposed = false;
        }
    }
    // These are deliberately only planning pins: no global provider proofs
    // or CompleteBlock authority are claimed by this roots-only fixture.
    var bound = try planning.?.bind(.{ .memory_plan_digest = @splat(2), .initial_source_plan_digest = @splat(3), .rw_endpoint_plan_digest = @splat(4), .register_endpoint_plan_digest = @splat(5) });
    defer bound.deinit();
    try std.testing.expectEqual(@as(usize, 3), bound.entries.len);
    try std.testing.expectEqual(@as(usize, 1), bound.lookup_plans.len);
    try std.testing.expect(bound.program_plan.expected_fetches > planned.last.cycle);
    try std.testing.expect(!std.mem.allEqual(u8, &(try bound.catalogAdmission().digest()), 0));
    {
        var reader = try source.openPass(.second);
        defer reader.deinit();
        while (try reader.next()) |owned_segment| {
            var segment = owned_segment;
            defer segment.deinit();
            var io = try public.Owned.init(a, &segment.base);
            defer io.deinit();
            io.data.program_root = source_pins.program_root;
            const owner = try native.Owner.init(a, &segment.base.execution_trace, io.data, &segment.base.state_chain_tracker);
            defer owner.deinit();
            try owner.sealNativeOnly();
            const index = segment.base.segment_index;
            var first = try NativeV3.ForBackend(Cpu).commitFirstRound(a, owner, bound.admissions[index], config, selected_profile, index);
            defer first.deinit(a);
            try planning.?.records.items[index].physical.requireReplay(&first);
            try std.testing.expectEqualDeep(bound.entries[index], first.entry());
        }
    }
    try std.testing.expect(source.second_complete);
    std.debug.print("BLOCK_V5_CPU_DRIVER_ADMISSION verified=true segments=3 passes=2 physical_roots_before_global_admission=true native_v3_replay_identical=true real_elf_rom_census=true no_stark_or_global_authority=true\n", .{});
}

fn hash(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
    return result;
}
