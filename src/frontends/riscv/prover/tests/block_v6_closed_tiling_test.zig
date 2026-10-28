//! Matched mixed execution through full fresh global closure, varying only
//! segmentation. All original provider files remain necessary; no closed root.
const std = @import("std");
const Driver = @import("../block_v6_cpu_native_batch_driver_v1.zig");
const Receive = @import("../block_v6_cpu_native_batch_receive_v1.zig");
const Source = @import("../block_v4_cpu_runner_source.zig");
const Guest = @import("block_v6_mixed_guest_test_support.zig");
const Profile = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile;
const Global = @import("../block_v5_global_receiver_v1.zig");

test "block-v6 closed mixed tiling complete bundles" {
    // One compiled test executable supports every workload size and both
    // explicitly reported security profiles without another LLVM build.
    try run(if (std.process.hasEnvVarConstant("STWO_CLOSED_TILE_CANONICAL")) .csp_q70_pow26 else .diagnostic_q8_pow0);
}

fn run(selected: Profile) !void {
    const a = std.testing.allocator;
    const iterations = if (std.posix.getenv("STWO_CLOSED_TILE_ITERATIONS")) |value| try std.fmt.parseInt(u32, value, 10) else 4096;
    if (iterations > 1 << 20) return error.InvalidClosedTileIterations;
    const code = try Guest.instructions(iterations);
    const elf = @import("../../runner/guest_precompile/test_elf.zig").buildReleaseProgram(code.len, &code, 256, Guest.profile);
    const oracle = [_]u8{1};
    var timer = try std.time.Timer.start();
    const planned = try @import("../blake3_execution_preflight.zig").runEthereumForProfile(Guest.profile, a, &elf, &.{}, &oracle, 3 * iterations);
    const preflight_ns = timer.read();
    const counts = [_]u32{ 1, 4, 8 };
    const count: usize = if (std.process.hasEnvVarConstant("STWO_CLOSED_TILE_EIGHT")) 3 else 2;
    var expected: ?Global.VerifiedGlobals = null;
    for (counts[0..count]) |segments| {
        const limit = std.math.cast(u32, try std.math.divCeil(u64, planned.last.cycle, segments)) orelse return error.InvalidClosedTileIterations;
        const schedule = try @import("../../runner/balanced_schedule.zig").Schedule.initExactWithTerminalSuffix(planned.last.cycle, limit, planned.required_terminal_cycles);
        try std.testing.expectEqual(segments, schedule.segments);
        const job = try @import("../../recursion/blake3_block_execution_span_v3.zig").initJobFromEndpoints(selected.config(), planned.first, planned.last, segments, planned.first.machine.rw_memory);
        const pins = Source.Pins{ .elf_sha256 = Source.sha256(&elf), .input_sha256 = Source.sha256(&.{}), .oracle_sha256 = Source.sha256(&oracle), .initial_rw_root = planned.first.machine.rw_memory, .program_root = planned.first.program, .expected_job = job };
        _ = timer.lap();
        var source = try Source.Source.initFromPlan(a, &elf, &.{}, &oracle, limit, selected.config(), pins, planned);
        defer source.deinit();
        const source_ns = timer.lap();
        var temporary = std.testing.tmpDir(.{});
        defer temporary.cleanup();
        var options = @import("../block_v5_cpu_product_options_v1.zig").options(selected, segments, 8);
        options.collection.globals.maximum_memory_log = 20;
        const policy = @import("../block_v5_cpu_driver_admission_v1.zig").InputPolicy{ .runner_pins = pins, .job_id = @splat(113), .expected_final_rw_root = planned.last.machine.rw_memory.bytes };
        std.debug.print("BLOCK_V6_CLOSED_TILE_BEGIN profile={s} iterations={d} cycles={d} segments={d} preflight_ns={d} source_ns={d} budget_bytes={d}\n", .{ @tagName(selected), iterations, planned.last.cycle, segments, preflight_ns, source_ns, options.total_host_limit });
        _ = timer.lap();
        const result = try Driver.run(a, temporary.dir, &source, policy, options);
        const wall_ns = timer.lap();
        const actual = result.verified.globals;
        try std.testing.expectEqual(segments, actual.execution_count);
        try std.testing.expectEqualDeep(planned.first.machine.rw_memory.bytes, actual.initial_rw_root);
        try std.testing.expectEqualDeep(planned.last.machine.rw_memory.bytes, actual.final_rw_root);
        try std.testing.expectEqual(planned.last.cycle, actual.span.last_cycle);
        try std.testing.expectEqual(@as(u64, 1), actual.span.first_cycle);
        try std.testing.expectEqual(@as(u32, 0), actual.span.first_index);
        try std.testing.expectEqual(segments, actual.span.segment_count);
        try std.testing.expectEqual(segments, actual.span.job_segment_count);
        try std.testing.expectEqual(.pending, actual.exact_recursive_forest);
        // Every nonterminal cut proves an additional unretired ROM fetch;
        // Boundary.deriveFromPinnedNativePublic supplies that exact term.
        try std.testing.expectEqual(planned.last.cycle + segments - 1, actual.program_fetches);
        if (expected) |old| {
            try std.testing.expectEqualDeep(old.initial_rw_root, actual.initial_rw_root);
            try std.testing.expectEqualDeep(old.final_rw_root, actual.final_rw_root);
            try std.testing.expectEqual(old.span.initial_pc, actual.span.initial_pc);
            try std.testing.expectEqual(old.span.final_pc, actual.span.final_pc);
            try std.testing.expectEqual(old.span.last_cycle, actual.span.last_cycle);
            try std.testing.expectEqual(old.memory_events, actual.memory_events);
            try std.testing.expectEqual(old.byte_requests, actual.byte_requests);
        } else expected = actual;
        const limits = Receive.Limits{ .metadata = options.metadata, .store = options.store, .max_proof_bytes = options.forest.max_proof_bytes };
        _ = timer.lap();
        const detached = try Receive.verify(a, temporary.dir, &.{}, result.pins, limits);
        const detached_ns = timer.lap();
        try std.testing.expectEqualDeep(result.verified, detached);
        var wrong = result.pins;
        wrong.identity.final_rw_root[0] ^= 1;
        try std.testing.expectError(error.UntrustedV5ReceiverPolicyIdentity, Receive.verify(a, temporary.dir, &.{}, wrong, limits));
        try temporary.dir.rename(Receive.PROOF_FILE, "withheld.proof");
        try std.testing.expectError(error.FileNotFound, Receive.verify(a, temporary.dir, &.{}, result.pins, limits));
        try temporary.dir.rename("withheld.proof", Receive.PROOF_FILE);
        const metadata = try Receive.Metadata.read(a, temporary.dir, result.pins.policy_sha256, result.pins.identity, options.metadata);
        defer metadata.deinit();
        const globals = metadata.globals();
        _ = try globals.validate();
        const area = try geometry(a, globals, metadata.recursion());
        std.debug.print("BLOCK_V6_CLOSED_TILE verified=true profile={s} iterations={d} cycles={d} segments={d} preflight_ns={d} source_ns={d} wall_ns={d} collection_ns={d} base_ns={d} recursive_ns={d} verification_ns={d} prepare_ns={d} setup_ns={d} prove_ns={d} encode_ns={d} detached_ns={d} charged_peak_bytes={d} base_files={d} base_file_bytes={d} batch_bytes={d} memory_ns={d} caller_ns={d} lookup_ns={d} rom_ns={d}", .{ @tagName(selected), iterations, planned.last.cycle, segments, preflight_ns, source_ns, wall_ns, result.collection_ns, result.base_ns, result.recursive_ns, result.verification_ns, result.prepare_ns, result.setup_ns, result.prove_ns, result.encode_ns, detached_ns, result.peak_bytes, result.base_files, result.base_file_bytes, result.pins.proof_bytes, result.families.family_ns[1], result.families.family_ns[0], result.families.family_ns[3], result.families.family_ns[2] });
        std.debug.print(" native_cells={d} companion_aux_cells={d} memory_cells={d} recursive_cells={d} memory_instances={d} native_components={d} memory_events={d} byte_requests={d} program_fetches={d} elf_sha256={s} initial_rw={s} final_rw={s} complete_bundle=true standalone_root=false negative_identity=rejected negative_missing_proof=rejected\n", .{ area.native, area.companion, area.memory, area.recursive, globals.memory.memory.instanceCount(), area.components, actual.memory_events, actual.byte_requests, actual.program_fetches, std.fmt.bytesToHex(pins.elf_sha256, .lower), std.fmt.bytesToHex(actual.initial_rw_root, .lower), std.fmt.bytesToHex(actual.final_rw_root, .lower) });
    }
    std.debug.print("BLOCK_V6_CLOSED_TILE_MATCHED profile={s} cycles={d} partitions={d} same_elf_input_output_endpoints=true fresh_global_closure=true standalone_root=false\n", .{ @tagName(selected), planned.last.cycle, count });
}

const Area = struct { native: u64 = 0, companion: u64 = 0, memory: u64 = 0, recursive: u64 = 0, components: usize = 0 };
fn geometry(a: std.mem.Allocator, globals: Global.Pins, recursion: Global.NativeBatchPins) !Area {
    var result = Area{};
    const Template = @import("../block_v5_native_template_protocol_v3.zig");
    const Fused = @import("../block_v5_native_projection_fused_proof_v2.zig");
    for (globals.tables.executions) |pin| {
        result.components += pin.shape.n_components + pin.shape.n_infra;
        inline for (.{ Template.ColumnTree.fixed, .main, .interaction }) |tree| {
            const logs = try Template.columnLogs(a, pin.shape, pin.template.external_retirements, tree);
            defer a.free(logs);
            for (logs) |log| result.native += @as(u64, 1) << @intCast(log);
        }
        const projections = try @import("../block_v5_native_projection_fused_source_v1.zig").slotsFromShapeForMode(a, pin.shape, pin.template.external_retirements, 1);
        defer a.free(projections);
        const slots = try @import("../block_execution_sidecar_batch_v2.zig").slotsFromStatementForMode(a, pin.shape, .{ .clock_frame = .leaf_local, .global_first_cycle = pin.admission.context.first_cycle, .cycle_count = pin.shape.public_data.clock }, 1);
        defer a.free(slots);
        const witness = try Fused.witnessLogs(a, slots);
        defer a.free(witness);
        const interactions = try Fused.interactionLogs(a, projections, slots);
        defer a.free(interactions);
        for (witness) |log| result.companion += @as(u64, 1) << @intCast(log);
        for (interactions) |log| result.companion += @as(u64, 1) << @intCast(log);
    }
    switch (globals.memory.memory) {
        .word => |word| {
            const S = @import("../block_v5_word_memory_component_v1.zig").Spec;
            for (word.claims) |claim| result.memory += (@as(u64, 1) << @intCast(claim.log_size)) * (S.FIXED_COUNT + S.MAIN_COUNT + S.INTERACTION_COUNT);
        },
        .lanes => |lanes| {
            const S = @import("../block_v5_ram_lanes_component_v1.zig").Spec;
            for (lanes.pins) |pin| result.memory += (@as(u64, 1) << @intCast(pin.claim.row_log)) * (S.FIXED_COUNT + S.MAIN_COUNT + S.INTERACTION_COUNT);
        },
    }
    inline for (@import("../../recursion/air/blake3_parent_row_storage.zig").Airs, 0..) |Air, i|
        result.recursive += (@as(u64, 1) << @intCast(recursion.key.log_sizes[i])) * (Air.PREPROCESSED_COLUMN_COUNT + Air.PHYSICAL_MAIN_COLUMN_COUNT + Air.INTERACTION_COLUMN_COUNT);
    return result;
}
