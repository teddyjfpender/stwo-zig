//! Matched mixed execution through full fresh global closure, varying only
//! segmentation. All original provider files remain necessary; no closed root.
const std = @import("std");
const Driver = @import("../block_v6_cpu_native_batch_driver_v1.zig");
const Receive = @import("../block_v6_cpu_native_batch_receive_v1.zig");
const Source = @import("../block_v4_cpu_runner_source.zig");
const Guest = @import("block_v6_mixed_guest_test_support.zig");
const Profile = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile;
const Global = @import("../block_v5_global_receiver_v1.zig");
const Commitments = @import("../block_v6_native_commitment_staging_v1.zig");

test "block-v6 closed mixed tiling complete bundles" {
    // One compiled test executable supports every workload size and both
    // explicitly reported security profiles without another LLVM build.
    try run(if (std.process.hasEnvVarConstant("STWO_CLOSED_TILE_CANONICAL")) .csp_q70_pow26 else .diagnostic_q8_pow0);
}

fn run(selected: Profile) !void {
    const a = std.testing.allocator;
    const commit_once = std.process.hasEnvVarConstant("STWO_CLOSED_TILE_COMMIT_ONCE");
    const callers_once = std.process.hasEnvVarConstant("STWO_CLOSED_TILE_CALLER_ONCE");
    const globals_once = std.process.hasEnvVarConstant("STWO_CLOSED_TILE_GLOBAL_ONCE");
    const access_once = std.process.hasEnvVarConstant("STWO_CLOSED_TILE_ACCESS_ONCE");
    const commitment_mode = if (commit_once) "retained" else "recomputed";
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
        if (commit_once) options.collection.native_commitments = .{ .max_total_file_bytes = 8 << 30 };
        if (access_once) options.collection.access_commitments = .{ .max_total_file_bytes = 8 << 30 };
        if (globals_once) {
            options.collection.globals.program_commitments = .{ .max_total_file_bytes = 8 << 30 };
            options.collection.globals.ram_commitments = .{ .storage = .{ .max_total_file_bytes = 8 << 30 } };
            options.collection.groups.commitments = .{ .max_total_file_bytes = 8 << 30 };
        }
        if (callers_once) {
            options.collection.caller_commitments = .{ .max_total_file_bytes = 8 << 30 };
            options.collection.external_commitments = .{ .max_total_file_bytes = 8 << 30 };
        }
        const policy = @import("../block_v5_cpu_driver_admission_v1.zig").InputPolicy{ .runner_pins = pins, .job_id = @splat(113), .expected_final_rw_root = planned.last.machine.rw_memory.bytes };
        std.debug.print("BLOCK_V6_CLOSED_TILE_BEGIN profile={s} iterations={d} cycles={d} segments={d} preflight_ns={d} source_ns={d} budget_bytes={d} commitment_mode={s} checkpoint_budget_bytes={d} access_mode={s} provider_mode={s}\n", .{ @tagName(selected), iterations, planned.last.cycle, segments, preflight_ns, source_ns, options.total_host_limit, commitment_mode, if (options.collection.native_commitments) |checkpoint_policy| checkpoint_policy.max_total_file_bytes else 0, if (access_once) "retained" else "recomputed", if (globals_once) "retained" else "recomputed" });
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
        const io = result.native_commitments;
        if (commit_once) {
            try std.testing.expectEqual(segments, io.reused_first_rounds);
            try std.testing.expectEqual(io.written_bytes, io.checkpoint_read_bytes);
            try std.testing.expect(io.written_bytes > 0 and io.raw_witness_read_bytes > 0);
            try std.testing.expect(io.column_bytes + io.merkle_bytes <= io.written_bytes);
            // Neither producer checkpoints nor staged raw witness files are
            // receiver authority. Verify again after deleting both families.
            for (0..segments) |index| {
                var name_buffer: [96]u8 = undefined;
                try temporary.dir.deleteFile(try Commitments.name(@intCast(index), &name_buffer));
                try temporary.dir.deleteFile(try @import("../block_v5_cpu_witness_staging_v1.zig").nativeName(@intCast(index), &name_buffer));
            }
        } else {
            try std.testing.expectEqual(@as(u64, 0), io.written_bytes + io.column_bytes + io.merkle_bytes + io.checkpoint_read_bytes + io.write_ns + io.reused_first_rounds);
            try std.testing.expect(io.raw_witness_read_bytes > 0 and io.native_restore_ns > 0);
        }
        const access_io = result.access_commitments;
        if (access_once) {
            try std.testing.expectEqual(segments, access_io.reused_access_trees);
            try std.testing.expect(access_io.written_bytes > 0);
            try std.testing.expectEqual(access_io.written_bytes, access_io.read_bytes);
            for (0..segments) |index| {
                var buffer: [96]u8 = undefined;
                try temporary.dir.deleteFile(try @import("../block_v6_access_commitment_staging_v1.zig").name(@intCast(index), &buffer));
            }
        } else try std.testing.expectEqual(@as(u64, 0), access_io.written_bytes + access_io.read_bytes + access_io.reused_access_trees);
        std.debug.print("BLOCK_V6_ACCESS_IO segments={d} retained={} written_bytes={d} read_bytes={d} raw_witness_payload_bytes={d} column_bytes={d} merkle_bytes={d} write_ns={d} restore_ns={d} reused_access_trees={d} checkpoint_dependency=false\n", .{ segments, access_once, access_io.written_bytes, access_io.read_bytes, access_io.raw_witness_payload_bytes, access_io.column_bytes, access_io.merkle_bytes, access_io.write_ns, access_io.restore_ns, access_io.reused_access_trees });
        const metadata = try Receive.Metadata.read(a, temporary.dir, result.pins.policy_sha256, result.pins.identity, options.metadata);
        defer metadata.deinit();
        const globals = metadata.globals();
        _ = try globals.validate();
        const Retention = @import("../block_v6_provider_commitment_staging_v1.zig");
        const RamRetention = @import("../block_v6_ram_commitment_staging_v1.zig");
        const ram = switch (globals.memory.memory) {
            .lanes => |lanes| lanes,
            else => return error.UnexpectedTilingMemoryMode,
        };
        if (globals_once) {
            try temporary.dir.deleteFile(Retention.PROGRAM_NAME);
            try temporary.dir.deleteFile(Retention.LOOKUP_FIXED_NAME);
            for (globals.tables.providers) |record| {
                var buffer: [64]u8 = undefined;
                try temporary.dir.deleteFile(try Retention.lookupName(record.plan.index, &buffer));
            }
            for (ram.pins) |pin| {
                var buffer: [64]u8 = undefined;
                try temporary.dir.deleteFile(try RamRetention.memoryName(pin.index, "columns", &buffer));
                try temporary.dir.deleteFile(try RamRetention.memoryName(pin.index, "pcs", &buffer));
            }
            for (0..ram.range_roots.len) |index| {
                var buffer: [64]u8 = undefined;
                try temporary.dir.deleteFile(try RamRetention.rangeName(@intCast(index), &buffer));
            }
            try std.testing.expectEqual(@as(u64, 1), result.program_commitments.reused_first_rounds);
            try std.testing.expectEqual(globals.tables.providers.len, result.lookup_commitments.reused_first_rounds);
            try std.testing.expectEqual(ram.pins.len + ram.range_roots.len, result.ram_commitments.reused_first_rounds);
            try std.testing.expectEqual(result.ram_raw_written_bytes, result.ram_raw_read_bytes);
        }
        inline for (.{ "program", "lookup", "ram" }) |family| {
            const stats = @field(result, family ++ "_commitments");
            try std.testing.expectEqual(stats.written_bytes, stats.read_bytes);
            if (!globals_once) try std.testing.expectEqual(@as(u64, 0), stats.written_bytes + stats.reused_first_rounds);
            std.debug.print("BLOCK_V6_PROVIDER_IO segments={d} retained={} family={s} written_bytes={d} read_bytes={d} column_bytes={d} merkle_bytes={d} write_ns={d} restore_ns={d} reused_first_rounds={d} max_loaded_bytes={d}\n", .{ segments, globals_once, family, stats.written_bytes, stats.read_bytes, stats.column_bytes, stats.merkle_bytes, stats.write_ns, stats.restore_ns, stats.reused_first_rounds, stats.max_loaded_bytes });
        }
        std.debug.print("BLOCK_V6_RAM_IO segments={d} raw_written_bytes={d} raw_read_bytes={d} checkpoint_dependency=false\n", .{ segments, result.ram_raw_written_bytes, result.ram_raw_read_bytes });
        const CallerRetention = @import("../block_v6_caller_commitment_staging_v1.zig");
        if (callers_once) {
            for (globals.tables.extensions) |extension| {
                var buffer: [96]u8 = undefined;
                try temporary.dir.deleteFile(try CallerRetention.name(extension.execution_index, &buffer));
                try temporary.dir.deleteFile(try CallerRetention.externalName(extension.execution_index, "columns", &buffer));
                try temporary.dir.deleteFile(try CallerRetention.externalName(extension.execution_index, "pcs", &buffer));
                try temporary.dir.deleteFile(try @import("../block_v5_cpu_witness_staging_v1.zig").callerName(extension.execution_index, &buffer));
            }
            try std.testing.expectEqual(globals.tables.extensions.len, result.caller_commitments.reused_first_rounds);
            try std.testing.expectEqual(globals.tables.extensions.len, result.external_commitments.pcs.reused_first_rounds);
        }
        inline for (.{ "caller", "external" }) |family| {
            const stats = if (std.mem.eql(u8, family, "caller")) result.caller_commitments else result.external_commitments.pcs;
            try std.testing.expectEqual(stats.written_bytes, stats.read_bytes);
            if (!callers_once) try std.testing.expectEqual(@as(u64, 0), stats.written_bytes + stats.reused_first_rounds);
            std.debug.print("BLOCK_V6_CALLER_IO segments={d} retained={} family={s} written_bytes={d} read_bytes={d} reused_first_rounds={d} write_ns={d} restore_ns={d} checkpoint_dependency=false\n", .{ segments, callers_once, family, stats.written_bytes, stats.read_bytes, stats.reused_first_rounds, stats.write_ns, stats.restore_ns });
        }
        try std.testing.expectEqual(result.external_commitments.raw_written_bytes, result.external_commitments.raw_read_bytes);
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
        const area = try geometry(a, globals, metadata.recursion());
        std.debug.print("BLOCK_V6_CLOSED_TILE verified=true profile={s} iterations={d} cycles={d} segments={d} preflight_ns={d} source_ns={d} wall_ns={d} collection_ns={d} base_ns={d} recursive_ns={d} verification_ns={d} prepare_ns={d} setup_ns={d} prove_ns={d} encode_ns={d} detached_ns={d} charged_peak_bytes={d} base_files={d} base_file_bytes={d} batch_bytes={d} memory_ns={d} caller_ns={d} lookup_ns={d} rom_ns={d}", .{ @tagName(selected), iterations, planned.last.cycle, segments, preflight_ns, source_ns, wall_ns, result.collection_ns, result.base_ns, result.recursive_ns, result.verification_ns, result.prepare_ns, result.setup_ns, result.prove_ns, result.encode_ns, detached_ns, result.peak_bytes, result.base_files, result.base_file_bytes, result.pins.proof_bytes, result.families.family_ns[1], result.families.family_ns[0], result.families.family_ns[3], result.families.family_ns[2] });
        std.debug.print(" native_cells={d} companion_aux_cells={d} memory_cells={d} recursive_cells={d} memory_instances={d} native_components={d} memory_events={d} byte_requests={d} program_fetches={d} elf_sha256={s} initial_rw={s} final_rw={s} commitment_mode={s} batch_sha256={s} bundle_sha256={s} access_mode={s} provider_mode={s} lookup_groups={d} range_shards={d} complete_bundle=true standalone_root=false negative_identity=rejected negative_missing_proof=rejected\n", .{ area.native, area.companion, area.memory, area.recursive, globals.memory.memory.instanceCount(), area.components, actual.memory_events, actual.byte_requests, actual.program_fetches, std.fmt.bytesToHex(pins.elf_sha256, .lower), std.fmt.bytesToHex(actual.initial_rw_root, .lower), std.fmt.bytesToHex(actual.final_rw_root, .lower), commitment_mode, std.fmt.bytesToHex(result.pins.proof_sha256, .lower), std.fmt.bytesToHex(result.pins.bundle_sha256, .lower), if (access_once) "retained" else "recomputed", if (globals_once) "retained" else "recomputed", globals.tables.providers.len, ram.range_roots.len });
        std.debug.print("BLOCK_V6_COMMITMENT_IO segments={d} written_bytes={d} column_bytes={d} merkle_bytes={d} checkpoint_read_bytes={d} raw_witness_read_bytes={d} write_ns={d} native_restore_ns={d} reused_first_rounds={d} checkpoint_dependency=false\n", .{ segments, io.written_bytes, io.column_bytes, io.merkle_bytes, io.checkpoint_read_bytes, io.raw_witness_read_bytes, io.write_ns, io.native_restore_ns, io.reused_first_rounds });
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
