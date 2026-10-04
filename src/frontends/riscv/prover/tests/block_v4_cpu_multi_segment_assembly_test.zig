const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const runner = @import("../../runner/mod.zig");
const Profile = @import("../blake3_ethereum_sha_profile.zig");
const Native = @import("../blake3_ethereum_sha_proof.zig").ForBackend(Cpu);
const Replay = @import("../block_memory_replay.zig").Replay;
const span = @import("../../recursion/span_statement_blake3.zig");
const v3 = @import("../../recursion/blake3_block_execution_span_v3.zig");
const io = @import("../../recursion/blake3_public_io.zig");
const assembly = @import("../block_v4_cpu_multi_segment_assembly.zig");
const streaming = @import("../block_v4_cpu_streaming_produce.zig");
const runner_source = @import("../block_v4_cpu_runner_source.zig");
const incremental = @import("../block_v4_cpu_incremental_core_receiver.zig");
const leaf_stage = @import("../block_v4_cpu_incremental_leaf_stage.zig");
const forest_fixture = @import("block_v4_cpu_forest_stage_fixture_test.zig");
const file_fixture = @import("block_v4_cpu_file_receiver_fixture_test.zig");
const complete_receiver = @import("../block_v4_cpu_streaming_complete_receiver.zig");
const recursion_pins_mod = @import("../block_memory_complete_receiver_v3.zig");
const recursion_fixture = @import("block_v4_multi_recursion_fixture_test.zig");
const parent = @import("../../recursion/blake3_execution_parent_protocol.zig");

test "block-v4 CPU multi assembler crosses real IO with a zero-call first leaf" {
    try runRealIo(null, false);
}

test "block-v4 streaming observer stages recursive leaves after fresh execution" {
    try runRealIo(null, true);
}

test "block-v4 streaming diagnostic complete receiver crosses real IO and sparse external roster" {
    try runRealIo(.diagnostic_q8_pow0, false);
}

test "block-v4 streaming canonical complete receiver crosses real IO and sparse external roster" {
    try runRealIo(.csp_q70_pow26, false);
}

fn runRealIo(comptime recursive_profile: ?parent.Profile, comptime staged_observer: bool) !void {
    const backing = std.testing.allocator;
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(backing, 16 * 1024 * 1024 * 1024);
    defer budget.destroy();
    const a = budget.allocator();
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    var binding_active = true;
    defer if (binding_active) binding.deinit();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pin_tmp = std.testing.tmpDir(.{});
    defer pin_tmp.cleanup();
    const instructions = [_]u32{
        0x0010_00b7, // LUI x1,0x100: I/O base.
        0x2000_a103, // LW x2,0x200(x1): public input word.
        0x0020_a423, // SW x2,8(x1): output word.
        0x0040_0193, // ADDI x3,x0,4.
        0x0030_a223, // SW x3,4(x1): output length.
        0x3000_8293, // ADDI x5,x1,0x300: Keccak state.
        @import("../../isa/custom0.zig").encodeKeccakf(5),
        0x0010_0193, // ADDI x3,x0,1.
        0x0030_a023, // SW x3,0(x1): halt flag.
        0x0000_006f,
    };
    var elf = @import("../../runner/guest_precompile/test_elf.zig").buildReleaseProgram(instructions.len, &instructions, 1024, .rv32im_zkvm_ethereum_sha_v1);
    const symbols = 640 + instructions.len * 4 + 1024;
    std.mem.writeInt(u32, elf[symbols + 8 * 16 + 4 ..][0..4], 0x0010_0200, .little);
    std.mem.writeInt(u32, elf[symbols + 9 * 16 + 4 ..][0..4], 0x0010_0204, .little);
    const input = [_]u8{ 0x2a, 0x17, 0x09, 0x01 };
    var session = try runner.EthereumShaExecutionSession.init(a, &elf, .{
        .input = &input,
        .strict_completion = true,
        .stop_on_halt_flag = true,
        .trace_retention = .segment_owned,
        .clock_frame = .leaf_local,
    });
    defer session.deinit();
    var segments: [2]runner.EthereumShaSegmentResult = undefined;
    // Keep output publication in the terminal leaf: its native statement
    // binds the output address through a local memory access.
    segments[0] = try session.startSegment(2);
    defer segments[0].deinit();
    try std.testing.expect(!segments[0].base.isComplete());
    segments[1] = try session.resumeSegment(segments[0].base.continuation.?, 9);
    defer segments[1].deinit();
    try std.testing.expect(segments[1].base.isComplete());
    try std.testing.expectEqualSlices(u8, &input, segments[1].base.output.?);
    const config = if (recursive_profile) |profile| profile.config() else core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    var owners: [2]Profile.Witness = undefined;
    var owner_count: usize = 0;
    defer for (owners[0..owner_count]) |*owner| owner.deinit();
    var keys: [2][32]u8 = undefined;
    for (&owners, &segments, &keys) |*owner, *segment, *key| {
        owner.* = try Profile.Witness.initCompactSegment(a, segment);
        owner_count += 1;
        const prepared = try Native.PreparedVerifier.initCompact(a, &owner.native.statement, owner.statement, try owner.admission(), config, owner.native.compact_ranges.?.plan);
        key.* = prepared.id;
        prepared.deinit();
    }
    var pin_replay = try Replay.initFromSnapshot(a, pin_tmp.dir, segments[0].base.entry_cpu.regs, &segments[0].base.rw_memory, 256);
    defer pin_replay.deinit();
    const anchor = try pin_replay.initialRwRoot();
    const first = &owners[0].native.statement.public_data;
    const last = &owners[1].native.statement.public_data;
    const entry = try span.MachineState.init(first.initial_pc, first.initial_regs, anchor, .{ .bytes = @splat(0) });
    const exit = try span.MachineState.init(last.final_pc, last.final_regs, anchor, .{ .bytes = @splat(0) });
    const cycles = segments[1].base.global_first_cycle - 1 + segments[1].base.cycle_count;
    const complete = try span.CompleteExecution.init(v3.protocolIdentity(config), first.program_root.?, entry, exit, try io.input(first), try io.output(last), cycles);
    const job = try span.JobContext.init(complete, 2);
    const trusted = assembly.Trusted{ .job = job, .base_seal = .{ .digest = @splat(42), .instance_count = 2 }, .native_key_ids = &keys, .outer_key_id = @splat(1), .forest_roster_digest = @splat(2) };
    const callback = struct {
        var allocator: std.mem.Allocator = undefined;
        var trusted_pins: assembly.Trusted = undefined;
        var expected_seal: @import("../block_memory_source_seal_v2.zig").SourceSeal = undefined;
        var expected_digest: [32]u8 = undefined;
        var security: core.pcs.PcsConfig = undefined;
        var exact_schedule: []const u8 = undefined;
        var work_pool: *engine.work_pool.WorkPool = undefined;
        var pool_binding: *engine.work_pool.ScopedPoolBinding = undefined;
        var pool_binding_active: *bool = undefined;
        var recursive_proofs: ?recursion_fixture.Proofs = null;
        fn verify(view: assembly.View) !void {
            try std.testing.expectEqual(@as(usize, 2), view.metrics.segments);
            try std.testing.expectEqual(@as(u64, 0), view.statement.execution_extension_active_counts[0]);
            try std.testing.expect(view.statement.execution_extension_active_counts[1] > 0);
            try std.testing.expectEqual(@as(usize, 1), view.statement.execution_extension_roots.len);
            try std.testing.expect(view.metrics.public_image_bytes > 0);
            try std.testing.expect(view.metrics.public_first_touch_bytes > 0);
            try std.testing.expect(view.metrics.tracked_peak_bytes != null);
            expected_seal = view.statement.seal;
            expected_digest = try view.statement.firstRoundDigest(allocator);
            if (recursive_profile) |profile| if (profile != .csp_q70_pow26) {
                recursive_proofs = try recursion_fixture.proveWithProfile(allocator, view, profile);
            };
            std.debug.print("BLOCK_V4_MULTI_REAL_IO verified=true segments=2 events={d} external={d} memory_instances={d} image_bytes={d} touches_bytes={d} staged_payload_bytes={d} elapsed_ns={d} tracked_peak_bytes={d}\n", .{ view.metrics.execution_events, view.metrics.external_events, view.metrics.memory_instances, view.metrics.public_image_bytes, view.metrics.public_first_touch_bytes, view.metrics.stark_payload_bytes, view.metrics.elapsed_ns, view.metrics.tracked_peak_bytes.? });
        }
        fn verifyStreaming(product: streaming.Product) !void {
            try std.testing.expect(std.meta.eql(expected_seal, product.statement.seal));
            const digest = try product.statement.firstRoundDigest(allocator);
            try std.testing.expectEqualSlices(u8, &expected_digest, &digest);
            try std.testing.expectEqual(@as(u64, 70), product.first.event_count);
            try std.testing.expectEqual(@as(u64, 51), product.first.external_events);
            try std.testing.expectEqual(product.first.external_plan.shards.len, product.first.external_counters.items.len);
            const receiver_budget = try engine.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 24 * 1024 * 1024 * 1024);
            defer receiver_budget.destroy();
            const receiver_a = receiver_budget.allocator();
            var receiver_timer = try std.time.Timer.start();
            if (recursive_profile == .csp_q70_pow26) {
                try file_fixture.run(receiver_a, product, trusted_pins, work_pool, pool_binding, pool_binding_active, exact_schedule);
                std.debug.print("BLOCK_V4_RECEIVER_TEARDOWN live_bytes={d}\n", .{receiver_budget.snapshot().live_bytes});
                return;
            }
            if (staged_observer) {
                var leaf_tmp = std.testing.tmpDir(.{});
                defer leaf_tmp.cleanup();
                var staged = try leaf_stage.verifyAndStage(receiver_a, product, trusted_pins, security, leaf_tmp.dir, .diagnostic_q8_pow0);
                defer staged.deinit(receiver_a);
                try std.testing.expectEqual(@as(u64, 70), staged.verified_core.core.summary.event_count);
                try std.testing.expectEqual(@as(usize, 2), staged.staged.next);
                for (0..staged.staged.next) |index| {
                    const bytes = try staged.staged.load(index);
                    defer receiver_a.free(bytes);
                    try std.testing.expectEqual(staged.staged.entries[index].byte_len, bytes.len);
                }
                pool_binding.deinit();
                pool_binding_active.* = false;
                try forest_fixture.check(receiver_a, leaf_tmp.dir, &staged.staged, trusted_pins.job, work_pool);
                std.debug.print("BLOCK_V4_STREAMING_LEAF_STAGE verified=true leaves={d} receiver_ns={d}\n", .{ staged.staged.next, receiver_timer.read() });
            } else if (recursive_profile) |profile| {
                const proofs = recursive_proofs orelse return error.MissingStreamingRecursiveProofs;
                const leaves_pins = [_]recursion_pins_mod.ProofPin{
                    .{ .admission = proofs.leaf_admissions[0], .expected_key_id = proofs.leaf_admissions[0].expected_id },
                    .{ .admission = proofs.leaf_admissions[1], .expected_key_id = proofs.leaf_admissions[1].expected_id },
                };
                const dyadic_pins = [_]recursion_pins_mod.DyadicPin{.{
                    .left_index = 0,
                    .right_index = 1,
                    .proof = .{ .admission = proofs.dyadic_admission, .expected_key_id = proofs.dyadic_admission.expected_id },
                }};
                const root_indices = [_]u32{2};
                const leaf_bytes = [_][]const u8{ proofs.leaf_bytes[0], proofs.leaf_bytes[1] };
                const dyadic_bytes = [_][]const u8{proofs.dyadic_bytes};
                const pins = complete_receiver.RecursionPins{
                    .leaf = &leaves_pins,
                    .dyadic = &dyadic_pins,
                    .root_indices = &root_indices,
                    .outer = .{ .admission = proofs.outer_admission, .expected_key_id = proofs.outer_admission.expected_id },
                };
                const bytes = complete_receiver.RecursionBytes{
                    .leaf = &leaf_bytes,
                    .dyadic = &dyadic_bytes,
                    .outer = proofs.outer_bytes,
                };
                if (profile == .csp_q70_pow26) {
                    try std.testing.expectEqual(@import("../block_memory_batch_verify_v2.zig").CompleteBlock.complete_block_verified, try complete_receiver.verifyCanonical(receiver_a, product, trusted_pins, pins, bytes));
                } else {
                    try complete_receiver.verifyDiagnostic(receiver_a, product, trusted_pins, pins, bytes);
                    var wrong_outer = trusted_pins;
                    wrong_outer.outer_key_id[0] ^= 1;
                    try std.testing.expectError(error.UntrustedStreamingCompletePins, complete_receiver.verifyDiagnostic(receiver_a, product, wrong_outer, pins, bytes));
                    var wrong_forest = trusted_pins;
                    wrong_forest.forest_roster_digest[0] ^= 1;
                    try std.testing.expectError(error.UntrustedStreamingCompletePins, complete_receiver.verifyDiagnostic(receiver_a, product, wrong_forest, pins, bytes));
                }
                std.debug.print("BLOCK_V4_STREAMING_COMPLETE profile={s} verified=true producer_ns={d} recursive_prove_ns={d} receiver_ns={d} receiver_allocator_peak_bytes={d} leaf_bytes={d}+{d} dyadic_bytes={d} outer_bytes={d}\n", .{ @tagName(profile), product.elapsed_ns, proofs.elapsed_ns, receiver_timer.read(), receiver_budget.snapshot().peak_live_bytes, proofs.leaf_bytes[0].len, proofs.leaf_bytes[1].len, proofs.dyadic_bytes.len, proofs.outer_bytes.len });
            } else {
                var verified = try incremental.verify(receiver_a, product, trusted_pins, security);
                defer verified.deinit(receiver_a);
                try std.testing.expectEqual(@as(u64, 70), verified.core.summary.event_count);
                try std.testing.expectEqual(@as(usize, 2), verified.leaves.len);
                std.debug.print("BLOCK_V4_STREAMING_CORE receiver_ns={d} receiver_allocator_peak_bytes={d}\n", .{ receiver_timer.read(), receiver_budget.snapshot().peak_live_bytes });
            }
            std.debug.print("BLOCK_V4_RECEIVER_TEARDOWN live_bytes={d}\n", .{receiver_budget.snapshot().live_bytes});
            std.debug.print("BLOCK_V4_STREAMING_REAL_IO verified=true segments=2 events={d} external={d} staged_payload_bytes={d} producer_ns={d}\n", .{ product.first.event_count, product.first.external_events, try product.payloadBytes(), product.elapsed_ns });
        }
    };
    callback.recursive_proofs = null;
    defer if (callback.recursive_proofs) |*proofs| proofs.deinit(a);
    callback.allocator = a;
    callback.trusted_pins = trusted;
    callback.security = config;
    callback.work_pool = &pool;
    callback.pool_binding = &binding;
    callback.pool_binding_active = &binding_active;
    try assembly.withAssembledSegments(a, tmp.dir, &pool, &segments, trusted, config, .{ .memory_instance_capacity = 1 << 12, .spool_chunk_events = 256 }, budget, callback.verify);
    var trusted_final = trusted;
    if (callback.recursive_proofs) |proofs| {
        trusted_final.outer_key_id = proofs.outer_admission.expected_id;
        trusted_final.forest_roster_digest = proofs.forest_digest;
    }
    callback.trusted_pins = trusted_final;
    var stream_tmp = std.testing.tmpDir(.{});
    defer stream_tmp.cleanup();
    const terminal_budget: u32 = @intCast(segments[1].base.cycle_count);
    const schedule_json = try std.fmt.allocPrint(a, "[2,{d}]", .{terminal_budget});
    defer a.free(schedule_json);
    callback.exact_schedule = schedule_json;
    var source = try runner_source.Source.initWithSchedule(a, &elf, &input, &input, terminal_budget, config, .{
        .elf_sha256 = runner_source.sha256(&elf),
        .input_sha256 = runner_source.sha256(&input),
        .oracle_sha256 = runner_source.sha256(&input),
        .initial_rw_root = anchor,
        .program_root = first.program_root.?,
        .expected_job = job,
        .schedule_json_sha256 = runner_source.sha256(schedule_json),
    }, schedule_json);
    defer source.deinit();
    try streaming.withProduced(a, stream_tmp.dir, &pool, &source, trusted_final, config, .{ .memory_instance_capacity = 1 << 12, .spool_chunk_events = 256, .parallel_families = true }, callback.verifyStreaming);
}
