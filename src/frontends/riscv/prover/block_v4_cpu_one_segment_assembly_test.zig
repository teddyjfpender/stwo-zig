const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const runner = @import("../runner/mod.zig");
const Profile = @import("blake3_ethereum_sha_profile.zig");
const Native = @import("blake3_ethereum_sha_proof.zig");
const segment_statement = @import("blake3_segment_statement.zig");
const v3 = @import("../recursion/blake3_block_execution_span_v3.zig");
const assembly = @import("block_v4_cpu_one_segment_assembly.zig");

test "v4 CPU assembler proves real public input output and Keccak caller access" {
    const backing = std.testing.allocator;
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(backing, 16 * 1024 * 1024 * 1024);
    defer budget.destroy();
    const a = budget.allocator();
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const instructions = [_]u32{
        0x0010_00b7, // LUI x1,0x100: I/O base.
        0x2000_a103, // LW x2,0x200(x1): public input word.
        0x0020_a423, // SW x2,8(x1): output word.
        0x0040_0193, // ADDI x3,x0,4.
        0x0030_a223, // SW x3,4(x1): output length.
        0x3000_8293, // ADDI x5,x1,0x300: Keccak state.
        @import("../isa/custom0.zig").encodeKeccakf(5),
        0x0010_0193, // ADDI x3,x0,1.
        0x0030_a023, // SW x3,0(x1): halt flag.
        0x0000_006f,
    };
    var elf = @import("../runner/guest_precompile/test_elf.zig").buildReleaseProgram(instructions.len, &instructions, 1024, .rv32im_zkvm_ethereum_sha_v1);
    const symbols = 640 + instructions.len * 4 + 1024;
    std.mem.writeInt(u32, elf[symbols + 8 * 16 + 4 ..][0..4], 0x0010_0200, .little);
    std.mem.writeInt(u32, elf[symbols + 9 * 16 + 4 ..][0..4], 0x0010_0204, .little);
    const input = [_]u8{ 0x2a, 0x17, 0x09, 0x01 };
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    var preflight = try runner.EthereumShaExecutionSession.init(a, &elf, .{
        .input = &input,
        .strict_completion = true,
        .stop_on_halt_flag = true,
        .trace_retention = .segment_owned,
        .clock_frame = .leaf_local,
    });
    defer preflight.deinit();
    var segment = try preflight.startSegment(11);
    defer segment.deinit();
    try std.testing.expect(segment.base.isComplete());
    try std.testing.expectEqualSlices(u8, &input, segment.base.output.?);
    var owner = try Profile.Witness.initCompactSegment(a, &segment);
    defer owner.deinit();
    const prepared = try Native.ForBackend(Cpu).PreparedVerifier.initCompact(a, &owner.native.statement, owner.statement, try owner.admission(), config, owner.native.compact_ranges.?.plan);
    defer prepared.deinit();
    const first = try segment_statement.captureEndpoint(a, &segment.base, &owner.native.statement.public_data, .entry);
    const last = try segment_statement.captureEndpoint(a, &segment.base, &owner.native.statement.public_data, .exit);
    const job = try v3.initJobFromEndpoints(config, first, last, 1, first.machine.rw_memory);
    const trusted = assembly.Trusted{ .job = job, .base_seal = .{ .digest = @splat(41), .instance_count = 1 }, .native_key_id = prepared.id, .outer_key_id = @splat(1), .forest_roster_digest = @splat(2) };
    const use = struct {
        fn receive(view: assembly.View) !void {
            try std.testing.expect(view.statement.seal.extension_rosters_bound);
            try std.testing.expect(view.metrics.extension_events >= 51);
            // The public image includes the initialized Keccak state as well
            // as the four-byte input word; this is fixture data, not I/O
            // overhead attributable to the proof format.
            try std.testing.expectEqual(@as(u64, 2_040), view.metrics.public_image_bytes);
            try std.testing.expect(view.metrics.public_first_touch_bytes > 0);
            try std.testing.expect(view.metrics.stark_payload_bytes > 0);
            try std.testing.expect(view.metrics.tracked_peak_bytes > 0);
            try std.testing.expectEqual(view.metrics.execution_events, view.verified.event_count);
            std.debug.print("BLOCK_V4_CPU_SMALL verified=true input_bytes=4 output_bytes=4 events={d} extension={d} image_bytes={d} touches_bytes={d} stark_payload_bytes={d} elapsed_ns={d} tracked_peak_bytes={d}\n", .{ view.metrics.execution_events, view.metrics.extension_events, view.metrics.public_image_bytes, view.metrics.public_first_touch_bytes, view.metrics.stark_payload_bytes, view.metrics.elapsed_ns, view.metrics.tracked_peak_bytes });
        }
    };
    try assembly.withAssembledCore(a, tmp.dir, &pool, &elf, &input, &input, trusted, config, .{ .max_cycles = 11, .memory_instance_capacity = 1 << 12 }, budget, use.receive);
}
