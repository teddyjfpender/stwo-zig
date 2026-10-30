const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Resident = @import("../block_v7_resident_native_stage_v1.zig");
const Driver = @import("../block_v7_streaming_execution_mode_v1.zig").ForMode(true);
const Producer = @import("../block_v7_window_union_producer_v1.zig");
const Multi = @import("../block_v7_multi_union_proof_v1.zig").ForMode(true);
const Codec = @import("../block_v7_multi_union_codec_v1.zig").ForMode(true);
const Capture = @import("../block_v7_real_window_capture_v1.zig");
const Guest = @import("block_v7_keccak_execution_test_support.zig");
const profile = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile.diagnostic_q8_pow0;
const limits = Multi.Limits{ .max_retained_pcs_bytes = 8 << 30 };
const Consumer = struct {
    pub const Result = *Producer.Artifact;
    pub fn consumeStagedWindow(f: Driver.StagedWindowFixture) !Result {
        if (f.resident_natives) |sources| {
            try std.testing.expectEqual(@as(usize, 0), f.natives.len);
            for (sources) |source| {
                try std.testing.expect(source.first.scheme.trees.items[0].coefficients != null);
                try std.testing.expect(source.first.scheme.trees.items[1].coefficients != null);
            }
            var entries = f.directory.iterate();
            try std.testing.expect((try entries.next()) == null);
        }
        return Producer.produce(f, .{ .limits = limits });
    }
    pub fn discardStagedResult(result: Result) void {
        result.deinit();
    }
};
test "resident original stages preserve exact shared proof bytes after runner and source destruction" {
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 12 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const elf = Guest.elf();
    const span = Capture.Window{ .skip_cycles = 9, .cycles = 4 };
    var captured = try Capture.capture(a, &elf, &.{}, .{ .elf = Capture.sha(&elf), .input = Capture.sha(&.{}) }, span, .{});
    defer captured.deinit();
    const request = Driver.Request{ .elf = &elf, .elf_sha256 = Capture.sha(&elf), .cycles = span.cycles, .config = profile.config(), .state = .{ .incoming = captured.incoming, .outgoing = captured.outgoing, .trusted = .{ .elf_sha256 = Capture.sha(&elf), .incoming_sha256 = captured.incoming.identity(), .outgoing_sha256 = captured.outgoing.identity(), .window = span } } };
    var directory = std.testing.tmpDir(.{ .iterate = true });
    defer directory.cleanup();
    const durable = try Driver.run(budget, directory.dir, request, .{ .segment_cycles = 2, .active_callers = true, .sparse_window_initialization = true }, &pool, Consumer);
    defer durable.value.deinit();
    const durable_verified = try durable.value.verify(limits);
    const reference = try Codec.encode(a, durable.value.proof.view(), durable.value.statement.input, .{ .scope = limits });
    defer a.free(reference);
    const resident = try Driver.run(budget, directory.dir, request, .{ .segment_cycles = 2, .active_callers = true, .sparse_window_initialization = true, .resident_original_stages = true }, &pool, Consumer);
    defer resident.value.deinit();
    try std.testing.expect(resident.stats.resident_original_stages);
    try std.testing.expectEqual(@as(u64, 0), resident.stats.checkpoint_bytes);
    try std.testing.expectEqual(@as(usize, 0), resident.stats.max_native_restore_codec_bytes);
    try std.testing.expect(resident.value.stats.fixed_polynomials_reused);
    try std.testing.expectEqualDeep(durable_verified, try resident.value.verify(limits));
    const bytes = try Codec.encode(a, resident.value.proof.view(), resident.value.statement.input, .{ .scope = limits });
    defer a.free(bytes);
    try std.testing.expectEqualSlices(u8, reference, bytes);
    var remaining = directory.dir.iterate();
    try std.testing.expect((try remaining.next()) == null);
}
fn limitsForStage() @import("../block_v7_native_checkpoint_v1.zig").Limits {
    return .{ .columns = .{ .columns = .{ .max_columns = 4096, .max_log_size = 24, .max_file_bytes = 8 << 30, .max_loaded_bytes = 8 << 30 }, .max_public_words = 0, .max_public_bytes = 0 }, .source = .{ .max_slots = 4096, .max_witness_cells = 1 << 24, .max_metadata_bytes = 1 << 20, .register_custody_mode = 1 }, .max_total_bytes = 8 << 30 };
}
/// Test fixture for the same nonterminal public boundary as Driver.current;
/// machine results retain their own I/O buffers, while native public I/O is
/// intentionally absent from this independently closed window theorem.
fn windowCurrent(a: std.mem.Allocator, owned: @import("../../runner/mod.zig").EthereumShaSegmentResult) !*@import("../block_v5_cpu_execution_source_v1.zig").Current {
    var segment = owned;
    errdefer segment.deinit();
    var io = try @import("../blake3_segment_public.zig").Owned.init(a, &segment.base);
    errdefer io.deinit();
    io.data.program_root = .{ .bytes = @splat(1) };
    io.data.io_entries.input_len = 0;
    io.data.io_entries.input_words = &.{};
    io.data.io_entries.output_len = 0;
    io.data.io_entries.output_words = &.{};
    const owner = try @import("../blake3_execution_trace.zig").Owner.initWithExternal(a, &segment.base.execution_trace, io.data, &segment.base.state_chain_tracker, 0);
    errdefer owner.deinit();
    try owner.sealNativeOnly();
    const current = try a.create(@import("../block_v5_cpu_execution_source_v1.zig").Current);
    current.* = .{ .a = a, .segment = segment, .io = io, .owner = owner, .recipe = .custody_v2 };
    return current;
}
fn stageAttempt(failing: *std.testing.FailingAllocator, fail_after: ?usize) !usize {
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(failing.allocator(), 512 << 20);
    var budget_live = true;
    defer if (budget_live) budget.destroy();
    const b = budget.allocator();
    const Runner = @import("../../runner/mod.zig");
    const elf = Guest.elf();
    var session = try Runner.EthereumShaExecutionSession.init(b, &elf, .{ .clock_frame = .leaf_local, .trace_retention = .segment_owned });
    var session_live = true;
    defer if (session_live) session.deinit();
    var prefix = try session.startSegment(9);
    var prefix_live = true;
    defer if (prefix_live) prefix.deinit();
    const segment = try session.resumeSegment(prefix.base.continuation.?, 4);
    const current = try windowCurrent(b, segment);
    var current_live = true;
    defer if (current_live) current.deinit();
    var counters = try @import("../../air/lookups/tables/counter.zig").Set.init(b);
    var counters_live = true;
    defer if (counters_live) counters.deinit(b);
    const Sink = struct {
        fn put(_: *anyopaque, _: @import("../../air/block/memory_transition.zig").Transition) !void {}
    };
    var sink_context: u8 = 0;
    // Loader/machine mutations intentionally use infallible allocation APIs.
    // This test targets the new resident handoff, not ELF-loader OOM behavior:
    // enable failure injection only after the independently owned runner,
    // original native columns and global counters have been prepared.
    const first_allocation = failing.alloc_index;
    if (fail_after) |index| failing.fail_index = try std.math.add(usize, first_allocation, index);
    const stage = try Resident.Owned.collect(b, current, profile.config(), .rv32im_zkvm_ethereum_sha_v1, 0, &counters, .{ .context = &sink_context, .put = Sink.put }, limitsForStage());
    defer stage.deinit();
    try std.testing.expect(stage.pin().expected_events > 0);
    try std.testing.expectError(error.NativeOwnerAlreadyTransferred, current.takeNativeOwner());
    current.deinit();
    current_live = false;
    counters.deinit(b);
    counters_live = false;
    prefix.deinit();
    prefix_live = false;
    session.deinit();
    session_live = false;
    // The retained resident owner, not the surrounding runner or explicit
    // budget root, now keeps every original column and tree allocator alive.
    budget.destroy();
    budget_live = false;
    _ = try stage.pin().entry(b);
    try std.testing.expect(stage.first.scheme.trees.items[0].coefficients != null);
    try std.testing.expect(stage.first.scheme.trees.items[1].coefficients != null);
    return failing.alloc_index - first_allocation;
}
fn stageLifetime(a: std.mem.Allocator) !usize {
    var failing = std.testing.FailingAllocator.init(a, .{});
    const allocations = try stageAttempt(&failing, null);
    try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    return allocations;
}
test "resident source retains raw owner and original coefficient leases independently of runner lifetime" {
    _ = try stageLifetime(std.testing.allocator);
}
test "resident source allocation failures release every partial raw and PCS owner" {
    const allocations = try stageLifetime(std.testing.allocator);
    for (0..allocations) |index| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        if (stageAttempt(&failing, index)) |_| {
            try std.testing.expect(!failing.has_induced_failure);
        } else |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expect(failing.has_induced_failure);
        }
        try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    }
}
