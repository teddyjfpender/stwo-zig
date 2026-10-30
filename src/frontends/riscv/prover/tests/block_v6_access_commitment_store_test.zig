//! Original access witness/tree -> bounded checkpoint -> identical fresh proof.
const Store = @import("../block_v6_access_commitment_store_v1.zig");
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const runner = @import("../../runner/mod.zig");
const physical = @import("../block_v5_cpu_native_root_proposal_v1.zig");
const stage_mod = @import("../block_v5_native_memory_stage_v1.zig");
const native = @import("../block_v5_native_execution_proof_v3.zig");
const sidecar = @import("../block_v5_opcode_memory_sidecar_proof_v1.zig");
const seals = @import("../block_v5_source_seal_v1.zig");
const Producer = @import("../block_v5_block_producer_v1.zig").ForLightweightBackend(Cpu);
const Capture = struct {
    proof: ?sidecar.Proof = null,
    fn put(raw: *anyopaque, index: u32, proof: *sidecar.Proof) anyerror!void {
        const self: *Capture = @ptrCast(@alignCast(raw));
        if (index != 0 or self.proof != null) return error.InvalidWarmMemorySink;
        self.proof = proof.*;
    }
    fn release(_: *anyopaque, _: *@import("../block_v5_block_producer_v1.zig").LightweightReplay) void {}
};
test "access commitment checkpoint reuses witness and tree with byte-identical verified proof" {
    const a = std.testing.allocator;
    const instructions = [_]u32{ 0x00500093, 0x0000006f };
    const elf = @import("../../runner/guest_precompile/test_elf.zig").buildProgram(instructions.len, &instructions, 0, .rv32im_zkvm_v1);
    var session = try runner.BaseExecutionSession.init(a, &elf, .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local });
    defer session.deinit();
    var segment = try session.startSegment(1);
    defer segment.deinit();
    var io = try @import("../blake3_segment_public.zig").Owned.init(a, &segment);
    defer io.deinit();
    io.data.program_root = .{ .bytes = @splat(3) };
    const owner = try @import("../blake3_execution_trace.zig").Owner.init(a, &segment.execution_trace, io.data, &segment.state_chain_tracker);
    defer owner.deinit();
    try owner.sealNativeOnly();
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    var proposed_native = try physical.ForBackend(Cpu).collect(a, owner, config, .rv32im_zkvm_v1, 0, 1, .{ .max_public_words = 1024, .max_metadata_bytes = 1024 * 1024 });
    defer proposed_native.deinit();
    var counters = try @import("../../air/lookups/tables/counter.zig").Set.init(a);
    defer counters.deinit(a);
    const limits = stage_mod.Limits{ .max_slots = 32, .max_witness_cells = 1024 * 1024, .max_metadata_bytes = 1024 * 1024 };
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    var proposed: stage_mod.Proposal = undefined;
    const checkpoint = blk: {
        var retained = try stage_mod.ForBackend(Cpu).collectRetainedTimed(a, owner, .{ .clock_frame = .leaf_local, .global_first_cycle = 1, .cycle_count = 1 }, &proposed_native, &counters, limits, null);
        defer retained.deinitPhysical(a);
        errdefer retained.proposal.deinit();
        const saved = try Store.write(a, temp.dir, "access.pcs", &proposed_native, &retained, .{ .source = limits });
        try std.testing.expectError(error.AccessCheckpointResourceLimit, Store.write(a, temp.dir, "too-big.pcs", &proposed_native, &retained, .{ .source = limits, .storage = .{ .max_file_bytes = saved.bytes - 1 } }));
        try std.testing.expectError(error.FileNotFound, temp.dir.openFile("too-big.pcs", .{}));
        proposed = retained.proposal;
        break :blk saved;
    };
    defer proposed.deinit();
    var restored = try Store.load(a, temp.dir, "access.pcs", &proposed_native, &proposed, owner, checkpoint, .{ .source = limits });
    defer restored.deinit(a);
    try std.testing.expectEqual(proposed.ordinary_events, try restored.source.census());
    var independently_generated = try stage_mod.Traces.init(a, owner, proposed.frame, limits);
    defer independently_generated.deinit();
    for (restored.source.traces, independently_generated.traces) |cached, original| try std.testing.expectEqualSlices(core.fields.m31.M31, cached.storage, original.storage);
    try std.testing.checkAllAllocationFailures(a, loadAndRelease, .{ temp.dir, &proposed_native, &proposed, owner, checkpoint, limits });
    try std.testing.expectError(error.AccessCheckpointResourceLimit, Store.load(a, temp.dir, "access.pcs", &proposed_native, &proposed, owner, checkpoint, .{ .source = limits, .storage = .{ .max_loaded_bytes = checkpoint.loaded_bytes - 1 } }));
    var wrong_proposal = proposed;
    wrong_proposal.frame.global_first_cycle += 1;
    try std.testing.expectError(error.ChangedAccessCheckpointScope, Store.load(a, temp.dir, "access.pcs", &proposed_native, &wrong_proposal, owner, checkpoint, .{ .source = limits }));
    wrong_proposal = proposed;
    wrong_proposal.witness_root[0] ^= 1;
    try std.testing.expectError(error.ChangedAccessCheckpointScope, Store.load(a, temp.dir, "access.pcs", &proposed_native, &wrong_proposal, owner, checkpoint, .{ .source = limits }));
    {
        const file = try temp.dir.openFile("access.pcs", .{ .mode = .read_write });
        defer file.close();
        var old: [4]u8 = undefined;
        try std.testing.expectEqual(@as(usize, 4), try file.preadAll(&old, 80));
        const invalid: [4]u8 = .{ 0xff, 0xff, 0xff, 0x7f };
        try file.pwriteAll(&invalid, 80);
        try std.testing.expectError(error.NonCanonicalNativeCheckpointM31, Store.load(a, temp.dir, "access.pcs", &proposed_native, &proposed, owner, checkpoint, .{ .source = limits }));
        try file.pwriteAll(&old, 80);
    }
    try std.testing.expectEqual(@as(u64, 2), proposed.ordinary_events);
    try std.testing.expectEqual(@as(u32, 28), counters.get(.range_check_8_8).signedTotal().toU32());
    const candidate = try proposed_native.bind(.{ .job_id = @splat(1), .source_image_digest = @splat(2), .program_root = @splat(3), .program_plan_digest = @splat(4), .memory_plan_digest = @splat(5), .initial_source_plan_digest = @splat(6), .rw_endpoint_plan_digest = @splat(7), .execution_index = 0, .first_cycle = 1, .last_cycle = 1 });
    const records = [_]@import("../block_v5_native_template_catalog_v1.zig").Record{candidate.catalog_record};
    const catalog = @import("../block_v5_native_template_catalog_v1.zig").Admission{ .records = &records };
    var counts: [seals.family_count]u32 = @splat(0);
    inline for ([_]seals.Family{ .program, .execution, .execution_sidecar, .program_request, .memory }) |family| counts[@intFromEnum(family) - 1] = 1;
    const pins = seals.Pins{ .job_id = @splat(1), .source_image_digest = @splat(2), .program_root = @splat(3), .program_plan_digest = @splat(4), .memory_plan_digest = @splat(5), .initial_source_plan_digest = @splat(6), .rw_endpoint_plan_digest = @splat(7), .native_template_catalog_digest = try catalog.digest(), .config = config, .counts = counts };
    // ROM/sorted/provider entries are explicitly scoped placeholders here.
    const entries = [_]seals.Entry{
        .{ .family = .program, .index = 0, .instance_id = @splat(8), .roots = .{ @splat(9), @splat(10) } },
        candidate.entry,
        try proposed.bind(&proposed_native, candidate.entry),
        .{ .family = .program_request, .index = 0, .instance_id = @splat(11), .roots = candidate.entry.roots },
        .{ .family = .memory, .index = 0, .instance_id = @splat(12), .roots = .{ @splat(13), @splat(14) } },
    };
    const sealed = try seals.seal(pins, &entries);
    const Native = native.ForBackend(Cpu);
    var first = try Native.commitFirstRound(a, owner, candidate.admission, config, .rv32im_zkvm_v1, 0);
    defer first.deinit(a);
    try proposed_native.requireReplay(&first);
    var replay = @import("../block_v5_block_producer_v1.zig").LightweightReplay{ .owner = owner, .admission = candidate.admission, .profile = .rv32im_zkvm_v1, .context = &segment, .release = Capture.release };
    const warm = Producer.WarmExecution{ .index = 0, .replay = &replay, .first = &first, .sealed = sealed, .pins = pins, .entries = &entries, .catalog = catalog };
    var capture = Capture{};
    defer if (capture.proof) |*proof| proof.deinit(a);
    var proposals = [_]stage_mod.Proposal{proposed};
    var stage = stage_mod.ForBackend(Cpu){ .proposals = &proposals, .limits = limits, .sink = .{ .context = &capture, .put_opcode = Capture.put } };
    const hooks = stage.hooks();
    var wrong = warm;
    wrong.index = 1;
    try std.testing.expectError(error.InvalidV5NativeMemoryStageOrder, hooks.on_first_round.?(hooks.context, a, wrong));
    proposals[0].byte_snapshot[0] ^= 1;
    try std.testing.expectError(error.V5NativeMemoryReplayMismatch, hooks.on_first_round.?(hooks.context, a, warm));
    proposals[0].byte_snapshot[0] ^= 1;
    try std.testing.expect(capture.proof == null and first.owns_scheme);
    const pointers = .{ first.scheme.trees.items[0].columns[0].values.ptr, first.scheme.trees.items[1].columns[0].values.ptr };
    hooks.on_first_round.?(hooks.context, a, warm) catch |err| {
        std.debug.print("WARM_MEMORY callback error={s}\n", .{@errorName(err)});
        return err;
    };
    try stage.requireFinished();
    try std.testing.expect(first.owns_scheme and first.scheme.trees.items.len == 2);
    try std.testing.expect(first.scheme.trees.items[0].columns[0].values.ptr == pointers[0] and first.scheme.trees.items[1].columns[0].values.ptr == pointers[1]);
    var retained_first = try stage_mod.ForBackend(Cpu).borrowRetained(a, &first.scheme, &restored.scheme, restored.snapshots, &proposed);
    defer retained_first.deinit(a);
    var retained_proof = try sidecar.ForPackedBackend(Cpu).proveForNativeFirstRound(a, &retained_first, restored.source.inputs, restored.source.slots, sealed, pins, &entries, catalog, &first, 0, proposed.witness_root);
    defer retained_proof.deinit(a);
    try std.testing.expectEqualDeep(capture.proof.?.claims, retained_proof.claims);
    var baseline_wire = std.Io.Writer.Allocating.init(a);
    defer baseline_wire.deinit();
    var retained_wire = std.Io.Writer.Allocating.init(a);
    defer retained_wire.deinit();
    try @import("interop_postcard").serializeProof(core.proof_suites.Blake3.Hasher, &baseline_wire.writer, capture.proof.?.stark);
    try @import("interop_postcard").serializeProof(core.proof_suites.Blake3.Hasher, &retained_wire.writer, retained_proof.stark);
    try std.testing.expectEqualSlices(u8, baseline_wire.written(), retained_wire.written());
    // A stale per-slot counter snapshot cannot bypass the existing interaction
    // check, even though it is permitted as untrusted cache content on load.
    restored.snapshots[0][0] ^= 1;
    var bad_first = try stage_mod.ForBackend(Cpu).borrowRetained(a, &first.scheme, &restored.scheme, restored.snapshots, &proposed);
    defer bad_first.deinit(a);
    try std.testing.expectError(error.ExecutionRangeCounterChangedAfterSeal, sidecar.ForPackedBackend(Cpu).proveForNativeFirstRound(a, &bad_first, restored.source.inputs, restored.source.slots, sealed, pins, &entries, catalog, &first, 0, proposed.witness_root));
    restored.snapshots[0][0] ^= 1;
    {
        var altered = try Store.load(a, temp.dir, "access.pcs", &proposed_native, &proposed, owner, checkpoint, .{ .source = limits });
        defer altered.deinit(a);
        for (@constCast(altered.scheme.trees.items[0].columns[0].values)) |*value| value.* = value.add(core.fields.m31.M31.one());
        var altered_first = try stage_mod.ForBackend(Cpu).borrowRetained(a, &first.scheme, &altered.scheme, altered.snapshots, &proposed);
        defer altered_first.deinit(a);
        try std.testing.expectError(error.ConstraintsNotSatisfied, sidecar.ForPackedBackend(Cpu).proveForNativeFirstRound(a, &altered_first, altered.source.inputs, altered.source.slots, sealed, pins, &entries, catalog, &first, 0, proposed.witness_root));
    }
    const proof = Native.proveWithCatalog(a, &first, sealed, pins, &entries, catalog) catch |err| {
        std.debug.print("WARM_MEMORY native prove error={s}\n", .{@errorName(err)});
        return err;
    };
    const fresh = try Native.verifyOwnedWithCatalog(a, proof, &owner.statement, candidate.admission, first.template, first.template_id, .rv32im_zkvm_v1, 0, sealed, pins, &entries, catalog);
    const fixed_logs = try @import("../block_v5_native_template_protocol_v3.zig").columnLogs(a, &owner.statement, 0, .fixed);
    defer a.free(fixed_logs);
    const main_logs = try @import("../block_v5_native_template_protocol_v3.zig").columnLogs(a, &owner.statement, 0, .main);
    defer a.free(main_logs);
    const received = capture.proof.?;
    capture.proof = null;
    var fresh_sidecar = try sidecar.ForPackedBackend(Cpu).verifyOwned(a, received, sealed, pins, &entries, catalog, &fresh, 0, proposed.slots, fixed_logs, main_logs, proposed.witness_root, config);
    defer fresh_sidecar.deinit(a);
    try std.testing.expectEqual(@as(u64, 2), fresh_sidecar.event_count);
    try std.testing.expect(fresh_sidecar.packed_transition);
    std.debug.print("ACCESS_CHECKPOINT verified=true proof_byte_parity=true original_pcs_destroyed=true bytes={d} raw_witness_bytes={d} column_bytes={d} merkle_bytes={d} loaded_bytes={d} global_claims_open=true\n", .{ checkpoint.bytes, checkpoint.raw_witness_bytes, checkpoint.column_bytes, checkpoint.merkle_bytes, checkpoint.loaded_bytes });
}
fn loadAndRelease(a: std.mem.Allocator, dir: std.fs.Dir, native_proposal: *const physical.Proposal, proposal: *const stage_mod.Proposal, owner: *@import("../blake3_execution_trace.zig").Owner, pin: Store.Pin, limits: stage_mod.Limits) !void {
    var restored = try Store.load(a, dir, "access.pcs", native_proposal, proposal, owner, pin, .{ .source = limits });
    defer restored.deinit(a);
}
