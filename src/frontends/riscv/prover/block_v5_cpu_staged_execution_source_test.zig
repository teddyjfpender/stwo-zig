//! Staged lifetime/physical-root gates. No execution segment is proved.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Runner = @import("../runner/mod.zig");
const fixture = @import("../runner/guest_precompile/test_elf.zig");
const Public = @import("blake3_segment_public.zig");
const Native = @import("blake3_execution_trace.zig");
const Roots = @import("block_v5_cpu_native_root_proposal_v1.zig");
const Admission = @import("block_v5_native_public_admission_v1.zig");
const Planning = @import("block_v5_cpu_driver_admission_v1.zig");
const Stage = @import("block_v5_native_columns_stage_v1.zig");
const Staged = @import("block_v5_cpu_staged_execution_source_v1.zig");
const Names = @import("block_v5_cpu_witness_staging_v1.zig");
const Store = @import("block_v5_witness_columns_store_v1.zig");
const profile = @import("../isa/execution_profile.zig").ExecutionProfile.rv32im_zkvm_ethereum_sha_v1;
const limits = Stage.Limits{ .columns = .{ .max_columns = 1024, .max_log_size = 22, .max_file_bytes = 64 << 20, .max_loaded_bytes = 64 << 20 }, .max_public_words = 1024, .max_public_bytes = 64 << 10 };

test "staged native source moves one recommit and bounds replay lifetime without guest replay" {
    const a = std.testing.allocator;
    const instructions = [_]u32{ 0x00700293, 0x00328313, 0x005302b3, 0x0000006f };
    const elf = fixture.buildReleaseProgram(instructions.len, &instructions, 64, profile);
    var session = try Runner.EthereumShaExecutionSession.init(a, &elf, .{ .clock_frame = .leaf_local, .trace_retention = .segment_owned });
    defer session.deinit();
    var segment = try session.startSegment(3);
    defer segment.deinit();
    var io = try Public.Owned.init(a, &segment.base);
    defer io.deinit();
    io.data.program_root = .{ .bytes = @splat(7) };
    const owner = try Native.Owner.initWithExternal(a, &segment.base.execution_trace, io.data, &segment.base.state_chain_tracker, 0);
    defer owner.deinit();
    try owner.sealNativeOnly();
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    var proposal = try Roots.ForBackend(Cpu).collect(a, owner, config, profile, 0, segment.base.global_first_cycle, .{ .max_public_words = 1024, .max_metadata_bytes = 1 << 20 });
    defer proposal.deinit();
    const pin = try Admission.Admission.init(.{
        .job_id = @splat(1),
        .source_image_digest = @splat(2),
        .program_root = io.data.program_root.?.bytes,
        .program_plan_digest = @splat(3),
        .memory_plan_digest = @splat(4),
        .initial_source_plan_digest = @splat(5),
        .rw_endpoint_plan_digest = @splat(6),
        .execution_index = 0,
        .first_cycle = proposal.first_cycle,
        .last_cycle = proposal.last_cycle,
    }, &proposal.shape.public_data);
    const records = [_]Planning.Record{.{ .physical = proposal, .complete_fetches = &.{}, .caller_fetches = &.{}, .lookup_demand = @splat(0) }};
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var name: [96]u8 = undefined;
    const stored = try Stage.write(a, tmp.dir, try Names.nativeName(0, &name), owner, &proposal, limits);
    var source = try Staged.Source.init(a, tmp.dir, &records, &.{stored}, &.{pin}, limits);
    defer source.deinit();
    try std.testing.expectError(error.IncompleteV5StagedExecution, source.requireFinished());
    {
        const callbacks = source.source();
        var replay = try callbacks.load(callbacks.context, 0);
        defer replay.deinit();
        try std.testing.expect(source.outstanding and source.next == 1);
        try std.testing.expectError(error.InvalidV5StagedExecutionOrder, callbacks.load(callbacks.context, 0));
        try std.testing.expectError(error.IncompleteV5StagedExecution, source.requireFinished());
        var first = try Staged.Source.takeFirstRound(&replay, 0);
        defer first.deinit(a);
        try proposal.requireReplay(&first);
        try std.testing.expect(first.native == replay.owner and first.owns_scheme);
        try std.testing.expectError(error.ChangedV5StagedNativeAdmission, Staged.Source.takeFirstRound(&replay, 0));
    }
    try source.requireFinished();
    try std.testing.expectError(error.InvalidV5StagedExecutionRoster, Staged.Source.init(a, tmp.dir, &records, &.{}, &.{pin}, limits));
    var changed = stored;
    changed.sha256[0] ^= 1;
    var rejected = try Staged.Source.init(a, tmp.dir, &records, &.{changed}, &.{pin}, limits);
    defer rejected.deinit();
    const callbacks = rejected.source();
    try std.testing.expectError(error.TamperedV5WitnessFile, callbacks.load(callbacks.context, 0));
    try std.testing.expect(!rejected.outstanding and rejected.next == 0);
}

test "staged witness aggregate cap is transactional" {
    const tiny = Names.Limits{ .max_total_file_bytes = 16 };
    const pin = Store.Pin{ .bytes = 8, .sha256 = @splat(1) };
    var total: u64 = 0;
    try Names.admitBytes(&total, pin, tiny);
    try Names.admitBytes(&total, pin, tiny);
    try std.testing.expectError(error.V5WitnessAggregateFileLimit, Names.admitBytes(&total, pin, tiny));
    try std.testing.expectEqual(@as(u64, 16), total);
}
