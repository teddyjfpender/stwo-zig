const std = @import("std");
const core = @import("stwo_core");
const memory = @import("../../air/block/memory_component.zig");
const seal_mod = @import("../block_memory_source_seal_v2.zig");
const shard_mod = @import("../block_memory_range_shard_v2.zig");
const batch = @import("../block_memory_batch_verify_v2.zig");
const MemoryPin = batch.MemoryPin;
const Roots = batch.Roots;
const PinnedStatement = batch.PinnedStatement;
const SerializedBatch = batch.SerializedBatch;
const PublicInitialSource = batch.PublicInitialSource;
const verifyBlockCoreEthereumSha = batch.verifyBlockCoreEthereumSha;
const table_proof = @import("../block_memory_shared_table_proof_v2.zig");
const postcard = @import("interop_postcard");
const suite = core.proof_suites.Blake3;
const decodeStark = batch.decodeStark;

test "batch statement seals exact memory, shard, and first-round rosters" {
    const a = std.testing.allocator;
    const t = @import("../../air/block/memory_transition.zig").Transition{
        .space = 1,
        .address = 4096,
        .clock = 1,
        .before = 0,
        .after = 7,
    };
    const claim = try memory.Claim.fromSummary(.{ .first_row = 0, .rows = 1, .first = t, .last = t }, 1, 1, null);
    const pins = [_]MemoryPin{.{ .claim = claim, .roots = .{ @splat(1), @splat(2) } }};
    const table_roots = [_]Roots{.{ @splat(3), @splat(4) }};
    const execution_roots = [_]Roots{.{ @splat(5), @splat(6) }};
    const source_roots = [_]seal_mod.FirstRoundEntry{.{ .family = .initial_rw, .index = 0, .roots = .{ @splat(7), @splat(8) } }};
    const base = @import("../block_commitment_manifest.zig").Sealed{ .digest = @splat(9), .instance_count = 1 };
    var statement = PinnedStatement{
        .seal = try seal_mod.SourceSeal.init(base, 0, @splat(10)),
        .expected_events = 1,
        .memory_instances = &pins,
        .range_table_roots = &table_roots,
        .execution_roots = &execution_roots,
        .provider_roots = &source_roots,
    };
    try std.testing.expectError(error.UnboundBlockProofRoster, statement.validate(a));
    var planned = try shard_mod.plan(a, &.{claim}, 1);
    defer planned.deinit(a);
    statement.seal = try seal_mod.SourceSeal.initBound(base, 0, @splat(10), 1, 1, planned.digest, try statement.firstRoundDigest(a));
    var admitted = try statement.validate(a);
    admitted.deinit(a);
    var changed_memory = pins;
    changed_memory[0].roots[1][0] ^= 1;
    statement.memory_instances = &changed_memory;
    try std.testing.expectError(error.UnsealedFirstRoundRoster, statement.validate(a));
    statement.memory_instances = &pins;
    var changed_seal = statement.seal;
    changed_seal.range_shard_digest[0] ^= 1;
    statement.seal = changed_seal;
    try std.testing.expectError(error.UnsealedRangeShardRoster, statement.validate(a));
    statement.seal.range_shard_digest = planned.digest;
    statement.seal.memory_instance_count = 2;
    try std.testing.expectError(error.InvalidBlockProofRoster, statement.validate(a));
    statement.seal.memory_instance_count = 1;
    changed_memory = pins;
    changed_memory[0].claim.total_rows = 2;
    statement.memory_instances = &changed_memory;
    try std.testing.expectError(error.InvalidMemoryInstanceCensus, statement.validate(a));
    statement.memory_instances = &pins;
    const two_execution_roots = [_]Roots{ execution_roots[0], .{ @splat(11), @splat(12) } };
    statement.execution_roots = &two_execution_roots;
    statement.seal = try seal_mod.SourceSeal.initBound(base, 0, @splat(10), 2, 1, planned.digest, try statement.firstRoundDigest(a));
    var independent_count = try statement.validate(a);
    independent_count.deinit(a);
    try std.testing.expectError(error.MissingExecutionSidecarRoots, statement.requireExecutionSidecars(a));
    const sidecars = [_]Roots{ .{ @splat(41), @splat(0) }, .{ @splat(42), @splat(0) } };
    const active_counts = [_]u64{ 2, 3 };
    const execution_tables = [_]Roots{.{ @splat(43), @splat(44) }};
    statement.execution_sidecar_roots = &sidecars;
    statement.execution_active_counts = &active_counts;
    statement.execution_range_table_roots = &execution_tables;
    statement.seal = try seal_mod.SourceSeal.initBound(base, 0, @splat(10), 2, 1, planned.digest, try statement.firstRoundDigest(a));
    try statement.requireExecutionSidecars(a);
    var with_sidecars = try statement.validate(a);
    with_sidecars.deinit(a);
    var changed_sidecars = sidecars;
    changed_sidecars[1][0][0] ^= 1;
    statement.execution_sidecar_roots = &changed_sidecars;
    try std.testing.expectError(error.UnsealedFirstRoundRoster, statement.validate(a));
    statement.execution_sidecar_roots = &sidecars;
    changed_sidecars[1][1][0] = 1;
    statement.execution_sidecar_roots = &changed_sidecars;
    try std.testing.expectError(error.InvalidExecutionSidecarRoster, statement.requireExecutionSidecars(a));
    statement.execution_sidecar_roots = &sidecars;
    var changed_counts = active_counts;
    changed_counts[0] += 1;
    statement.execution_active_counts = &changed_counts;
    try std.testing.expectError(error.UnsealedFirstRoundRoster, statement.validate(a));
    statement.execution_active_counts = &active_counts;
    var changed_tables = execution_tables;
    changed_tables[0][0][0] ^= 1;
    statement.execution_range_table_roots = &changed_tables;
    try std.testing.expectError(error.UnsealedFirstRoundRoster, statement.validate(a));
    statement.execution_range_table_roots = &execution_tables;
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    const empty = SerializedBatch{ .memory = &.{}, .range_tables = &.{}, .execution = &.{}, .initial_sources = &.{} };
    try std.testing.expectError(error.MissingCompleteBlockPublicPins, statement.requireCompletePins(@splat(51)));
    const span = @import("../../recursion/span_statement_blake3.zig");
    const registers: [32]u32 = @splat(0);
    const entry = try span.MachineState.init(4, registers, .{ .bytes = @splat(51) }, .{ .bytes = @splat(0) });
    const exit_state = try span.MachineState.init(8, registers, .{ .bytes = @splat(51) }, .{ .bytes = @splat(0) });
    const complete = try span.CompleteExecution.init(.{ .bytes = @splat(56) }, .{ .bytes = @splat(55) }, entry, exit_state, .{ .bytes = @splat(57) }, .{ .bytes = @splat(58) }, 2);
    const job = try span.JobContext.init(complete, 2);
    statement.complete_pins = .{ .expected_job = job, .initial_rw_anchor = @splat(51), .program_root = @splat(55), .outer_recursive_key_id = @splat(52), .forest_roster_digest = @splat(53) };
    _ = try statement.requireCompletePins(@splat(51));
    try std.testing.expectError(error.InitialRwAnchorMismatch, statement.requireCompletePins(@splat(54)));
    const no_source = PublicInitialSource{ .pin = undefined, .registers = @splat(0), .files = undefined, .roster = &.{} };
    try std.testing.expectError(error.InvalidExecutionProofCensus, verifyBlockCoreEthereumSha(@import("stwo_cpu_backend").CpuBackend, a, statement, empty, &.{}, no_source, config));
}

test "serialized STARK decoder rejects trailing bytes after a real proof" {
    const a = std.testing.allocator;
    const Cpu = @import("stwo_cpu_backend").CpuBackend;
    const counter_mod = @import("../../air/lookups/tables/counter.zig");
    var counter = try counter_mod.Counter.init(a, .range_check_8_8);
    defer counter.deinit(a);
    const shard = shard_mod.Shard{
        .index = 0,
        .first_instance = 0,
        .instance_count = 1,
        .first_event = 0,
        .event_count = 1,
        .max_requests = 35,
    };
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    const api = table_proof.ForBackend(Cpu);
    var first = try api.commitFirstRound(a, &counter, shard, config);
    defer first.deinit(a);
    const base = @import("../block_commitment_manifest.zig").Sealed{ .digest = @splat(9), .instance_count = 1 };
    const sealed = try seal_mod.SourceSeal.init(base, 0, @splat(10));
    var proof = try api.prove(a, &first, &counter, shard, sealed, first.roots);
    defer proof.deinit(a);
    var bytes = std.Io.Writer.Allocating.init(a);
    defer bytes.deinit();
    try postcard.serializeProof(suite.Hasher, &bytes.writer, proof.stark);
    var decoded = try decodeStark(a, bytes.written());
    decoded.deinit(a);
    try bytes.writer.writeByte(0);
    try std.testing.expectError(error.TrailingSerializedStarkBytes, decodeStark(a, bytes.written()));
}
