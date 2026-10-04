const std = @import("std");
const core = @import("stwo_core");
const suite = core.proof_suites.Blake3;
const postcard = @import("interop_postcard");
const batch = @import("../block_memory_batch_verify_v2.zig");
const memory = @import("../../air/block/memory_component.zig");
const trace_mod = @import("../../air/block/memory_component_trace.zig");
const counter_mod = @import("../../air/lookups/tables/counter.zig");
const shard_mod = @import("../block_memory_range_shard_v2.zig");
const instance_proof = @import("../block_memory_shared_instance_proof_v2.zig");
const table_proof = @import("../block_memory_shared_table_proof_v2.zig");
const seal_mod = @import("../block_memory_source_seal_v2.zig");

test "batch receiver freshly verifies serialized memory and shared-table proofs" {
    const a = std.testing.allocator;
    const Cpu = @import("stwo_cpu_backend").CpuBackend;
    const t = @import("../../air/block/memory_transition.zig").Transition{
        .space = 1,
        .address = 4096,
        .clock = 1,
        .before = 0,
        .after = 7,
    };
    const claim = try memory.Claim.fromSummary(.{ .first_row = 0, .rows = 1, .first = t, .last = t }, 1, 8, null);
    var trace = try trace_mod.Trace.init(a, claim);
    defer trace.deinit();
    try trace.append(t);
    try trace.seal();
    var counter = try counter_mod.Counter.init(a, .range_check_8_8);
    defer counter.deinit(a);
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    const memory_api = instance_proof.ForBackend(Cpu);
    var memory_first = try memory_api.commitFirstRound(a, &trace, &counter, 0, config);
    defer memory_first.deinit(a);
    var plan = try shard_mod.plan(a, &.{claim}, 1);
    defer plan.deinit(a);
    const table_api = table_proof.ForBackend(Cpu);
    var table_first = try table_api.commitFirstRound(a, &counter, plan.shards[0], config);
    defer table_first.deinit(a);
    const memory_pins = [_]batch.MemoryPin{.{ .claim = claim, .roots = memory_first.roots }};
    const table_pins = [_]batch.Roots{table_first.roots};
    const execution_pins = [_]batch.Roots{.{ @splat(31), @splat(32) }};
    const source_pins = [_]seal_mod.FirstRoundEntry{.{ .family = .initial_rw, .index = 0, .roots = .{ @splat(33), @splat(34) } }};
    const base = @import("../block_commitment_manifest.zig").Sealed{ .digest = @splat(35), .instance_count = 1 };
    var pinned = batch.PinnedStatement{
        .seal = try seal_mod.SourceSeal.init(base, 0, @splat(36)),
        .expected_events = 1,
        .memory_instances = &memory_pins,
        .range_table_roots = &table_pins,
        .execution_roots = &execution_pins,
        .provider_roots = &source_pins,
    };
    pinned.seal = try seal_mod.SourceSeal.initBound(base, 0, @splat(36), 1, 1, plan.digest, try pinned.firstRoundDigest(a));
    var memory_proved = try memory_api.prove(a, &memory_first, &trace, pinned.seal, 0, memory_first.roots);
    defer memory_proved.deinit(a);
    var table_proved = try table_api.prove(a, &table_first, &counter, plan.shards[0], pinned.seal, table_first.roots);
    defer table_proved.deinit(a);
    var memory_bytes = std.Io.Writer.Allocating.init(a);
    defer memory_bytes.deinit();
    try postcard.serializeProof(suite.Hasher, &memory_bytes.writer, memory_proved.stark);
    var table_bytes = std.Io.Writer.Allocating.init(a);
    defer table_bytes.deinit();
    try postcard.serializeProof(suite.Hasher, &table_bytes.writer, table_proved.stark);
    const memory_wire = [_]batch.SerializedMemoryProof{.{
        .stark_bytes = memory_bytes.written(),
        .interaction_claim = memory_proved.relation,
        .range_claims = memory_proved.range_claims,
    }};
    const table_wire = [_]batch.SerializedTableProof{.{ .stark_bytes = table_bytes.written(), .claim = table_proved.claim }};
    const received = batch.SerializedBatch{
        .memory = &memory_wire,
        .range_tables = &table_wire,
        .execution = &.{&.{}},
        .initial_sources = &.{&.{}},
    };
    try batch.verifyMemoryRangeOnly(Cpu, a, pinned, received, config);
    try std.testing.expectError(error.ExecutionAndInitialProofVerifiersUnimplemented, batch.verifyCompleteBlock(Cpu, a, pinned, received, config));

    var tampered = memory_wire;
    tampered[0].stark_bytes = memory_bytes.written()[0 .. memory_bytes.written().len - 1];
    const truncated = batch.SerializedBatch{
        .memory = &tampered,
        .range_tables = &table_wire,
        .execution = received.execution,
        .initial_sources = received.initial_sources,
    };
    try std.testing.expectError(error.EndOfStream, batch.verifyMemoryRangeOnly(Cpu, a, pinned, truncated, config));
}
