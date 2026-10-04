//! Scoped family11 + family13 fixture. Other family roots are placeholders;
//! no complete native/program/range/global memory authority is issued here.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const runner = @import("../../runner/mod.zig");
const profile = @import("../blake3_ethereum_sha_profile.zig");
const family = @import("../block_v5_precompile_family_proof_v1.zig");
const protocol = @import("../block_v5_precompile_protocol_v1.zig");
const seal = @import("../block_v5_source_seal_v1.zig");
const sidecar = @import("../block_v5_external_memory_sidecar_proof_v1.zig");
const old = @import("../block_execution_external_batch_v2.zig");
const source = @import("../block_execution_external_trace_v2.zig");
const counter = @import("../../air/lookups/tables/counter.zig");

test "block-v5 external memory sidecar fresh verifies separate precompile caller roots" {
    try exercise(false);
}
test "block-v5 packed external memory sidecar fresh verifies separate precompile caller roots" {
    try exercise(true);
}
fn exercise(comptime word_mode: bool) !void {
    const Sidecar = if (word_mode) sidecar.ForPackedBackend(Cpu) else sidecar.ForBackend(Cpu);
    const a = std.testing.allocator;
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var scoped = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer scoped.deinit();
    const fixture = @import("../../runner/guest_precompile/test_elf.zig");
    const diagnostic = fixture.buildEthereumSha(.rv32im_zkvm_ethereum_sha_v1);
    const elf = fixture.withReleaseAbi(diagnostic.len, &diagnostic);
    var session = try runner.EthereumShaExecutionSession.init(a, &elf, .{ .clock_frame = .leaf_local, .trace_retention = .segment_owned });
    defer session.deinit();
    var segment = try session.startSegment(16);
    defer segment.deinit();
    var owner = try @import("../block_v5_precompile_witness_v1.zig").Witness.initSegment(a, &segment);
    defer owner.deinit();
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    const execution_id: [32]u8 = @splat(22);
    const Api = family.ForBackend(Cpu);
    var first = try Api.commitFirstRound(a, &owner, owner.total_steps, config, 0, execution_id);
    defer first.deinit(a);
    const fixed = try profile.preprocessed(a, &owner.statement);
    defer {
        for (fixed) |column| a.free(column.values);
        a.free(fixed);
    }
    var main = try profile.mainWitness(a, &owner);
    defer main.deinit(a);
    const fixed_logs = try protocol.columnLogs(a, &owner.statement, .fixed);
    defer a.free(fixed_logs);
    const main_logs = try protocol.columnLogs(a, &owner.statement, .main);
    defer a.free(main_logs);
    const slots = try source.descriptorsFromStatement(a, &owner.statement, fixed_logs, main_logs, .{ .clock_frame = .leaf_local, .global_first_cycle = segment.base.global_first_cycle, .cycle_count = @intCast(segment.base.cycle_count) });
    defer a.free(slots);
    const traces = try a.alloc(source.Trace, slots.len);
    defer a.free(traces);
    var initialized: usize = 0;
    defer for (traces[0..initialized]) |*trace| trace.deinit();
    const inputs = try a.alloc(old.Input, slots.len);
    defer a.free(inputs);
    for (slots, traces, inputs) |slot, *trace, *input| {
        trace.* = try source.Trace.init(a, slot, fixed, main.columns);
        initialized += 1;
        input.* = .{ .descriptor = slot, .trace = trace };
    }
    var multiplicities = try counter.Counter.init(a, .range_check_8_8);
    defer multiplicities.deinit(a);
    var memory_first = try old.ForBackend(Cpu).commitFirstRound(a, fixed, main.columns, inputs, slots, &multiplicities, 0, first.key_id, config);
    defer memory_first.deinit(a);
    try std.testing.expectEqualDeep(first.roots, memory_first.roots[0..2].*);
    if (word_mode) {
        const Demand = @import("../block_v5_memory_byte_demand_v1.zig");
        const byte_demand = try Demand.externalDemand(&owner.statement, slots);
        var independent = try counter.Counter.init(a, .range_check_8_8);
        defer independent.deinit(a);
        const digest = try Demand.collectExternal(a, inputs, slots, byte_demand, &independent);
        try std.testing.expectEqualDeep(digest, @import("../../air/block/memory_range_interaction_v2.zig").counterSnapshot(&multiplicities));
    }
    var counts: [seal.family_count]u32 = @splat(0);
    inline for ([_]seal.Family{ .program, .execution, .execution_sidecar, .program_request, .memory, .precompile, .execution_external_sidecar }) |kind| counts[@intFromEnum(kind) - 1] = 1;
    const pins = seal.Pins{ .job_id = @splat(1), .source_image_digest = @splat(2), .native_template_id = @splat(3), .program_root = @splat(4), .program_plan_digest = @splat(5), .memory_plan_digest = @splat(6), .initial_source_plan_digest = @splat(7), .config = config, .counts = counts };
    const memory_entry = (if (word_mode) sidecar.packedEntry else sidecar.entry)(execution_id, first.instance_id, first.key_id, first.roots, memory_first.roots[2], 0, slots);
    const entries = [_]seal.Entry{
        .{ .family = .program, .index = 0, .instance_id = @splat(10), .roots = .{ @splat(11), @splat(12) } },
        .{ .family = .execution, .index = 0, .instance_id = execution_id, .roots = .{ @splat(13), @splat(14) } },
        .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(15), .roots = .{ @splat(16), @splat(17) } },
        .{ .family = .program_request, .index = 0, .instance_id = @splat(18), .roots = .{ @splat(19), @splat(20) } },
        .{ .family = .memory, .index = 0, .instance_id = @splat(23), .roots = .{ @splat(24), @splat(25) } },
        first.entry(),
        memory_entry,
    };
    const sealed = try seal.seal(pins, &entries);
    const binding = first.binding(sealed);
    const family_proof = try Api.prove(a, &first, sealed, pins, &entries, &pool);
    const memory_proof = try Sidecar.prove(a, &memory_first, inputs, slots, sealed, pins, &entries, &binding, 0, memory_first.roots[2]);
    const receipt = try Api.verifyOwned(a, family_proof, &owner.statement, owner.total_steps, first.key_id, execution_id, 0, sealed, pins, &entries);
    var opposite = try Sidecar.verifyOwned(a, memory_proof, sealed, pins, &entries, &receipt.binding, 0, slots, fixed_logs, main_logs, memory_first.roots[2], config);
    defer opposite.deinit(a);
    try std.testing.expectEqual(try source.expectedEventCount(&owner.statement), opposite.event_count);
    try std.testing.expectEqual(@as(u64, 103), opposite.event_count);
    try std.testing.expectEqual(word_mode, opposite.packed_transition);
    if (word_mode) {
        const Demand = @import("../block_v5_memory_byte_demand_v1.zig");
        _ = try Demand.freshRequests(opposite, try Demand.externalDemand(&owner.statement, slots), sealed.digest);
        const word_protocol = @import("../block_v5_word_memory_protocol_v1.zig");
        const elements = try word_protocol.Challenges.draw(a, sealed);
        var expected = core.fields.qm31.QM31.zero();
        for (traces) |*trace| for (0..trace.domainSize()) |logical| {
            const row = try trace.row(logical);
            if (row.active) expected = expected.add(try elements.transition.combineBase(word_protocol.fromByteTransition(core.fields.m31.M31, row.tuple)).inv());
        };
        try std.testing.expectEqualDeep(expected, opposite.transition_sum);
    }
    try std.testing.expectEqualDeep(receipt.binding.first_roots, opposite.caller_roots);
    try std.testing.expect(!opposite.universal_sum.isZero());
    var changed = receipt.binding;
    changed.first_roots[1][0] ^= 1;
    try std.testing.expectError(error.UntrustedBlockV5PrecompileInstance, protocol.admit(changed, sealed, pins, &entries));
}
