//! Focused challenge-bound byte-table closure and quotient differential.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const memory = @import("memory_component.zig");
const trace_mod = @import("memory_component_trace.zig");
const transition = @import("memory_transition.zig");
const instance = @import("memory_instance.zig");
const evaluator = @import("memory_component_eval.zig");
const range = @import("memory_range_interaction_v2.zig");
const provider_mod = @import("memory_range_provider_v2.zig");
const tables = @import("../lookups/tables/mod.zig");
const bus = @import("../../prover/block_memory_relation_v2.zig");
const manifest = @import("../../prover/block_commitment_manifest.zig");

fn fixture() !struct { definition: memory.Definition, trace: trace_mod.Trace } {
    const first = transition.Transition{ .space = 1, .address = 4096, .clock = 1, .before = 7, .after = 8 };
    const last = transition.Transition{ .space = 1, .address = 4096, .clock = 5, .before = 8, .after = 9 };
    const claim = try memory.Claim.fromSummary(instance.Summary{ .first_row = 0, .rows = 2, .first = first, .last = last }, 2, 1, null);
    var definition = try memory.build(std.testing.allocator, claim);
    errdefer definition.deinit();
    var trace = try trace_mod.Trace.init(std.testing.allocator, claim);
    errdefer trace.deinit();
    try trace.append(first);
    try trace.append(last);
    try trace.seal();
    return .{ .definition = definition, .trace = trace };
}

fn secureAt(result: *const range.Result, batch: usize, physical: usize) Q {
    return Q.fromM31(
        result.columns[4 * batch][physical],
        result.columns[4 * batch + 1][physical],
        result.columns[4 * batch + 2][physical],
        result.columns[4 * batch + 3][physical],
    );
}

test "block V2 range 35 effects close against committed 8x8 provider" {
    var setup = try fixture();
    defer setup.definition.deinit();
    defer setup.trace.deinit();
    const plan = try range.RangePlan.init(&setup.definition);
    var counter = try tables.counter.Counter.init(std.testing.allocator, .range_check_8_8);
    defer counter.deinit(std.testing.allocator);
    const snapshot = try range.collectCounter(std.testing.allocator, &plan, &setup.definition, &setup.trace, &counter);
    try std.testing.expectEqual(@as(u32, 37), counter.signedTotal().toU32());
    var provider_main = try provider_mod.precommit(std.testing.allocator, &counter);
    defer provider_main.deinit(std.testing.allocator);

    const sealed = manifest.Sealed{ .digest = @splat(7), .instance_count = 1 };
    const challenges = try bus.Challenges.draw(std.testing.allocator, sealed);
    const range_challenge = challenges.universal_prefix.get(.range_check_8_8);
    var interaction = try range.generate(std.testing.allocator, &plan, &setup.definition, &setup.trace, range_challenge, snapshot);
    defer interaction.deinit(std.testing.allocator);
    var provider = try provider_mod.finishInteraction(std.testing.allocator, &counter, &challenges, provider_main.counter_snapshot);
    defer provider.deinit(std.testing.allocator);
    _ = try provider.component(0, 0, 0);
    var claim_channel = sealed.sharedChannel();
    try range.mixClaimsInto(interaction.claims, 0, &claim_channel);
    try provider.mixClaimInto(&claim_channel);
    const claims = [_]range.Claims{interaction.claims};
    try std.testing.expect(provider_mod.closed(&claims, &provider));

    const scratch = try std.testing.allocator.alloc(Q, setup.definition.arena.nodeCount());
    defer std.testing.allocator.free(scratch);
    const direct = try std.testing.allocator.alloc(Q, setup.definition.arena.constraintsView().len);
    defer std.testing.allocator.free(direct);
    for (0..setup.trace.domainSize()) |logical| {
        const row = setup.trace.inputRow(logical);
        var inputs: [memory.Layout.len]Q = undefined;
        for (row, &inputs) |value, *out| out.* = Q.fromBase(value);
        try evaluator.evaluate(Q, &setup.definition.arena, &inputs, scratch, direct);
        const physical = trace_mod.committedRow(logical, setup.trace.claim.log_size);
        const previous = trace_mod.committedRow(if (logical == 0) setup.trace.domainSize() - 1 else logical - 1, setup.trace.claim.log_size);
        var current: [range.BATCH_COUNT]Q = undefined;
        var before: [range.BATCH_COUNT]Q = undefined;
        for (&current, &before, 0..) |*now, *prior, batch| {
            now.* = secureAt(&interaction, batch, physical);
            prior.* = secureAt(&interaction, batch, previous);
        }
        const roots = try plan.evaluateAt(scratch, current, before, Q.fromBase(M.fromCanonical(@intFromBool(logical == 0))), interaction.claims, range_challenge);
        for (roots) |root| try std.testing.expect(root.isZero());
    }
}

test "block V2 range rejects changed post-seal multiplicity snapshot" {
    var setup = try fixture();
    defer setup.definition.deinit();
    defer setup.trace.deinit();
    const plan = try range.RangePlan.init(&setup.definition);
    var counter = try tables.counter.Counter.init(std.testing.allocator, .range_check_8_8);
    defer counter.deinit(std.testing.allocator);
    var snapshot = try range.collectCounter(std.testing.allocator, &plan, &setup.definition, &setup.trace, &counter);
    var provider_main = try provider_mod.precommit(std.testing.allocator, &counter);
    defer provider_main.deinit(std.testing.allocator);
    snapshot[0] ^= 1;
    const sealed = manifest.Sealed{ .digest = @splat(7), .instance_count = 1 };
    const challenges = try bus.Challenges.draw(std.testing.allocator, sealed);
    try std.testing.expectError(
        error.BlockRangeCounterChangedAfterSeal,
        range.generate(std.testing.allocator, &plan, &setup.definition, &setup.trace, challenges.universal_prefix.get(.range_check_8_8), snapshot),
    );
    try std.testing.expectEqual(@as(u32, 37), counter.signedTotal().toU32());
    counter.values[0] = counter.values[0].add(M.one());
    try std.testing.expectError(error.BlockRangeCounterChangedAfterSeal, provider_mod.finishInteraction(std.testing.allocator, &counter, &challenges, provider_main.counter_snapshot));
}
