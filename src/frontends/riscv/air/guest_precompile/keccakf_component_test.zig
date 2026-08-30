//! Construction and adapter-surface tests for the Keccak shard component.

const std = @import("std");
const authority = @import("keccakf_authority.zig");
const call_buffer = @import("../../runner/guest_precompile/keccakf_call_buffer.zig");
const component_mod = @import("keccakf_component.zig");
const counters_mod = @import("keccakf_multiplicities.zig");
const interaction_mod = @import("keccakf_interaction.zig");
const relations_mod = @import("keccakf_relations.zig");
const trace_mod = @import("keccakf_trace.zig");
const work_pool = @import("stwo_prover_engine").work_pool;

fn record(seed: u32) call_buffer.Record {
    var input: [call_buffer.word_count]u32 = undefined;
    for (&input, 0..) |*word, index| word.* = seed +% @as(u32, @intCast(index * 19));
    var state = trace_mod.stateFromWords(input);
    authority.permute(&state);
    var output: [call_buffer.word_count]u32 = undefined;
    for (state, 0..) |lane, index| {
        output[2 * index] = @truncate(lane);
        output[2 * index + 1] = @truncate(lane >> 32);
    }
    return .{
        .execution_clock = seed + 1,
        .pc = seed + 4,
        .state_ptr = 0x3000,
        .pointer_register = 6,
        .pointer_previous_clock = 0,
        .input = input,
        .output = output,
        .memory_previous_clocks = @splat(0),
    };
}

test "keccakf component: claim and prover/verifier geometry are identical" {
    const records = [_]call_buffer.Record{ record(1), record(2), record(3) };
    var counters = try counters_mod.Counters.init(std.testing.allocator);
    defer counters.deinit();
    var trace = try trace_mod.generateShard(std.testing.allocator, &records, 9, &counters);
    defer trace.deinit();
    const relations = relations_mod.Relations.dummy();
    var pool: work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 1 });
    defer pool.deinit();
    var interaction = try interaction_mod.generate(
        std.testing.allocator,
        &trace,
        &relations,
        &pool,
    );
    defer interaction.deinit(std.testing.allocator);
    const claim = try component_mod.Claim.canonical(&trace, interaction.claims);
    const placement = component_mod.Placement{
        .preprocessed_offset = 0,
        .main_offset = 0,
        .interaction_offset = 0,
    };
    const prover = try component_mod.KeccakShardComponent.initProver(
        claim,
        placement,
        &relations,
    );
    const verifier = try component_mod.KeccakShardComponent.initVerifier(
        claim,
        placement,
        &relations,
    );
    try std.testing.expectEqual(
        component_mod.constraint_count,
        prover.asProverComponent().nConstraints(),
    );
    try std.testing.expectEqual(
        prover.maxConstraintLogDegreeBound(),
        verifier.maxConstraintLogDegreeBound(),
    );
    var bounds = try prover.traceLogDegreeBounds(std.testing.allocator);
    defer bounds.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 3), bounds.items.len);
    try std.testing.expectEqual(
        @as(usize, component_mod.preprocessed_column_count),
        bounds.items[0].len,
    );
    try std.testing.expectEqual(
        @as(usize, component_mod.main_column_count),
        bounds.items[1].len,
    );
    try std.testing.expectEqual(
        @as(usize, component_mod.interaction_column_count),
        bounds.items[2].len,
    );

    const displaced = try component_mod.KeccakShardComponent.initProver(
        claim,
        .{
            .preprocessed_offset = 31,
            .main_offset = 17,
            .interaction_offset = 9,
        },
        &relations,
    );
    var displaced_bounds = try displaced.traceLogDegreeBounds(std.testing.allocator);
    defer displaced_bounds.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(bounds.items[0].len, displaced_bounds.items[0].len);
    try std.testing.expectEqual(bounds.items[1].len, displaced_bounds.items[1].len);
    try std.testing.expectEqual(bounds.items[2].len, displaced_bounds.items[2].len);

    var forged = claim;
    forged.n_rows += 1;
    try std.testing.expectError(error.InvalidClaim, forged.validate());
    var sums = claim.batch_sums;
    sums[0] = sums[0].add(@import("stwo_core").fields.qm31.QM31.one());
    forged = claim;
    forged.batch_sums = sums;
    try std.testing.expectError(error.InvalidClaim, forged.validate());
}
