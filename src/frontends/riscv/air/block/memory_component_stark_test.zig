const std = @import("std");
const Q = @import("stwo_core").fields.qm31.QM31;
const component = @import("memory_component.zig");
const trace = @import("memory_component_trace.zig");
const evaluator = @import("memory_component_eval.zig");
const range = @import("memory_range_interaction_v2.zig");
const bus = @import("../../prover/block_memory_relation_v2.zig");
const stark = @import("memory_component_stark.zig");
const Component = stark.Component;
const fixed_count = stark.fixed_count;
const main_count = stark.main_count;
const interaction_count = stark.interaction_count;
const expansion_bits = stark.expansion_bits;
const composeInputs = stark.composeInputs;
const interactionPoint = stark.interactionPoint;
const rangeSums = stark.rangeSums;

test "sorted memory Stwo adapter exposes prover and verifier quotient geometry" {
    const first = @import("memory_transition.zig").Transition{ .space = 1, .address = 4096, .clock = 1, .before = 7, .after = 8 };
    const summary = @import("memory_instance.zig").Summary{ .first_row = 0, .rows = 1, .first = first, .last = first };
    const claim = try component.Claim.fromSummary(summary, 1, 1, null);
    var definition = try component.build(std.testing.allocator, claim);
    defer definition.deinit();
    const range_plan = try range.RangePlan.init(&definition);
    const sealed = @import("../../prover/block_commitment_manifest.zig").Sealed{ .digest = @splat(7), .instance_count = 1 };
    const challenges = try bus.Challenges.draw(std.testing.allocator, sealed);
    var adapter = try Component.init(&definition, claim, .{ .instance_index = 0, .transition_sum = Q.zero(), .link_sum = Q.zero() }, &range_plan, @splat(Q.zero()), &challenges, .{});
    _ = adapter.asProverComponent();
    _ = adapter.asVerifierComponent();
    try std.testing.expect(adapter.nConstraints() > 100);
    try std.testing.expectEqual(claim.log_size + expansion_bits, adapter.maxConstraintLogDegreeBound());
    try std.testing.expectEqual(expansion_bits, adapter.compositionLogSplit());
}

test "sorted memory v2 quotient closes across active rows and padded domain" {
    const Transition = @import("memory_transition.zig").Transition;
    const Summary = @import("memory_instance.zig").Summary;
    const first = Transition{ .space = 1, .address = 4096, .clock = 1, .before = 7, .after = 8 };
    const second = Transition{ .space = 1, .address = 4096, .clock = 5, .before = 8, .after = 9 };
    const claim = try component.Claim.fromSummary(Summary{ .first_row = 0, .rows = 2, .first = first, .last = second }, 2, 2, null);
    var definition = try component.build(std.testing.allocator, claim);
    defer definition.deinit();
    var witness_trace = try trace.Trace.init(std.testing.allocator, claim);
    defer witness_trace.deinit();
    try witness_trace.append(first);
    try witness_trace.append(second);
    try witness_trace.seal();
    const sealed = @import("../../prover/block_commitment_manifest.zig").Sealed{ .digest = @splat(7), .instance_count = 1 };
    const challenges = try bus.Challenges.draw(std.testing.allocator, sealed);
    var generated = try bus.generateInteractionFromSource(std.testing.allocator, &challenges, 0, .sorted, &witness_trace, claim.log_size);
    defer generated.deinit(std.testing.allocator);
    const range_plan = try range.RangePlan.init(&definition);
    var counter = try @import("../lookups/tables/counter.zig").Counter.init(std.testing.allocator, .range_check_8_8);
    defer counter.deinit(std.testing.allocator);
    const snapshot = try range.collectCounter(std.testing.allocator, &range_plan, &definition, &witness_trace, &counter);
    var range_generated = try range.generate(std.testing.allocator, &range_plan, &definition, &witness_trace, challenges.universal_prefix.get(.range_check_8_8), snapshot);
    defer range_generated.deinit(std.testing.allocator);
    for (0..witness_trace.domainSize()) |logical| {
        const physical = trace.committedRow(logical, claim.log_size);
        const prior_physical = trace.committedRow(if (logical == 0) witness_trace.domainSize() - 1 else logical - 1, claim.log_size);
        var fixed: [fixed_count]Q = undefined;
        var main: [main_count]Q = undefined;
        var previous: [main_count]Q = undefined;
        var interaction: [interaction_count]Q = undefined;
        var prior_interaction: [interaction_count]Q = undefined;
        for (&fixed, 0..) |*value, i| value.* = Q.fromBase(witness_trace.fixedColumn(i)[physical]);
        for (&main, &previous, 0..) |*value, *before, i| {
            value.* = Q.fromBase(witness_trace.mainColumn(i)[physical]);
            before.* = Q.fromBase(witness_trace.mainColumn(i)[prior_physical]);
        }
        for (&interaction, &prior_interaction, 0..) |*value, *before, i| {
            value.* = if (i < 12) Q.fromBase(generated.columns[i][physical]) else Q.fromBase(range_generated.columns[i - 12][physical]);
            before.* = if (i < 12) Q.fromBase(generated.columns[i][prior_physical]) else Q.fromBase(range_generated.columns[i - 12][prior_physical]);
        }
        const source = composeInputs(fixed, main, previous);
        const scratch = try std.testing.allocator.alloc(Q, definition.arena.nodeCount());
        defer std.testing.allocator.free(scratch);
        const direct = try std.testing.allocator.alloc(Q, definition.arena.constraintsView().len);
        defer std.testing.allocator.free(direct);
        try evaluator.evaluate(Q, &definition.arena, &source, scratch, direct);
        for (direct) |residual| try std.testing.expect(residual.isZero());
        for (try bus.interactionConstraints(&challenges, .sorted, interactionPoint(fixed, main, interaction, prior_interaction), generated.claim, @intCast(witness_trace.domainSize()))) |residual| try std.testing.expect(residual.isZero());
        const point = interactionPoint(fixed, main, interaction, prior_interaction);
        try std.testing.expect(point.link_emit.eql(fixed[trace.fixed.active].sub(fixed[trace.fixed.global_last])));
        try std.testing.expect(point.link_consume.eql(fixed[trace.fixed.active].sub(fixed[trace.fixed.global_first])));
        for (try range_plan.evaluateAt(scratch, rangeSums(interaction), rangeSums(prior_interaction), fixed[trace.fixed.first], range_generated.claims, challenges.universal_prefix.get(.range_check_8_8))) |residual| try std.testing.expect(residual.isZero());
        if (logical == 0) {
            var altered_prior = prior_interaction;
            altered_prior[8] = altered_prior[8].add(Q.one());
            const cyclic_bad = try bus.interactionConstraints(&challenges, .sorted, interactionPoint(fixed, main, interaction, altered_prior), generated.claim, @intCast(witness_trace.domainSize()));
            try std.testing.expect(!cyclic_bad[2].isZero());
            var altered = interaction;
            altered[4] = altered[4].add(Q.one());
            const initial_bad = try bus.interactionConstraints(&challenges, .sorted, interactionPoint(fixed, main, altered, prior_interaction), generated.claim, @intCast(witness_trace.domainSize()));
            try std.testing.expect(!initial_bad[1].isZero());
            altered = interaction;
            altered[12] = altered[12].add(Q.one());
            const range_bad = try range_plan.evaluateAt(scratch, rangeSums(altered), rangeSums(prior_interaction), fixed[trace.fixed.first], range_generated.claims, challenges.universal_prefix.get(.range_check_8_8));
            try std.testing.expect(!range_bad[0].isZero());
        }
        if (logical + 1 == witness_trace.domainSize()) {
            var altered = interaction;
            altered[8] = altered[8].add(Q.one());
            const terminal_bad = try bus.interactionConstraints(&challenges, .sorted, interactionPoint(fixed, main, altered, prior_interaction), generated.claim, @intCast(witness_trace.domainSize()));
            try std.testing.expect(!terminal_bad[3].isZero());
        }
    }
}
