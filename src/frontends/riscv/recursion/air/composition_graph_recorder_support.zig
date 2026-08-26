//! Internal composition graph recorder authority shard; use composition_graph_recorder.zig publicly.

const dependency_0 = @import("composition_graph_recorder_builder.zig");
const dependency_1 = @import("composition_graph_recorder_record_component.zig");

const Builder = dependency_0.Builder;
const ChallengeSet = dependency_0.ChallengeSet;
const DenominatorCache = dependency_1.DenominatorCache;
const M31 = dependency_0.M31;
const QM31 = dependency_0.QM31;
const Scalar = dependency_0.Scalar;
const canonic = dependency_0.canonic;
const circle = dependency_0.circle;
const direct = dependency_0.direct;
const frameworkConstraintNative = dependency_1.frameworkConstraintNative;
const pointFromSeed = dependency_1.pointFromSeed;
const quotientDenominator = dependency_1.quotientDenominator;
const reconstructSplitComposition = dependency_1.reconstructSplitComposition;
const recordComponent = dependency_1.recordComponent;
const relation_interaction = dependency_0.relation_interaction;
const std = dependency_0.std;
const stwo_core = dependency_0.stwo_core;
const universal = dependency_0.universal;

test "R-012 recorder matches native component quotient and split composition" {
    const control = @import("control.zig");
    const Runtime = relation_interaction.Runtime(
        control.LOGICAL_INPUT_COUNT,
        control.RELATION_EVENT_COUNT,
        control.LOOKUP_BATCH_SIZE,
    );
    const FakeComponent = struct {
        direct: direct.Program,
        relation_plan: Runtime.Plan,
        claimed_sum_shift: QM31,
    };

    var definition = try control.build(std.testing.allocator);
    defer definition.deinit();
    const component = FakeComponent{
        .direct = try direct.authenticate(
            &definition.arena,
            control.SEMANTIC_DIGEST,
            control.LOGICAL_INPUT_COUNT,
        ),
        .relation_plan = try Runtime.authenticate(
            &definition.arena,
            control.SEMANTIC_DIGEST,
            definition.events,
        ),
        .claimed_sum_shift = QM31.fromU32Unchecked(9, 8, 7, 6),
    };

    var builder = Builder.init(std.testing.allocator);
    defer builder.deinit();
    var graph_row: [control.LOGICAL_INPUT_COUNT]Scalar = undefined;
    var native_row: [control.LOGICAL_INPUT_COUNT]QM31 = undefined;
    for (&graph_row, &native_row, 0..) |*symbolic, *concrete, index| {
        symbolic.* = (try builder.input()).value;
        concrete.* = QM31.fromBase(M31.fromU64(index + 1));
    }
    var graph_current: [Runtime.BATCH_COUNT]Scalar = undefined;
    var native_current: [Runtime.BATCH_COUNT]QM31 = undefined;
    for (&graph_current, &native_current, 0..) |*symbolic, *concrete, index| {
        symbolic.* = (try builder.input()).value;
        concrete.* = QM31.fromBase(M31.fromU64(index + 31));
    }
    const graph_previous = (try builder.input()).value;
    const native_previous = QM31.fromBase(M31.fromU64(41));
    const graph_random = (try builder.input()).value;
    const native_random = QM31.fromBase(M31.fromU64(43));
    const graph_seed = (try builder.input()).value;
    const native_seed = QM31.fromBase(M31.fromU64(47));
    var graph_chunks: [2]Scalar = undefined;
    var native_chunks: [2]QM31 = undefined;
    for (&graph_chunks, &native_chunks, 0..) |*symbolic, *concrete, index| {
        symbolic.* = (try builder.input()).value;
        concrete.* = QM31.fromBase(M31.fromU64(index + 53));
    }

    var native_direct_scratch: [direct.MAX_NODES]QM31 = undefined;
    var native_direct: [control.DIRECT_CONSTRAINT_COUNT]QM31 = undefined;
    try component.direct.evaluateSecureInto(
        &native_row,
        &native_direct_scratch,
        &native_direct,
    );
    const native_relations = universal.UniversalRelations.dummy();
    const native_pairs = try component.relation_plan.preparedSecureRowPairs(
        native_row,
        &native_relations,
    );
    const native_point = circle.secureFieldPointFromRandomSeed(native_seed);
    const log_size: u32 = 4;
    const max_log_degree_bound: u32 = 6;
    const native_denominator = try stwo_core.constraints.cosetVanishing(
        QM31,
        canonic.CanonicCoset.new(log_size).coset(),
        native_point.repeatedDouble(max_log_degree_bound - log_size),
    ).inv();
    var native_accumulation = QM31.zero();
    for (native_direct) |root| native_accumulation = native_accumulation
        .mul(native_random)
        .add(root.mul(native_denominator));
    for (native_pairs, 0..) |pair, batch| {
        const final = batch + 1 == Runtime.BATCH_COUNT;
        const previous_column = if (batch == 0)
            QM31.zero()
        else
            native_current[batch - 1];
        const root = frameworkConstraintNative(
            native_current[batch],
            if (final) native_previous else QM31.zero(),
            previous_column,
            if (final) component.claimed_sum_shift else QM31.zero(),
            pair,
        );
        native_accumulation = native_accumulation
            .mul(native_random)
            .add(root.mul(native_denominator));
    }

    try builder.activate();
    defer if (builder.active) builder.deactivate();
    var symbolic_draws: [universal.RELATION_COUNT][2]Scalar = undefined;
    for (&symbolic_draws, native_relations.elements) |*pair, element| {
        pair.* = .{
            Scalar.fromSecure(element.z),
            Scalar.fromSecure(element.alpha),
        };
    }
    const graph_relations = try ChallengeSet.init(symbolic_draws);
    const graph_point = pointFromSeed(graph_seed);
    var denominator_cache: DenominatorCache = .{null} **
        circle.M31_CIRCLE_LOG_ORDER;
    const graph_denominator = try quotientDenominator(
        log_size,
        max_log_degree_bound,
        graph_point,
        &denominator_cache,
    );
    var graph_accumulation = Scalar.zero();
    try std.testing.expectEqual(
        @as(usize, control.DIRECT_CONSTRAINT_COUNT + Runtime.BATCH_COUNT),
        try recordComponent(
            Runtime,
            &component,
            graph_row,
            graph_current,
            graph_previous,
            Scalar.fromSecure(component.claimed_sum_shift),
            &graph_relations,
            graph_random,
            graph_denominator,
            &graph_accumulation,
        ),
    );
    try builder.constrainZero(
        graph_accumulation.sub(Scalar.fromSecure(native_accumulation)),
    );

    const graph_composition = try reconstructSplitComposition(
        &graph_chunks,
        graph_point,
        5,
        1,
    );
    const native_composition = native_chunks[0].add(
        native_point.repeatedDouble(3).x.mul(native_chunks[1]),
    );
    try builder.constrainZero(
        graph_composition.sub(Scalar.fromSecure(native_composition)),
    );

    builder.deactivate();
    var circuit = try builder.finish();
    defer circuit.deinit();
    var native_inputs: [
        control.LOGICAL_INPUT_COUNT +
            Runtime.BATCH_COUNT + 5
    ]QM31 = undefined;
    var cursor: usize = 0;
    for (native_row) |value| {
        native_inputs[cursor] = value;
        cursor += 1;
    }
    for (native_current) |value| {
        native_inputs[cursor] = value;
        cursor += 1;
    }
    for ([_]QM31{
        native_previous,
        native_random,
        native_seed,
        native_chunks[0],
        native_chunks[1],
    }) |value| {
        native_inputs[cursor] = value;
        cursor += 1;
    }
    try std.testing.expectEqual(native_inputs.len, cursor);
    const values = try std.testing.allocator.alloc(QM31, circuit.nodes.len);
    defer std.testing.allocator.free(values);
    try circuit.evaluateInto(&native_inputs, values);
}
