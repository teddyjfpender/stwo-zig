//! Internal composition graph recorder authority shard; use composition_graph_recorder.zig publicly.

const dependency_0 = @import("composition_graph_recorder_builder.zig");

const Builder = dependency_0.Builder;
const ChallengeSet = dependency_0.ChallengeSet;
const Error = dependency_0.Error;
const M31 = dependency_0.M31;
const Pair = dependency_0.Pair;
const QM31 = dependency_0.QM31;
const Scalar = dependency_0.Scalar;
const canonic = dependency_0.canonic;
const circle = dependency_0.circle;
const currentBuilder = dependency_0.currentBuilder;
const direct = dependency_0.direct;
const qm31 = dependency_0.qm31;
const relation = dependency_0.relation;
const relation_interaction = dependency_0.relation_interaction;
const replayDirect = dependency_0.replayDirect;
const std = dependency_0.std;
const universal = dependency_0.universal;
const verifier_types = dependency_0.verifier_types;

/// Replay one exact authenticated LogUp plan.  The `Runtime` comptime argument
/// is the same specialization that produced `plan`; no schema switch or
/// component-specific lookup transcription exists here.
pub fn replayRelation(
    comptime Runtime: type,
    plan: *const Runtime.Plan,
    row: [Runtime.LOGICAL_INPUT_COUNT]Scalar,
    challenges: *const ChallengeSet,
) Error![Runtime.BATCH_COUNT]Pair {
    const slot_count = Runtime.LOGICAL_INPUT_COUNT +
        relation_interaction.MAX_COMPILED_NODES;
    try preflightRelation(Runtime, plan, slot_count);
    var slots: [slot_count]Scalar = undefined;
    @memcpy(slots[0..Runtime.LOGICAL_INPUT_COUNT], &row);
    for (plan.compiled_nodes[0..plan.compiled_node_count]) |node| {
        slots[node.destination] = switch (node.op) {
            .constant => |value| Scalar.fromBase(M31.fromU64(value)),
            .add => |binary| slots[binary.lhs].add(slots[binary.rhs]),
            .sub => |binary| slots[binary.lhs].sub(slots[binary.rhs]),
            .mul => |binary| slots[binary.lhs].mul(slots[binary.rhs]),
            .neg => |operand| slots[operand].neg(),
            .select => |selection| slots[selection.selector]
                .mul(slots[selection.when_true])
                .add(Scalar.one().sub(slots[selection.selector])
                .mul(slots[selection.when_false])),
        };
    }

    var result: [Runtime.BATCH_COUNT]Pair = undefined;
    for (&result, plan.batches) |*pair, batch| {
        const first = try relationFraction(plan.events[batch.first], &slots, challenges);
        if (batch.second) |second| {
            const next = try relationFraction(plan.events[second], &slots, challenges);
            pair.* = .{
                .n1 = first.numerator,
                .d1 = first.denominator,
                .n2 = next.numerator,
                .d2 = next.denominator,
            };
        } else {
            pair.* = .{
                .n1 = first.numerator,
                .d1 = first.denominator,
                .n2 = Scalar.zero(),
                .d2 = Scalar.one(),
            };
        }
    }
    try currentBuilder().check();
    return result;
}

/// Exact framework LogUp constraint used by the universal typed adapter.
pub fn frameworkConstraint(
    current: Scalar,
    previous_row: Scalar,
    previous_column: Scalar,
    claimed_sum_shift: Scalar,
    pair: Pair,
) Scalar {
    const denominator = pair.d1.mul(pair.d2);
    const numerator = pair.n1.mul(pair.d2).add(pair.n2.mul(pair.d1));
    return current
        .sub(previous_row)
        .sub(previous_column)
        .add(claimed_sum_shift)
        .mul(denominator)
        .sub(numerator);
}

/// Records one complete universal typed component in the exact native adapter
/// order: direct compiler roots first, followed by LogUp recurrence roots.
/// The caller supplies already-bound mask values and the cached inverse of the
/// component's coset vanishing polynomial. `claimed_sum_shift` is deliberately
/// explicit: recursive callers must derive it from the claimed-sum graph input,
/// never embed the concrete child proof's claim as a circuit constant. This
/// function performs no component dispatch and allocates no memory.
pub fn recordComponent(
    comptime Runtime: type,
    component: anytype,
    row: [Runtime.LOGICAL_INPUT_COUNT]Scalar,
    interaction_current: [Runtime.BATCH_COUNT]Scalar,
    final_previous_row: Scalar,
    claimed_sum_shift: Scalar,
    challenges: *const ChallengeSet,
    composition_randomness: Scalar,
    denominator_inverse: Scalar,
    accumulation: *Scalar,
) Error!usize {
    var direct_roots: [direct.MAX_CONSTRAINTS]Scalar = undefined;
    const direct_count: usize = component.direct.constraint_count;
    if (direct_count > direct_roots.len) return error.InvalidDirectProgram;
    try replayDirect(
        &component.direct,
        &row,
        direct_roots[0..direct_count],
    );
    for (direct_roots[0..direct_count]) |root|
        accumulate(
            accumulation,
            composition_randomness,
            root,
            denominator_inverse,
        );

    const pairs = try replayRelation(
        Runtime,
        &component.relation_plan,
        row,
        challenges,
    );
    for (pairs, 0..) |pair, batch| {
        const final = batch + 1 == Runtime.BATCH_COUNT;
        const previous_column = if (batch == 0)
            Scalar.zero()
        else
            interaction_current[batch - 1];
        const root = frameworkConstraint(
            interaction_current[batch],
            if (final) final_previous_row else Scalar.zero(),
            previous_column,
            if (final) claimed_sum_shift else Scalar.zero(),
            pair,
        );
        accumulate(
            accumulation,
            composition_randomness,
            root,
            denominator_inverse,
        );
    }
    return direct_count + Runtime.BATCH_COUNT;
}

/// Horner convention shared by native STWO composition accumulation.
pub fn accumulate(
    accumulation: *Scalar,
    random: Scalar,
    constraint: Scalar,
    denominator_inverse: Scalar,
) void {
    accumulation.* = accumulation.mul(random).add(
        constraint.mul(denominator_inverse),
    );
}

pub fn fromPartialEvals(values: [qm31.SECURE_EXTENSION_DEGREE]Scalar) Scalar {
    return values[0]
        .add(values[1].mul(Scalar.fromSecure(
            QM31.fromU32Unchecked(0, 1, 0, 0),
        )))
        .add(values[2].mul(Scalar.fromSecure(
            QM31.fromU32Unchecked(0, 0, 1, 0),
        )))
        .add(values[3].mul(Scalar.fromSecure(
        QM31.fromU32Unchecked(0, 0, 0, 1),
    )));
}

pub fn pointFromSeed(seed: Scalar) circle.CirclePoint(Scalar) {
    const square = seed.square();
    const inverse = square.add(Scalar.one()).inverse();
    return .{
        .x = Scalar.one().sub(square).mul(inverse),
        .y = seed.add(seed).mul(inverse),
    };
}

pub const DenominatorCache = [circle.M31_CIRCLE_LOG_ORDER]?Scalar;

/// Cached inverse of the component-domain vanishing polynomial at the OODS
/// point.  Equal log sizes across the 36-row roster share one graph node.
pub fn quotientDenominator(
    log_size: u32,
    max_log_degree_bound: u32,
    point: circle.CirclePoint(Scalar),
    cache: *DenominatorCache,
) Error!Scalar {
    if (log_size >= cache.len or max_log_degree_bound < log_size)
        return error.InvalidProtocolGeometry;
    if (cache[log_size]) |cached| return cached;
    const coset = canonic.CanonicCoset.new(log_size).coset();
    const folded = point.repeatedDouble(max_log_degree_bound - log_size);
    const shifted = folded
        .sub(.{
            .x = Scalar.fromBase(coset.initial.x),
            .y = Scalar.fromBase(coset.initial.y),
        })
        .add(.{
        .x = Scalar.fromBase(coset.half_step.x),
        .y = Scalar.fromBase(coset.half_step.y),
    });
    var x = shifted.x;
    var round: u32 = 1;
    while (round < coset.log_size) : (round += 1)
        x = circle.CirclePoint(Scalar).doubleX(x);
    const inverse = x.inverse();
    cache[log_size] = inverse;
    return inverse;
}

/// Recombines the split composition-tree columns exactly as the native
/// verifier does.  `chunks` are secure values reconstructed from their four
/// sampled base columns in chunk order.
pub fn reconstructSplitComposition(
    chunks: []const Scalar,
    point: circle.CirclePoint(Scalar),
    composition_log_size: u32,
    split_depth: u32,
) Error!Scalar {
    const chunk_count = verifier_types.compositionChunkCount(split_depth) orelse
        return error.InvalidProtocolGeometry;
    if (chunks.len != chunk_count or composition_log_size <= split_depth)
        return error.InvalidProtocolGeometry;
    var working: [
        @as(usize, 1) <<
            verifier_types.MAX_COMPOSITION_LOG_SPLIT
    ]Scalar = undefined;
    @memcpy(working[0..chunk_count], chunks);
    var active = chunk_count;
    var parent_log = composition_log_size - split_depth + 1;
    while (active > 1) {
        const factor = point.repeatedDouble(parent_log - 2).x;
        var output: usize = 0;
        var input: usize = 0;
        while (input < active) : (input += 2) {
            working[output] = working[input].add(
                factor.mul(working[input + 1]),
            );
            output += 1;
        }
        active /= 2;
        parent_log += 1;
    }
    return working[0];
}

pub fn preflightRelation(
    comptime Runtime: type,
    plan: *const Runtime.Plan,
    comptime slot_count: usize,
) Error!void {
    if (plan.format_version != relation_interaction.FORMAT_VERSION or
        plan.compiled_node_count > relation_interaction.MAX_COMPILED_NODES)
    {
        return error.InvalidRelationPlan;
    }
    for (plan.compiled_nodes[0..plan.compiled_node_count], 0..) |node, ordinal| {
        const destination: usize = node.destination;
        if (destination != Runtime.LOGICAL_INPUT_COUNT + ordinal or
            destination >= slot_count)
            return error.InvalidRelationPlan;
        switch (node.op) {
            .constant => {},
            .add, .sub, .mul => |binary| {
                if (binary.lhs >= destination or binary.rhs >= destination)
                    return error.InvalidRelationPlan;
            },
            .neg => |operand| if (operand >= destination)
                return error.InvalidRelationPlan,
            .select => |selection| if (selection.selector >= destination or
                selection.when_true >= destination or
                selection.when_false >= destination)
            {
                return error.InvalidRelationPlan;
            },
        }
    }
    for (plan.events, 0..) |event, ordinal| {
        const descriptor = relation.universal_descriptors[
            @intFromEnum(event.domain)
        ];
        const schema = relation.get(event.domain);
        const live_slot_count = Runtime.LOGICAL_INPUT_COUNT +
            plan.compiled_node_count;
        if (event.ordinal != ordinal or event.arity == 0 or
            event.arity > universal.MAX_ARITY or
            event.arity != descriptor.arity or
            event.schema != schema.id or
            event.schema_version != schema.version or
            event.numerator_slot >= live_slot_count)
        {
            return error.InvalidRelationPlan;
        }
        for (event.value_slots[0..event.arity]) |slot| {
            if (slot >= live_slot_count) return error.InvalidRelationPlan;
        }
    }
    for (plan.batches, 0..) |batch, ordinal| {
        const expected_first = ordinal * Runtime.BATCH_SIZE;
        const expected_second: ?usize = if (Runtime.BATCH_SIZE == 2 and
            expected_first + 1 < Runtime.EVENT_COUNT)
            expected_first + 1
        else
            null;
        if (batch.ordinal != ordinal or batch.first >= Runtime.EVENT_COUNT or
            batch.first != expected_first or
            batch.interaction_column_start != 4 * ordinal or
            (batch.second != null and batch.second.? >= Runtime.EVENT_COUNT) or
            (expected_second == null) != (batch.second == null) or
            (expected_second != null and batch.second.? != expected_second.?))
        {
            return error.InvalidRelationPlan;
        }
    }
}

pub fn relationFraction(
    event: relation_interaction.EventPlan,
    slots: anytype,
    challenges: *const ChallengeSet,
) Error!struct { numerator: Scalar, denominator: Scalar } {
    var values: [universal.MAX_ARITY]Scalar = undefined;
    for (values[0..event.arity], event.value_slots[0..event.arity]) |*value, slot|
        value.* = slots[slot];
    const magnitude = slots[event.numerator_slot];
    return .{
        .numerator = switch (event.role) {
            .request, .consume => magnitude.neg(),
            .emit => magnitude,
        },
        .denominator = try challenges.get(event.domain).combine(values[0..event.arity]),
    };
}

test "R-012 recorder differentially replays authenticated direct and relation programs" {
    const control = @import("control.zig");
    const Runtime = relation_interaction.Runtime(
        control.LOGICAL_INPUT_COUNT,
        control.RELATION_EVENT_COUNT,
        control.LOOKUP_BATCH_SIZE,
    );

    var definition = try control.build(std.testing.allocator);
    defer definition.deinit();
    const direct_program = try direct.authenticate(
        &definition.arena,
        control.SEMANTIC_DIGEST,
        control.LOGICAL_INPUT_COUNT,
    );
    const relation_plan = try Runtime.authenticate(
        &definition.arena,
        control.SEMANTIC_DIGEST,
        definition.events,
    );

    var builder = Builder.init(std.testing.allocator);
    defer builder.deinit();
    try builder.reserve(control.LOGICAL_INPUT_COUNT, 128);
    var graph_row: [control.LOGICAL_INPUT_COUNT]Scalar = undefined;
    var native_row: [control.LOGICAL_INPUT_COUNT]QM31 = undefined;
    for (&graph_row, &native_row, 0..) |*symbolic, *concrete, index| {
        symbolic.* = (try builder.input()).value;
        concrete.* = QM31.fromU32Unchecked(
            @intCast(index + 1),
            @intCast(index + 2),
            @intCast(index + 3),
            @intCast(index + 4),
        );
    }

    try builder.activate();
    defer if (builder.active) builder.deactivate();

    var graph_direct: [control.DIRECT_CONSTRAINT_COUNT]Scalar = undefined;
    try replayDirect(&direct_program, &graph_row, &graph_direct);
    var direct_scratch: [direct.MAX_NODES]QM31 = undefined;
    var native_direct: [control.DIRECT_CONSTRAINT_COUNT]QM31 = undefined;
    try direct_program.evaluateSecureInto(
        &native_row,
        &direct_scratch,
        &native_direct,
    );
    for (graph_direct, native_direct) |actual, expected|
        try builder.constrainZero(actual.sub(Scalar.fromSecure(expected)));

    const native_relations = universal.UniversalRelations.dummy();
    var symbolic_draws: [universal.RELATION_COUNT][2]Scalar = undefined;
    for (&symbolic_draws, native_relations.elements) |*pair, element| {
        pair.* = .{
            Scalar.fromSecure(element.z),
            Scalar.fromSecure(element.alpha),
        };
    }
    const graph_relations = try ChallengeSet.init(symbolic_draws);
    const graph_pairs = try replayRelation(
        Runtime,
        &relation_plan,
        graph_row,
        &graph_relations,
    );
    const native_pairs = try relation_plan.preparedSecureRowPairs(
        native_row,
        &native_relations,
    );
    for (graph_pairs, native_pairs) |actual, expected| {
        try builder.constrainZero(actual.n1.sub(Scalar.fromSecure(expected.n1)));
        try builder.constrainZero(actual.d1.sub(Scalar.fromSecure(expected.d1)));
        try builder.constrainZero(actual.n2.sub(Scalar.fromSecure(expected.n2)));
        try builder.constrainZero(actual.d2.sub(Scalar.fromSecure(expected.d2)));
    }

    builder.deactivate();
    var circuit = try builder.finish();
    defer circuit.deinit();
    const values = try std.testing.allocator.alloc(QM31, circuit.nodes.len);
    defer std.testing.allocator.free(values);
    try circuit.evaluateInto(&native_row, values);
}

test "R-012 recorder hash-conses commutative operations and rejects program mutation" {
    const control = @import("control.zig");
    const Runtime = relation_interaction.Runtime(
        control.LOGICAL_INPUT_COUNT,
        control.RELATION_EVENT_COUNT,
        control.LOOKUP_BATCH_SIZE,
    );
    var definition = try control.build(std.testing.allocator);
    defer definition.deinit();
    var program = try direct.authenticate(
        &definition.arena,
        control.SEMANTIC_DIGEST,
        control.LOGICAL_INPUT_COUNT,
    );
    var relation_plan = try Runtime.authenticate(
        &definition.arena,
        control.SEMANTIC_DIGEST,
        definition.events,
    );

    var builder = Builder.init(std.testing.allocator);
    defer builder.deinit();
    var inputs: [control.LOGICAL_INPUT_COUNT]Scalar = undefined;
    for (&inputs) |*input| input.* = (try builder.input()).value;
    try builder.activate();
    defer if (builder.active) builder.deactivate();

    const lhs = inputs[0].add(inputs[1]);
    const rhs = inputs[1].add(inputs[0]);
    try builder.constrainZero(lhs.sub(rhs));
    var add_count: usize = 0;
    for (builder.nodes.items) |node|
        add_count += @intFromBool(std.meta.activeTag(node.op) == .add);
    try std.testing.expectEqual(@as(usize, 1), add_count);

    program.nodes[0].destination = 0;
    var roots: [control.DIRECT_CONSTRAINT_COUNT]Scalar = undefined;
    try std.testing.expectError(
        error.InvalidDirectProgram,
        replayDirect(&program, &inputs, &roots),
    );

    const native_relations = universal.UniversalRelations.dummy();
    var symbolic_draws: [universal.RELATION_COUNT][2]Scalar = undefined;
    for (&symbolic_draws, native_relations.elements) |*pair, element| {
        pair.* = .{
            Scalar.fromSecure(element.z),
            Scalar.fromSecure(element.alpha),
        };
    }
    const challenges = try ChallengeSet.init(symbolic_draws);
    relation_plan.events[0].numerator_slot = std.math.maxInt(u16);
    try std.testing.expectError(
        error.InvalidRelationPlan,
        replayRelation(Runtime, &relation_plan, inputs, &challenges),
    );

    builder.deactivate();
    var circuit = try builder.finish();
    defer circuit.deinit();
    var native_inputs = [_]QM31{QM31.zero()} ** control.LOGICAL_INPUT_COUNT;
    native_inputs[0] = QM31.one();
    const values = try std.testing.allocator.alloc(QM31, circuit.nodes.len);
    defer std.testing.allocator.free(values);
    try circuit.evaluateInto(&native_inputs, values);
}

pub fn frameworkConstraintNative(
    current: QM31,
    previous_row: QM31,
    previous_column: QM31,
    claimed_sum_shift: QM31,
    pair: @import("../../air/logup.zig").RowPair,
) QM31 {
    return current
        .sub(previous_row)
        .sub(previous_column)
        .add(claimed_sum_shift)
        .mul(pair.d1.mul(pair.d2))
        .sub(pair.n1.mul(pair.d2).add(pair.n2.mul(pair.d1)));
}
