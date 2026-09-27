//! Internal pcs deep circuit authority shard; use pcs_deep_circuit.zig publicly.

const dependency_0 = @import("pcs_deep_circuit_circuit.zig");
const dependency_1 = @import("pcs_deep_circuit_builder.zig");

const Builder = dependency_1.Builder;
const Circuit = dependency_0.Circuit;
const CircuitBatch = dependency_1.CircuitBatch;
const CircuitLine = dependency_1.CircuitLine;
const CircuitPoint = dependency_1.CircuitPoint;
const Error = dependency_0.Error;
const Handle = dependency_0.Handle;
const Layout = dependency_0.Layout;
const M31 = dependency_0.M31;
const M31_BIT_COUNT = dependency_0.M31_BIT_COUNT;
const Profile = dependency_0.Profile;
const QM31 = dependency_0.QM31;
const SECURE_WORD_COUNT = dependency_0.SECURE_WORD_COUNT;
const SecureHandle = dependency_1.SecureHandle;
const addBasePoint = dependency_1.addBasePoint;
const buildSampleBatches = dependency_1.buildSampleBatches;
const deinitBatchBuilders = dependency_1.deinitBatchBuilders;
const denominatorComponents = dependency_1.denominatorComponents;
const evaluateQuery = dependency_1.evaluateQuery;
const pointFromSeed = dependency_1.pointFromSeed;
const queryCirclePoint = dependency_1.queryCirclePoint;
const secureAt = dependency_1.secureAt;
const select = dependency_1.select;
const std = dependency_0.std;
const trackedInput = dependency_1.trackedInput;
const trackedSecureInput = dependency_1.trackedSecureInput;

/// Builds the proof-independent graph. The implementation is deliberately
/// flat and capacity-planned: graph construction is cold, while evaluation is
/// a single forward pass with no recursion or per-node allocation.
pub fn build(allocator: std.mem.Allocator, profile: Profile) Error!Circuit {
    try profile.validate();
    const layout = try Layout.init(profile);
    const input_handles = try allocator.alloc(Handle, layout.input_count);
    defer allocator.free(input_handles);
    var builder = Builder.init(allocator);
    defer builder.deinit();
    const estimated_nodes = std.math.mul(usize, layout.input_count, 5) catch
        return error.ArithmeticOverflow;
    try builder.nodes.ensureTotalCapacity(allocator, estimated_nodes);
    try builder.bindings.ensureTotalCapacity(allocator, layout.input_count);

    var input_cursor: usize = 0;
    const active = try trackedInput(&builder, input_handles, &input_cursor, .active_selector);
    for (0..try profile.sampleCount()) |sample| {
        _ = try trackedSecureInput(
            &builder,
            input_handles,
            &input_cursor,
            .sampled_value_word,
            @intCast(sample),
        );
    }
    for (profile.trees, 0..) |tree, tree_index| {
        for (tree.column_log_sizes, 0..) |_, column| {
            for (0..profile.query_count) |query| {
                _ = try trackedInput(&builder, input_handles, &input_cursor, .{
                    .queried_value = .{
                        .tree = @intCast(tree_index),
                        .column = @intCast(column),
                        .query = @intCast(query),
                    },
                });
            }
        }
    }
    _ = try trackedSecureInput(
        &builder,
        input_handles,
        &input_cursor,
        .oods_seed_word,
        0,
    );
    _ = try trackedSecureInput(
        &builder,
        input_handles,
        &input_cursor,
        .deep_randomness_word,
        0,
    );
    for (0..profile.query_count) |query| {
        for (0..M31_BIT_COUNT) |bit| {
            _ = try trackedInput(&builder, input_handles, &input_cursor, .{
                .query_bit = .{ .query = @intCast(query), .bit = @intCast(bit) },
            });
        }
        _ = try trackedInput(&builder, input_handles, &input_cursor, .{
            .query_position = @intCast(query),
        });
    }
    for (0..profile.query_count) |query| {
        _ = try trackedSecureInput(
            &builder,
            input_handles,
            &input_cursor,
            .answer_word,
            @intCast(query),
        );
    }
    if (input_cursor != input_handles.len)
        return error.BindingCountMismatch;

    const zero = Handle{ .constant = QM31.zero() };
    const one = Handle{ .constant = QM31.one() };
    try builder.constrainZero(try builder.mul(active, try builder.sub(one, active)));

    const sampled_values = try allocator.alloc(SecureHandle, try profile.sampleCount());
    defer allocator.free(sampled_values);
    for (sampled_values, 0..) |*sample, index|
        sample.* = try secureAt(
            &builder,
            input_handles,
            layout.sampled + index * SECURE_WORD_COUNT,
        );
    const oods_seed = try secureAt(&builder, input_handles, layout.oods_seed);
    const deep_randomness = try secureAt(&builder, input_handles, layout.deep_randomness);

    const safe_seed_value = QM31.fromU32Unchecked(17, 29, 43, 71);
    const effective_seed = SecureHandle{
        .value = try select(
            &builder,
            active,
            oods_seed.value,
            .{ .constant = safe_seed_value },
        ),
        .conjugate = try select(
            &builder,
            active,
            oods_seed.conjugate,
            .{ .constant = safe_seed_value.complexConjugate() },
        ),
    };
    const oods_point = try pointFromSeed(&builder, effective_seed);
    const effective_randomness = try select(
        &builder,
        active,
        deep_randomness.value,
        one,
    );

    const query_points = try allocator.alloc(CircuitPoint, profile.query_count);
    defer allocator.free(query_points);
    for (query_points, 0..) |*point, query| {
        const base = layout.query_coordinates + query * (M31_BIT_COUNT + 1);
        const bits = input_handles[base..][0..M31_BIT_COUNT];
        for (bits) |bit_value|
            try builder.constrainZero(try builder.mul(
                bit_value,
                try builder.sub(one, bit_value),
            ));
        var reconstructed = zero;
        for (bits[0..profile.lifting_log_size], 0..) |bit_value, bit| {
            const weight = QM31.fromBase(M31.fromCanonical(
                @as(u32, 1) << @intCast(bit),
            ));
            reconstructed = try builder.add(
                reconstructed,
                try builder.mul(bit_value, .{ .constant = weight }),
            );
        }
        try builder.constrainZero(try builder.sub(
            input_handles[base + M31_BIT_COUNT],
            reconstructed,
        ));
        var effective_bits: [M31_BIT_COUNT]Handle = undefined;
        for (&effective_bits, bits) |*destination, bit_value|
            destination.* = try builder.mul(active, bit_value);
        point.* = try queryCirclePoint(
            &builder,
            effective_bits[0..profile.lifting_log_size],
            profile.lifting_log_size,
        );
    }

    const answers = try allocator.alloc(SecureHandle, profile.query_count);
    defer allocator.free(answers);
    for (answers, 0..) |*answer, query|
        answer.* = try secureAt(
            &builder,
            input_handles,
            layout.answers + query * SECURE_WORD_COUNT,
        );

    const powers = try allocator.alloc(Handle, try profile.termCount());
    defer allocator.free(powers);
    var current_power = one;
    for (powers) |*power| {
        power.* = current_power;
        current_power = try builder.mul(current_power, effective_randomness);
    }

    var batch_builders = try buildSampleBatches(allocator, profile);
    defer deinitBatchBuilders(allocator, &batch_builders);
    var initialized_batches: usize = 0;
    const batches = try allocator.alloc(CircuitBatch, batch_builders.items.len);
    defer {
        for (batches[0..initialized_batches]) |batch| allocator.free(batch.lines);
        allocator.free(batches);
    }
    for (batch_builders.items, batches) |source_batch, *batch| {
        const point = try addBasePoint(&builder, oods_point, source_batch.point_offset);
        const denominator = try denominatorComponents(&builder, point);
        const lines = try allocator.alloc(CircuitLine, source_batch.terms.items.len);
        batch.* = .{
            .point = point,
            .lines = lines,
            .conjugate_y_delta = try builder.sub(point.conjugate_y, point.y),
            .weighted_a_sum = zero,
            .weighted_value_sum = zero,
            .denominator_determinant = denominator.determinant,
            .imaginary_x = denominator.imaginary_x,
            .imaginary_y = denominator.imaginary_y,
        };
        initialized_batches += 1;
        for (source_batch.terms.items, lines) |term, *line| {
            const sample = sampled_values[term.sample];
            const power = powers[term.random_power];
            const a = try builder.sub(sample.conjugate, sample.value);
            const weighted_a = try builder.mul(power, a);
            const weighted_value = try builder.mul(power, sample.value);
            batch.weighted_a_sum = try builder.add(
                batch.weighted_a_sum,
                weighted_a,
            );
            batch.weighted_value_sum = try builder.add(
                batch.weighted_value_sum,
                weighted_value,
            );
            line.* = .{
                .column = term.column,
                .power = power,
            };
        }
    }

    for (query_points, answers, 0..) |domain_point, answer, query| {
        const quotient = try evaluateQuery(
            &builder,
            query,
            domain_point,
            batches,
            input_handles[layout.queried..layout.oods_seed],
            profile.query_count,
        );
        try builder.constrainZero(try builder.mul(
            active,
            try builder.sub(quotient, answer.value),
        ));
    }

    var result = try builder.finish(profile);
    errdefer result.deinit();
    try result.validate();
    return result;
}

pub fn computeUseCountsInto(circuit: *const Circuit, scratch: []u32) Error![]u32 {
    try circuit.validate();
    if (scratch.len < circuit.nodes.len) return error.InvalidWitness;
    const uses = scratch[0..circuit.nodes.len];
    @memset(uses, 0);
    for (circuit.nodes) |node| switch (node.op) {
        .add, .sub, .mul => |operation| {
            uses[operation.lhs] = std.math.add(u32, uses[operation.lhs], 1) catch
                return error.ArithmeticOverflow;
            uses[operation.rhs] = std.math.add(u32, uses[operation.rhs], 1) catch
                return error.ArithmeticOverflow;
        },
        .neg, .inverse => |operand| uses[operand] = std.math.add(
            u32,
            uses[operand],
            1,
        ) catch return error.ArithmeticOverflow,
        .input, .constant => {},
    };
    for (circuit.outputs) |output| uses[output] = std.math.add(
        u32,
        uses[output],
        1,
    ) catch return error.ArithmeticOverflow;
    return uses;
}
