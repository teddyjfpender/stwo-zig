//! Internal fri verifier circuit authority shard; use fri_verifier_circuit.zig publicly.

const dependency_0 = @import("fri_verifier_circuit_circuit.zig");
const dependency_1 = @import("fri_verifier_circuit_builder.zig");

const Builder = dependency_1.Builder;
const Circuit = dependency_0.Circuit;
const Error = dependency_0.Error;
const Handle = dependency_0.Handle;
const Layout = dependency_0.Layout;
const M31_BIT_COUNT = dependency_0.M31_BIT_COUNT;
const MAX_FOLD_WIDTH = dependency_0.MAX_FOLD_WIDTH;
const Profile = dependency_0.Profile;
const QM31 = dependency_0.QM31;
const SECURE_WORD_COUNT = dependency_0.SECURE_WORD_COUNT;
const circleDomainPoint = dependency_1.circleDomainPoint;
const evaluateLastLayer = dependency_1.evaluateLastLayer;
const foldCircleSubset = dependency_1.foldCircleSubset;
const foldLineSubset = dependency_1.foldLineSubset;
const lineDomainPoint = dependency_1.lineDomainPoint;
const reconstructBits = dependency_1.reconstructBits;
const secureAt = dependency_1.secureAt;
const selectOffset = dependency_1.selectOffset;
const std = dependency_0.std;
const trackedInput = dependency_1.trackedInput;
const trackedSecureInput = dependency_1.trackedSecureInput;

/// Builds the proof-independent canonical FRI graph. All witness assignments
/// share this graph and its exact input-node coordinates.
pub fn build(allocator: std.mem.Allocator, profile: Profile) Error!Circuit {
    try profile.validate();
    const layout = try Layout.init(profile);
    const input_handles = try allocator.alloc(Handle, layout.input_count);
    defer allocator.free(input_handles);
    var builder = Builder.init(allocator);
    defer builder.deinit();
    try builder.nodes.ensureTotalCapacity(allocator, layout.input_count * 8);
    try builder.bindings.ensureTotalCapacity(allocator, layout.input_count);

    var input_cursor: usize = 0;
    const active = try trackedInput(
        &builder,
        input_handles,
        &input_cursor,
        .active_selector,
    );
    const one = Handle{ .constant = QM31.one() };
    try builder.constrainZero(try builder.mul(
        active,
        try builder.sub(one, active),
    ));

    for (0..profile.query_count) |query| {
        _ = try trackedSecureInput(
            &builder,
            input_handles,
            &input_cursor,
            .deep_answer_word,
            @intCast(query),
            0,
            0,
        );
    }
    for (profile.fold_widths, 0..) |width, layer| {
        for (0..profile.query_count) |query| for (0..width) |offset| {
            _ = try trackedSecureInput(
                &builder,
                input_handles,
                &input_cursor,
                .authenticated_value_word,
                @intCast(layer),
                @intCast(query),
                @intCast(offset),
            );
        };
    }
    for (0..profile.layerCount()) |layer| {
        _ = try trackedSecureInput(
            &builder,
            input_handles,
            &input_cursor,
            .fri_alpha_word,
            @intCast(layer),
            0,
            0,
        );
    }
    for (0..profile.query_count) |query| for (0..M31_BIT_COUNT) |bit| {
        const tracked = try trackedInput(
            &builder,
            input_handles,
            &input_cursor,
            .{ .query_bit = .{ .query = @intCast(query), .bit = @intCast(bit) } },
        );
        try builder.constrainZero(try builder.mul(
            tracked,
            try builder.sub(one, tracked),
        ));
    };
    // Stark-V records each layer's positions immediately followed by that
    // layer's offsets. This order is part of the circuit identity.
    for (0..profile.layerCount()) |layer| {
        for (0..profile.query_count) |query| {
            _ = try trackedInput(
                &builder,
                input_handles,
                &input_cursor,
                .{ .fri_position = .{ .layer = @intCast(layer), .query = @intCast(query) } },
            );
        }
        for (0..profile.query_count) |query| {
            _ = try trackedInput(
                &builder,
                input_handles,
                &input_cursor,
                .{ .fri_offset = .{ .layer = @intCast(layer), .query = @intCast(query) } },
            );
        }
    }
    for (0..profile.query_count) |query| {
        _ = try trackedInput(
            &builder,
            input_handles,
            &input_cursor,
            .{ .last_layer_position = .{ .query = @intCast(query) } },
        );
    }
    for (0..try profile.lastLayerCoefficientCount()) |coefficient| {
        _ = try trackedSecureInput(
            &builder,
            input_handles,
            &input_cursor,
            .last_layer_coefficient_word,
            @intCast(coefficient),
            0,
            0,
        );
    }
    std.debug.assert(input_cursor == input_handles.len);

    const coefficient_count = try profile.lastLayerCoefficientCount();
    const coefficients = try allocator.alloc(Handle, coefficient_count);
    defer allocator.free(coefficients);
    for (coefficients, 0..) |*coefficient, index| {
        coefficient.* = try secureAt(
            &builder,
            input_handles,
            layout.coefficients + index * SECURE_WORD_COUNT,
        );
    }
    const last_layer_scratch = try allocator.alloc(Handle, coefficient_count);
    defer allocator.free(last_layer_scratch);

    for (0..profile.query_count) |query| {
        var bits: [M31_BIT_COUNT]Handle = undefined;
        for (&bits, 0..) |*bit, index|
            bit.* = input_handles[layout.query_bits + query * M31_BIT_COUNT + index];
        var folded_bits: u32 = 0;
        var current_log_size = profile.lifting_log_size;
        var previous = try secureAt(&builder, input_handles, layout.deep + query * 4);

        for (profile.fold_widths, 0..) |width_u32, layer| {
            const width: usize = @intCast(width_u32);
            const fold_step = std.math.log2_int(u32, width_u32);
            const current = bits[folded_bits..][0..current_log_size];
            const position = try reconstructBits(&builder, current);
            const offset = try reconstructBits(&builder, current[0..fold_step]);
            try builder.constrainZero(try builder.sub(
                input_handles[layout.position_bases[layer] + query],
                position,
            ));
            try builder.constrainZero(try builder.sub(
                input_handles[layout.offset_bases[layer] + query],
                offset,
            ));

            var authenticated: [MAX_FOLD_WIDTH]Handle = undefined;
            for (authenticated[0..width], 0..) |*value, value_offset| {
                const word_base = layout.auth_bases[layer] +
                    (query * width + value_offset) * SECURE_WORD_COUNT;
                value.* = try secureAt(&builder, input_handles, word_base);
            }
            const selected = try selectOffset(
                &builder,
                authenticated[0..width],
                current[0..fold_step],
            );
            try builder.constrainZero(try builder.mul(
                active,
                try builder.sub(selected, previous),
            ));

            var subset_bits: [M31_BIT_COUNT]Handle = undefined;
            @memcpy(subset_bits[0..current.len], current);
            for (subset_bits[0..fold_step]) |*bit| bit.* = .{ .constant = QM31.zero() };
            const initial = if (layer == 0)
                try circleDomainPoint(&builder, subset_bits[0..current.len], current_log_size)
            else
                try lineDomainPoint(&builder, subset_bits[0..current.len], current_log_size);
            const alpha = try secureAt(
                &builder,
                input_handles,
                layout.alpha + layer * SECURE_WORD_COUNT,
            );
            previous = if (layer == 0)
                try foldCircleSubset(&builder, authenticated[0..width], initial, fold_step, alpha)
            else
                try foldLineSubset(&builder, authenticated[0..width], initial, fold_step, alpha);
            folded_bits += fold_step;
            current_log_size -= fold_step;
        }

        const last_log = try profile.lastLayerDomainLogSize();
        const last_bits = bits[folded_bits..][0..last_log];
        try builder.constrainZero(try builder.sub(
            input_handles[layout.last_position + query],
            try reconstructBits(&builder, last_bits),
        ));
        const point = try lineDomainPoint(&builder, last_bits, last_log);
        const expected = try evaluateLastLayer(
            &builder,
            coefficients,
            point.x,
            last_layer_scratch,
        );
        try builder.constrainZero(try builder.mul(
            active,
            try builder.sub(previous, expected),
        ));
    }

    var built = try builder.finish(profile);
    errdefer built.deinit();
    try built.validate();
    return built;
}

pub fn computeUseCountsInto(circuit: *const Circuit, scratch: []u32) Error![]u32 {
    try circuit.validate();
    if (scratch.len < circuit.nodes.len) return error.InvalidWitness;
    const uses = scratch[0..circuit.nodes.len];
    @memset(uses, 0);
    for (circuit.nodes) |node| switch (node.op) {
        .add, .sub, .mul => |op| {
            uses[op.lhs] = std.math.add(u32, uses[op.lhs], 1) catch
                return error.ArithmeticOverflow;
            uses[op.rhs] = std.math.add(u32, uses[op.rhs], 1) catch
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
