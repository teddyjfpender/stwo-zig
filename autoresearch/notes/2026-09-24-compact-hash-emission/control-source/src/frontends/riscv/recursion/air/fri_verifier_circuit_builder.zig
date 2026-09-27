//! Internal fri verifier circuit authority shard; use fri_verifier_circuit.zig publicly.

const dependency_0 = @import("fri_verifier_circuit_circuit.zig");

const Circuit = dependency_0.Circuit;
const Error = dependency_0.Error;
const Handle = dependency_0.Handle;
const InputBinding = dependency_0.InputBinding;
const InputSource = dependency_0.InputSource;
const M31 = dependency_0.M31;
const M31_BIT_COUNT = dependency_0.M31_BIT_COUNT;
const MAX_DOMAIN_LOG = dependency_0.MAX_DOMAIN_LOG;
const MAX_FOLD_WIDTH = dependency_0.MAX_FOLD_WIDTH;
const OpKey = dependency_0.OpKey;
const Profile = dependency_0.Profile;
const QM31 = dependency_0.QM31;
const SECURE_WORD_COUNT = dependency_0.SECURE_WORD_COUNT;
const circuitDigest = dependency_0.circuitDigest;
const graph_mod = dependency_0.graph_mod;
const qm31Words = dependency_0.qm31Words;
const std = dependency_0.std;
const stwo_core = dependency_0.stwo_core;

pub const Builder = struct {
    allocator: std.mem.Allocator,
    nodes: std.ArrayList(graph_mod.Node),
    outputs: std.ArrayList(u32),
    bindings: std.ArrayList(InputBinding),
    interned: std.AutoHashMap(OpKey, u32),

    pub fn init(allocator: std.mem.Allocator) Builder {
        return .{
            .allocator = allocator,
            .nodes = .empty,
            .outputs = .empty,
            .bindings = .empty,
            .interned = std.AutoHashMap(OpKey, u32).init(allocator),
        };
    }

    pub fn deinit(self: *Builder) void {
        self.interned.deinit();
        self.bindings.deinit(self.allocator);
        self.outputs.deinit(self.allocator);
        self.nodes.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn input(self: *Builder, source: InputSource) Error!Handle {
        const node_id = try indexU32(self.nodes.items.len);
        try self.nodes.append(self.allocator, .{ .op = .input });
        try self.bindings.append(self.allocator, .{ .node_id = node_id, .source = source });
        return .{ .node = node_id };
    }

    pub fn constrainZero(self: *Builder, value: Handle) Error!void {
        try self.outputs.append(self.allocator, try self.nodeId(value));
    }

    pub fn add(self: *Builder, lhs: Handle, rhs: Handle) Error!Handle {
        if (constantPair(lhs, rhs)) |pair| return .{ .constant = pair[0].add(pair[1]) };
        const lhs_id = try self.nodeId(lhs);
        const rhs_id = try self.nodeId(rhs);
        return .{ .node = try self.intern(
            .{ .add = canonicalPair(lhs_id, rhs_id) },
            .{ .add = .{ .lhs = lhs_id, .rhs = rhs_id } },
        ) };
    }

    pub fn sub(self: *Builder, lhs: Handle, rhs: Handle) Error!Handle {
        if (constantPair(lhs, rhs)) |pair| return .{ .constant = pair[0].sub(pair[1]) };
        const lhs_id = try self.nodeId(lhs);
        const rhs_id = try self.nodeId(rhs);
        return .{ .node = try self.intern(
            .{ .sub = .{ .lhs = lhs_id, .rhs = rhs_id } },
            .{ .sub = .{ .lhs = lhs_id, .rhs = rhs_id } },
        ) };
    }

    pub fn mul(self: *Builder, lhs: Handle, rhs: Handle) Error!Handle {
        if (constantPair(lhs, rhs)) |pair| return .{ .constant = pair[0].mul(pair[1]) };
        const lhs_id = try self.nodeId(lhs);
        const rhs_id = try self.nodeId(rhs);
        return .{ .node = try self.intern(
            .{ .mul = canonicalPair(lhs_id, rhs_id) },
            .{ .mul = .{ .lhs = lhs_id, .rhs = rhs_id } },
        ) };
    }

    fn neg(self: *Builder, value: Handle) Error!Handle {
        return switch (value) {
            .constant => |constant| .{ .constant = constant.neg() },
            .node => |node_id| .{ .node = try self.intern(
                .{ .neg = node_id },
                .{ .neg = node_id },
            ) },
        };
    }

    fn inverse(self: *Builder, value: Handle) Error!Handle {
        return switch (value) {
            .constant => |constant| .{ .constant = try constant.inv() },
            .node => |node_id| .{ .node = try self.intern(
                .{ .inverse = node_id },
                .{ .inverse = node_id },
            ) },
        };
    }

    fn nodeId(self: *Builder, value: Handle) Error!u32 {
        return switch (value) {
            .node => |node_id| node_id,
            .constant => |constant| blk: {
                const words = qm31Words(constant);
                break :blk try self.intern(
                    .{ .constant = words },
                    .{ .constant = words },
                );
            },
        };
    }

    fn intern(self: *Builder, key: OpKey, op: graph_mod.Op) Error!u32 {
        if (self.interned.get(key)) |node_id| return node_id;
        const node_id = try indexU32(self.nodes.items.len);
        try self.nodes.append(self.allocator, .{ .op = op });
        try self.interned.put(key, node_id);
        return node_id;
    }

    pub fn finish(self: *Builder, profile: Profile) Error!Circuit {
        const fold_widths = try self.allocator.dupe(u32, profile.fold_widths);
        errdefer self.allocator.free(fold_widths);
        const nodes = try self.nodes.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(nodes);
        const outputs = try self.outputs.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(outputs);
        const bindings = try self.bindings.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(bindings);
        const profile_digest = profile.identityDigest();
        const graph_digest = graph_mod.computeGraphDigest(nodes, outputs);
        return .{
            .allocator = self.allocator,
            .lifting_log_size = profile.lifting_log_size,
            .log_blowup_factor = profile.log_blowup_factor,
            .log_last_layer_degree_bound = profile.log_last_layer_degree_bound,
            .query_count = profile.query_count,
            .fold_widths = fold_widths,
            .nodes = nodes,
            .outputs = outputs,
            .bindings = bindings,
            .profile_digest = profile_digest,
            .graph_digest = graph_digest,
            .identity_digest = circuitDigest(profile_digest, graph_digest, bindings),
        };
    }
};

pub const CircuitPoint = struct { x: Handle, y: Handle };

pub fn trackedInput(
    builder: *Builder,
    handles: []Handle,
    cursor: *usize,
    source: InputSource,
) Error!Handle {
    if (cursor.* >= handles.len) return error.BindingCountMismatch;
    const value = try builder.input(source);
    handles[cursor.*] = value;
    cursor.* += 1;
    return value;
}

pub const SecureSourceKind = enum {
    deep_answer_word,
    authenticated_value_word,
    fri_alpha_word,
    last_layer_coefficient_word,
};

pub fn trackedSecureInput(
    builder: *Builder,
    handles: []Handle,
    cursor: *usize,
    kind: SecureSourceKind,
    index_0: u32,
    index_1: u32,
    index_2: u32,
) Error!Handle {
    var words: [SECURE_WORD_COUNT]Handle = undefined;
    for (&words, 0..) |*word, word_index| {
        const source: InputSource = switch (kind) {
            .deep_answer_word => .{ .deep_answer_word = .{
                .query = index_0,
                .word = @intCast(word_index),
            } },
            .authenticated_value_word => .{ .authenticated_value_word = .{
                .layer = index_0,
                .query = index_1,
                .offset = index_2,
                .word = @intCast(word_index),
            } },
            .fri_alpha_word => .{ .fri_alpha_word = .{
                .layer = index_0,
                .word = @intCast(word_index),
            } },
            .last_layer_coefficient_word => .{ .last_layer_coefficient_word = .{
                .coefficient = index_0,
                .word = @intCast(word_index),
            } },
        };
        word.* = try trackedInput(builder, handles, cursor, source);
    }
    return secureFromWords(builder, words);
}

pub fn secureAt(builder: *Builder, handles: []const Handle, base: usize) Error!Handle {
    return secureFromWords(builder, handles[base..][0..SECURE_WORD_COUNT].*);
}

pub fn secureFromWords(builder: *Builder, words: [SECURE_WORD_COUNT]Handle) Error!Handle {
    const basis_1 = Handle{ .constant = QM31.fromU32Unchecked(0, 1, 0, 0) };
    const basis_2 = Handle{ .constant = QM31.fromU32Unchecked(0, 0, 1, 0) };
    const basis_3 = Handle{ .constant = QM31.fromU32Unchecked(0, 0, 0, 1) };
    return builder.add(
        try builder.add(
            try builder.add(words[0], try builder.mul(words[1], basis_1)),
            try builder.mul(words[2], basis_2),
        ),
        try builder.mul(words[3], basis_3),
    );
}

pub fn reconstructBits(builder: *Builder, bits: []const Handle) Error!Handle {
    var sum = Handle{ .constant = QM31.zero() };
    for (bits, 0..) |bit, index| {
        const weight = QM31.fromBase(M31.fromCanonical(@as(u32, 1) << @intCast(index)));
        sum = try builder.add(sum, try builder.mul(bit, .{ .constant = weight }));
    }
    return sum;
}

pub fn selectOffset(
    builder: *Builder,
    values: []const Handle,
    bits: []const Handle,
) Error!Handle {
    var selected = Handle{ .constant = QM31.zero() };
    const one = Handle{ .constant = QM31.one() };
    for (values, 0..) |value, offset| {
        var selector = one;
        for (bits, 0..) |bit_value, bit| {
            selector = try builder.mul(
                selector,
                if (((offset >> @intCast(bit)) & 1) == 1)
                    bit_value
                else
                    try builder.sub(one, bit_value),
            );
        }
        selected = try builder.add(selected, try builder.mul(selector, value));
    }
    return selected;
}

pub fn circleDomainPoint(
    builder: *Builder,
    bits: []const Handle,
    log_size: u32,
) Error!CircuitPoint {
    const half_coset = stwo_core.poly.circle.CanonicCoset.new(log_size).circleDomain().half_coset;
    var point = CircuitPoint{
        .x = .{ .constant = QM31.fromBase(half_coset.initial.x) },
        .y = .{ .constant = QM31.fromBase(half_coset.initial.y) },
    };
    const one = Handle{ .constant = QM31.one() };
    for (bits[1..log_size], 1..) |bit, source_bit| {
        const scalar = @as(usize, 1) << @intCast(log_size - 1 - source_bit);
        const contribution = half_coset.step_size.mul(scalar).toPoint();
        const selected = CircuitPoint{
            .x = try builder.add(one, try builder.mul(
                bit,
                try builder.sub(.{ .constant = QM31.fromBase(contribution.x) }, one),
            )),
            .y = try builder.mul(bit, .{ .constant = QM31.fromBase(contribution.y) }),
        };
        point = try circleAdd(builder, point, selected);
    }
    point.y = try builder.mul(
        point.y,
        try builder.sub(one, try builder.add(bits[0], bits[0])),
    );
    return point;
}

pub fn lineDomainPoint(
    builder: *Builder,
    bits: []const Handle,
    log_size: u32,
) Error!CircuitPoint {
    var circle_bits: [M31_BIT_COUNT]Handle = undefined;
    circle_bits[0] = .{ .constant = QM31.zero() };
    @memcpy(circle_bits[1 .. bits.len + 1], bits);
    return circleDomainPoint(builder, circle_bits[0 .. bits.len + 1], log_size + 1);
}

pub fn circleAdd(builder: *Builder, lhs: CircuitPoint, rhs: CircuitPoint) Error!CircuitPoint {
    return .{
        .x = try builder.sub(
            try builder.mul(lhs.x, rhs.x),
            try builder.mul(lhs.y, rhs.y),
        ),
        .y = try builder.add(
            try builder.mul(lhs.x, rhs.y),
            try builder.mul(lhs.y, rhs.x),
        ),
    };
}

pub fn circleDouble(builder: *Builder, point: CircuitPoint) Error!CircuitPoint {
    const two = Handle{ .constant = QM31.fromBase(M31.fromCanonical(2)) };
    return .{
        .x = try builder.sub(
            try builder.mul(try builder.mul(point.x, point.x), two),
            .{ .constant = QM31.one() },
        ),
        .y = try builder.mul(try builder.mul(point.x, point.y), two),
    };
}

pub fn addConstantPoint(
    builder: *Builder,
    point: CircuitPoint,
    offset: stwo_core.circle.CirclePointIndex,
) Error!CircuitPoint {
    const value = offset.toPoint();
    return circleAdd(builder, point, .{
        .x = .{ .constant = QM31.fromBase(value.x) },
        .y = .{ .constant = QM31.fromBase(value.y) },
    });
}

pub fn foldPair(
    builder: *Builder,
    lhs: Handle,
    rhs: Handle,
    inverse_twiddle: Handle,
    alpha: Handle,
) Error!Handle {
    const even = try builder.add(lhs, rhs);
    const odd = try builder.mul(try builder.sub(lhs, rhs), inverse_twiddle);
    return builder.add(even, try builder.mul(alpha, odd));
}

pub fn foldCircleSubset(
    builder: *Builder,
    values: []const Handle,
    initial: CircuitPoint,
    fold_step: u32,
    alpha: Handle,
) Error!Handle {
    const first_log = fold_step - 1;
    var line_values: [MAX_FOLD_WIDTH / 2]Handle = undefined;
    for (0..values.len / 2) |pair| {
        const reversed = stwo_core.utils.bitReverseIndex(pair, first_log);
        const offset = stwo_core.circle.CirclePointIndex.subgroupGen(first_log).mul(reversed);
        const point = try addConstantPoint(builder, initial, offset);
        line_values[pair] = try foldPair(
            builder,
            values[pair * 2],
            values[pair * 2 + 1],
            try builder.inverse(point.y),
            alpha,
        );
    }
    if (fold_step == 1) return line_values[0];
    return foldCoset(
        builder,
        line_values[0 .. values.len / 2],
        initial,
        fold_step - 1,
        try builder.mul(alpha, alpha),
    );
}

pub fn foldLineSubset(
    builder: *Builder,
    values: []const Handle,
    initial: CircuitPoint,
    fold_step: u32,
    alpha: Handle,
) Error!Handle {
    return foldCoset(builder, values, initial, fold_step, alpha);
}

pub fn foldCoset(
    builder: *Builder,
    source_values: []const Handle,
    source_initial: CircuitPoint,
    log_size: u32,
    source_alpha: Handle,
) Error!Handle {
    var values: [MAX_FOLD_WIDTH]Handle = undefined;
    @memcpy(values[0..source_values.len], source_values);
    var initial = source_initial;
    var alpha = source_alpha;
    var current_log = log_size;
    while (current_log > 0) : (current_log -= 1) {
        const current_len = @as(usize, 1) << @intCast(current_log);
        for (0..current_len / 2) |pair| {
            const source_index = pair * 2;
            const reversed = stwo_core.utils.bitReverseIndex(source_index, current_log);
            const offset = stwo_core.circle.CirclePointIndex.subgroupGen(current_log).mul(reversed);
            const point = try addConstantPoint(builder, initial, offset);
            values[pair] = try foldPair(
                builder,
                values[source_index],
                values[source_index + 1],
                try builder.inverse(point.x),
                alpha,
            );
        }
        alpha = try builder.mul(alpha, alpha);
        initial = try circleDouble(builder, initial);
    }
    return values[0];
}

pub fn evaluateLastLayer(
    builder: *Builder,
    coefficients: []const Handle,
    source_x: Handle,
    scratch: []Handle,
) Error!Handle {
    if (coefficients.len == 0 or !std.math.isPowerOfTwo(coefficients.len))
        return error.InvalidProfile;
    if (scratch.len < coefficients.len) return error.InvalidWitness;
    const log_count = std.math.log2_int(usize, coefficients.len);
    var factor_storage: [MAX_DOMAIN_LOG]Handle = undefined;
    const factors = factor_storage[0..log_count];
    const values = scratch[0..coefficients.len];
    @memcpy(values, coefficients);
    var x = source_x;
    const two = Handle{ .constant = QM31.fromBase(M31.fromCanonical(2)) };
    for (factors) |*factor| {
        factor.* = x;
        x = try builder.sub(
            try builder.mul(try builder.mul(x, x), two),
            .{ .constant = QM31.one() },
        );
    }
    var value_count = values.len;
    var factor_index = factors.len;
    while (factor_index > 0) {
        factor_index -= 1;
        for (0..value_count / 2) |pair| {
            values[pair] = try builder.add(
                values[pair * 2],
                try builder.mul(factors[factor_index], values[pair * 2 + 1]),
            );
        }
        value_count /= 2;
    }
    return values[0];
}

pub fn constantPair(lhs: Handle, rhs: Handle) ?[2]QM31 {
    return switch (lhs) {
        .constant => |left| switch (rhs) {
            .constant => |right| .{ left, right },
            .node => null,
        },
        .node => null,
    };
}

pub fn canonicalPair(lhs: u32, rhs: u32) graph_mod.BinaryOperands {
    return .{ .lhs = @min(lhs, rhs), .rhs = @max(lhs, rhs) };
}

pub fn indexU32(value: usize) Error!u32 {
    return std.math.cast(u32, value) orelse error.CircuitTooLarge;
}
