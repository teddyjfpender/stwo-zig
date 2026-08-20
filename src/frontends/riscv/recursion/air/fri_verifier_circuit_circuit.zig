//! Internal fri verifier circuit authority shard; use fri_verifier_circuit.zig publicly.

pub const std = @import("std");
pub const stwo_core = @import("stwo_core");
pub const M31 = stwo_core.fields.m31.M31;
pub const m31 = stwo_core.fields.m31;
pub const QM31 = stwo_core.fields.qm31.QM31;
pub const digest = @import("../../air/lang/digest.zig");
pub const graph_mod = @import("composition_circuit.zig");

pub const SECURE_WORD_COUNT: usize = 4;
pub const M31_BIT_COUNT: usize = 31;
pub const MAX_DOMAIN_LOG: u32 = 30;
/// A width-two schedule can consume one domain bit per layer, so the exact
/// proof-independent upper bound is the maximum supported domain log. The old
/// value 16 rejected valid recursive outer proofs with 20 folds.
pub const MAX_FRI_LAYERS: usize = MAX_DOMAIN_LOG;
pub const MAX_FOLD_STEP: u32 = 4;
pub const MAX_FOLD_WIDTH: usize = 1 << MAX_FOLD_STEP;
pub const PROFILE_FORMAT_VERSION: u16 = 1;
pub const PROFILE_DOMAIN = "stwo-zig/typed-air/recursion-fri-verifier-profile/v1\x00";
pub const CIRCUIT_FORMAT_VERSION: u16 = 1;
pub const CIRCUIT_DOMAIN = "stwo-zig/typed-air/recursion-fri-verifier-circuit/v1\x00";

pub const Error = std.mem.Allocator.Error || graph_mod.Error || QM31.Error || error{
    ArithmeticOverflow,
    BindingCountMismatch,
    BindingNodeMismatch,
    BindingTargetsNonInput,
    CircuitIdentityMismatch,
    CircuitTooLarge,
    FoldCountMismatch,
    InputIsNotBaseField,
    InvalidDegreeRange,
    InvalidFoldWidth,
    InvalidProfile,
    InvalidWitness,
    ProfileIdentityMismatch,
    UnsatisfiedCircuit,
};

pub const Profile = struct {
    lifting_log_size: u32,
    log_blowup_factor: u32,
    log_last_layer_degree_bound: u32,
    fold_widths: []const u32,
    query_count: u32,

    pub fn validate(self: Profile) Error!void {
        if (self.lifting_log_size == 0 or self.lifting_log_size > MAX_DOMAIN_LOG or
            self.query_count == 0 or self.query_count >= m31.Modulus or
            self.fold_widths.len == 0 or self.fold_widths.len > MAX_FRI_LAYERS)
        {
            return error.InvalidProfile;
        }
        const terminal_log = std.math.add(
            u32,
            self.log_blowup_factor,
            self.log_last_layer_degree_bound,
        ) catch return error.ArithmeticOverflow;
        const required_folds = std.math.sub(
            u32,
            self.lifting_log_size,
            terminal_log,
        ) catch return error.InvalidDegreeRange;
        if (required_folds == 0) return error.InvalidDegreeRange;
        var actual_folds: u32 = 0;
        for (self.fold_widths) |width| {
            if (width < 2 or width > MAX_FOLD_WIDTH or !std.math.isPowerOfTwo(width))
                return error.InvalidFoldWidth;
            actual_folds = std.math.add(u32, actual_folds, std.math.log2_int(u32, width)) catch
                return error.ArithmeticOverflow;
        }
        if (actual_folds != required_folds) return error.FoldCountMismatch;
        _ = try self.lastLayerCoefficientCount();
        _ = try expectedInputCount(self);
    }

    pub fn layerCount(self: Profile) usize {
        return self.fold_widths.len;
    }

    pub fn lastLayerDomainLogSize(self: Profile) Error!u32 {
        return std.math.add(
            u32,
            self.log_blowup_factor,
            self.log_last_layer_degree_bound,
        ) catch error.ArithmeticOverflow;
    }

    pub fn lastLayerCoefficientCount(self: Profile) Error!usize {
        if (self.log_last_layer_degree_bound >= @bitSizeOf(usize))
            return error.ArithmeticOverflow;
        return @as(usize, 1) << @intCast(self.log_last_layer_degree_bound);
    }

    pub fn identityDigest(self: Profile) digest.Digest {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(PROFILE_DOMAIN);
        hashInt(&hash, u16, PROFILE_FORMAT_VERSION);
        hashInt(&hash, u32, self.lifting_log_size);
        hashInt(&hash, u32, self.log_blowup_factor);
        hashInt(&hash, u32, self.log_last_layer_degree_bound);
        hashInt(&hash, u32, self.query_count);
        hashInt(&hash, u32, self.fold_widths.len);
        for (self.fold_widths) |width| hashInt(&hash, u32, width);
        return hash.finalResult();
    }
};

pub const InputSource = union(enum) {
    active_selector,
    deep_answer_word: struct { query: u32, word: u32 },
    authenticated_value_word: struct { layer: u32, query: u32, offset: u32, word: u32 },
    fri_alpha_word: struct { layer: u32, word: u32 },
    query_bit: struct { query: u32, bit: u32 },
    fri_position: struct { layer: u32, query: u32 },
    fri_offset: struct { layer: u32, query: u32 },
    last_layer_position: struct { query: u32 },
    last_layer_coefficient_word: struct { coefficient: u32, word: u32 },
};

pub const InputBinding = struct {
    node_id: u32,
    source: InputSource,
};

pub const Witness = struct {
    active: bool,
    deep_answers: []const QM31,
    authenticated_values: []const []const QM31,
    fri_alphas: []const QM31,
    raw_queries: []const M31,
    fri_positions: []const []const M31,
    fri_offsets: []const []const M31,
    last_layer_positions: []const M31,
    last_layer_coefficients: []const QM31,
};

pub const Circuit = struct {
    allocator: std.mem.Allocator,
    lifting_log_size: u32,
    log_blowup_factor: u32,
    log_last_layer_degree_bound: u32,
    query_count: u32,
    fold_widths: []u32,
    nodes: []graph_mod.Node,
    outputs: []u32,
    bindings: []InputBinding,
    profile_digest: digest.Digest,
    graph_digest: digest.Digest,
    identity_digest: digest.Digest,

    pub fn deinit(self: *Circuit) void {
        self.allocator.free(self.bindings);
        self.allocator.free(self.outputs);
        self.allocator.free(self.nodes);
        self.allocator.free(self.fold_widths);
        self.* = undefined;
    }

    pub fn profile(self: *const Circuit) Profile {
        return .{
            .lifting_log_size = self.lifting_log_size,
            .log_blowup_factor = self.log_blowup_factor,
            .log_last_layer_degree_bound = self.log_last_layer_degree_bound,
            .fold_widths = self.fold_widths,
            .query_count = self.query_count,
        };
    }

    pub fn graph(self: *const Circuit) graph_mod.CircuitGraph {
        return .{
            .nodes = self.nodes,
            .outputs = self.outputs,
            .identity_digest = self.graph_digest,
        };
    }

    pub fn validate(self: *const Circuit) Error!void {
        const profile_value = self.profile();
        try profile_value.validate();
        if (!std.mem.eql(u8, &self.profile_digest, &profile_value.identityDigest()))
            return error.ProfileIdentityMismatch;
        try self.graph().validate();
        if (self.bindings.len != try expectedInputCount(profile_value))
            return error.BindingCountMismatch;
        var binding_cursor: usize = 0;
        for (self.nodes, 0..) |node, node_id| switch (node.op) {
            .input => {
                if (binding_cursor >= self.bindings.len)
                    return error.BindingCountMismatch;
                const binding = self.bindings[binding_cursor];
                if (binding.node_id != node_id) return error.BindingNodeMismatch;
                const expected = (try expectedSource(profile_value, binding_cursor)) orelse
                    return error.BindingCountMismatch;
                if (!std.meta.eql(binding.source, expected))
                    return error.BindingNodeMismatch;
                binding_cursor += 1;
            },
            else => {},
        };
        if (binding_cursor != self.bindings.len) return error.BindingTargetsNonInput;
        const actual = circuitDigest(
            self.profile_digest,
            self.graph_digest,
            self.bindings,
        );
        if (!std.mem.eql(u8, &actual, &self.identity_digest))
            return error.CircuitIdentityMismatch;
    }

    pub fn evaluate(
        self: *const Circuit,
        allocator: std.mem.Allocator,
        witness: Witness,
    ) Error!Evaluation {
        try self.validate();
        try validateWitness(self.profile(), witness);
        const values = try allocator.alloc(QM31, self.nodes.len);
        errdefer allocator.free(values);
        var binding_cursor: usize = 0;
        for (self.nodes, 0..) |node, node_id| {
            values[node_id] = switch (node.op) {
                .input => blk: {
                    if (binding_cursor >= self.bindings.len)
                        return error.BindingCountMismatch;
                    defer binding_cursor += 1;
                    break :blk try inputValue(self.bindings[binding_cursor].source, witness);
                },
                .constant => |words| QM31.fromU32Unchecked(
                    words[0],
                    words[1],
                    words[2],
                    words[3],
                ),
                else => try evaluateOperation(node, values, node_id),
            };
        }
        if (binding_cursor != self.bindings.len) return error.BindingCountMismatch;
        for (self.outputs) |output| if (!values[output].isZero())
            return error.UnsatisfiedCircuit;
        return .{
            .allocator = allocator,
            .values = values,
            .circuit_identity = self.identity_digest,
        };
    }

    /// Allocation-free replay for proof-path evaluations. The circuit itself
    /// must already have passed verifier-owned cold admission; operand bounds
    /// are nevertheless checked here so corrupted borrowed storage fails
    /// closed instead of indexing outside the evaluated prefix.
    pub fn validateEvaluationHot(
        self: *const Circuit,
        evaluation: *const Evaluation,
    ) Error!void {
        if (evaluation.values.len != self.nodes.len or
            !std.mem.eql(u8, &evaluation.circuit_identity, &self.identity_digest))
        {
            return error.CircuitIdentityMismatch;
        }
        for (self.nodes, 0..) |node, node_id| switch (node.op) {
            .input => {},
            .constant => |words| {
                const expected = QM31.fromU32Unchecked(
                    words[0],
                    words[1],
                    words[2],
                    words[3],
                );
                if (!evaluation.values[node_id].eql(expected))
                    return error.InvalidWitness;
            },
            else => {
                const expected = try evaluateOperation(node, evaluation.values, node_id);
                if (!evaluation.values[node_id].eql(expected))
                    return error.InvalidWitness;
            },
        };
        for (self.outputs) |output| {
            if (output >= evaluation.values.len) return error.InvalidGraphOperand;
            if (!evaluation.values[output].isZero()) return error.UnsatisfiedCircuit;
        }
    }
};

pub const Evaluation = struct {
    allocator: std.mem.Allocator,
    values: []QM31,
    circuit_identity: digest.Digest,

    pub fn deinit(self: *Evaluation) void {
        self.allocator.free(self.values);
        self.* = undefined;
    }

    pub fn validateAgainst(self: *const Evaluation, circuit: *const Circuit) Error!void {
        try circuit.validate();
        try circuit.validateEvaluationHot(self);
    }
};

pub fn evaluateOperation(node: graph_mod.Node, values: []const QM31, node_id: usize) Error!QM31 {
    return switch (node.op) {
        .add => |op| (try operandValue(values, node_id, op.lhs)).add(
            try operandValue(values, node_id, op.rhs),
        ),
        .sub => |op| (try operandValue(values, node_id, op.lhs)).sub(
            try operandValue(values, node_id, op.rhs),
        ),
        .mul => |op| (try operandValue(values, node_id, op.lhs)).mul(
            try operandValue(values, node_id, op.rhs),
        ),
        .neg => |operand| (try operandValue(values, node_id, operand)).neg(),
        .inverse => |operand| try (try operandValue(values, node_id, operand)).inv(),
        .input, .constant => unreachable,
    };
}

pub fn operandValue(values: []const QM31, node_id: usize, operand: u32) Error!QM31 {
    if (operand >= node_id or operand >= values.len) return error.InvalidGraphOperand;
    return values[operand];
}

pub fn expectedInputCount(profile: Profile) Error!usize {
    return (try Layout.initUnchecked(profile)).input_count;
}

pub fn expectedSource(profile: Profile, source_index: usize) Error!?InputSource {
    const layout = try Layout.initUnchecked(profile);
    if (source_index >= layout.input_count) return null;
    if (source_index == 0) return .active_selector;
    if (source_index < layout.auth) {
        const local = source_index - layout.deep;
        return .{ .deep_answer_word = .{
            .query = @intCast(local / SECURE_WORD_COUNT),
            .word = @intCast(local % SECURE_WORD_COUNT),
        } };
    }
    for (profile.fold_widths, 0..) |width, layer| {
        const start = layout.auth_bases[layer];
        const count = @as(usize, profile.query_count) * width * SECURE_WORD_COUNT;
        if (source_index >= start and source_index < start + count) {
            const local = source_index - start;
            const value_index = local / SECURE_WORD_COUNT;
            return .{ .authenticated_value_word = .{
                .layer = @intCast(layer),
                .query = @intCast(value_index / width),
                .offset = @intCast(value_index % width),
                .word = @intCast(local % SECURE_WORD_COUNT),
            } };
        }
    }
    if (source_index < layout.query_bits) {
        const local = source_index - layout.alpha;
        return .{ .fri_alpha_word = .{
            .layer = @intCast(local / SECURE_WORD_COUNT),
            .word = @intCast(local % SECURE_WORD_COUNT),
        } };
    }
    if (source_index < layout.position) {
        const local = source_index - layout.query_bits;
        return .{ .query_bit = .{
            .query = @intCast(local / M31_BIT_COUNT),
            .bit = @intCast(local % M31_BIT_COUNT),
        } };
    }
    for (0..profile.layerCount()) |layer| {
        const position_start = layout.position_bases[layer];
        if (source_index >= position_start and
            source_index < position_start + profile.query_count)
        {
            return .{ .fri_position = .{
                .layer = @intCast(layer),
                .query = @intCast(source_index - position_start),
            } };
        }
        const offset_start = layout.offset_bases[layer];
        if (source_index >= offset_start and
            source_index < offset_start + profile.query_count)
        {
            return .{ .fri_offset = .{
                .layer = @intCast(layer),
                .query = @intCast(source_index - offset_start),
            } };
        }
    }
    if (source_index < layout.coefficients) {
        return .{ .last_layer_position = .{
            .query = @intCast(source_index - layout.last_position),
        } };
    }
    const local = source_index - layout.coefficients;
    return .{ .last_layer_coefficient_word = .{
        .coefficient = @intCast(local / SECURE_WORD_COUNT),
        .word = @intCast(local % SECURE_WORD_COUNT),
    } };
}

pub const Layout = struct {
    input_count: usize,
    deep: usize,
    auth: usize,
    auth_bases: [MAX_FRI_LAYERS]usize,
    alpha: usize,
    query_bits: usize,
    position: usize,
    position_bases: [MAX_FRI_LAYERS]usize,
    offset: usize,
    offset_bases: [MAX_FRI_LAYERS]usize,
    last_position: usize,
    coefficients: usize,

    pub fn init(profile: Profile) Error!Layout {
        try profile.validate();
        return initUnchecked(profile);
    }

    fn initUnchecked(profile: Profile) Error!Layout {
        var result = Layout{
            .input_count = 0,
            .deep = 1,
            .auth = 0,
            .auth_bases = [_]usize{0} ** MAX_FRI_LAYERS,
            .alpha = 0,
            .query_bits = 0,
            .position = 0,
            .position_bases = [_]usize{0} ** MAX_FRI_LAYERS,
            .offset = 0,
            .offset_bases = [_]usize{0} ** MAX_FRI_LAYERS,
            .last_position = 0,
            .coefficients = 0,
        };
        var cursor = try addProduct(1, profile.query_count, SECURE_WORD_COUNT);
        result.auth = cursor;
        for (profile.fold_widths, 0..) |width, layer| {
            result.auth_bases[layer] = cursor;
            const value_count = std.math.mul(usize, profile.query_count, width) catch
                return error.ArithmeticOverflow;
            cursor = try addProduct(cursor, value_count, SECURE_WORD_COUNT);
        }
        result.alpha = cursor;
        cursor = try addProduct(cursor, profile.layerCount(), SECURE_WORD_COUNT);
        result.query_bits = cursor;
        cursor = try addProduct(cursor, profile.query_count, M31_BIT_COUNT);
        result.position = cursor;
        for (0..profile.layerCount()) |layer| {
            result.position_bases[layer] = cursor;
            cursor = std.math.add(usize, cursor, profile.query_count) catch
                return error.ArithmeticOverflow;
            if (layer == 0) result.offset = cursor;
            result.offset_bases[layer] = cursor;
            cursor = std.math.add(usize, cursor, profile.query_count) catch
                return error.ArithmeticOverflow;
        }
        result.last_position = cursor;
        cursor = std.math.add(usize, cursor, profile.query_count) catch
            return error.ArithmeticOverflow;
        result.coefficients = cursor;
        cursor = try addProduct(
            cursor,
            try profile.lastLayerCoefficientCount(),
            SECURE_WORD_COUNT,
        );
        if (cursor >= m31.Modulus) return error.CircuitTooLarge;
        result.input_count = cursor;
        return result;
    }
};

pub const Handle = union(enum) {
    constant: QM31,
    node: u32,
};

pub const OpKey = union(enum) {
    constant: [4]u32,
    add: graph_mod.BinaryOperands,
    sub: graph_mod.BinaryOperands,
    mul: graph_mod.BinaryOperands,
    neg: u32,
    inverse: u32,
};

pub fn validateWitness(profile: Profile, witness: Witness) Error!void {
    if (witness.deep_answers.len != profile.query_count or
        witness.authenticated_values.len != profile.layerCount() or
        witness.fri_alphas.len != profile.layerCount() or
        witness.raw_queries.len != profile.query_count or
        witness.fri_positions.len != profile.layerCount() or
        witness.fri_offsets.len != profile.layerCount() or
        witness.last_layer_positions.len != profile.query_count or
        witness.last_layer_coefficients.len != try profile.lastLayerCoefficientCount())
    {
        return error.InvalidWitness;
    }
    for (profile.fold_widths, 0..) |width, layer| {
        const expected = std.math.mul(usize, profile.query_count, width) catch
            return error.ArithmeticOverflow;
        if (witness.authenticated_values[layer].len != expected or
            witness.fri_positions[layer].len != profile.query_count or
            witness.fri_offsets[layer].len != profile.query_count)
        {
            return error.InvalidWitness;
        }
    }
}

pub fn inputValue(source: InputSource, witness: Witness) Error!QM31 {
    return switch (source) {
        .active_selector => QM31.fromBase(M31.fromCanonical(@intFromBool(witness.active))),
        .deep_answer_word => |item| baseWord(witness.deep_answers[item.query], item.word),
        .authenticated_value_word => |item| baseWord(
            witness.authenticated_values[item.layer][
                @as(usize, item.query) *
                    (witness.authenticated_values[item.layer].len /
                        witness.deep_answers.len) + item.offset
            ],
            item.word,
        ),
        .fri_alpha_word => |item| baseWord(witness.fri_alphas[item.layer], item.word),
        .query_bit => |item| QM31.fromBase(M31.fromCanonical(
            (witness.raw_queries[item.query].toU32() >> @intCast(item.bit)) & 1,
        )),
        .fri_position => |item| QM31.fromBase(witness.fri_positions[item.layer][item.query]),
        .fri_offset => |item| QM31.fromBase(witness.fri_offsets[item.layer][item.query]),
        .last_layer_position => |item| QM31.fromBase(witness.last_layer_positions[item.query]),
        .last_layer_coefficient_word => |item| baseWord(
            witness.last_layer_coefficients[item.coefficient],
            item.word,
        ),
    };
}

pub fn baseWord(value: QM31, word: u32) Error!QM31 {
    if (word >= SECURE_WORD_COUNT) return error.InvalidWitness;
    return QM31.fromBase(value.toM31Array()[word]);
}

pub fn circuitDigest(
    profile_digest: digest.Digest,
    graph_digest: digest.Digest,
    bindings: []const InputBinding,
) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(CIRCUIT_DOMAIN);
    hashInt(&hash, u16, CIRCUIT_FORMAT_VERSION);
    hash.update(&profile_digest);
    hash.update(&graph_digest);
    hashInt(&hash, u32, bindings.len);
    for (bindings) |binding| {
        hashInt(&hash, u32, binding.node_id);
        hashSource(&hash, binding.source);
    }
    return hash.finalResult();
}

pub fn hashSource(hash: anytype, source: InputSource) void {
    hashInt(hash, u8, @intFromEnum(std.meta.activeTag(source)));
    switch (source) {
        .active_selector => {},
        .deep_answer_word => |item| {
            hashInt(hash, u32, item.query);
            hashInt(hash, u32, item.word);
        },
        .authenticated_value_word => |item| {
            hashInt(hash, u32, item.layer);
            hashInt(hash, u32, item.query);
            hashInt(hash, u32, item.offset);
            hashInt(hash, u32, item.word);
        },
        .fri_alpha_word => |item| {
            hashInt(hash, u32, item.layer);
            hashInt(hash, u32, item.word);
        },
        .query_bit => |item| {
            hashInt(hash, u32, item.query);
            hashInt(hash, u32, item.bit);
        },
        .fri_position => |item| {
            hashInt(hash, u32, item.layer);
            hashInt(hash, u32, item.query);
        },
        .fri_offset => |item| {
            hashInt(hash, u32, item.layer);
            hashInt(hash, u32, item.query);
        },
        .last_layer_position => |item| hashInt(hash, u32, item.query),
        .last_layer_coefficient_word => |item| {
            hashInt(hash, u32, item.coefficient);
            hashInt(hash, u32, item.word);
        },
    }
}

pub fn qm31Words(value: QM31) [4]u32 {
    var result: [4]u32 = undefined;
    for (&result, value.toM31Array()) |*word, limb| word.* = limb.toU32();
    return result;
}

pub fn addProduct(base: usize, lhs: anytype, rhs: anytype) Error!usize {
    const product = std.math.mul(usize, @intCast(lhs), @intCast(rhs)) catch
        return error.ArithmeticOverflow;
    return std.math.add(usize, base, product) catch return error.ArithmeticOverflow;
}

pub fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}
