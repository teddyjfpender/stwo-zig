//! Internal pcs deep circuit authority shard; use pcs_deep_circuit.zig publicly.

pub const std = @import("std");
pub const stwo_core = @import("stwo_core");
pub const M31 = stwo_core.fields.m31.M31;
pub const m31 = stwo_core.fields.m31;
pub const QM31 = stwo_core.fields.qm31.QM31;
pub const digest = @import("../../air/lang/digest.zig");
pub const graph_mod = @import("composition_circuit.zig");
pub const input_mod = @import("pcs_deep_input_witness.zig");
pub const sample_point_layout = @import("../sample_point_layout.zig");

pub const SECURE_WORD_COUNT: usize = input_mod.SECURE_WORD_COUNT;
pub const M31_BIT_COUNT: usize = input_mod.M31_BIT_COUNT;
pub const MAX_DOMAIN_LOG: u32 = input_mod.MAX_LOG_SIZE;
pub const MAX_SAMPLE_COUNT_PER_COLUMN: u8 = 2;
// V1 remains valid: layout tags 0/1/2 are byte-identical to its former
// count-only encoding. Reverse order uses tag 3, which V1 previously rejected,
// and its distinct profile digest also binds the correspondingly distinct
// graph. No published legacy profile or circuit identity changes.
pub const PROFILE_FORMAT_VERSION: u16 = 1;
pub const PROFILE_DOMAIN = "stwo-zig/typed-air/recursion-pcs-deep-profile/v1\x00";
pub const CIRCUIT_FORMAT_VERSION: u16 = 1;
pub const CIRCUIT_DOMAIN = "stwo-zig/typed-air/recursion-pcs-deep-circuit/v1\x00";

pub const InputSource = input_mod.Source;
pub const InputBinding = input_mod.InputBinding;

pub const Error = std.mem.Allocator.Error || graph_mod.Error || input_mod.Error ||
    QM31.Error || error{
    ArithmeticOverflow,
    BindingCountMismatch,
    BindingNodeMismatch,
    BindingTargetsNonInput,
    CircuitIdentityMismatch,
    CircuitTooLarge,
    ColumnCountMismatch,
    InputIsNotBaseField,
    InvalidProfile,
    InvalidWitness,
    ProfileIdentityMismatch,
    SampleCountMismatch,
    UnsatisfiedCircuit,
};

pub const TreeProfile = input_mod.TreeProfile;
pub const SamplePointLayout = sample_point_layout.Layout;

/// Verifier-owned PCS geometry. `sample_layouts` is flattened tree/column
/// order. It preserves exact point order because the native PCS assigns DEEP
/// powers in that order and applies the two-sample periodicity term to the
/// second point. Counts alone are therefore insufficient protocol metadata.
pub const Profile = struct {
    trees: []const TreeProfile,
    sample_layouts: []const SamplePointLayout,
    lifting_log_size: u32,
    log_blowup_factor: u32,
    query_count: u32,

    pub fn validate(self: Profile) Error!void {
        if (self.trees.len == 0 or self.trees.len >= m31.Modulus or
            self.lifting_log_size == 0 or self.lifting_log_size > MAX_DOMAIN_LOG or
            self.log_blowup_factor >= self.lifting_log_size or
            self.query_count == 0 or self.query_count >= m31.Modulus)
        {
            return error.InvalidProfile;
        }
        var column_count: usize = 0;
        var sample_count: usize = 0;
        for (self.trees) |tree| {
            if (tree.column_log_sizes.len == 0 or
                tree.column_log_sizes.len >= m31.Modulus)
            {
                return error.InvalidProfile;
            }
            for (tree.column_log_sizes) |log_size| {
                if (log_size == 0 or log_size > self.lifting_log_size)
                    return error.InvalidProfile;
            }
            column_count = checkedAdd(column_count, tree.column_log_sizes.len) catch
                return error.ArithmeticOverflow;
        }
        if (column_count != self.sample_layouts.len)
            return error.ColumnCountMismatch;
        for (self.sample_layouts) |layout| {
            sample_count = checkedAdd(sample_count, layout.sampleCount()) catch
                return error.ArithmeticOverflow;
        }
        if (sample_count == 0 or sample_count >= m31.Modulus or
            column_count >= m31.Modulus)
        {
            return error.InvalidProfile;
        }
        _ = try self.termCount();
        _ = try self.inputCount();
    }

    pub fn columnCount(self: Profile) Error!usize {
        var result: usize = 0;
        for (self.trees) |tree|
            result = try checkedAdd(result, tree.column_log_sizes.len);
        return result;
    }

    pub fn sampleCount(self: Profile) Error!usize {
        var result: usize = 0;
        for (self.sample_layouts) |layout|
            result = try checkedAdd(result, layout.sampleCount());
        return result;
    }

    pub fn termCount(self: Profile) Error!usize {
        var result = try self.sampleCount();
        for (self.sample_layouts) |layout| {
            if (layout.hasPeriodicity()) result = try checkedAdd(result, 1);
        }
        if (result >= m31.Modulus) return error.InvalidProfile;
        return result;
    }

    pub fn inputCount(self: Profile) Error!usize {
        const lane = try self.laneProfile();
        return lane.inputCount();
    }

    pub fn laneProfile(self: Profile) Error!input_mod.LaneProfile {
        return .{
            .sample_count = std.math.cast(u32, try self.sampleCount()) orelse
                return error.ArithmeticOverflow,
            .query_count = self.query_count,
            .lifting_log_size = self.lifting_log_size,
            .trees = self.trees,
        };
    }

    pub fn identityDigest(self: Profile) digest.Digest {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(PROFILE_DOMAIN);
        hashInt(&hash, u16, PROFILE_FORMAT_VERSION);
        hashInt(&hash, u32, self.lifting_log_size);
        hashInt(&hash, u32, self.log_blowup_factor);
        hashInt(&hash, u32, self.query_count);
        hashInt(&hash, u32, self.trees.len);
        var sample_cursor: usize = 0;
        for (self.trees) |tree| {
            hashInt(&hash, u32, tree.column_log_sizes.len);
            for (tree.column_log_sizes) |log_size| {
                hashInt(&hash, u32, log_size);
                hashInt(&hash, u8, @intFromEnum(self.sample_layouts[sample_cursor]));
                sample_cursor += 1;
            }
        }
        return hash.finalResult();
    }
};

pub const Witness = struct {
    active: bool,
    sampled_values: []const QM31,
    queried_values: []const M31,
    oods_seed: QM31,
    deep_randomness: QM31,
    raw_queries: []const M31,
    answers: []const QM31,
};

pub const Circuit = struct {
    allocator: std.mem.Allocator,
    trees: []TreeProfile,
    column_log_storage: []u32,
    sample_layouts: []SamplePointLayout,
    lifting_log_size: u32,
    log_blowup_factor: u32,
    query_count: u32,
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
        self.allocator.free(self.sample_layouts);
        self.allocator.free(self.column_log_storage);
        self.allocator.free(self.trees);
        self.* = undefined;
    }

    pub fn profile(self: *const Circuit) Profile {
        return .{
            .trees = self.trees,
            .sample_layouts = self.sample_layouts,
            .lifting_log_size = self.lifting_log_size,
            .log_blowup_factor = self.log_blowup_factor,
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

    pub fn laneProfile(self: *const Circuit) Error!input_mod.LaneProfile {
        return self.profile().laneProfile();
    }

    pub fn validate(self: *const Circuit) Error!void {
        const profile_value = self.profile();
        try profile_value.validate();
        if (!std.mem.eql(u8, &self.profile_digest, &profile_value.identityDigest()))
            return error.ProfileIdentityMismatch;
        try self.graph().validate();
        if (self.bindings.len != try profile_value.inputCount())
            return error.BindingCountMismatch;
        const lane_profile = try profile_value.laneProfile();
        var binding_cursor: usize = 0;
        for (self.nodes, 0..) |node, node_id| switch (node.op) {
            .input => {
                if (binding_cursor >= self.bindings.len)
                    return error.BindingCountMismatch;
                const binding = self.bindings[binding_cursor];
                if (binding.node_id != node_id) return error.BindingNodeMismatch;
                const expected = (try input_mod.expectedSource(lane_profile, binding_cursor)) orelse
                    return error.BindingCountMismatch;
                if (!std.meta.eql(binding.source, expected))
                    return error.BindingNodeMismatch;
                binding_cursor += 1;
            },
            else => {},
        };
        if (binding_cursor != self.bindings.len)
            return error.BindingTargetsNonInput;
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
                    break :blk try inputValue(
                        self.bindings[binding_cursor].source,
                        witness,
                        self.profile(),
                    );
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
        if (binding_cursor != self.bindings.len)
            return error.BindingCountMismatch;
        for (self.outputs) |output| if (!values[output].isZero())
            return error.UnsatisfiedCircuit;
        return .{
            .allocator = allocator,
            .values = values,
            .circuit_identity = self.identity_digest,
        };
    }

    /// Evaluates the canonical inactive assignment without allocating large
    /// zero-valued source arrays. Every graph input is zero; the circuit's
    /// selector substitutes its fixed off-domain seed and unit randomness.
    pub fn evaluateInactive(
        self: *const Circuit,
        allocator: std.mem.Allocator,
    ) Error!Evaluation {
        try self.validate();
        const values = try allocator.alloc(QM31, self.nodes.len);
        errdefer allocator.free(values);
        for (self.nodes, 0..) |node, node_id| {
            values[node_id] = switch (node.op) {
                .input => QM31.zero(),
                .constant => |words| QM31.fromU32Unchecked(
                    words[0],
                    words[1],
                    words[2],
                    words[3],
                ),
                else => try evaluateOperation(node, values, node_id),
            };
        }
        for (self.outputs) |output| if (!values[output].isZero())
            return error.UnsatisfiedCircuit;
        return .{
            .allocator = allocator,
            .values = values,
            .circuit_identity = self.identity_digest,
        };
    }

    /// Allocation-free replay used at the proof boundary after cold authority
    /// admission. Every non-input node and every designated zero output is
    /// rechecked, so mutated evaluation storage cannot enter lowering.
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
            if (output >= evaluation.values.len)
                return error.InvalidWitness;
            if (!evaluation.values[output].isZero())
                return error.UnsatisfiedCircuit;
        }
    }

    pub fn inputValuesInto(
        self: *const Circuit,
        evaluation: *const Evaluation,
        destination: []M31,
    ) Error!void {
        try self.validateEvaluationHot(evaluation);
        if (destination.len != self.bindings.len)
            return error.BindingCountMismatch;
        for (self.bindings, destination) |binding, *value| {
            if (binding.node_id >= evaluation.values.len)
                return error.InvalidWitness;
            value.* = evaluation.values[binding.node_id].tryIntoM31() catch
                return error.InputIsNotBaseField;
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

pub const Layout = struct {
    input_count: usize,
    sampled: usize,
    queried: usize,
    oods_seed: usize,
    deep_randomness: usize,
    query_coordinates: usize,
    answers: usize,

    pub fn init(profile: Profile) Error!Layout {
        try profile.validate();
        var result = Layout{
            .input_count = 0,
            .sampled = 1,
            .queried = 0,
            .oods_seed = 0,
            .deep_randomness = 0,
            .query_coordinates = 0,
            .answers = 0,
        };
        var cursor = try addProduct(1, try profile.sampleCount(), SECURE_WORD_COUNT);
        result.queried = cursor;
        cursor = try addProduct(cursor, try profile.columnCount(), profile.query_count);
        result.oods_seed = cursor;
        cursor = try checkedAdd(cursor, SECURE_WORD_COUNT);
        result.deep_randomness = cursor;
        cursor = try checkedAdd(cursor, SECURE_WORD_COUNT);
        result.query_coordinates = cursor;
        cursor = try addProduct(cursor, profile.query_count, M31_BIT_COUNT + 1);
        result.answers = cursor;
        cursor = try addProduct(cursor, profile.query_count, SECURE_WORD_COUNT);
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
    const queried_value_count = std.math.mul(
        usize,
        try profile.columnCount(),
        @intCast(profile.query_count),
    ) catch return error.ArithmeticOverflow;
    if (witness.sampled_values.len != try profile.sampleCount() or
        witness.queried_values.len != queried_value_count or
        witness.raw_queries.len != profile.query_count or
        witness.answers.len != profile.query_count)
    {
        return error.InvalidWitness;
    }
}

pub fn inputValue(
    source: InputSource,
    witness: Witness,
    profile: Profile,
) Error!QM31 {
    return switch (source) {
        .active_selector => QM31.fromBase(M31.fromCanonical(@intFromBool(witness.active))),
        .sampled_value_word => |item| baseWord(
            witness.sampled_values[item.sample],
            item.word,
        ),
        .queried_value => |item| blk: {
            const tree_index: usize = @intCast(item.tree);
            const column_index: usize = @intCast(item.column);
            if (tree_index >= profile.trees.len or
                column_index >= profile.trees[tree_index].column_log_sizes.len or
                item.query >= profile.query_count)
            {
                return error.InvalidWitness;
            }
            var flat_column = column_index;
            for (profile.trees[0..tree_index]) |tree|
                flat_column = try checkedAdd(flat_column, tree.column_log_sizes.len);
            const index = try checkedAdd(
                std.math.mul(
                    usize,
                    flat_column,
                    @intCast(profile.query_count),
                ) catch return error.ArithmeticOverflow,
                item.query,
            );
            if (index >= witness.queried_values.len)
                return error.InvalidWitness;
            break :blk QM31.fromBase(witness.queried_values[index]);
        },
        .oods_seed_word => |word| baseWord(witness.oods_seed, word),
        .deep_randomness_word => |word| baseWord(witness.deep_randomness, word),
        .query_bit => |item| QM31.fromBase(M31.fromCanonical(
            (witness.raw_queries[item.query].toU32() >> @intCast(item.bit)) & 1,
        )),
        .query_position => |query| QM31.fromBase(M31.fromCanonical(
            witness.raw_queries[query].toU32() &
                ((@as(u32, 1) << @intCast(profile.lifting_log_size)) - 1),
        )),
        .answer_word => |item| baseWord(witness.answers[item.query], item.word),
    };
}

pub fn evaluateOperation(
    node: graph_mod.Node,
    values: []const QM31,
    node_id: usize,
) Error!QM31 {
    return switch (node.op) {
        .add => |operation| (try operandValue(values, node_id, operation.lhs)).add(
            try operandValue(values, node_id, operation.rhs),
        ),
        .sub => |operation| (try operandValue(values, node_id, operation.lhs)).sub(
            try operandValue(values, node_id, operation.rhs),
        ),
        .mul => |operation| (try operandValue(values, node_id, operation.lhs)).mul(
            try operandValue(values, node_id, operation.rhs),
        ),
        .neg => |operand| (try operandValue(values, node_id, operand)).neg(),
        .inverse => |operand| try (try operandValue(values, node_id, operand)).inv(),
        .input, .constant => unreachable,
    };
}

pub fn operandValue(values: []const QM31, node_id: usize, operand: u32) Error!QM31 {
    if (operand >= node_id or operand >= values.len)
        return error.InvalidWitness;
    return values[operand];
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
        .sampled_value_word => |item| {
            hashInt(hash, u32, item.sample);
            hashInt(hash, u32, item.word);
        },
        .queried_value => |item| {
            hashInt(hash, u32, item.tree);
            hashInt(hash, u32, item.column);
            hashInt(hash, u32, item.query);
        },
        .oods_seed_word, .deep_randomness_word => |word| hashInt(hash, u32, word),
        .query_bit => |item| {
            hashInt(hash, u32, item.query);
            hashInt(hash, u32, item.bit);
        },
        .query_position => |query| hashInt(hash, u32, query),
        .answer_word => |item| {
            hashInt(hash, u32, item.query);
            hashInt(hash, u32, item.word);
        },
    }
}

pub fn qm31Words(value: QM31) [4]u32 {
    var result: [4]u32 = undefined;
    for (&result, value.toM31Array()) |*word, limb| word.* = limb.toU32();
    return result;
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

pub fn checkedAdd(lhs: usize, rhs: anytype) Error!usize {
    const canonical = std.math.cast(usize, rhs) orelse
        return error.ArithmeticOverflow;
    return std.math.add(usize, lhs, canonical) catch
        return error.ArithmeticOverflow;
}

pub fn addProduct(base: usize, lhs: anytype, rhs: anytype) Error!usize {
    const left = std.math.cast(usize, lhs) orelse
        return error.ArithmeticOverflow;
    const right = std.math.cast(usize, rhs) orelse
        return error.ArithmeticOverflow;
    const product = std.math.mul(usize, left, right) catch
        return error.ArithmeticOverflow;
    return checkedAdd(base, product);
}

pub fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}
