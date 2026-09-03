//! Internal composition circuit authority shard; use composition_circuit.zig publicly.

pub const std = @import("std");
pub const stwo_core = @import("stwo_core");
pub const M31 = stwo_core.fields.m31.M31;
pub const m31 = stwo_core.fields.m31;
pub const digest = @import("../../air/lang/digest.zig");
pub const relation = @import("../../air/lang/relation.zig");
pub const proof_kind_mod = @import("proof_kind.zig");
pub const statement = @import("statement_input.zig");

pub const ProofKind = proof_kind_mod.ProofKind;
pub const SECURE_VALUE_WORD_COUNT: u32 = 4;
pub const RELATION_CHALLENGE_WORD_COUNT: u32 = 8;
pub const SEGMENT_VERIFIER_ID: u32 = 0;
pub const GRAPH_FORMAT_VERSION: u16 = 1;
pub const GRAPH_DOMAIN = "stwo-zig/typed-air/recursion-composition-graph/v1\x00";
pub const REFERENCE_FORMAT_VERSION: u16 = 1;
pub const REFERENCE_DOMAIN = "stwo-zig/typed-air/recursion-composition-reference/v1\x00";
pub const SCHEDULE_FORMAT_VERSION: u16 = 1;
pub const SCHEDULE_DOMAIN = "stwo-zig/typed-air/recursion-composition-schedule/v1\x00";

pub const Error = std.mem.Allocator.Error || error{
    ArithmeticOverflow,
    AnchorGraphMismatch,
    AnchorModeMismatch,
    CircuitIdNotCanonical,
    DuplicateCircuitId,
    DuplicateRecursionLane,
    FixedValueNotCanonical,
    GraphEmpty,
    GraphSealMismatch,
    InputBindingCountMismatch,
    InputBindingNodeMismatch,
    InputBindingTargetsNonInput,
    InvalidGraphOperand,
    InvalidInputSource,
    InvalidScheduleOrder,
    MissingCircuitAnchor,
    MissingGraphOutput,
    NodeCountNotCanonical,
    OutputNodeMissing,
    RecursionLaneNotCanonical,
    ReferenceSealMismatch,
    ScheduleTooLarge,
    UseCountNotCanonical,
};

pub const BinaryOperands = struct {
    lhs: u32,
    rhs: u32,
};

/// Structural graph node. Only constants carry values; every other value is
/// witness-derived and therefore intentionally absent from verifier authority.
pub const Op = union(enum) {
    input,
    constant: [4]u32,
    add: BinaryOperands,
    sub: BinaryOperands,
    mul: BinaryOperands,
    neg: u32,
    inverse: u32,
};

pub const Node = struct {
    op: Op,
};

/// A circuit graph is accepted only against an independently supplied seal.
/// `authenticate` never invents authority by sealing its own input.
pub const CircuitGraph = struct {
    nodes: []const Node,
    outputs: []const u32,
    identity_digest: digest.Digest,

    pub fn authenticate(
        nodes: []const Node,
        outputs: []const u32,
        expected_digest: digest.Digest,
    ) Error!CircuitGraph {
        try validateGraphStructure(nodes, outputs);
        const actual = computeGraphDigest(nodes, outputs);
        if (!std.mem.eql(u8, &actual, &expected_digest))
            return error.GraphSealMismatch;
        return .{
            .nodes = nodes,
            .outputs = outputs,
            .identity_digest = actual,
        };
    }

    pub fn validate(self: CircuitGraph) Error!void {
        try validateGraphStructure(self.nodes, self.outputs);
        const actual = computeGraphDigest(self.nodes, self.outputs);
        if (!std.mem.eql(u8, &actual, &self.identity_digest))
            return error.GraphSealMismatch;
    }
};

pub const SecureCoordinate = struct {
    item_index: u32,
    word_index: u32,
};

pub const ChallengeCoordinate = struct {
    challenge: u32,
    word_index: u32,
};

pub const VmSource = union(enum) {
    segment_selector,
    sampled_value: SecureCoordinate,
    claimed_sum: SecureCoordinate,
    relation_challenge: ChallengeCoordinate,
    composition_randomness: u32,
    oods_point: u32,
    /// Fixed 28-entry transcript claim vector. This is distinct from the
    /// declaration-ordered detailed claims above and is constrained against
    /// their exact per-component aggregation by the VM composition graph.
    transcript_claimed_sum: SecureCoordinate,
};

pub const RecursionSource = union(enum) {
    parent_binary_selector,
    child_kind_selector: ProofKind,
    statement_word: u32,
    sampled_value: SecureCoordinate,
    claimed_sum: SecureCoordinate,
    relation_challenge: ChallengeCoordinate,
    composition_randomness: u32,
    oods_point: u32,
    /// Verifier-authenticated public-wire LogUp boundary. This is a distinct
    /// graph authority even though row 18 transports it through the existing
    /// claimed-sum lookup namespace. Appending the tag preserves frozen V1
    /// source tags and default-zero profiles preserve its exact schedule.
    public_wire_boundary: SecureCoordinate,
    /// Canonical transcript claim vector, distinct from the physical
    /// declaration-ordered claims above. This tag is append-only: profiles
    /// with a zero count retain every legacy tag, input index, and identity.
    transcript_claimed_sum: SecureCoordinate,
};

pub fn InputBinding(comptime Source: type) type {
    return struct {
        node_id: u32,
        source: Source,
    };
}

pub const VmInputBinding = InputBinding(VmSource);
pub const RecursionInputBinding = InputBinding(RecursionSource);

pub const InputProfile = struct {
    sampled_value_count: u32,
    claimed_sum_count: u32,
    relation_challenge_count: u32,
    transcript_claimed_sum_count: u32 = 0,
    public_wire_boundary_count: u32 = 0,
};

pub const VmLane = struct {
    circuit_id: u32,
    graph: CircuitGraph,
    profile: InputProfile,
    bindings: []const VmInputBinding,
};

pub const RecursionLane = struct {
    verifier_id: u32,
    circuit_id: u32,
    statement_scope: u32,
    graph: CircuitGraph,
    profile: InputProfile,
    bindings: []const RecursionInputBinding,
};

pub const ModeSet = packed struct(u8) {
    segment: bool = false,
    binary: bool = false,
    empty: bool = false,
    reserved: u5 = 0,

    pub const SEGMENT = ModeSet{ .segment = true };
    pub const BINARY = ModeSet{ .binary = true };
    pub const ALL = ModeSet{ .segment = true, .binary = true, .empty = true };

    pub fn contains(self: ModeSet, kind: ProofKind) bool {
        return switch (kind) {
            .segment_leaf => self.segment,
            .binary_node => self.binary,
            .empty_leaf => self.empty,
        };
    }

    pub fn selectors(self: ModeSet) [3]u32 {
        return .{
            @intFromBool(self.segment),
            @intFromBool(self.binary),
            @intFromBool(self.empty),
        };
    }

    pub fn validate(self: ModeSet) Error!void {
        if (self.reserved != 0 or
            (!std.meta.eql(self, SEGMENT) and
                !std.meta.eql(self, BINARY) and
                !std.meta.eql(self, ALL)))
        {
            return error.AnchorModeMismatch;
        }
    }
};

pub const AnchorLane = struct {
    circuit_id: u32,
    graph: CircuitGraph,
    active_in: ModeSet,
};

/// All borrowed inputs remain owned by the caller. Mutation is detected by
/// `validate` before compilation and by the compiled schedule seal afterward.
pub const Reference = struct {
    vm: VmLane,
    recursion_lanes: []const RecursionLane,
    additional_anchors: []const AnchorLane,
    identity_digest: digest.Digest,

    pub fn authenticate(
        vm: VmLane,
        recursion_lanes: []const RecursionLane,
        additional_anchors: []const AnchorLane,
        expected_digest: digest.Digest,
    ) Error!Reference {
        const candidate = Reference{
            .vm = vm,
            .recursion_lanes = recursion_lanes,
            .additional_anchors = additional_anchors,
            .identity_digest = expected_digest,
        };
        try candidate.validateStructure();
        const actual = computeReferenceDigest(vm, recursion_lanes, additional_anchors);
        if (!std.mem.eql(u8, &actual, &expected_digest))
            return error.ReferenceSealMismatch;
        return .{
            .vm = vm,
            .recursion_lanes = recursion_lanes,
            .additional_anchors = additional_anchors,
            .identity_digest = actual,
        };
    }

    pub fn validate(self: Reference) Error!void {
        try self.validateStructure();
        const actual = computeReferenceDigest(
            self.vm,
            self.recursion_lanes,
            self.additional_anchors,
        );
        if (!std.mem.eql(u8, &actual, &self.identity_digest))
            return error.ReferenceSealMismatch;
    }

    fn validateStructure(self: Reference) Error!void {
        try validateCircuitId(self.vm.circuit_id);
        try self.vm.graph.validate();
        try validateVmBindings(self.vm);

        for (self.recursion_lanes, 0..) |lane, index| {
            try validateCircuitId(lane.circuit_id);
            if (lane.verifier_id >= m31.Modulus or lane.statement_scope >= m31.Modulus)
                return error.RecursionLaneNotCanonical;
            try lane.graph.validate();
            try validateRecursionBindings(lane);
            for (self.recursion_lanes[0..index]) |previous| {
                if (lane.circuit_id == previous.circuit_id or
                    lane.verifier_id == previous.verifier_id)
                {
                    return error.DuplicateRecursionLane;
                }
            }
        }

        for (self.additional_anchors, 0..) |anchor, index| {
            try validateCircuitId(anchor.circuit_id);
            try anchor.active_in.validate();
            try anchor.graph.validate();
            if (anchor.circuit_id == self.vm.circuit_id)
                return error.DuplicateCircuitId;
            for (self.additional_anchors[0..index]) |previous| {
                if (anchor.circuit_id == previous.circuit_id)
                    return error.DuplicateCircuitId;
            }
        }

        for (self.recursion_lanes) |lane| {
            var matching_anchor: ?AnchorLane = null;
            for (self.additional_anchors) |anchor| {
                if (anchor.circuit_id == lane.circuit_id) matching_anchor = anchor;
            }
            const anchor = matching_anchor orelse return error.MissingCircuitAnchor;
            if (!std.meta.eql(anchor.active_in, ModeSet.BINARY) or
                !std.mem.eql(u8, &anchor.graph.identity_digest, &lane.graph.identity_digest))
            {
                return error.AnchorGraphMismatch;
            }
        }
    }
};

pub const RecursionInput = struct {
    verifier_id: u32,
    statement_scope: u32,
    source: RecursionSource,
};

pub fn computeGraphDigest(nodes: []const Node, outputs: []const u32) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(GRAPH_DOMAIN);
    hashInt(&hash, u16, GRAPH_FORMAT_VERSION);
    hashInt(&hash, u32, nodes.len);
    for (nodes) |node| hashOp(&hash, node.op);
    hashInt(&hash, u32, outputs.len);
    for (outputs) |output| hashInt(&hash, u32, output);
    return hash.finalResult();
}

pub fn computeReferenceDigest(
    vm: VmLane,
    recursion_lanes: []const RecursionLane,
    additional_anchors: []const AnchorLane,
) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(REFERENCE_DOMAIN);
    hashInt(&hash, u16, REFERENCE_FORMAT_VERSION);
    hashInt(&hash, u32, vm.circuit_id);
    hash.update(&vm.graph.identity_digest);
    hashProfile(&hash, vm.profile);
    hashInt(&hash, u32, vm.bindings.len);
    for (vm.bindings) |binding| {
        hashInt(&hash, u32, binding.node_id);
        hashVmSource(&hash, binding.source);
    }
    hashInt(&hash, u32, recursion_lanes.len);
    for (recursion_lanes) |lane| {
        hashInt(&hash, u32, lane.verifier_id);
        hashInt(&hash, u32, lane.circuit_id);
        hashInt(&hash, u32, lane.statement_scope);
        hash.update(&lane.graph.identity_digest);
        hashProfile(&hash, lane.profile);
        hashInt(&hash, u32, lane.bindings.len);
        for (lane.bindings) |binding| {
            hashInt(&hash, u32, binding.node_id);
            hashRecursionSource(&hash, binding.source);
        }
    }
    hashInt(&hash, u32, additional_anchors.len);
    for (additional_anchors) |anchor| {
        hashInt(&hash, u32, anchor.circuit_id);
        hash.update(&anchor.graph.identity_digest);
        hashInt(&hash, u8, @as(u8, @bitCast(anchor.active_in)));
    }
    return hash.finalResult();
}

pub fn validateGraphStructure(nodes: []const Node, outputs: []const u32) Error!void {
    if (nodes.len == 0) return error.GraphEmpty;
    if (nodes.len >= m31.Modulus) return error.NodeCountNotCanonical;
    if (outputs.len == 0) return error.MissingGraphOutput;
    for (nodes, 0..) |node, index| {
        switch (node.op) {
            .input => {},
            .constant => |limbs| for (limbs) |limb| if (limb >= m31.Modulus)
                return error.FixedValueNotCanonical,
            .add, .sub, .mul => |operands| {
                if (operands.lhs >= index or operands.rhs >= index)
                    return error.InvalidGraphOperand;
            },
            .neg, .inverse => |operand| if (operand >= index)
                return error.InvalidGraphOperand,
        }
    }
    for (outputs) |output| if (output >= nodes.len)
        return error.OutputNodeMissing;
}

pub fn validateVmBindings(lane: VmLane) Error!void {
    const expected_count = try vmInputCount(lane.profile);
    if (lane.bindings.len != expected_count) return error.InputBindingCountMismatch;
    try validateBindingsTargetInputs(VmSource, lane.graph, lane.bindings);
    for (lane.bindings, 0..) |binding, index| {
        const expected = expectedVmSource(lane.profile, index) orelse
            return error.InvalidInputSource;
        if (!std.meta.eql(binding.source, expected)) return error.InvalidInputSource;
    }
}

pub fn validateRecursionBindings(lane: RecursionLane) Error!void {
    const expected_count = try recursionInputCount(lane.profile);
    if (lane.bindings.len != expected_count) return error.InputBindingCountMismatch;
    try validateBindingsTargetInputs(RecursionSource, lane.graph, lane.bindings);
    for (lane.bindings, 0..) |binding, index| {
        const expected = expectedRecursionSource(lane.profile, index) orelse
            return error.InvalidInputSource;
        if (!std.meta.eql(binding.source, expected)) return error.InvalidInputSource;
    }
}

pub fn validateBindingsTargetInputs(
    comptime Source: type,
    graph: CircuitGraph,
    bindings: []const InputBinding(Source),
) Error!void {
    var binding_cursor: usize = 0;
    for (graph.nodes, 0..) |node, node_id| switch (node.op) {
        .input => {
            if (binding_cursor >= bindings.len) return error.InputBindingCountMismatch;
            const binding = bindings[binding_cursor];
            if (binding.node_id != node_id) return error.InputBindingNodeMismatch;
            binding_cursor += 1;
        },
        else => {},
    };
    if (binding_cursor != bindings.len) return error.InputBindingTargetsNonInput;
}

pub fn vmInputCount(profile: InputProfile) Error!usize {
    var count: usize = 1;
    count = try addProduct(count, profile.sampled_value_count, SECURE_VALUE_WORD_COUNT);
    count = try addProduct(count, profile.claimed_sum_count, SECURE_VALUE_WORD_COUNT);
    count = try addProduct(
        count,
        profile.transcript_claimed_sum_count,
        SECURE_VALUE_WORD_COUNT,
    );
    count = try addProduct(count, profile.relation_challenge_count, RELATION_CHALLENGE_WORD_COUNT);
    count = std.math.add(usize, count, 2 * SECURE_VALUE_WORD_COUNT) catch
        return error.ArithmeticOverflow;
    return count;
}

pub fn recursionInputCount(profile: InputProfile) Error!usize {
    var count: usize = 1 + 3 + statement.CANONICAL_WORD_COUNT;
    count = try addProduct(count, profile.sampled_value_count, SECURE_VALUE_WORD_COUNT);
    count = try addProduct(count, profile.claimed_sum_count, SECURE_VALUE_WORD_COUNT);
    count = try addProduct(
        count,
        profile.transcript_claimed_sum_count,
        SECURE_VALUE_WORD_COUNT,
    );
    count = try addProduct(
        count,
        profile.public_wire_boundary_count,
        SECURE_VALUE_WORD_COUNT,
    );
    count = try addProduct(count, profile.relation_challenge_count, RELATION_CHALLENGE_WORD_COUNT);
    count = std.math.add(usize, count, 2 * SECURE_VALUE_WORD_COUNT) catch
        return error.ArithmeticOverflow;
    return count;
}

pub fn addProduct(base: usize, lhs: u32, rhs: u32) Error!usize {
    const product = std.math.mul(usize, lhs, rhs) catch return error.ArithmeticOverflow;
    return std.math.add(usize, base, product) catch return error.ArithmeticOverflow;
}

pub fn expectedVmSource(profile: InputProfile, source_index: usize) ?VmSource {
    if (source_index == 0) return .segment_selector;
    var index = source_index - 1;
    if (secureSource(VmSource, .sampled_value, profile.sampled_value_count, &index)) |source_value|
        return source_value;
    if (secureSource(VmSource, .claimed_sum, profile.claimed_sum_count, &index)) |source_value|
        return source_value;
    if (secureSource(
        VmSource,
        .transcript_claimed_sum,
        profile.transcript_claimed_sum_count,
        &index,
    )) |source_value| return source_value;
    if (challengeSource(VmSource, profile.relation_challenge_count, &index)) |source_value|
        return source_value;
    if (index < SECURE_VALUE_WORD_COUNT) return .{ .composition_randomness = @intCast(index) };
    index -= SECURE_VALUE_WORD_COUNT;
    if (index < SECURE_VALUE_WORD_COUNT) return .{ .oods_point = @intCast(index) };
    return null;
}

pub fn expectedRecursionSource(profile: InputProfile, source_index: usize) ?RecursionSource {
    if (source_index == 0) return .parent_binary_selector;
    var index = source_index - 1;
    if (index < 3) return .{ .child_kind_selector = @enumFromInt(index) };
    index -= 3;
    if (index < statement.CANONICAL_WORD_COUNT)
        return .{ .statement_word = @intCast(index) };
    index -= statement.CANONICAL_WORD_COUNT;
    if (secureSource(RecursionSource, .sampled_value, profile.sampled_value_count, &index)) |source_value|
        return source_value;
    if (secureSource(RecursionSource, .claimed_sum, profile.claimed_sum_count, &index)) |source_value|
        return source_value;
    if (secureSource(
        RecursionSource,
        .transcript_claimed_sum,
        profile.transcript_claimed_sum_count,
        &index,
    )) |source_value| return source_value;
    if (secureSource(
        RecursionSource,
        .public_wire_boundary,
        profile.public_wire_boundary_count,
        &index,
    )) |source_value| {
        var coordinate = source_value.public_wire_boundary;
        coordinate.item_index = std.math.add(
            u32,
            coordinate.item_index,
            profile.claimed_sum_count,
        ) catch return null;
        return .{ .public_wire_boundary = coordinate };
    }
    if (challengeSource(RecursionSource, profile.relation_challenge_count, &index)) |source_value|
        return source_value;
    if (index < SECURE_VALUE_WORD_COUNT) return .{ .composition_randomness = @intCast(index) };
    index -= SECURE_VALUE_WORD_COUNT;
    if (index < SECURE_VALUE_WORD_COUNT) return .{ .oods_point = @intCast(index) };
    return null;
}

pub fn secureSource(
    comptime Source: type,
    comptime tag: std.meta.Tag(Source),
    item_count: u32,
    index: *usize,
) ?Source {
    const count = @as(usize, item_count) * SECURE_VALUE_WORD_COUNT;
    if (index.* >= count) {
        index.* -= count;
        return null;
    }
    const coordinate = SecureCoordinate{
        .item_index = @intCast(index.* / SECURE_VALUE_WORD_COUNT),
        .word_index = @intCast(index.* % SECURE_VALUE_WORD_COUNT),
    };
    return @unionInit(Source, @tagName(tag), coordinate);
}

pub fn challengeSource(
    comptime Source: type,
    challenge_count: u32,
    index: *usize,
) ?Source {
    const count = @as(usize, challenge_count) * RELATION_CHALLENGE_WORD_COUNT;
    if (index.* >= count) {
        index.* -= count;
        return null;
    }
    return @unionInit(Source, "relation_challenge", ChallengeCoordinate{
        .challenge = @intCast(index.* / RELATION_CHALLENGE_WORD_COUNT),
        .word_index = @intCast(index.* % RELATION_CHALLENGE_WORD_COUNT),
    });
}

pub fn vmSourceIndices(source_value: VmSource) [2]u32 {
    return switch (source_value) {
        .segment_selector => .{ 0, 0 },
        .sampled_value, .claimed_sum, .transcript_claimed_sum => |coordinate| .{ coordinate.item_index, coordinate.word_index },
        .relation_challenge => |coordinate| .{ coordinate.challenge, coordinate.word_index },
        .composition_randomness, .oods_point => |word_index| .{ 0, word_index },
    };
}

pub fn recursionSourceIndices(source_value: RecursionSource) [2]u32 {
    return switch (source_value) {
        .parent_binary_selector => .{ 0, 0 },
        .child_kind_selector => |kind| .{ @intFromEnum(kind), 0 },
        .statement_word => |word_index| .{ word_index, 0 },
        .sampled_value, .claimed_sum, .transcript_claimed_sum => |coordinate| .{ coordinate.item_index, coordinate.word_index },
        .relation_challenge => |coordinate| .{ coordinate.challenge, coordinate.word_index },
        .composition_randomness, .oods_point => |word_index| .{ 0, word_index },
        .public_wire_boundary => |coordinate| .{ coordinate.item_index, coordinate.word_index },
    };
}

pub fn validateCircuitId(circuit_id: u32) Error!void {
    if (circuit_id >= m31.Modulus) return error.CircuitIdNotCanonical;
}

pub fn hashOp(hash: anytype, op: Op) void {
    hashInt(hash, u8, @intFromEnum(std.meta.activeTag(op)));
    switch (op) {
        .input => {},
        .constant => |limbs| for (limbs) |limb| hashInt(hash, u32, limb),
        .add, .sub, .mul => |operands| {
            hashInt(hash, u32, operands.lhs);
            hashInt(hash, u32, operands.rhs);
        },
        .neg, .inverse => |operand| hashInt(hash, u32, operand),
    }
}

pub fn hashProfile(hash: anytype, profile: InputProfile) void {
    hashInt(hash, u32, profile.sampled_value_count);
    hashInt(hash, u32, profile.claimed_sum_count);
    hashInt(hash, u32, profile.relation_challenge_count);
    if (profile.transcript_claimed_sum_count != 0) {
        hashInt(hash, u32, 0x5452_434c); // "TRCL"
        hashInt(hash, u32, profile.transcript_claimed_sum_count);
    }
    if (profile.public_wire_boundary_count != 0) {
        hashInt(hash, u32, 0x5057_4244); // "PWBD"
        hashInt(hash, u32, profile.public_wire_boundary_count);
    }
}

pub fn hashVmSource(hash: anytype, source_value: VmSource) void {
    hashInt(hash, u8, @intFromEnum(std.meta.activeTag(source_value)));
    const indices = vmSourceIndices(source_value);
    hashInt(hash, u32, indices[0]);
    hashInt(hash, u32, indices[1]);
}

pub fn hashRecursionSource(hash: anytype, source_value: RecursionSource) void {
    hashInt(hash, u8, @intFromEnum(std.meta.activeTag(source_value)));
    const indices = recursionSourceIndices(source_value);
    hashInt(hash, u32, indices[0]);
    hashInt(hash, u32, indices[1]);
}

pub fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}
