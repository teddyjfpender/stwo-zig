//! Internal statement semantics circuit authority shard; use statement_semantics_circuit.zig publicly.

pub const std = @import("std");
pub const stwo_core = @import("stwo_core");

pub const M31 = stwo_core.fields.m31.M31;
pub const QM31 = stwo_core.fields.qm31.QM31;
pub const Sha256 = std.crypto.hash.sha2.Sha256;
pub const arithmetic = @import("arithmetic_circuit.zig");
pub const row11 = @import("air/statement_semantics_input_witness.zig");
pub const statement_input = @import("air/statement_input.zig");
pub const statement = @import("span_statement.zig");

pub const Value = arithmetic.Value;
pub const ScopedStatementWords = [statement.SPAN_STATEMENT_CANONICAL_WORDS]M31;
pub const layout = statement.canonical_layout;

pub const ProofKind = row11.ProofKind;
pub const InputBinding = row11.InputBinding;
pub const StatementWords = statement.StatementWords;

pub const FORMAT_VERSION: u16 = 1;
pub const IDENTITY_DOMAIN =
    "stwo-zig/typed-air/recursion-statement-semantics-circuit/v1\x00";
pub const STARK_V_COMMIT = "59172a201bd01f2f4b699bc2f7d4442d8ee81597";
pub const STARK_V_SOURCE_SHA256 =
    "1c136c50f45ae592806649abf802e41b49d78320086ba729990d03e704107899";
pub const IDENTITY_DIGEST_HEX =
    "8f7a0f9bf0dd638993f489f58c13b2f3aeee9dff7e804d49c4c02366fd1f6408";
pub const IDENTITY_DIGEST = hexDigest(
    IDENTITY_DIGEST_HEX,
    "invalid pinned row-11 statement-semantics circuit digest",
);
pub const SELECTOR_INPUT_COUNT: usize = 3;
pub const STATEMENT_INPUT_COUNT: usize = 4 * statement.SPAN_STATEMENT_CANONICAL_WORDS;
pub const PRIVATE_INPUT_COUNT: usize = 313;
pub const INPUT_COUNT: usize =
    SELECTOR_INPUT_COUNT + STATEMENT_INPUT_COUNT + PRIVATE_INPUT_COUNT;
pub const NODE_COUNT: usize = 9_564;
pub const OUTPUT_COUNT: usize = 2_416;

pub const U16_BASE: u32 = 1 << 16;
pub const Error = arithmetic.Error || std.mem.Allocator.Error || error{
    BindingCountMismatch,
    BindingNodeMismatch,
    CircuitIdentityMismatch,
    InputBufferLengthMismatch,
    SemanticGeometryMismatch,
    UnsatisfiedCircuit,
};

/// Raw values for one universal row-11 instance.  Inactive statement scopes are
/// zeroed by `prepareInputsInto`; callers do not need to allocate zero arrays.
/// Invalid selector combinations remain representable and are rejected by the
/// graph's one-hot equations.
pub const Witness = struct {
    segment_selector: bool,
    binary_selector: bool,
    empty_selector: bool,
    segment: *const StatementWords,
    left: *const StatementWords,
    right: *const StatementWords,
    parent: *const StatementWords,

    pub fn forSegment(words: *const StatementWords) Witness {
        return .{
            .segment_selector = true,
            .binary_selector = false,
            .empty_selector = false,
            .segment = words,
            .left = words,
            .right = words,
            .parent = words,
        };
    }

    pub fn forEmpty(words: *const StatementWords) Witness {
        return .{
            .segment_selector = false,
            .binary_selector = false,
            .empty_selector = true,
            .segment = words,
            .left = words,
            .right = words,
            .parent = words,
        };
    }

    pub fn forBinary(
        left: *const StatementWords,
        right: *const StatementWords,
        parent: *const StatementWords,
    ) Witness {
        return .{
            .segment_selector = false,
            .binary_selector = true,
            .empty_selector = false,
            .segment = parent,
            .left = left,
            .right = right,
            .parent = parent,
        };
    }
};

pub const StatementCoordinate = struct {
    scope: u32,
    index: u32,
};

pub const Addition = enum(u8) {
    slot_sibling,
    slot_parent,
    folded_segment_count,
    folded_cycle_count,
    segment_continuity,
    cycle_continuity,
};

pub const PrivateSource = union(enum) {
    statement_bit: struct {
        scope: u32,
        index: u32,
        bit: u8,
    },
    segment_count_minus_one_bit: u8,
    body_executed: u32,
    edge_present: struct {
        scope: u32,
        tag_index: u32,
    },
    addition_carry: struct {
        addition: Addition,
        limb: u8,
    },
};

pub const ValueSource = union(enum) {
    selector: ProofKind,
    statement: StatementCoordinate,
    private: PrivateSource,
};

pub const InputDescriptor = struct {
    node_id: u32,
    active_kinds: row11.ProofKindSet,
    row_source: row11.Source,
    value_source: ValueSource,
};

pub const Circuit = struct {
    allocator: std.mem.Allocator,
    arithmetic_graph: arithmetic.Circuit,
    descriptors: []InputDescriptor,
    bindings: []InputBinding,
    identity_digest: [Sha256.digest_length]u8,

    pub fn deinit(self: *Circuit) void {
        self.allocator.free(self.bindings);
        self.allocator.free(self.descriptors);
        self.arithmetic_graph.deinit();
        self.* = undefined;
    }

    pub fn graph(self: *const Circuit) *const arithmetic.Circuit {
        return &self.arithmetic_graph;
    }

    pub fn inputBindings(self: *const Circuit) []const InputBinding {
        return self.bindings;
    }

    pub fn inputCount(_: *const Circuit) usize {
        return INPUT_COUNT;
    }

    pub fn nodeCount(self: *const Circuit) usize {
        return self.arithmetic_graph.nodes().len;
    }

    pub fn outputCount(self: *const Circuit) usize {
        return self.arithmetic_graph.outputs().len;
    }

    pub fn validate(self: *const Circuit) Error!void {
        if (self.descriptors.len != INPUT_COUNT or self.bindings.len != INPUT_COUNT or
            self.arithmetic_graph.inputNodes().len != INPUT_COUNT)
        {
            return error.BindingCountMismatch;
        }
        try self.arithmetic_graph.validate();
        for (self.descriptors, self.bindings, 0..) |descriptor, binding, input_id| {
            const node_id = self.arithmetic_graph.inputNodes()[input_id];
            if (descriptor.node_id != node_id or binding.node_id != node_id or
                !std.meta.eql(descriptor.row_source, binding.source) or
                binding.use_count != try self.arithmetic_graph.inputUseCount(@intCast(input_id)))
            {
                return error.BindingNodeMismatch;
            }
        }
        const actual = computeIdentity(
            &self.arithmetic_graph,
            self.descriptors,
            self.bindings,
        );
        if (!std.mem.eql(u8, &actual, &self.identity_digest) or
            !std.mem.eql(u8, &actual, &IDENTITY_DIGEST))
            return error.CircuitIdentityMismatch;
    }

    /// Allocation-free population of the exact dense graph input order.
    pub fn prepareInputsInto(
        self: *const Circuit,
        witness: Witness,
        destination: []QM31,
    ) Error!void {
        if (destination.len != INPUT_COUNT) return error.InputBufferLengthMismatch;
        const selected_kind = selectedKind(witness);
        for (self.descriptors, destination) |descriptor, *value| {
            const active = if (selected_kind) |kind|
                descriptor.active_kinds.contains(kind)
            else
                false;
            value.* = switch (descriptor.value_source) {
                .selector => |kind| QM31.fromBase(M31.fromCanonical(@intFromBool(
                    selectorValue(witness, kind),
                ))),
                .statement => |coordinate| if (active)
                    QM31.fromBase(statementWord(witness, coordinate.scope, coordinate.index))
                else
                    QM31.zero(),
                .private => |source| if (active)
                    QM31.fromBase(M31.fromCanonical(privateValue(witness, source)))
                else
                    QM31.zero(),
            };
        }
    }

    /// Validating, allocation-free evaluation into caller-owned buffers.
    pub fn evaluateInto(
        self: *const Circuit,
        witness: Witness,
        inputs: []QM31,
        values: []QM31,
    ) Error!void {
        try self.validate();
        return self.evaluateIntoAssumeValid(witness, inputs, values);
    }

    /// Hot replay after the immutable circuit has passed `validate` once.
    pub fn evaluateIntoAssumeValid(
        self: *const Circuit,
        witness: Witness,
        inputs: []QM31,
        values: []QM31,
    ) Error!void {
        if (!try self.checkIntoAssumeValid(witness, inputs, values))
            return error.UnsatisfiedCircuit;
    }

    /// Diagnostic form used by mutation fleets. Production proof paths should
    /// use `evaluateIntoAssumeValid`, which fail-closes on a nonzero output.
    pub fn checkIntoAssumeValid(
        self: *const Circuit,
        witness: Witness,
        inputs: []QM31,
        values: []QM31,
    ) Error!bool {
        try self.prepareInputsInto(witness, inputs);
        try self.arithmetic_graph.evaluateIntoAssumeValid(inputs, values);
        return self.arithmetic_graph.outputsAreZero(values);
    }

    /// One-allocation convenience evaluation.  Proof loops should reuse the
    /// buffers accepted by `evaluateIntoAssumeValid`.
    pub fn evaluate(
        self: *const Circuit,
        allocator: std.mem.Allocator,
        witness: Witness,
    ) Error!Evaluation {
        try self.validate();
        const total = std.math.add(usize, INPUT_COUNT, self.nodeCount()) catch
            return error.ArithmeticOverflow;
        const storage = try allocator.alloc(QM31, total);
        errdefer allocator.free(storage);
        const inputs = storage[0..INPUT_COUNT];
        const values = storage[INPUT_COUNT..];
        try self.evaluateIntoAssumeValid(witness, inputs, values);
        return .{
            .allocator = allocator,
            .storage = storage,
            .input_count = INPUT_COUNT,
            .circuit_identity = self.identity_digest,
        };
    }
};

pub const Evaluation = struct {
    allocator: std.mem.Allocator,
    storage: []QM31,
    input_count: usize,
    circuit_identity: [Sha256.digest_length]u8,

    pub fn deinit(self: *Evaluation) void {
        self.allocator.free(self.storage);
        self.* = undefined;
    }

    pub fn inputs(self: *const Evaluation) []const QM31 {
        return self.storage[0..self.input_count];
    }

    pub fn values(self: *const Evaluation) []const QM31 {
        return self.storage[self.input_count..];
    }
};

pub fn constant(value: u32) Value {
    return Value.fromBase(M31.fromCanonical(value));
}

pub fn kindSet(kind: ProofKind) row11.ProofKindSet {
    return switch (kind) {
        .segment_leaf => row11.ProofKindSet.SEGMENT,
        .binary_node => row11.ProofKindSet.BINARY,
        .empty_leaf => row11.ProofKindSet.EMPTY,
    };
}

pub fn selectedKind(witness: Witness) ?ProofKind {
    if (witness.segment_selector and !witness.binary_selector and !witness.empty_selector)
        return .segment_leaf;
    if (!witness.segment_selector and witness.binary_selector and !witness.empty_selector)
        return .binary_node;
    if (!witness.segment_selector and !witness.binary_selector and witness.empty_selector)
        return .empty_leaf;
    return null;
}

pub fn selectorValue(witness: Witness, kind: ProofKind) bool {
    return switch (kind) {
        .segment_leaf => witness.segment_selector,
        .binary_node => witness.binary_selector,
        .empty_leaf => witness.empty_selector,
    };
}

pub fn statementWordsForScope(witness: Witness, scope: u32) *const ScopedStatementWords {
    return switch (scope) {
        statement_input.SEGMENT_STATEMENT_SCOPE => witness.segment,
        statement_input.LEFT_STATEMENT_SCOPE => witness.left,
        statement_input.RIGHT_STATEMENT_SCOPE => witness.right,
        statement_input.PARENT_STATEMENT_SCOPE => witness.parent,
        else => unreachable,
    };
}

pub fn statementWord(witness: Witness, scope: u32, index: u32) M31 {
    return statementWordsForScope(witness, scope)[index];
}

pub fn privateValue(witness: Witness, source: PrivateSource) u32 {
    return switch (source) {
        .statement_bit => |item| (statementWord(witness, item.scope, item.index).toU32() >> @intCast(item.bit)) & 1,
        .segment_count_minus_one_bit => |bit| blk: {
            const words = witness.parent;
            const low = @as(u64, words[layout.job_segment_count_start].toU32());
            const high = @as(u64, words[layout.job_segment_count_start + 1].toU32()) << 16;
            const value: u32 = @truncate(low | high);
            break :blk (value -% 1) >> @intCast(bit) & 1;
        },
        .body_executed => |scope| @intFromBool(
            statementWord(witness, scope, layout.body_tag).toU32() ==
                @intFromEnum(statement.Tag.executed_body),
        ),
        .edge_present => |item| @intFromBool(
            statementWord(witness, item.scope, item.tag_index).toU32() ==
                @intFromEnum(statement.Tag.present_edge),
        ),
        .addition_carry => |item| additionCarry(witness, item.addition, item.limb),
    };
}

pub fn additionCarry(witness: Witness, addition: Addition, target_limb: u8) u32 {
    var carry: u64 = 0;
    for (0..@as(usize, target_limb) + 1) |limb| {
        const operands = additionOperands(witness, addition, limb);
        carry = (@as(u64, operands[0]) + @as(u64, operands[1]) + carry) / U16_BASE;
    }
    return @intCast(carry);
}

pub fn additionOperands(witness: Witness, addition: Addition, limb: usize) [2]u32 {
    return switch (addition) {
        .slot_sibling => .{
            witness.left[layout.slot_node_index_start + limb].toU32(),
            @intFromBool(limb == 0),
        },
        .slot_parent => .{
            witness.parent[layout.slot_node_index_start + limb].toU32(),
            witness.parent[layout.slot_node_index_start + limb].toU32(),
        },
        .folded_segment_count => .{
            witness.left[layout.executed_segment_count_start + limb].toU32(),
            witness.right[layout.executed_segment_count_start + limb].toU32(),
        },
        .folded_cycle_count => .{
            witness.left[layout.executed_cycle_count_start + limb].toU32(),
            witness.right[layout.executed_cycle_count_start + limb].toU32(),
        },
        .segment_continuity => .{
            witness.left[layout.first_segment_start + limb].toU32(),
            witness.left[layout.executed_segment_count_start + limb].toU32(),
        },
        .cycle_continuity => .{
            witness.left[layout.first_cycle_start + limb].toU32(),
            witness.left[layout.executed_cycle_count_start + limb].toU32(),
        },
    };
}

pub fn computeIdentity(
    graph: *const arithmetic.Circuit,
    descriptors: []const InputDescriptor,
    bindings: []const InputBinding,
) [Sha256.digest_length]u8 {
    var hash = Sha256.init(.{});
    hash.update(IDENTITY_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hash.update(STARK_V_COMMIT);
    hash.update(STARK_V_SOURCE_SHA256);
    hashInt(&hash, u32, graph.nodes().len);
    for (graph.nodes()) |node| {
        hashInt(&hash, u8, @intFromEnum(std.meta.activeTag(node.op)));
        switch (node.op) {
            .input => {},
            .constant => |words| for (words) |word| hashInt(&hash, u32, word),
            .add, .sub, .mul => |operands| {
                hashInt(&hash, u32, operands.lhs);
                hashInt(&hash, u32, operands.rhs);
            },
            .neg, .inverse => |operand| hashInt(&hash, u32, operand),
        }
    }
    hashInt(&hash, u32, graph.inputNodes().len);
    for (graph.inputNodes()) |node_id| hashInt(&hash, u32, node_id);
    hashInt(&hash, u32, graph.outputs().len);
    for (graph.outputs()) |node_id| hashInt(&hash, u32, node_id);
    hashInt(&hash, u32, graph.useCounts().len);
    for (graph.useCounts()) |count| hashInt(&hash, u32, count);
    hashInt(&hash, u32, descriptors.len);
    for (descriptors) |descriptor| hashDescriptor(&hash, descriptor);
    hashInt(&hash, u32, bindings.len);
    for (bindings) |binding| hashBinding(&hash, binding);
    return hash.finalResult();
}

pub fn hashDescriptor(hash: *Sha256, descriptor: InputDescriptor) void {
    hashInt(hash, u32, descriptor.node_id);
    hashInt(hash, u8, @as(u8, @bitCast(descriptor.active_kinds)));
    hashRowSource(hash, descriptor.row_source);
    hashInt(hash, u8, @intFromEnum(std.meta.activeTag(descriptor.value_source)));
    switch (descriptor.value_source) {
        .selector => |kind| hashInt(hash, u8, @intFromEnum(kind)),
        .statement => |item| {
            hashInt(hash, u32, item.scope);
            hashInt(hash, u32, item.index);
        },
        .private => |source| hashPrivateSource(hash, source),
    }
}

pub fn hashBinding(hash: *Sha256, binding: InputBinding) void {
    hashInt(hash, u32, binding.node_id);
    hashInt(hash, u32, binding.use_count);
    hashRowSource(hash, binding.source);
}

pub fn hashRowSource(hash: *Sha256, source: row11.Source) void {
    hashInt(hash, u8, @intFromEnum(std.meta.activeTag(source)));
    switch (source) {
        .statement => |item| {
            hashInt(hash, u32, item.scope);
            hashInt(hash, u32, item.index);
            hashInt(hash, u8, @as(u8, @bitCast(item.active_kinds)));
        },
        .selector => |kind| hashInt(hash, u8, @intFromEnum(kind)),
        .private => |kinds| hashInt(hash, u8, @as(u8, @bitCast(kinds))),
    }
}

pub fn hashPrivateSource(hash: *Sha256, source: PrivateSource) void {
    hashInt(hash, u8, @intFromEnum(std.meta.activeTag(source)));
    switch (source) {
        .statement_bit => |item| {
            hashInt(hash, u32, item.scope);
            hashInt(hash, u32, item.index);
            hashInt(hash, u8, item.bit);
        },
        .segment_count_minus_one_bit => |bit| hashInt(hash, u8, bit),
        .body_executed => |scope| hashInt(hash, u32, scope),
        .edge_present => |item| {
            hashInt(hash, u32, item.scope);
            hashInt(hash, u32, item.tag_index);
        },
        .addition_carry => |item| {
            hashInt(hash, u8, @intFromEnum(item.addition));
            hashInt(hash, u8, item.limb);
        },
    }
}

pub fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

pub fn hexDigest(comptime value: []const u8, comptime message: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}
