//! Shared QM31 arithmetic-circuit construction for recursive verification.
//!
//! The builder records the same topological node vocabulary consumed by the
//! universal recursion arithmetic rows. Inputs are indexed densely in caller
//! authority order; constants and arithmetic operations are hash-consed;
//! commutative operands are stored canonically; and total algebraic identities
//! fold before a node is allocated. Finalization derives exact wire-use counts
//! once, while evaluation can replay into caller-owned storage without an
//! allocation.
//!
//! This module owns graph mechanics, not input semantics. Rows 11 and 15--17
//! remain responsible for mapping each dense input index to its authenticated
//! statement, claim, challenge, or selector source.

const std = @import("std");
const stwo_core = @import("stwo_core");

const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;
const QM31 = stwo_core.fields.qm31.QM31;

pub const NodeId = u32;
pub const InputId = u32;

/// Kept wire-compatible with `air/composition_circuit.zig` while avoiding a
/// dependency from this graph primitive back into the AIR layer. Integration
/// may make these declarations the shared vocabulary or perform an explicit
/// typed copy; either direction keeps the ownership boundary reviewable.
pub const BinaryOperands = struct {
    lhs: NodeId,
    rhs: NodeId,
};

pub const Op = union(enum) {
    input,
    constant: [4]u32,
    add: BinaryOperands,
    sub: BinaryOperands,
    mul: BinaryOperands,
    neg: NodeId,
    inverse: NodeId,
};

pub const Node = struct {
    op: Op,
};

pub const Error = std.mem.Allocator.Error || QM31.Error || error{
    ArithmeticOverflow,
    InputCountMismatch,
    InputLimitExceeded,
    InputOrderNotCanonical,
    InvalidConstant,
    InvalidInputLayout,
    InvalidLimits,
    InvalidNodeId,
    InvalidOperand,
    MissingOutput,
    NodeLimitExceeded,
    OutputIndexOutOfBounds,
    OutputLimitExceeded,
    ReservationBelowCurrentUsage,
    UseCountBufferTooSmall,
    UseCountLimitExceeded,
    UseCountMismatch,
    ValueBufferLengthMismatch,
};

/// Cold-construction bounds. Defaults are deliberately well above the current
/// recursion circuits while remaining finite. All field-visible identifiers
/// and multiplicities are kept canonical M31 values.
pub const Limits = struct {
    max_nodes: u32 = 1 << 20,
    max_inputs: u32 = 1 << 18,
    max_outputs: u32 = 1 << 16,
    max_use_count: u32 = m31.Modulus - 1,

    pub fn validate(self: Limits) Error!void {
        if (self.max_nodes == 0 or self.max_inputs > self.max_nodes or
            self.max_outputs == 0 or self.max_nodes > m31.Modulus or
            self.max_inputs > m31.Modulus or self.max_outputs > m31.Modulus or
            self.max_use_count == 0 or self.max_use_count >= m31.Modulus)
        {
            return error.InvalidLimits;
        }
    }
};

/// An authored value is immediate until an operation or public output needs a
/// node. This keeps constant-only subexpressions out of the graph.
pub const Value = union(enum) {
    constant: QM31,
    node: NodeId,

    pub fn zero() Value {
        return .{ .constant = QM31.zero() };
    }

    pub fn one() Value {
        return .{ .constant = QM31.one() };
    }

    pub fn fromBase(value: M31) Value {
        return .{ .constant = QM31.fromBase(value) };
    }

    pub fn fromSecure(value: QM31) Value {
        return .{ .constant = value };
    }
};

const OpKey = union(enum) {
    constant: [4]u32,
    add: BinaryOperands,
    sub: BinaryOperands,
    mul: BinaryOperands,
    neg: NodeId,
    inverse: NodeId,
};

const PlannedOperand = struct {
    id: NodeId,
    new_constant: ?[4]u32 = null,
};

pub const Builder = struct {
    allocator: std.mem.Allocator,
    limits: Limits,
    nodes_storage: std.ArrayList(Node) = .empty,
    input_nodes_storage: std.ArrayList(NodeId) = .empty,
    outputs_storage: std.ArrayList(NodeId) = .empty,
    interned: std.AutoHashMap(OpKey, NodeId),

    pub fn init(allocator: std.mem.Allocator, limits: Limits) Error!Builder {
        try limits.validate();
        return .{
            .allocator = allocator,
            .limits = limits,
            .interned = std.AutoHashMap(OpKey, NodeId).init(allocator),
        };
    }

    pub fn initDefault(allocator: std.mem.Allocator) Builder {
        return .{
            .allocator = allocator,
            .limits = .{},
            .interned = std.AutoHashMap(OpKey, NodeId).init(allocator),
        };
    }

    pub fn deinit(self: *Builder) void {
        self.interned.deinit();
        self.outputs_storage.deinit(self.allocator);
        self.input_nodes_storage.deinit(self.allocator);
        self.nodes_storage.deinit(self.allocator);
        self.* = undefined;
    }

    /// Preallocates all cold builder storage. When these bounds are accurate,
    /// input and operation recording perform no further allocations;
    /// `finish` performs the single use-count allocation.
    pub fn reserve(
        self: *Builder,
        total_inputs: usize,
        total_nodes: usize,
        total_outputs: usize,
    ) Error!void {
        if (total_inputs < self.input_nodes_storage.items.len or
            total_nodes < self.nodes_storage.items.len or
            total_outputs < self.outputs_storage.items.len)
        {
            return error.ReservationBelowCurrentUsage;
        }
        try self.checkInputCount(total_inputs);
        try self.checkNodeCount(total_nodes);
        try self.checkOutputCount(total_outputs);
        try self.nodes_storage.ensureTotalCapacity(self.allocator, total_nodes);
        try self.input_nodes_storage.ensureTotalCapacity(self.allocator, total_inputs);
        try self.outputs_storage.ensureTotalCapacity(self.allocator, total_outputs);
        try self.interned.ensureTotalCapacity(@intCast(total_nodes));
    }

    pub fn nodes(self: *const Builder) []const Node {
        return self.nodes_storage.items;
    }

    pub fn inputNodes(self: *const Builder) []const NodeId {
        return self.input_nodes_storage.items;
    }

    pub fn outputs(self: *const Builder) []const NodeId {
        return self.outputs_storage.items;
    }

    /// Returns the existing node for a repeated input index. A new input must
    /// be the next dense index; gaps and reordered first declarations reject.
    pub fn input(self: *Builder, input_id: InputId) Error!Value {
        const index: usize = input_id;
        if (index < self.input_nodes_storage.items.len)
            return .{ .node = self.input_nodes_storage.items[index] };
        if (index != self.input_nodes_storage.items.len)
            return error.InputOrderNotCanonical;
        try self.checkInputCount(index + 1);
        try self.ensureRawNodes(1);
        try self.input_nodes_storage.ensureUnusedCapacity(self.allocator, 1);
        const node_id = try indexNode(self.nodes_storage.items.len);
        self.nodes_storage.appendAssumeCapacity(.{ .op = .input });
        self.input_nodes_storage.appendAssumeCapacity(node_id);
        return .{ .node = node_id };
    }

    pub fn constant(_: *const Builder, value: QM31) Value {
        return Value.fromSecure(value);
    }

    pub fn baseConstant(_: *const Builder, value: M31) Value {
        return Value.fromBase(value);
    }

    pub fn add(self: *Builder, lhs: Value, rhs: Value) Error!Value {
        try self.validateValue(lhs);
        try self.validateValue(rhs);
        if (constantPair(lhs, rhs)) |pair|
            return .{ .constant = pair[0].add(pair[1]) };
        if (isZero(lhs)) return rhs;
        if (isZero(rhs)) return lhs;
        return .{ .node = try self.binaryNode(.add, lhs, rhs) };
    }

    pub fn sub(self: *Builder, lhs: Value, rhs: Value) Error!Value {
        try self.validateValue(lhs);
        try self.validateValue(rhs);
        if (constantPair(lhs, rhs)) |pair|
            return .{ .constant = pair[0].sub(pair[1]) };
        if (isZero(rhs)) return lhs;
        if (valueEql(lhs, rhs)) return Value.zero();
        return .{ .node = try self.binaryNode(.sub, lhs, rhs) };
    }

    pub fn mul(self: *Builder, lhs: Value, rhs: Value) Error!Value {
        try self.validateValue(lhs);
        try self.validateValue(rhs);
        if (constantPair(lhs, rhs)) |pair|
            return .{ .constant = pair[0].mul(pair[1]) };
        if (isZero(lhs) or isZero(rhs)) return Value.zero();
        if (isOne(lhs)) return rhs;
        if (isOne(rhs)) return lhs;
        return .{ .node = try self.binaryNode(.mul, lhs, rhs) };
    }

    pub fn neg(self: *Builder, value: Value) Error!Value {
        try self.validateValue(value);
        return switch (value) {
            .constant => |constant_value| .{ .constant = constant_value.neg() },
            .node => |node_id| switch (self.nodes_storage.items[node_id].op) {
                .neg => |operand| .{ .node = operand },
                else => .{ .node = try self.unaryNode(.neg, node_id) },
            },
        };
    }

    /// Only immediate constants fold. In particular, `inverse(inverse(x))` is
    /// retained because inversion is partial and both nonzero checks belong in
    /// the arithmetic circuit.
    pub fn inverse(self: *Builder, value: Value) Error!Value {
        try self.validateValue(value);
        return switch (value) {
            .constant => |constant_value| .{ .constant = try constant_value.inv() },
            .node => |node_id| .{ .node = try self.unaryNode(.inverse, node_id) },
        };
    }

    /// Adds one public consumption of `value`. Duplicate outputs are valid and
    /// deliberately increase the derived use count once per occurrence.
    pub fn markOutput(self: *Builder, value: Value) Error!NodeId {
        try self.validateValue(value);
        try self.checkOutputCount(self.outputs_storage.items.len + 1);
        try self.outputs_storage.ensureUnusedCapacity(self.allocator, 1);
        const plan = try self.planOperand(value, self.nodes_storage.items.len);
        const new_nodes: usize = @intFromBool(plan.new_constant != null);
        try self.ensureInternedNodes(new_nodes);
        self.appendPlannedConstant(plan);
        self.outputs_storage.appendAssumeCapacity(plan.id);
        return plan.id;
    }

    /// Moves the recorded lists into an owned circuit. The builder is reset to
    /// a valid empty state and may be reused or deinitialized normally.
    pub fn finish(self: *Builder) Error!Circuit {
        if (self.outputs_storage.items.len == 0) return error.MissingOutput;
        try validateStructure(
            self.nodes_storage.items,
            self.input_nodes_storage.items,
            self.outputs_storage.items,
            self.limits,
        );
        const use_counts = try self.allocator.alloc(u32, self.nodes_storage.items.len);
        errdefer self.allocator.free(use_counts);
        try deriveUseCounts(
            self.nodes_storage.items,
            self.outputs_storage.items,
            use_counts,
            self.limits.max_use_count,
        );

        const result = Circuit{
            .allocator = self.allocator,
            .limits = self.limits,
            .nodes_storage = self.nodes_storage,
            .input_nodes_storage = self.input_nodes_storage,
            .outputs_storage = self.outputs_storage,
            .use_counts_storage = use_counts,
        };
        self.nodes_storage = .empty;
        self.input_nodes_storage = .empty;
        self.outputs_storage = .empty;
        self.interned.deinit();
        self.interned = std.AutoHashMap(OpKey, NodeId).init(self.allocator);
        return result;
    }

    fn binaryNode(
        self: *Builder,
        comptime tag: enum { add, sub, mul },
        lhs: Value,
        rhs: Value,
    ) Error!NodeId {
        var next_id = self.nodes_storage.items.len;
        const lhs_plan = try self.planOperand(lhs, next_id);
        next_id += @intFromBool(lhs_plan.new_constant != null);
        const rhs_plan = try self.planOperand(rhs, next_id);
        next_id += @intFromBool(rhs_plan.new_constant != null);

        const operands = if (tag == .add or tag == .mul)
            canonicalPair(lhs_plan.id, rhs_plan.id)
        else
            BinaryOperands{ .lhs = lhs_plan.id, .rhs = rhs_plan.id };
        const key: OpKey = switch (tag) {
            .add => .{ .add = operands },
            .sub => .{ .sub = operands },
            .mul => .{ .mul = operands },
        };
        const existing = self.interned.get(key);
        const new_nodes = @as(usize, @intFromBool(lhs_plan.new_constant != null)) +
            @as(usize, @intFromBool(rhs_plan.new_constant != null)) +
            @as(usize, @intFromBool(existing == null));
        try self.ensureInternedNodes(new_nodes);
        self.appendPlannedConstant(lhs_plan);
        self.appendPlannedConstant(rhs_plan);
        if (existing) |node_id| return node_id;
        const op: Op = switch (tag) {
            .add => .{ .add = operands },
            .sub => .{ .sub = operands },
            .mul => .{ .mul = operands },
        };
        return self.appendInternedAssumeCapacity(key, op);
    }

    fn unaryNode(
        self: *Builder,
        comptime tag: enum { neg, inverse },
        operand: NodeId,
    ) Error!NodeId {
        const key: OpKey = switch (tag) {
            .neg => .{ .neg = operand },
            .inverse => .{ .inverse = operand },
        };
        if (self.interned.get(key)) |node_id| return node_id;
        try self.ensureInternedNodes(1);
        const op: Op = switch (tag) {
            .neg => .{ .neg = operand },
            .inverse => .{ .inverse = operand },
        };
        return self.appendInternedAssumeCapacity(key, op);
    }

    fn planOperand(
        self: *const Builder,
        value: Value,
        next_id: usize,
    ) Error!PlannedOperand {
        return switch (value) {
            .node => |node_id| .{ .id = node_id },
            .constant => |constant_value| blk: {
                const words = qm31Words(constant_value);
                if (self.interned.get(.{ .constant = words })) |node_id|
                    break :blk .{ .id = node_id };
                break :blk .{
                    .id = try indexNode(next_id),
                    .new_constant = words,
                };
            },
        };
    }

    fn appendPlannedConstant(self: *Builder, plan: PlannedOperand) void {
        const words = plan.new_constant orelse return;
        std.debug.assert(plan.id == self.nodes_storage.items.len);
        _ = self.appendInternedAssumeCapacity(
            .{ .constant = words },
            .{ .constant = words },
        );
    }

    fn appendInternedAssumeCapacity(
        self: *Builder,
        key: OpKey,
        op: Op,
    ) NodeId {
        std.debug.assert(self.interned.get(key) == null);
        const node_id: NodeId = @intCast(self.nodes_storage.items.len);
        self.nodes_storage.appendAssumeCapacity(.{ .op = op });
        self.interned.putAssumeCapacity(key, node_id);
        return node_id;
    }

    fn ensureRawNodes(self: *Builder, additional: usize) Error!void {
        const target = std.math.add(usize, self.nodes_storage.items.len, additional) catch
            return error.ArithmeticOverflow;
        try self.checkNodeCount(target);
        try self.nodes_storage.ensureUnusedCapacity(self.allocator, additional);
    }

    fn ensureInternedNodes(self: *Builder, additional: usize) Error!void {
        if (additional == 0) return;
        try self.ensureRawNodes(additional);
        try self.interned.ensureUnusedCapacity(@intCast(additional));
    }

    fn validateValue(self: *const Builder, value: Value) Error!void {
        switch (value) {
            .constant => |constant_value| for (qm31Words(constant_value)) |word| {
                if (word >= m31.Modulus) return error.InvalidConstant;
            },
            .node => |node_id| if (node_id >= self.nodes_storage.items.len)
                return error.InvalidNodeId,
        }
    }

    fn checkNodeCount(self: *const Builder, count: usize) Error!void {
        if (count > self.limits.max_nodes) return error.NodeLimitExceeded;
    }

    fn checkInputCount(self: *const Builder, count: usize) Error!void {
        if (count > self.limits.max_inputs) return error.InputLimitExceeded;
    }

    fn checkOutputCount(self: *const Builder, count: usize) Error!void {
        if (count > self.limits.max_outputs) return error.OutputLimitExceeded;
    }
};

pub const Circuit = struct {
    allocator: std.mem.Allocator,
    limits: Limits,
    nodes_storage: std.ArrayList(Node),
    input_nodes_storage: std.ArrayList(NodeId),
    outputs_storage: std.ArrayList(NodeId),
    use_counts_storage: []u32,

    pub fn deinit(self: *Circuit) void {
        self.allocator.free(self.use_counts_storage);
        self.outputs_storage.deinit(self.allocator);
        self.input_nodes_storage.deinit(self.allocator);
        self.nodes_storage.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn nodes(self: *const Circuit) []const Node {
        return self.nodes_storage.items;
    }

    pub fn inputNodes(self: *const Circuit) []const NodeId {
        return self.input_nodes_storage.items;
    }

    pub fn outputs(self: *const Circuit) []const NodeId {
        return self.outputs_storage.items;
    }

    pub fn useCounts(self: *const Circuit) []const u32 {
        return self.use_counts_storage;
    }

    pub fn inputUseCount(self: *const Circuit, input_id: InputId) Error!u32 {
        if (input_id >= self.input_nodes_storage.items.len)
            return error.InvalidInputLayout;
        const node_id = self.input_nodes_storage.items[input_id];
        if (node_id >= self.use_counts_storage.len) return error.InvalidInputLayout;
        return self.use_counts_storage[node_id];
    }

    /// Cold validation uses one scratch allocation. Proof paths can call
    /// `validateInto` with reusable storage instead.
    pub fn validate(self: *const Circuit) Error!void {
        try self.validateStructureAndCountShape();
        const scratch = try self.allocator.alloc(u32, self.nodes_storage.items.len);
        defer self.allocator.free(scratch);
        try self.validateUseCountsInto(scratch);
    }

    pub fn validateInto(self: *const Circuit, use_scratch: []u32) Error!void {
        try self.validateStructureAndCountShape();
        try self.validateUseCountsInto(use_scratch);
    }

    fn validateStructureAndCountShape(self: *const Circuit) Error!void {
        try validateStructure(
            self.nodes_storage.items,
            self.input_nodes_storage.items,
            self.outputs_storage.items,
            self.limits,
        );
        if (self.use_counts_storage.len != self.nodes_storage.items.len)
            return error.UseCountMismatch;
    }

    fn validateUseCountsInto(self: *const Circuit, use_scratch: []u32) Error!void {
        try deriveUseCounts(
            self.nodes_storage.items,
            self.outputs_storage.items,
            use_scratch,
            self.limits.max_use_count,
        );
        if (!std.mem.eql(
            u32,
            use_scratch[0..self.nodes_storage.items.len],
            self.use_counts_storage,
        )) return error.UseCountMismatch;
    }

    /// One-allocation owned evaluation.
    pub fn evaluate(
        self: *const Circuit,
        allocator: std.mem.Allocator,
        inputs: []const QM31,
    ) Error!Evaluation {
        try self.validateEvaluationShape(inputs, self.nodes_storage.items.len);
        const values = try allocator.alloc(QM31, self.nodes_storage.items.len);
        errdefer allocator.free(values);
        try self.replayIntoAssumeValid(inputs, values);
        return .{ .allocator = allocator, .values = values };
    }

    /// Allocation-free topological replay. On an inverse-of-zero failure the
    /// evaluated prefix remains in `values`; callers needing transactional
    /// ownership should use `evaluate`.
    pub fn evaluateInto(
        self: *const Circuit,
        inputs: []const QM31,
        values: []QM31,
    ) Error!void {
        try self.validateEvaluationShape(inputs, values.len);
        try self.replayIntoAssumeValid(inputs, values);
    }

    /// Single-pass replay for a graph returned by `Builder.finish`, or one
    /// which has passed `validate` and has not subsequently been mutated.
    /// Lengths remain checked; the caller-owned trust decision only skips the
    /// O(nodes) structural admission pass on repeated evaluations.
    pub fn evaluateIntoAssumeValid(
        self: *const Circuit,
        inputs: []const QM31,
        values: []QM31,
    ) Error!void {
        if (inputs.len != self.input_nodes_storage.items.len)
            return error.InputCountMismatch;
        if (values.len != self.nodes_storage.items.len)
            return error.ValueBufferLengthMismatch;
        try self.replayIntoAssumeValid(inputs, values);
    }

    fn validateEvaluationShape(
        self: *const Circuit,
        inputs: []const QM31,
        value_count: usize,
    ) Error!void {
        try validateStructure(
            self.nodes_storage.items,
            self.input_nodes_storage.items,
            self.outputs_storage.items,
            self.limits,
        );
        if (inputs.len != self.input_nodes_storage.items.len)
            return error.InputCountMismatch;
        if (value_count != self.nodes_storage.items.len)
            return error.ValueBufferLengthMismatch;
    }

    fn replayIntoAssumeValid(
        self: *const Circuit,
        inputs: []const QM31,
        values: []QM31,
    ) Error!void {
        var input_cursor: usize = 0;
        for (self.nodes_storage.items, 0..) |node, node_index| {
            values[node_index] = switch (node.op) {
                .input => blk: {
                    if (input_cursor >= inputs.len or
                        self.input_nodes_storage.items[input_cursor] != node_index)
                    {
                        return error.InvalidInputLayout;
                    }
                    defer input_cursor += 1;
                    break :blk inputs[input_cursor];
                },
                .constant => |words| qm31FromWords(words),
                .add => |operands| values[operands.lhs].add(values[operands.rhs]),
                .sub => |operands| values[operands.lhs].sub(values[operands.rhs]),
                .mul => |operands| values[operands.lhs].mul(values[operands.rhs]),
                .neg => |operand| values[operand].neg(),
                .inverse => |operand| try values[operand].inv(),
            };
        }
        if (input_cursor != inputs.len) return error.InvalidInputLayout;
    }

    pub fn outputValue(
        self: *const Circuit,
        values: []const QM31,
        output_index: usize,
    ) Error!QM31 {
        if (values.len != self.nodes_storage.items.len)
            return error.ValueBufferLengthMismatch;
        if (output_index >= self.outputs_storage.items.len)
            return error.OutputIndexOutOfBounds;
        const node_id = self.outputs_storage.items[output_index];
        if (node_id >= values.len) return error.InvalidNodeId;
        return values[node_id];
    }

    pub fn outputsAreZero(
        self: *const Circuit,
        values: []const QM31,
    ) Error!bool {
        if (values.len != self.nodes_storage.items.len)
            return error.ValueBufferLengthMismatch;
        for (self.outputs_storage.items) |output| {
            if (output >= values.len) return error.InvalidNodeId;
            if (!values[output].isZero()) return false;
        }
        return true;
    }
};

pub const Evaluation = struct {
    allocator: std.mem.Allocator,
    values: []QM31,

    pub fn deinit(self: *Evaluation) void {
        self.allocator.free(self.values);
        self.* = undefined;
    }
};

/// Derives operand consumption plus one use for every public output. The
/// caller owns scratch, so this is suitable for verifier-owned cold admission
/// and repeated row-11/15/16 schedule checks.
pub fn deriveUseCounts(
    nodes: []const Node,
    outputs: []const NodeId,
    destination: []u32,
    max_use_count: u32,
) Error!void {
    if (max_use_count == 0 or max_use_count >= m31.Modulus)
        return error.InvalidLimits;
    if (destination.len < nodes.len) return error.UseCountBufferTooSmall;
    const uses = destination[0..nodes.len];
    @memset(uses, 0);
    for (nodes, 0..) |node, node_index| switch (node.op) {
        .input, .constant => {},
        .add, .sub, .mul => |operands| {
            if (operands.lhs >= node_index or operands.rhs >= node_index)
                return error.InvalidOperand;
            try incrementUse(&uses[operands.lhs], max_use_count);
            try incrementUse(&uses[operands.rhs], max_use_count);
        },
        .neg, .inverse => |operand| {
            if (operand >= node_index) return error.InvalidOperand;
            try incrementUse(&uses[operand], max_use_count);
        },
    };
    for (outputs) |output| {
        if (output >= nodes.len) return error.InvalidNodeId;
        try incrementUse(&uses[output], max_use_count);
    }
}

pub fn validateStructure(
    nodes: []const Node,
    input_nodes: []const NodeId,
    outputs: []const NodeId,
    limits: Limits,
) Error!void {
    try limits.validate();
    if (nodes.len > limits.max_nodes) return error.NodeLimitExceeded;
    if (input_nodes.len > limits.max_inputs) return error.InputLimitExceeded;
    if (outputs.len == 0) return error.MissingOutput;
    if (outputs.len > limits.max_outputs) return error.OutputLimitExceeded;

    var input_cursor: usize = 0;
    for (nodes, 0..) |node, node_index| switch (node.op) {
        .input => {
            if (input_cursor >= input_nodes.len or
                input_nodes[input_cursor] != node_index)
            {
                return error.InvalidInputLayout;
            }
            input_cursor += 1;
        },
        .constant => |words| for (words) |word| {
            if (word >= m31.Modulus) return error.InvalidConstant;
        },
        .add, .mul => |operands| {
            if (operands.lhs >= node_index or operands.rhs >= node_index)
                return error.InvalidOperand;
            if (operands.lhs > operands.rhs) return error.InvalidOperand;
        },
        .sub => |operands| {
            if (operands.lhs >= node_index or operands.rhs >= node_index)
                return error.InvalidOperand;
        },
        .neg, .inverse => |operand| if (operand >= node_index)
            return error.InvalidOperand,
    };
    if (input_cursor != input_nodes.len) return error.InvalidInputLayout;
    for (outputs) |output| if (output >= nodes.len)
        return error.InvalidNodeId;
}

fn incrementUse(value: *u32, maximum: u32) Error!void {
    value.* = std.math.add(u32, value.*, 1) catch return error.ArithmeticOverflow;
    if (value.* > maximum) return error.UseCountLimitExceeded;
}

fn indexNode(index: usize) Error!NodeId {
    if (index >= m31.Modulus) return error.NodeLimitExceeded;
    return @intCast(index);
}

fn canonicalPair(lhs: NodeId, rhs: NodeId) BinaryOperands {
    return if (lhs <= rhs)
        .{ .lhs = lhs, .rhs = rhs }
    else
        .{ .lhs = rhs, .rhs = lhs };
}

fn constantPair(lhs: Value, rhs: Value) ?[2]QM31 {
    return switch (lhs) {
        .constant => |a| switch (rhs) {
            .constant => |b| .{ a, b },
            .node => null,
        },
        .node => null,
    };
}

fn valueEql(lhs: Value, rhs: Value) bool {
    return switch (lhs) {
        .constant => |a| switch (rhs) {
            .constant => |b| a.eql(b),
            .node => false,
        },
        .node => |a| switch (rhs) {
            .constant => false,
            .node => |b| a == b,
        },
    };
}

fn isZero(value: Value) bool {
    return switch (value) {
        .constant => |constant_value| constant_value.isZero(),
        .node => false,
    };
}

fn isOne(value: Value) bool {
    return switch (value) {
        .constant => |constant_value| constant_value.eql(QM31.one()),
        .node => false,
    };
}

fn qm31Words(value: QM31) [4]u32 {
    const words = value.toM31Array();
    return .{ words[0].v, words[1].v, words[2].v, words[3].v };
}

fn qm31FromWords(words: [4]u32) QM31 {
    return QM31.fromU32Unchecked(words[0], words[1], words[2], words[3]);
}
