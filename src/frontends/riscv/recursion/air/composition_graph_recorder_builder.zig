//! Internal composition graph recorder authority shard; use composition_graph_recorder.zig publicly.

pub const std = @import("std");
pub const stwo_core = @import("stwo_core");
pub const circle = stwo_core.circle;
pub const M31 = stwo_core.fields.m31.M31;
pub const m31 = stwo_core.fields.m31;
pub const QM31 = stwo_core.fields.qm31.QM31;
pub const qm31 = stwo_core.fields.qm31;
pub const canonic = stwo_core.poly.circle.canonic;
pub const verifier_types = stwo_core.verifier_types;

pub const graph_mod = @import("composition_circuit.zig");
pub const direct = @import("direct_constraint_program.zig");
pub const relation_interaction = @import("relation_interaction.zig");
pub const universal = @import("universal_challenges.zig");
pub const relation = @import("../../air/lang/relation.zig");

pub const Error = std.mem.Allocator.Error || graph_mod.Error || QM31.Error || error{
    BuilderAlreadyActive,
    BuilderNotActive,
    CircuitTooLarge,
    GraphConstructionFailed,
    InputCountMismatch,
    InvalidDirectProgram,
    InvalidEvaluationShape,
    InvalidProtocolGeometry,
    InvalidRelationPlan,
    UnsatisfiedCircuit,
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

pub const Input = struct {
    node_id: u32,
    value: Scalar,
};

/// Cold graph builder.  Callers create every verifier-owned input first,
/// activate the builder, replay authenticated programs, constrain the final
/// equality, deactivate, and finish.  Constants and commutative operations are
/// canonicalized and hash-consed; recording never allocates in a row loop.
pub const Builder = struct {
    allocator: std.mem.Allocator,
    nodes: std.ArrayList(graph_mod.Node) = .empty,
    outputs: std.ArrayList(u32) = .empty,
    interned: std.AutoHashMap(OpKey, u32),
    input_count: usize = 0,
    failure: ?anyerror = null,
    active: bool = false,

    pub fn init(allocator: std.mem.Allocator) Builder {
        return .{
            .allocator = allocator,
            .interned = std.AutoHashMap(OpKey, u32).init(allocator),
        };
    }

    pub fn deinit(self: *Builder) void {
        if (self.active) self.deactivate();
        self.interned.deinit();
        self.outputs.deinit(self.allocator);
        self.nodes.deinit(self.allocator);
        self.* = undefined;
    }

    /// Reserve once from a static component profile.  `operation_hint` is not
    /// protocol authority; underestimation merely lets ArrayList grow.
    pub fn reserve(
        self: *Builder,
        input_hint: usize,
        operation_hint: usize,
    ) Error!void {
        const capacity = std.math.add(usize, input_hint, operation_hint) catch
            return error.CircuitTooLarge;
        if (capacity >= m31.Modulus) return error.CircuitTooLarge;
        try self.nodes.ensureTotalCapacity(self.allocator, capacity);
        try self.outputs.ensureTotalCapacity(self.allocator, 1);
        try self.interned.ensureTotalCapacity(@intCast(capacity));
    }

    /// Inputs must form the leading node block required by the authenticated
    /// graph ABI.  This makes source-to-node bindings an identity-order walk.
    pub fn input(self: *Builder) Error!Input {
        try self.check();
        if (self.active or self.nodes.items.len != self.input_count)
            return error.InvalidDirectProgram;
        const node_id = try indexU32(self.nodes.items.len);
        try self.nodes.append(self.allocator, .{ .op = .input });
        self.input_count += 1;
        return .{ .node_id = node_id, .value = .{ .handle = .{ .node = node_id } } };
    }

    pub fn activate(self: *Builder) Error!void {
        try self.check();
        if (self.active or installed_builder != null)
            return error.BuilderAlreadyActive;
        self.active = true;
        installed_builder = self;
    }

    pub fn deactivate(self: *Builder) void {
        std.debug.assert(self.active and installed_builder == self);
        installed_builder = null;
        self.active = false;
    }

    pub fn constrainZero(self: *Builder, value: Scalar) Error!void {
        try self.requireActive();
        try self.outputs.append(self.allocator, try self.nodeId(value.handle));
    }

    pub fn finish(self: *Builder) Error!Circuit {
        if (self.active) return error.BuilderAlreadyActive;
        try self.check();
        if (self.outputs.items.len == 0) return error.MissingGraphOutput;
        const nodes = try self.nodes.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(nodes);
        const outputs = try self.outputs.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(outputs);
        const identity = graph_mod.computeGraphDigest(nodes, outputs);
        const result = Circuit{
            .allocator = self.allocator,
            .nodes = nodes,
            .outputs = outputs,
            .input_count = self.input_count,
            .identity_digest = identity,
        };
        try result.validate();
        return result;
    }

    fn add(self: *Builder, lhs: Handle, rhs: Handle) Handle {
        return self.addFallible(lhs, rhs) catch |err| self.poison(err);
    }

    fn addFallible(self: *Builder, lhs: Handle, rhs: Handle) Error!Handle {
        try self.requireActive();
        if (constantPair(lhs, rhs)) |pair|
            return .{ .constant = pair[0].add(pair[1]) };
        if (handleIsZero(lhs)) return rhs;
        if (handleIsZero(rhs)) return lhs;
        const a = try self.nodeId(lhs);
        const b = try self.nodeId(rhs);
        const operands = canonicalPair(a, b);
        return .{ .node = try self.intern(.{ .add = operands }, .{ .add = operands }) };
    }

    fn sub(self: *Builder, lhs: Handle, rhs: Handle) Handle {
        return self.subFallible(lhs, rhs) catch |err| self.poison(err);
    }

    fn subFallible(self: *Builder, lhs: Handle, rhs: Handle) Error!Handle {
        try self.requireActive();
        if (constantPair(lhs, rhs)) |pair|
            return .{ .constant = pair[0].sub(pair[1]) };
        if (handleIsZero(rhs)) return lhs;
        if (std.meta.eql(lhs, rhs)) return .{ .constant = QM31.zero() };
        const operands = graph_mod.BinaryOperands{
            .lhs = try self.nodeId(lhs),
            .rhs = try self.nodeId(rhs),
        };
        return .{ .node = try self.intern(.{ .sub = operands }, .{ .sub = operands }) };
    }

    fn mul(self: *Builder, lhs: Handle, rhs: Handle) Handle {
        return self.mulFallible(lhs, rhs) catch |err| self.poison(err);
    }

    fn mulFallible(self: *Builder, lhs: Handle, rhs: Handle) Error!Handle {
        try self.requireActive();
        if (constantPair(lhs, rhs)) |pair|
            return .{ .constant = pair[0].mul(pair[1]) };
        if (handleIsZero(lhs) or handleIsZero(rhs))
            return .{ .constant = QM31.zero() };
        if (handleIsOne(lhs)) return rhs;
        if (handleIsOne(rhs)) return lhs;
        const a = try self.nodeId(lhs);
        const b = try self.nodeId(rhs);
        const operands = canonicalPair(a, b);
        return .{ .node = try self.intern(.{ .mul = operands }, .{ .mul = operands }) };
    }

    fn neg(self: *Builder, value: Handle) Handle {
        return self.negFallible(value) catch |err| self.poison(err);
    }

    fn negFallible(self: *Builder, value: Handle) Error!Handle {
        try self.requireActive();
        return switch (value) {
            .constant => |constant| .{ .constant = constant.neg() },
            .node => |node_id| .{ .node = try self.intern(
                .{ .neg = node_id },
                .{ .neg = node_id },
            ) },
        };
    }

    fn inverse(self: *Builder, value: Handle) Handle {
        return self.inverseFallible(value) catch |err| self.poison(err);
    }

    fn inverseFallible(self: *Builder, value: Handle) Error!Handle {
        try self.requireActive();
        return switch (value) {
            .constant => |constant| .{ .constant = try constant.inv() },
            .node => |node_id| .{ .node = try self.intern(
                .{ .inverse = node_id },
                .{ .inverse = node_id },
            ) },
        };
    }

    fn nodeId(self: *Builder, value: Handle) Error!u32 {
        try self.requireActive();
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
        try self.requireActive();
        if (self.interned.get(key)) |node_id| return node_id;
        const node_id = try indexU32(self.nodes.items.len);
        try self.nodes.append(self.allocator, .{ .op = op });
        try self.interned.put(key, node_id);
        return node_id;
    }

    fn poison(self: *Builder, failure: anyerror) Handle {
        if (self.failure == null) self.failure = failure;
        return .{ .constant = QM31.zero() };
    }

    pub fn check(self: *const Builder) Error!void {
        if (self.failure != null) return error.GraphConstructionFailed;
    }

    fn requireActive(self: *const Builder) Error!void {
        try self.check();
        if (!self.active or installed_builder != self)
            return error.BuilderNotActive;
    }
};

threadlocal var installed_builder: ?*Builder = null;

/// Field interface accepted by typed generic AIR evaluators.
pub const Scalar = struct {
    handle: Handle,

    pub fn zero() Scalar {
        return fromSecure(QM31.zero());
    }

    pub fn one() Scalar {
        return fromSecure(QM31.one());
    }

    pub fn fromBase(value: M31) Scalar {
        return fromSecure(QM31.fromBase(value));
    }

    pub fn fromSecure(value: QM31) Scalar {
        return .{ .handle = .{ .constant = value } };
    }

    pub fn add(lhs: Scalar, rhs: Scalar) Scalar {
        return .{ .handle = currentBuilder().add(lhs.handle, rhs.handle) };
    }

    pub fn sub(lhs: Scalar, rhs: Scalar) Scalar {
        return .{ .handle = currentBuilder().sub(lhs.handle, rhs.handle) };
    }

    pub fn mul(lhs: Scalar, rhs: Scalar) Scalar {
        return .{ .handle = currentBuilder().mul(lhs.handle, rhs.handle) };
    }

    pub fn neg(self: Scalar) Scalar {
        return .{ .handle = currentBuilder().neg(self.handle) };
    }

    pub fn square(self: Scalar) Scalar {
        return self.mul(self);
    }

    pub fn inverse(self: Scalar) Scalar {
        return .{ .handle = currentBuilder().inverse(self.handle) };
    }

    pub fn isZero(self: Scalar) bool {
        return handleIsZero(self.handle);
    }
};

pub const Circuit = struct {
    allocator: std.mem.Allocator,
    nodes: []graph_mod.Node,
    outputs: []u32,
    input_count: usize,
    identity_digest: [32]u8,

    pub fn deinit(self: *Circuit) void {
        self.allocator.free(self.outputs);
        self.allocator.free(self.nodes);
        self.* = undefined;
    }

    pub fn graph(self: *const Circuit) graph_mod.CircuitGraph {
        return .{
            .nodes = self.nodes,
            .outputs = self.outputs,
            .identity_digest = self.identity_digest,
        };
    }

    pub fn validate(self: *const Circuit) Error!void {
        try self.graph().validate();
        var inputs: usize = 0;
        for (self.nodes) |node|
            inputs += @intFromBool(std.meta.activeTag(node.op) == .input);
        if (inputs != self.input_count) return error.InputCountMismatch;
    }

    /// Allocation-free concrete replay into caller-owned node storage.
    pub fn evaluateInto(
        self: *const Circuit,
        inputs: []const QM31,
        values: []QM31,
    ) Error!void {
        try self.validate();
        if (inputs.len != self.input_count or values.len != self.nodes.len)
            return error.InvalidEvaluationShape;
        var input_cursor: usize = 0;
        for (self.nodes, 0..) |node, node_id| {
            values[node_id] = switch (node.op) {
                .input => blk: {
                    const value = inputs[input_cursor];
                    input_cursor += 1;
                    break :blk value;
                },
                .constant => |words| QM31.fromU32Unchecked(
                    words[0],
                    words[1],
                    words[2],
                    words[3],
                ),
                .add => |operands| values[operands.lhs].add(values[operands.rhs]),
                .sub => |operands| values[operands.lhs].sub(values[operands.rhs]),
                .mul => |operands| values[operands.lhs].mul(values[operands.rhs]),
                .neg => |operand| values[operand].neg(),
                .inverse => |operand| try values[operand].inv(),
            };
        }
        for (self.outputs) |output| {
            if (!values[output].isZero()) return error.UnsatisfiedCircuit;
        }
    }
};

/// Replay the exact authenticated direct-expression program over graph values.
/// Structural preflight precedes every array access so a corrupted cached
/// program fails closed instead of becoming a graph-construction primitive.
pub fn replayDirect(
    program: *const direct.Program,
    inputs: []const Scalar,
    roots: []Scalar,
) Error!void {
    const input_count: usize = program.input_count;
    const compiled_count: usize = program.compiled_node_count;
    const node_count: usize = program.node_count;
    const constraint_count: usize = program.constraint_count;
    if (inputs.len != input_count or
        roots.len != constraint_count or
        node_count != input_count + compiled_count or
        node_count > direct.MAX_NODES or
        compiled_count > direct.MAX_NODES or
        constraint_count > direct.MAX_CONSTRAINTS)
    {
        return error.InvalidDirectProgram;
    }
    try preflightDirect(program);
    var slots: [direct.MAX_NODES]Scalar = undefined;
    @memcpy(slots[0..inputs.len], inputs);
    for (program.nodes[0..program.compiled_node_count]) |node| {
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
    for (program.constraints[0..program.constraint_count], roots) |constraint, *root| {
        root.* = slots[constraint.root];
        if (constraint.gate != std.math.maxInt(u16))
            root.* = root.mul(slots[constraint.gate]);
    }
    try currentBuilder().check();
}

pub const Pair = struct {
    n1: Scalar,
    d1: Scalar,
    n2: Scalar,
    d2: Scalar,
};

/// Symbolic counterpart of the 47-domain universal challenge bundle.
pub const ChallengeSet = struct {
    elements: [universal.RELATION_COUNT]Element,

    pub const Element = struct {
        z: Scalar,
        alpha_powers: [universal.MAX_ARITY]Scalar,
        arity: u8,

        pub fn init(arity: u8, z: Scalar, alpha: Scalar) Error!Element {
            if (arity == 0 or arity > universal.MAX_ARITY)
                return error.InvalidRelationPlan;
            var result = Element{
                .z = z,
                .alpha_powers = undefined,
                .arity = arity,
            };
            var power = Scalar.one();
            for (&result.alpha_powers) |*slot| {
                slot.* = power;
                power = power.mul(alpha);
            }
            return result;
        }

        pub fn combine(self: *const Element, values: []const Scalar) Error!Scalar {
            if (values.len != self.arity) return error.InvalidRelationPlan;
            var result = Scalar.zero();
            for (values, self.alpha_powers[0..values.len]) |value, power|
                result = result.add(power.mul(value));
            return result.sub(self.z);
        }
    };

    pub fn init(draws: [universal.RELATION_COUNT][2]Scalar) Error!ChallengeSet {
        var elements: [universal.RELATION_COUNT]Element = undefined;
        for (&elements, draws, relation.universal_descriptors) |
            *element,
            pair,
            descriptor,
        | element.* = try Element.init(descriptor.arity, pair[0], pair[1]);
        return .{ .elements = elements };
    }

    pub fn get(
        self: *const ChallengeSet,
        domain: relation.Domain,
    ) *const Element {
        return &self.elements[@intFromEnum(domain)];
    }
};

pub fn preflightDirect(program: *const direct.Program) Error!void {
    const input_count: usize = program.input_count;
    const node_count: usize = program.node_count;
    for (program.nodes[0..program.compiled_node_count], 0..) |node, ordinal| {
        const destination: usize = node.destination;
        if (destination != input_count + ordinal or destination >= node_count)
            return error.InvalidDirectProgram;
        switch (node.op) {
            .constant => {},
            .add, .sub, .mul => |binary| {
                if (binary.lhs >= destination or binary.rhs >= destination)
                    return error.InvalidDirectProgram;
            },
            .neg => |operand| if (operand >= destination)
                return error.InvalidDirectProgram,
            .select => |selection| if (selection.selector >= destination or
                selection.when_true >= destination or
                selection.when_false >= destination)
            {
                return error.InvalidDirectProgram;
            },
        }
    }
    for (program.constraints[0..program.constraint_count]) |constraint| {
        if (constraint.root >= node_count or
            (constraint.gate != std.math.maxInt(u16) and
                constraint.gate >= node_count))
        {
            return error.InvalidDirectProgram;
        }
    }
}

pub fn currentBuilder() *Builder {
    return installed_builder orelse
        @panic("composition recording scalar used outside an active builder");
}

pub fn constantPair(lhs: Handle, rhs: Handle) ?[2]QM31 {
    return switch (lhs) {
        .constant => |a| switch (rhs) {
            .constant => |b| .{ a, b },
            else => null,
        },
        else => null,
    };
}

pub fn handleIsZero(value: Handle) bool {
    return switch (value) {
        .constant => |constant| constant.isZero(),
        else => false,
    };
}

pub fn handleIsOne(value: Handle) bool {
    return switch (value) {
        .constant => |constant| constant.eql(QM31.one()),
        else => false,
    };
}

pub fn canonicalPair(lhs: u32, rhs: u32) graph_mod.BinaryOperands {
    return if (lhs <= rhs)
        .{ .lhs = lhs, .rhs = rhs }
    else
        .{ .lhs = rhs, .rhs = lhs };
}

pub fn qm31Words(value: QM31) [4]u32 {
    var words: [4]u32 = undefined;
    for (value.toM31Array(), &words) |limb, *word| word.* = limb.toU32();
    return words;
}

pub fn indexU32(index: usize) Error!u32 {
    if (index >= m31.Modulus) return error.CircuitTooLarge;
    return @intCast(index);
}
