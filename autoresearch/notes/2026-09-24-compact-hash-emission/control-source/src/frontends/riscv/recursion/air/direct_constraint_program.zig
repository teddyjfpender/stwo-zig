//! Authenticated, allocation-free evaluator for typed direct constraints.
//!
//! The cold compiler seals one typed arena and lowers its canonical expression
//! DAG into fixed-capacity instructions. Concrete AIR adapters then evaluate
//! those exact instructions over either M31 domain values or QM31 OODS values;
//! no second handwritten constraint implementation exists on the proof path.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const digest = @import("../../air/lang/digest.zig");
const expr = @import("../../air/lang/expr.zig");
const ir = @import("../../air/lang/ir.zig");
const types = @import("../../air/lang/types.zig");
const validate = @import("../../air/lang/validate.zig");

pub const MAX_NODES: usize = 512;
pub const MAX_CONSTRAINTS: usize = 192;
const NO_SLOT = std.math.maxInt(u16);

pub const Error = error{
    BindingSealMismatch,
    ConstraintLimitExceeded,
    InputCountOverflow,
    InvalidConstraint,
    InvalidInputGeometry,
    InvalidProgramShape,
    NodeLimitExceeded,
    SlotOverflow,
    UnsupportedExpression,
} || validate.Error;

const Binary = struct {
    lhs: u16,
    rhs: u16,
};

const Selection = struct {
    selector: u16,
    when_true: u16,
    when_false: u16,
};

pub const Op = union(enum) {
    constant: u32,
    add: Binary,
    sub: Binary,
    mul: Binary,
    neg: u16,
    select: Selection,
};

pub const Node = struct {
    destination: u16,
    op: Op,
};

pub const Constraint = struct {
    root: u16,
    gate: u16,
};

/// Immutable value returned by the cold authentication pass. Its evaluation
/// methods use only caller-owned fixed-size scratch and never allocate.
pub const Program = struct {
    semantic_format_version: u16,
    semantic_digest: digest.Digest,
    input_count: u16,
    node_count: u16,
    compiled_node_count: u16,
    constraint_count: u16,
    nodes: [MAX_NODES]Node,
    constraints: [MAX_CONSTRAINTS]Constraint,
    // The complete canonical program remains available to recursive recording.
    // Native execution visits only nodes reachable from roots and gates.
    evaluation_node_count: u16,
    evaluation_nodes: [MAX_NODES]Node,

    pub fn evaluateBaseInto(
        self: *const Program,
        inputs: []const M31,
        scratch: *[MAX_NODES]M31,
        roots: []M31,
    ) error{InvalidProgramShape}!void {
        if (inputs.len != self.input_count or
            roots.len != self.constraint_count)
        {
            return error.InvalidProgramShape;
        }
        @memcpy(scratch[0..inputs.len], inputs);
        for (self.evaluation_nodes[0..self.evaluation_node_count]) |node| {
            scratch[node.destination] = evaluateBaseOp(node.op, scratch);
        }
        for (self.constraints[0..self.constraint_count], roots) |constraint, *root| {
            root.* = scratch[constraint.root];
            if (constraint.gate != NO_SLOT)
                root.* = root.mul(scratch[constraint.gate]);
        }
    }

    pub fn evaluateSecureInto(
        self: *const Program,
        inputs: []const QM31,
        scratch: *[MAX_NODES]QM31,
        roots: []QM31,
    ) error{InvalidProgramShape}!void {
        if (inputs.len != self.input_count or
            roots.len != self.constraint_count)
        {
            return error.InvalidProgramShape;
        }
        @memcpy(scratch[0..inputs.len], inputs);
        for (self.evaluation_nodes[0..self.evaluation_node_count]) |node| {
            scratch[node.destination] = evaluateSecureOp(node.op, scratch);
        }
        for (self.constraints[0..self.constraint_count], roots) |constraint, *root| {
            root.* = scratch[constraint.root];
            if (constraint.gate != NO_SLOT)
                root.* = root.mul(scratch[constraint.gate]);
        }
    }
};

/// Authenticates `arena` against its semantic seal and compiles every direct
/// constraint in canonical arena order. Inputs must be the exact leading node
/// block, which makes source-ID-to-slot mapping an identity operation.
pub fn authenticate(
    arena: *const ir.Arena,
    expected_digest: digest.Digest,
    input_count: usize,
) Error!Program {
    try validate.validate(arena);
    const identity = try digest.computeIdentity(arena);
    if (identity.format_version != digest.typed_effect_format_version or
        !std.mem.eql(u8, &identity.bytes, &expected_digest))
    {
        return error.BindingSealMismatch;
    }
    if (input_count > std.math.maxInt(u16)) return error.InputCountOverflow;
    if (arena.nodesView().len > MAX_NODES) return error.NodeLimitExceeded;
    if (arena.constraintsView().len > MAX_CONSTRAINTS)
        return error.ConstraintLimitExceeded;
    if (arena.nodesView().len < input_count)
        return error.InvalidInputGeometry;

    for (arena.nodesView(), 0..) |node, index| {
        if (index < input_count) {
            if (std.meta.activeTag(node.key.op) != .input)
                return error.InvalidInputGeometry;
        } else if (std.meta.activeTag(node.key.op) == .input) {
            return error.InvalidInputGeometry;
        }
    }

    var result = Program{
        .semantic_format_version = identity.format_version,
        .semantic_digest = identity.bytes,
        .input_count = @intCast(input_count),
        .node_count = @intCast(arena.nodesView().len),
        .compiled_node_count = @intCast(arena.nodesView().len - input_count),
        .constraint_count = @intCast(arena.constraintsView().len),
        .nodes = [_]Node{emptyNode()} ** MAX_NODES,
        .evaluation_node_count = 0,
        .evaluation_nodes = [_]Node{emptyNode()} ** MAX_NODES,
        .constraints = [_]Constraint{.{ .root = NO_SLOT, .gate = NO_SLOT }} **
            MAX_CONSTRAINTS,
    };
    for (arena.nodesView()[input_count..], result.nodes[0..result.compiled_node_count], input_count..) |
        source,
        *target,
        source_index,
    | {
        target.* = .{
            .destination = try slot(source_index),
            .op = try compileOp(source.key.op, source_index),
        };
    }
    for (arena.constraintsView(), result.constraints[0..result.constraint_count]) |
        source_constraint,
        *target,
    | {
        const root_index = types.idIndex(source_constraint.root);
        if (root_index >= arena.nodesView().len)
            return error.InvalidConstraint;
        target.* = .{
            .root = try slot(root_index),
            .gate = if (source_constraint.gate) |gate| blk: {
                const gate_index = types.idIndex(gate);
                if (gate_index >= arena.nodesView().len)
                    return error.InvalidConstraint;
                break :blk try slot(gate_index);
            } else NO_SLOT,
        };
    }
    prepareEvaluationNodes(&result);
    return result;
}

/// Prune execution only after the complete arena and every operation have been
/// authenticated. Preserve canonical node numbering and graph serialization.
fn prepareEvaluationNodes(program: *Program) void {
    program.evaluation_node_count = 0;
    var live = [_]bool{false} ** MAX_NODES;
    for (program.constraints[0..program.constraint_count]) |constraint| {
        live[constraint.root] = true;
        if (constraint.gate != NO_SLOT) live[constraint.gate] = true;
    }
    var index: usize = program.compiled_node_count;
    while (index > 0) {
        index -= 1;
        const node = program.nodes[index];
        if (!live[node.destination]) continue;
        switch (node.op) {
            .constant => {},
            .add, .sub, .mul => |binary| {
                live[binary.lhs] = true;
                live[binary.rhs] = true;
            },
            .neg => |operand| live[operand] = true,
            .select => |selection| {
                live[selection.selector] = true;
                live[selection.when_true] = true;
                live[selection.when_false] = true;
            },
        }
    }
    for (program.nodes[0..program.compiled_node_count]) |node| {
        if (!live[node.destination]) continue;
        program.evaluation_nodes[program.evaluation_node_count] = node;
        program.evaluation_node_count += 1;
    }
}

fn compileOp(op: expr.Op, source_index: usize) Error!Op {
    return switch (op) {
        .constant => |constant| .{ .constant = switch (constant) {
            .field, .unsigned => |value| value,
        } },
        .add => |binary| .{ .add = try compileBinary(binary, source_index) },
        .sub => |binary| .{ .sub = try compileBinary(binary, source_index) },
        .mul => |binary| .{ .mul = try compileBinary(binary, source_index) },
        .neg => |operand| .{ .neg = try priorSlot(operand, source_index) },
        .select => |selection| .{ .select = .{
            .selector = try priorSlot(selection.selector, source_index),
            .when_true = try priorSlot(selection.when_true, source_index),
            .when_false = try priorSlot(selection.when_false, source_index),
        } },
        .input, .hint_output, .call_output, .machine_derived => error.UnsupportedExpression,
    };
}

fn compileBinary(binary: expr.Binary, source_index: usize) Error!Binary {
    return .{
        .lhs = try priorSlot(binary.lhs, source_index),
        .rhs = try priorSlot(binary.rhs, source_index),
    };
}

fn priorSlot(value: types.ValueId, source_index: usize) Error!u16 {
    const index = types.idIndex(value);
    if (index >= source_index) return error.InvalidProgramShape;
    return slot(index);
}

fn slot(index: usize) Error!u16 {
    const value = std.math.cast(u16, index) orelse return error.SlotOverflow;
    if (value == NO_SLOT) return error.SlotOverflow;
    return value;
}

inline fn evaluateBaseOp(op: Op, values: *const [MAX_NODES]M31) M31 {
    return switch (op) {
        .constant => |value| M31.fromU64(value),
        .add => |binary| values[binary.lhs].add(values[binary.rhs]),
        .sub => |binary| values[binary.lhs].sub(values[binary.rhs]),
        .mul => |binary| values[binary.lhs].mul(values[binary.rhs]),
        .neg => |operand| values[operand].neg(),
        .select => |selection| values[selection.selector]
            .mul(values[selection.when_true])
            .add(M31.one().sub(values[selection.selector])
            .mul(values[selection.when_false])),
    };
}

inline fn evaluateSecureOp(op: Op, values: *const [MAX_NODES]QM31) QM31 {
    return switch (op) {
        .constant => |value| QM31.fromBase(M31.fromU64(value)),
        .add => |binary| values[binary.lhs].add(values[binary.rhs]),
        .sub => |binary| values[binary.lhs].sub(values[binary.rhs]),
        .mul => |binary| values[binary.lhs].mul(values[binary.rhs]),
        .neg => |operand| values[operand].neg(),
        .select => |selection| values[selection.selector]
            .mul(values[selection.when_true])
            .add(QM31.one().sub(values[selection.selector])
            .mul(values[selection.when_false])),
    };
}

fn emptyNode() Node {
    return .{ .destination = NO_SLOT, .op = .{ .constant = 0 } };
}

test "R-012 direct compiler evaluates control roots identically over M31 and QM31" {
    const control = @import("control.zig");
    var definition = try control.build(std.testing.allocator);
    defer definition.deinit();
    const compiled = try authenticate(
        &definition.arena,
        control.SEMANTIC_DIGEST,
        control.LOGICAL_INPUT_COUNT,
    );
    try std.testing.expectEqual(
        @as(u16, control.DIRECT_CONSTRAINT_COUNT),
        compiled.constraint_count,
    );

    var base_inputs = [_]M31{M31.zero()} ** control.LOGICAL_INPUT_COUNT;
    base_inputs[0] = M31.one();
    base_inputs[control.PREPROCESSED_COLUMN_COUNT] = M31.one();
    var base_scratch: [MAX_NODES]M31 = undefined;
    var base_roots: [control.DIRECT_CONSTRAINT_COUNT]M31 = undefined;
    try compiled.evaluateBaseInto(&base_inputs, &base_scratch, &base_roots);

    var secure_inputs: [control.LOGICAL_INPUT_COUNT]QM31 = undefined;
    for (&secure_inputs, base_inputs) |*target, value|
        target.* = QM31.fromBase(value);
    var secure_scratch: [MAX_NODES]QM31 = undefined;
    var secure_roots: [control.DIRECT_CONSTRAINT_COUNT]QM31 = undefined;
    try compiled.evaluateSecureInto(
        &secure_inputs,
        &secure_scratch,
        &secure_roots,
    );
    for (base_roots, secure_roots) |base, secure|
        try std.testing.expect(secure.eql(QM31.fromBase(base)));

    var wrong_digest = control.SEMANTIC_DIGEST;
    wrong_digest[0] ^= 1;
    try std.testing.expectError(
        error.BindingSealMismatch,
        authenticate(
            &definition.arena,
            wrong_digest,
            control.LOGICAL_INPUT_COUNT,
        ),
    );
}

test "R-012 direct execution pruning preserves every parent catalog root over base and extension fields" {
    @setEvalBranchQuota(500_000);
    const catalog = @import("detached_parent_catalog_v1.zig");
    var full_count: usize = 0;
    var live_count: usize = 0;
    inline for (catalog.LOGICAL_ROWS) |entry| {
        const Air = entry.Air;
        var definition = if (entry.requires_location)
            try Air.build(std.testing.allocator, .generated)
        else
            try Air.build(std.testing.allocator);
        defer definition.deinit();
        const pruned = try authenticate(&definition.arena, Air.SEMANTIC_DIGEST, Air.LOGICAL_INPUT_COUNT);
        full_count += pruned.compiled_node_count;
        live_count += pruned.evaluation_node_count;
        var complete = pruned;
        complete.evaluation_node_count = complete.compiled_node_count;
        @memcpy(complete.evaluation_nodes[0..complete.compiled_node_count], complete.nodes[0..complete.compiled_node_count]);
        // Arbitrary off-trace values are essential: satisfied zero roots
        // alone cannot detect a dropped direct constraint dependency.
        for (0..4) |sample| {
            var base: [Air.LOGICAL_INPUT_COUNT]M31 = undefined;
            var secure: [Air.LOGICAL_INPUT_COUNT]QM31 = undefined;
            for (&base, &secure, 0..) |*word, *extension, index| {
                word.* = M31.fromU64((sample + 3) * (index + 17) * 1_234_567);
                extension.* = QM31.fromM31(word.*, M31.fromU64(index + 1), M31.fromU64(sample + 2), M31.fromU64(index * 31 + sample));
            }
            var base_scratch: [MAX_NODES]M31 = undefined;
            var secure_scratch: [MAX_NODES]QM31 = undefined;
            var actual_base: [Air.DIRECT_CONSTRAINT_COUNT]M31 = undefined;
            var expected_base: [Air.DIRECT_CONSTRAINT_COUNT]M31 = undefined;
            var actual_secure: [Air.DIRECT_CONSTRAINT_COUNT]QM31 = undefined;
            var expected_secure: [Air.DIRECT_CONSTRAINT_COUNT]QM31 = undefined;
            try pruned.evaluateBaseInto(&base, &base_scratch, &actual_base);
            try complete.evaluateBaseInto(&base, &base_scratch, &expected_base);
            try pruned.evaluateSecureInto(&secure, &secure_scratch, &actual_secure);
            try complete.evaluateSecureInto(&secure, &secure_scratch, &expected_secure);
            try std.testing.expectEqualDeep(expected_base, actual_base);
            try std.testing.expectEqualDeep(expected_secure, actual_secure);
        }
        std.debug.print("DIRECT_EXECUTION_PRUNING row={d} canonical_nodes={d} executed_nodes={d}\n", .{ @intFromEnum(entry.row), pruned.compiled_node_count, pruned.evaluation_node_count });
    }
    try std.testing.expect(live_count < full_count);
}

test "R-012 direct execution pruning retains gates and the complete arena seal" {
    const source = @import("../../air/lang/source.zig").SourceSpan.generated();
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const input = try arena.input("value", .felt, source);
    const gate = try arena.input("gate", .selector, source);
    const two = try arena.constantField(2, source);
    const product = try arena.mul(input, two, source);
    const negative = try arena.neg(product, source);
    const root = try arena.sub(negative, two, source);
    const lookup_only = try arena.mul(product, product, source);
    _ = try arena.assertZero("gated", root, gate, .semantic, source);
    _ = try @import("relation_effect.zig").append(&arena, .{
        .domain = .recursion_statement_word,
        .role = .emit,
        .values = &.{ input, root, lookup_only },
        .weight = gate,
    }, source);
    const identity = try digest.computeIdentity(&arena);
    const program = try authenticate(&arena, identity.bytes, 2);
    try std.testing.expectEqual(@as(u16, 4), program.evaluation_node_count);
    var scratch: [MAX_NODES]M31 = undefined;
    var roots: [1]M31 = undefined;
    try program.evaluateBaseInto(&.{ M31.fromU64(7), M31.one() }, &scratch, &roots);
    try std.testing.expectEqual(M31.fromU64(16).neg(), roots[0]);
    var wrong_digest = identity.bytes;
    wrong_digest[0] ^= 1;
    try std.testing.expectError(error.BindingSealMismatch, authenticate(&arena, wrong_digest, 2));
}
