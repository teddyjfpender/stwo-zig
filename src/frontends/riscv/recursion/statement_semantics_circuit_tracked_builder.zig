//! Internal statement semantics circuit authority shard; use statement_semantics_circuit.zig publicly.

const dependency_0 = @import("statement_semantics_circuit_contract.zig");

const Addition = dependency_0.Addition;
const Circuit = dependency_0.Circuit;
const Error = dependency_0.Error;
const IDENTITY_DIGEST = dependency_0.IDENTITY_DIGEST;
const INPUT_COUNT = dependency_0.INPUT_COUNT;
const InputBinding = dependency_0.InputBinding;
const InputDescriptor = dependency_0.InputDescriptor;
const NODE_COUNT = dependency_0.NODE_COUNT;
const OUTPUT_COUNT = dependency_0.OUTPUT_COUNT;
const PrivateSource = dependency_0.PrivateSource;
const ProofKind = dependency_0.ProofKind;
const U16_BASE = dependency_0.U16_BASE;
const Value = dependency_0.Value;
const ValueSource = dependency_0.ValueSource;
const arithmetic = dependency_0.arithmetic;
const computeIdentity = dependency_0.computeIdentity;
const constant = dependency_0.constant;
const kindSet = dependency_0.kindSet;
const layout = dependency_0.layout;
const row11 = dependency_0.row11;
const statement = dependency_0.statement;
const std = dependency_0.std;

pub const TrackedBuilder = struct {
    allocator: std.mem.Allocator,
    arithmetic_builder: arithmetic.Builder,
    descriptors: std.ArrayList(InputDescriptor) = .empty,

    pub fn init(allocator: std.mem.Allocator) Error!TrackedBuilder {
        var arithmetic_builder = arithmetic.Builder.initDefault(allocator);
        arithmetic_builder.reserve(
            INPUT_COUNT,
            NODE_COUNT,
            OUTPUT_COUNT,
        ) catch |err| {
            arithmetic_builder.deinit();
            return err;
        };
        var result = TrackedBuilder{
            .allocator = allocator,
            .arithmetic_builder = arithmetic_builder,
        };
        result.descriptors.ensureTotalCapacity(allocator, INPUT_COUNT) catch |err| {
            result.deinit();
            return err;
        };
        return result;
    }

    pub fn deinit(self: *TrackedBuilder) void {
        self.descriptors.deinit(self.allocator);
        self.arithmetic_builder.deinit();
    }

    pub fn selector(self: *TrackedBuilder, kind: ProofKind) Error!Value {
        const set = kindSet(kind);
        return self.input(
            set,
            .{ .selector = kind },
            .{ .selector = kind },
        );
    }

    fn statement(
        self: *TrackedBuilder,
        scope: u32,
        index: u32,
        active_kinds: row11.ProofKindSet,
    ) Error!Value {
        return self.input(
            active_kinds,
            .{ .statement = .{
                .scope = scope,
                .index = index,
                .active_kinds = active_kinds,
            } },
            .{ .statement = .{ .scope = scope, .index = index } },
        );
    }

    pub fn private(
        self: *TrackedBuilder,
        active_kinds: row11.ProofKindSet,
        source: PrivateSource,
    ) Error!Value {
        return self.input(
            active_kinds,
            .{ .private = active_kinds },
            .{ .private = source },
        );
    }

    fn input(
        self: *TrackedBuilder,
        active_kinds: row11.ProofKindSet,
        row_source: row11.Source,
        value_source: ValueSource,
    ) Error!Value {
        if (self.descriptors.items.len >= INPUT_COUNT)
            return error.SemanticGeometryMismatch;
        const input_id: u32 = @intCast(self.descriptors.items.len);
        const value = try self.arithmetic_builder.input(input_id);
        const node_id = switch (value) {
            .node => |id| id,
            .constant => unreachable,
        };
        self.descriptors.appendAssumeCapacity(.{
            .node_id = node_id,
            .active_kinds = active_kinds,
            .row_source = row_source,
            .value_source = value_source,
        });
        return value;
    }

    pub fn add(self: *TrackedBuilder, lhs: Value, rhs: Value) Error!Value {
        return self.arithmetic_builder.add(lhs, rhs);
    }

    pub fn sub(self: *TrackedBuilder, lhs: Value, rhs: Value) Error!Value {
        return self.arithmetic_builder.sub(lhs, rhs);
    }

    pub fn mul(self: *TrackedBuilder, lhs: Value, rhs: Value) Error!Value {
        return self.arithmetic_builder.mul(lhs, rhs);
    }

    pub fn constrain(self: *TrackedBuilder, gate: Value, expression: Value) Error!void {
        _ = try self.arithmetic_builder.markOutput(try self.mul(gate, expression));
    }

    pub fn finish(self: *TrackedBuilder) Error!Circuit {
        if (self.descriptors.items.len != INPUT_COUNT)
            return error.SemanticGeometryMismatch;
        var arithmetic_graph = try self.arithmetic_builder.finish();
        errdefer arithmetic_graph.deinit();
        if (arithmetic_graph.nodes().len != NODE_COUNT or
            arithmetic_graph.outputs().len != OUTPUT_COUNT)
        {
            return error.SemanticGeometryMismatch;
        }
        const descriptors = try self.descriptors.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(descriptors);
        const bindings = try self.allocator.alloc(InputBinding, descriptors.len);
        errdefer self.allocator.free(bindings);
        for (descriptors, bindings, 0..) |descriptor, *binding, input_id| {
            binding.* = .{
                .node_id = descriptor.node_id,
                .use_count = try arithmetic_graph.inputUseCount(@intCast(input_id)),
                .source = descriptor.row_source,
            };
        }
        const identity_digest = computeIdentity(&arithmetic_graph, descriptors, bindings);
        if (!std.mem.eql(u8, &identity_digest, &IDENTITY_DIGEST))
            return error.CircuitIdentityMismatch;
        return .{
            .allocator = self.allocator,
            .arithmetic_graph = arithmetic_graph,
            .descriptors = descriptors,
            .bindings = bindings,
            .identity_digest = identity_digest,
        };
    }
};

pub const ScopedWords = struct {
    scope: u32,
    values: [statement.SPAN_STATEMENT_CANONICAL_WORDS]Value,

    pub fn init(
        builder: *TrackedBuilder,
        scope: u32,
        active_kinds: row11.ProofKindSet,
    ) Error!ScopedWords {
        var result: ScopedWords = .{ .scope = scope, .values = undefined };
        for (&result.values, 0..) |*word_value, index| {
            word_value.* = try builder.statement(scope, @intCast(index), active_kinds);
        }
        return result;
    }

    pub fn value(self: *const ScopedWords, index: usize) Value {
        return self.values[index];
    }
};

pub fn constrainSlotFold(
    builder: *TrackedBuilder,
    gate: Value,
    left: *const ScopedWords,
    right: *const ScopedWords,
    parent: *const ScopedWords,
) Error!void {
    try constrainEqual(builder, gate, left.value(layout.slot_tag), right.value(layout.slot_tag));
    try constrainEqual(builder, gate, parent.value(layout.slot_tag), left.value(layout.slot_tag));
    try constrainEqual(
        builder,
        gate,
        left.value(layout.slot_height),
        right.value(layout.slot_height),
    );
    try builder.constrain(
        gate,
        try builder.sub(
            try builder.sub(parent.value(layout.slot_height), left.value(layout.slot_height)),
            constant(1),
        ),
    );

    const left_node = limbRange(left, layout.slot_node_index_start);
    const right_node = limbRange(right, layout.slot_node_index_start);
    const parent_node = limbRange(parent, layout.slot_node_index_start);
    const one_limbs = [4]Value{ constant(1), constant(0), constant(0), constant(0) };
    try addLimbs(
        builder,
        gate,
        left_node[0..4],
        one_limbs[0..4],
        right_node[0..4],
        .slot_sibling,
    );
    try addLimbs(
        builder,
        gate,
        parent_node[0..4],
        parent_node[0..4],
        left_node[0..4],
        .slot_parent,
    );
}

pub fn constrainBodyFold(
    builder: *TrackedBuilder,
    binary: Value,
    left: *const ScopedWords,
    right: *const ScopedWords,
    parent: *const ScopedWords,
) Error!void {
    const left_executed = try bodyFlag(builder, binary, left);
    const right_executed = try bodyFlag(builder, binary, right);
    const parent_executed = try bodyFlag(builder, binary, parent);
    const left_empty = try builder.sub(constant(1), left_executed);
    const right_empty = try builder.sub(constant(1), right_executed);
    const both_executed = try builder.mul(
        try builder.mul(binary, left_executed),
        right_executed,
    );
    const left_only = try builder.mul(try builder.mul(binary, left_executed), right_empty);
    const both_empty = try builder.mul(try builder.mul(binary, left_empty), right_empty);

    try builder.constrain(binary, try builder.mul(left_empty, right_executed));
    const executed_or = try builder.sub(
        try builder.add(left_executed, right_executed),
        try builder.mul(left_executed, right_executed),
    );
    try builder.constrain(binary, try builder.sub(parent_executed, executed_or));

    for (layout.executed_start..statement.SPAN_STATEMENT_CANONICAL_WORDS) |index| {
        try constrainEqual(builder, left_only, parent.value(index), left.value(index));
        try builder.constrain(both_empty, parent.value(index));
    }
    try constrainBothExecuted(builder, both_executed, left, right, parent);
}

pub fn constrainMachineStateShape(
    builder: *TrackedBuilder,
    gate: Value,
    words: *const ScopedWords,
    start: usize,
) Error!void {
    try constrainTag(
        builder,
        gate,
        words,
        start + layout.machine_state_tag_offset,
        .machine_state,
    );
    try builder.constrain(
        gate,
        words.value(start + layout.machine_state_registers_start_offset),
    );
    try builder.constrain(
        gate,
        words.value(start + layout.machine_state_registers_start_offset + 1),
    );
}

pub fn constrainEdge(
    builder: *TrackedBuilder,
    gate: Value,
    present: Value,
    words: *const ScopedWords,
    tag_index: usize,
    digest_start: usize,
    complete_digest_start: usize,
) Error!void {
    const tag_expression = try builder.sub(
        try builder.sub(words.value(tag_index), tagConstant(.absent_edge)),
        try builder.mul(
            present,
            try builder.sub(tagConstant(.present_edge), tagConstant(.absent_edge)),
        ),
    );
    try builder.constrain(gate, tag_expression);
    for (0..8) |offset| {
        try builder.constrain(
            gate,
            try builder.sub(
                words.value(digest_start + offset),
                try builder.mul(present, words.value(complete_digest_start + offset)),
            ),
        );
    }
}

pub fn constrainTag(
    builder: *TrackedBuilder,
    gate: Value,
    words: *const ScopedWords,
    index: usize,
    tag: statement.Tag,
) Error!void {
    try builder.constrain(gate, try builder.sub(words.value(index), tagConstant(tag)));
}

pub const Bits = struct {
    values: [64]Value = undefined,
    len: usize = 0,

    pub fn slice(self: *const Bits) []const Value {
        return self.values[0..self.len];
    }
};

pub fn decomposeWordBits(
    builder: *TrackedBuilder,
    gate: Value,
    words: *const ScopedWords,
    start: usize,
    width: usize,
) Error!Bits {
    std.debug.assert(width <= 4);
    var result = Bits{};
    for (0..width) |limb_index| {
        var reconstructed = constant(0);
        for (0..16) |bit_index| {
            const bit = try builder.private(row11.ProofKindSet.LEAVES, .{
                .statement_bit = .{
                    .scope = words.scope,
                    .index = @intCast(start + limb_index),
                    .bit = @intCast(bit_index),
                },
            });
            try constrainBoolean(builder, gate, bit);
            reconstructed = try builder.add(
                reconstructed,
                try builder.mul(bit, constant(@as(u32, 1) << @intCast(bit_index))),
            );
            result.values[result.len] = bit;
            result.len += 1;
        }
        try builder.constrain(
            gate,
            try builder.sub(words.value(start + limb_index), reconstructed),
        );
    }
    return result;
}

pub fn constrainBothExecuted(
    builder: *TrackedBuilder,
    gate: Value,
    left: *const ScopedWords,
    right: *const ScopedWords,
    parent: *const ScopedWords,
) Error!void {
    try copyRange(builder, gate, parent, left, layout.executed_tag, 1);
    try copyRange(builder, gate, parent, left, layout.first_segment_start, 2);
    try addFieldRange(
        builder,
        gate,
        left,
        right,
        parent,
        layout.executed_segment_count_start,
        2,
        .folded_segment_count,
    );
    try copyRange(builder, gate, parent, left, layout.first_cycle_start, 4);
    try addFieldRange(
        builder,
        gate,
        left,
        right,
        parent,
        layout.executed_cycle_count_start,
        4,
        .folded_cycle_count,
    );
    try copyRange(
        builder,
        gate,
        parent,
        left,
        layout.entry_state_start,
        statement.MACHINE_STATE_CANONICAL_WORDS,
    );
    try copyRange(
        builder,
        gate,
        parent,
        right,
        layout.exit_state_start,
        statement.MACHINE_STATE_CANONICAL_WORDS,
    );
    try copyRange(
        builder,
        gate,
        parent,
        left,
        layout.input_edge_start,
        statement.EDGE_CLAIM_CANONICAL_WORDS,
    );
    try copyRange(
        builder,
        gate,
        parent,
        right,
        layout.output_edge_start,
        statement.EDGE_CLAIM_CANONICAL_WORDS,
    );

    try addCrossRange(
        builder,
        gate,
        left,
        layout.first_segment_start,
        layout.executed_segment_count_start,
        right,
        layout.first_segment_start,
        2,
        .segment_continuity,
    );
    try addCrossRange(
        builder,
        gate,
        left,
        layout.first_cycle_start,
        layout.executed_cycle_count_start,
        right,
        layout.first_cycle_start,
        4,
        .cycle_continuity,
    );
    for (0..statement.MACHINE_STATE_CANONICAL_WORDS) |offset| {
        try constrainEqual(
            builder,
            gate,
            left.value(layout.exit_state_start + offset),
            right.value(layout.entry_state_start + offset),
        );
    }

    const left_output_present = try edgeFlag(builder, gate, left, layout.output_edge_tag);
    const right_input_present = try edgeFlag(builder, gate, right, layout.input_edge_tag);
    try builder.constrain(gate, left_output_present);
    try builder.constrain(gate, right_input_present);
}

pub fn bodyFlag(
    builder: *TrackedBuilder,
    gate: Value,
    words: *const ScopedWords,
) Error!Value {
    const flag = try builder.private(row11.ProofKindSet.BINARY, .{
        .body_executed = words.scope,
    });
    try constrainBoolean(builder, gate, flag);
    try builder.constrain(
        gate,
        try builder.sub(
            try builder.sub(words.value(layout.body_tag), tagConstant(.empty_body)),
            try builder.mul(
                flag,
                try builder.sub(tagConstant(.executed_body), tagConstant(.empty_body)),
            ),
        ),
    );
    return flag;
}

pub fn edgeFlag(
    builder: *TrackedBuilder,
    gate: Value,
    words: *const ScopedWords,
    tag_index: usize,
) Error!Value {
    const flag = try builder.private(row11.ProofKindSet.BINARY, .{
        .edge_present = .{ .scope = words.scope, .tag_index = @intCast(tag_index) },
    });
    try constrainBoolean(builder, gate, flag);
    try builder.constrain(
        gate,
        try builder.sub(
            try builder.sub(words.value(tag_index), tagConstant(.absent_edge)),
            try builder.mul(
                flag,
                try builder.sub(tagConstant(.present_edge), tagConstant(.absent_edge)),
            ),
        ),
    );
    return flag;
}

pub fn addFieldRange(
    builder: *TrackedBuilder,
    gate: Value,
    left: *const ScopedWords,
    right: *const ScopedWords,
    parent: *const ScopedWords,
    start: usize,
    width: usize,
    addition: Addition,
) Error!void {
    const lhs = limbRange(left, start);
    const rhs = limbRange(right, start);
    const output = limbRange(parent, start);
    try addLimbs(builder, gate, lhs[0..width], rhs[0..width], output[0..width], addition);
}

pub fn addCrossRange(
    builder: *TrackedBuilder,
    gate: Value,
    left: *const ScopedWords,
    left_start: usize,
    left_count_start: usize,
    right: *const ScopedWords,
    right_start: usize,
    width: usize,
    addition: Addition,
) Error!void {
    const lhs = limbRange(left, left_start);
    const rhs = limbRange(left, left_count_start);
    const output = limbRange(right, right_start);
    try addLimbs(builder, gate, lhs[0..width], rhs[0..width], output[0..width], addition);
}

pub fn addLimbs(
    builder: *TrackedBuilder,
    gate: Value,
    lhs: []const Value,
    rhs: []const Value,
    output: []const Value,
    addition: Addition,
) Error!void {
    std.debug.assert(lhs.len == rhs.len and lhs.len == output.len and lhs.len <= 4);
    var carry = constant(0);
    for (lhs, rhs, output, 0..) |left, right, result, limb| {
        const next_carry = try builder.private(row11.ProofKindSet.BINARY, .{
            .addition_carry = .{ .addition = addition, .limb = @intCast(limb) },
        });
        try constrainBoolean(builder, gate, next_carry);
        try builder.constrain(
            gate,
            try builder.sub(
                try builder.sub(
                    try builder.add(try builder.add(left, right), carry),
                    result,
                ),
                try builder.mul(next_carry, constant(U16_BASE)),
            ),
        );
        carry = next_carry;
    }
    try builder.constrain(gate, carry);
}

pub fn copyRange(
    builder: *TrackedBuilder,
    gate: Value,
    target: *const ScopedWords,
    source: *const ScopedWords,
    start: usize,
    width: usize,
) Error!void {
    for (start..start + width) |index| {
        try constrainEqual(builder, gate, target.value(index), source.value(index));
    }
}

pub fn copyCrossRange(
    builder: *TrackedBuilder,
    gate: Value,
    words: *const ScopedWords,
    target_start: usize,
    source_start: usize,
    width: usize,
) Error!void {
    for (0..width) |offset| {
        try constrainEqual(
            builder,
            gate,
            words.value(target_start + offset),
            words.value(source_start + offset),
        );
    }
}

pub fn limbRange(words: *const ScopedWords, start: usize) [4]Value {
    return .{
        words.value(start),
        words.value(start + 1),
        words.value(start + 2),
        words.value(start + 3),
    };
}

pub fn constrainEqual(
    builder: *TrackedBuilder,
    gate: Value,
    lhs: Value,
    rhs: Value,
) Error!void {
    try builder.constrain(gate, try builder.sub(lhs, rhs));
}

pub fn constrainBoolean(builder: *TrackedBuilder, gate: Value, value: Value) Error!void {
    try builder.constrain(
        gate,
        try builder.mul(value, try builder.sub(constant(1), value)),
    );
}

pub fn tagConstant(tag: statement.Tag) Value {
    return constant(@intFromEnum(tag));
}
