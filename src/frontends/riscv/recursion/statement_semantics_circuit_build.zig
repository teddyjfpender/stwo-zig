//! Internal statement semantics circuit authority shard; use statement_semantics_circuit.zig publicly.

const dependency_0 = @import("statement_semantics_circuit_contract.zig");
const dependency_1 = @import("statement_semantics_circuit_tracked_builder.zig");

const Bits = dependency_1.Bits;
const Circuit = dependency_0.Circuit;
const Error = dependency_0.Error;
const ScopedWords = dependency_1.ScopedWords;
const TrackedBuilder = dependency_1.TrackedBuilder;
const Value = dependency_0.Value;
const constant = dependency_0.constant;
const constrainBodyFold = dependency_1.constrainBodyFold;
const constrainBoolean = dependency_1.constrainBoolean;
const constrainEdge = dependency_1.constrainEdge;
const constrainEqual = dependency_1.constrainEqual;
const constrainMachineStateShape = dependency_1.constrainMachineStateShape;
const constrainSlotFold = dependency_1.constrainSlotFold;
const constrainTag = dependency_1.constrainTag;
const copyCrossRange = dependency_1.copyCrossRange;
const decomposeWordBits = dependency_1.decomposeWordBits;
const layout = dependency_0.layout;
const row11 = dependency_0.row11;
const statement = dependency_0.statement;
const statement_input = dependency_0.statement_input;
const std = dependency_0.std;
const tagConstant = dependency_1.tagConstant;

pub fn build(allocator: std.mem.Allocator) Error!Circuit {
    var builder = try TrackedBuilder.init(allocator);
    defer builder.deinit();

    const segment_selector = try builder.selector(.segment_leaf);
    const binary_selector = try builder.selector(.binary_node);
    const empty_selector = try builder.selector(.empty_leaf);
    const one = constant(1);
    try constrainBoolean(&builder, one, segment_selector);
    try constrainBoolean(&builder, one, binary_selector);
    try constrainBoolean(&builder, one, empty_selector);
    try builder.constrain(one, try builder.mul(segment_selector, binary_selector));
    try builder.constrain(one, try builder.mul(segment_selector, empty_selector));
    try builder.constrain(one, try builder.mul(binary_selector, empty_selector));

    const segment = try ScopedWords.init(
        &builder,
        statement_input.SEGMENT_STATEMENT_SCOPE,
        row11.ProofKindSet.SEGMENT,
    );
    const left = try ScopedWords.init(
        &builder,
        statement_input.LEFT_STATEMENT_SCOPE,
        row11.ProofKindSet.BINARY,
    );
    const right = try ScopedWords.init(
        &builder,
        statement_input.RIGHT_STATEMENT_SCOPE,
        row11.ProofKindSet.BINARY,
    );
    const parent = try ScopedWords.init(
        &builder,
        statement_input.PARENT_STATEMENT_SCOPE,
        row11.ProofKindSet.ALL,
    );

    try constrainCommonJob(&builder, binary_selector, &left, &right, &parent);
    try constrainSlotFold(&builder, binary_selector, &left, &right, &parent);
    try constrainBodyFold(&builder, binary_selector, &left, &right, &parent);
    try constrainLeafSemantics(
        &builder,
        segment_selector,
        empty_selector,
        &segment,
        &parent,
    );
    return builder.finish();
}

pub fn constrainCommonJob(
    builder: *TrackedBuilder,
    gate: Value,
    left: *const ScopedWords,
    right: *const ScopedWords,
    parent: *const ScopedWords,
) Error!void {
    for (layout.span_tag..layout.job_slot_height + 1) |index| {
        try constrainEqual(builder, gate, left.value(index), right.value(index));
        try constrainEqual(builder, gate, parent.value(index), left.value(index));
    }
}

pub fn constrainLeafSemantics(
    builder: *TrackedBuilder,
    segment_selector: Value,
    empty_selector: Value,
    segment: *const ScopedWords,
    parent: *const ScopedWords,
) Error!void {
    const leaf = try builder.add(segment_selector, empty_selector);
    for (0..statement.SPAN_STATEMENT_CANONICAL_WORDS) |index| {
        try constrainEqual(
            builder,
            segment_selector,
            segment.value(index),
            parent.value(index),
        );
    }

    try constrainTag(builder, leaf, parent, layout.span_tag, .span_statement);
    try constrainTag(builder, leaf, parent, layout.job_tag, .job_context);
    try constrainTag(builder, leaf, parent, layout.complete_tag, .complete_execution);
    try constrainMachineStateShape(builder, leaf, parent, layout.initial_state_start);
    try constrainMachineStateShape(builder, leaf, parent, layout.final_state_start);
    try constrainTag(builder, leaf, parent, layout.slot_tag, .slot_span);
    try builder.constrain(leaf, parent.value(layout.slot_height));

    const total_cycle_bits = try decomposeWordBits(
        builder,
        leaf,
        parent,
        layout.total_cycles_start,
        4,
    );
    try builder.constrain(leaf, try builder.sub(constant(1), try orBits(builder, total_cycle_bits.slice())));

    const segment_count_bits = try decomposeWordBits(
        builder,
        leaf,
        parent,
        layout.job_segment_count_start,
        2,
    );
    const segment_count_minus_one = try subtractOneBits(
        builder,
        leaf,
        segment_count_bits.slice(),
    );
    const height_flags = try bitLengthFlags(builder, segment_count_minus_one.slice());
    var encoded_height = constant(0);
    for (height_flags.slice(), 0..) |flag, height| {
        encoded_height = try builder.add(
            encoded_height,
            try builder.mul(flag, constant(@intCast(height))),
        );
    }
    try builder.constrain(
        leaf,
        try builder.sub(parent.value(layout.job_slot_height), encoded_height),
    );

    const node_bits = try decomposeWordBits(
        builder,
        leaf,
        parent,
        layout.slot_node_index_start,
        2,
    );
    try builder.constrain(leaf, parent.value(layout.slot_node_index_start + 2));
    try builder.constrain(leaf, parent.value(layout.slot_node_index_start + 3));
    for (node_bits.slice(), 0..) |node_bit, bit_index| {
        var height_too_small = constant(0);
        for (height_flags.slice()[0 .. bit_index + 1]) |flag| {
            height_too_small = try builder.add(height_too_small, flag);
        }
        try builder.constrain(leaf, try builder.mul(node_bit, height_too_small));
    }

    const node_before_segment_count = try lessThanBits(
        builder,
        node_bits.slice(),
        segment_count_bits.slice(),
    );
    try builder.constrain(
        segment_selector,
        try builder.sub(constant(1), node_before_segment_count),
    );
    try builder.constrain(empty_selector, node_before_segment_count);

    const body_tag = try builder.sub(
        try builder.sub(
            parent.value(layout.body_tag),
            try builder.mul(segment_selector, tagConstant(.executed_body)),
        ),
        try builder.mul(empty_selector, tagConstant(.empty_body)),
    );
    try builder.constrain(leaf, body_tag);
    for (layout.executed_start..statement.SPAN_STATEMENT_CANONICAL_WORDS) |index| {
        try builder.constrain(empty_selector, parent.value(index));
    }

    try constrainSegmentLeaf(
        builder,
        segment_selector,
        parent,
        node_bits.slice(),
        segment_count_minus_one.slice(),
        total_cycle_bits.slice(),
    );
}

pub fn constrainSegmentLeaf(
    builder: *TrackedBuilder,
    segment: Value,
    words: *const ScopedWords,
    node_bits: []const Value,
    segment_count_minus_one: []const Value,
    total_cycle_bits: []const Value,
) Error!void {
    try constrainTag(builder, segment, words, layout.executed_tag, .executed_span);
    try constrainEqual(
        builder,
        segment,
        words.value(layout.first_segment_start),
        words.value(layout.slot_node_index_start),
    );
    try constrainEqual(
        builder,
        segment,
        words.value(layout.first_segment_start + 1),
        words.value(layout.slot_node_index_start + 1),
    );
    try builder.constrain(
        segment,
        try builder.sub(words.value(layout.executed_segment_count_start), constant(1)),
    );
    try builder.constrain(segment, words.value(layout.executed_segment_count_start + 1));

    try constrainMachineStateShape(builder, segment, words, layout.entry_state_start);
    try constrainMachineStateShape(builder, segment, words, layout.exit_state_start);

    const first_cycle_bits = try decomposeWordBits(
        builder,
        segment,
        words,
        layout.first_cycle_start,
        4,
    );
    const cycle_count_bits = try decomposeWordBits(
        builder,
        segment,
        words,
        layout.executed_cycle_count_start,
        4,
    );
    try builder.constrain(
        segment,
        try builder.sub(constant(1), try orBits(builder, cycle_count_bits.slice())),
    );
    const end_cycle = try addBits(builder, first_cycle_bits.slice(), cycle_count_bits.slice());
    try builder.constrain(segment, end_cycle.overflow);
    try builder.constrain(
        segment,
        try lessThanBits(builder, total_cycle_bits, end_cycle.bits.slice()),
    );

    const first = try builder.sub(constant(1), try orBits(builder, node_bits));
    const last = try equalBits(builder, node_bits, segment_count_minus_one);
    const first_gate = try builder.mul(segment, first);
    const last_gate = try builder.mul(segment, last);

    for (layout.first_cycle_start..layout.first_cycle_start + 4) |index| {
        try builder.constrain(first_gate, words.value(index));
    }
    try copyCrossRange(
        builder,
        first_gate,
        words,
        layout.entry_state_start,
        layout.initial_state_start,
        statement.MACHINE_STATE_CANONICAL_WORDS,
    );
    for (end_cycle.bits.slice(), total_cycle_bits) |end_bit, total_bit| {
        try constrainEqual(builder, last_gate, end_bit, total_bit);
    }
    try copyCrossRange(
        builder,
        last_gate,
        words,
        layout.exit_state_start,
        layout.final_state_start,
        statement.MACHINE_STATE_CANONICAL_WORDS,
    );

    try constrainEdge(
        builder,
        segment,
        first,
        words,
        layout.input_edge_tag,
        layout.input_edge_digest_start,
        layout.public_input_start,
    );
    try constrainEdge(
        builder,
        segment,
        last,
        words,
        layout.output_edge_tag,
        layout.output_edge_digest_start,
        layout.public_output_start,
    );
}

pub fn subtractOneBits(
    builder: *TrackedBuilder,
    gate: Value,
    value_bits: []const Value,
) Error!Bits {
    std.debug.assert(value_bits.len == 32);
    var result = Bits{ .len = 32 };
    for (0..32) |bit_index| {
        result.values[bit_index] = try builder.private(row11.ProofKindSet.LEAVES, .{
            .segment_count_minus_one_bit = @intCast(bit_index),
        });
        try constrainBoolean(builder, gate, result.values[bit_index]);
    }

    var carry = constant(1);
    for (value_bits, result.slice()) |value_bit, minus_one_bit| {
        const xor_term = try builder.sub(
            try builder.add(minus_one_bit, carry),
            try builder.mul(constant(2), try builder.mul(minus_one_bit, carry)),
        );
        try constrainEqual(builder, gate, value_bit, xor_term);
        carry = try builder.mul(minus_one_bit, carry);
    }
    try builder.constrain(gate, carry);
    return result;
}

pub fn bitLengthFlags(builder: *TrackedBuilder, bits: []const Value) Error!Bits {
    std.debug.assert(bits.len < 64);
    var result = Bits{ .len = bits.len + 1 };
    for (result.values[0..result.len]) |*flag| flag.* = constant(0);
    var seen = constant(0);
    var index = bits.len;
    while (index != 0) {
        index -= 1;
        const highest = try builder.mul(bits[index], try builder.sub(constant(1), seen));
        result.values[index + 1] = highest;
        seen = try builder.sub(
            try builder.add(seen, bits[index]),
            try builder.mul(seen, bits[index]),
        );
    }
    result.values[0] = try builder.sub(constant(1), seen);
    return result;
}

pub fn orBits(builder: *TrackedBuilder, bits: []const Value) Error!Value {
    var seen = constant(0);
    for (bits) |bit| {
        seen = try builder.sub(
            try builder.add(seen, bit),
            try builder.mul(seen, bit),
        );
    }
    return seen;
}

pub fn equalBits(
    builder: *TrackedBuilder,
    lhs: []const Value,
    rhs: []const Value,
) Error!Value {
    std.debug.assert(lhs.len == rhs.len);
    var equal = constant(1);
    for (lhs, rhs) |left, right| {
        const same = try builder.add(
            try builder.sub(try builder.sub(constant(1), left), right),
            try builder.mul(constant(2), try builder.mul(left, right)),
        );
        equal = try builder.mul(equal, same);
    }
    return equal;
}

pub fn lessThanBits(
    builder: *TrackedBuilder,
    lhs: []const Value,
    rhs: []const Value,
) Error!Value {
    std.debug.assert(lhs.len == rhs.len);
    var equal_above = constant(1);
    var less = constant(0);
    var index = lhs.len;
    while (index != 0) {
        index -= 1;
        less = try builder.add(
            less,
            try builder.mul(
                equal_above,
                try builder.mul(try builder.sub(constant(1), lhs[index]), rhs[index]),
            ),
        );
        const same = try builder.add(
            try builder.sub(try builder.sub(constant(1), lhs[index]), rhs[index]),
            try builder.mul(constant(2), try builder.mul(lhs[index], rhs[index])),
        );
        equal_above = try builder.mul(equal_above, same);
    }
    return less;
}

pub const AddBitsResult = struct {
    bits: Bits,
    overflow: Value,
};

pub fn addBits(
    builder: *TrackedBuilder,
    lhs: []const Value,
    rhs: []const Value,
) Error!AddBitsResult {
    std.debug.assert(lhs.len == rhs.len and lhs.len <= 64);
    var result = AddBitsResult{ .bits = .{ .len = lhs.len }, .overflow = constant(0) };
    var carry = constant(0);
    for (lhs, rhs, 0..) |left, right, index| {
        const left_xor_right = try builder.sub(
            try builder.add(left, right),
            try builder.mul(constant(2), try builder.mul(left, right)),
        );
        result.bits.values[index] = try builder.sub(
            try builder.add(left_xor_right, carry),
            try builder.mul(constant(2), try builder.mul(left_xor_right, carry)),
        );
        carry = try builder.add(
            try builder.mul(left, right),
            try builder.mul(carry, left_xor_right),
        );
    }
    result.overflow = carry;
    return result;
}
