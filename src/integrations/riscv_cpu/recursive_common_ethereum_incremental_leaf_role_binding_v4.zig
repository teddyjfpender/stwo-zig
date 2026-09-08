//! Pointwise memory-role binding in the admitted public-sum arithmetic graph.
//!
//! Child claim coordinates are fixed by the frozen claim shape. Output slots
//! are selected by a value-independent polynomial in the authenticated input
//! count, never by proof-dependent preprocessing. This deliberately bounded
//! development route uses quadratic work; the admission check precedes graph
//! allocation. Completion is a separate program/native-boundary obligation.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const arithmetic = frontend.recursion.arithmetic_circuit;
const claim = frontend.recursion.vm_public_claim;
const role = @import("recursive_common_ethereum_incremental_leaf_role_aware_io_v4.zig");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Value = arithmetic.Value;
const Builder = arithmetic.Builder;

pub const SCHEMA_VERSION: u16 = 1;
pub const MAX_TUPLE_CAPACITY: u32 = 32;
pub const HEADER_INPUT_COUNT: usize = 6;
pub const INPUT_SLOT_INPUT_COUNT: usize = 7;
pub const OUTPUT_SLOT_INPUT_COUNT: usize = 11;
pub const LIMB_COUNT: usize = 14;
pub const BIT_COUNT: usize = 16;
pub const Source = union(enum) {
    claim_word: u32,
    claim_byte: struct { word_index: u32, byte_index: u1 },
    limb_bit: struct { slot: u32, limb: u4, bit: u4 },
    input_carry: u32,
    /// Source projection42..45: addresslow/high, rawinstructionlow/high.
    completion_word: u2,
    completion_decoded_word: u2,
    completion_policy_word: u2,
    nonfinal_inverse,
    /// Canonical zero in the explicit terminal profile; preserves the old ABI.
    terminal_reserved,
};

pub const Budget = struct { input_count: usize, estimated_extra_nodes: usize };
pub fn budget(capacity: u32) !Budget {
    if (capacity == 0 or capacity > MAX_TUPLE_CAPACITY or !std.math.isPowerOfTwo(capacity))
        return error.EthereumRoleBindingCapacityExceeded;
    // Upper reservation estimate, not a claimed measurement. Focused gates
    // print actual graph counts alongside it before widening this admission.
    return .{ .input_count = HEADER_INPUT_COUNT + @as(usize, capacity) * (INPUT_SLOT_INPUT_COUNT + OUTPUT_SLOT_INPUT_COUNT + LIMB_COUNT * BIT_COUNT + 1), .estimated_extra_nodes = 80 * @as(usize, capacity) * capacity + 2200 * @as(usize, capacity) + 128 };
}

pub fn sourceAt(capacity: u32, index: usize) !Source {
    const shape = try claim.defaultShape();
    if (index >= (try budget(capacity)).input_count) return error.InvalidEthereumRoleBinding;
    if (index < HEADER_INPUT_COUNT) return .{ .claim_word = @intCast(switch (index / 2) {
        0 => claim.canonical_layout.input_word_count_start,
        1 => claim.canonical_layout.outputWordCountStart(shape),
        2 => claim.canonical_layout.input_start_start,
        else => unreachable,
    } + index % 2) };
    var offset = index - HEADER_INPUT_COUNT;
    const input_count = @as(usize, capacity) * INPUT_SLOT_INPUT_COUNT;
    if (offset < input_count) {
        const field_index = offset % INPUT_SLOT_INPUT_COUNT;
        const first = claim.canonical_layout.inputSlotPresent(offset / INPUT_SLOT_INPUT_COUNT);
        return if (field_index < 3) .{ .claim_word = @intCast(first + field_index) } else .{ .claim_byte = .{
            .word_index = @intCast(first + 1 + (field_index - 3) / 2),
            .byte_index = @intCast((field_index - 3) % 2),
        } };
    }
    offset -= input_count;
    const output_count = @as(usize, capacity) * OUTPUT_SLOT_INPUT_COUNT;
    if (offset < output_count) {
        const field_index = offset % OUTPUT_SLOT_INPUT_COUNT;
        const first = claim.canonical_layout.outputSlotPresent(shape, offset / OUTPUT_SLOT_INPUT_COUNT);
        return if (field_index < 7) .{ .claim_word = @intCast(first + field_index) } else .{ .claim_byte = .{
            .word_index = @intCast(first + 3 + (field_index - 7) / 2),
            .byte_index = @intCast((field_index - 7) % 2),
        } };
    }
    offset -= output_count;
    const bit_count = @as(usize, capacity) * LIMB_COUNT * BIT_COUNT;
    if (offset < bit_count) return .{ .limb_bit = .{
        .slot = @intCast(offset / (LIMB_COUNT * BIT_COUNT)),
        .limb = @intCast((offset / BIT_COUNT) % LIMB_COUNT),
        .bit = @intCast(offset % BIT_COUNT),
    } };
    return .{ .input_carry = @intCast(offset - bit_count) };
}

/// Reads the exact shared claim encoding, rather than maintaining a second
/// host description of its fields. Private witnesses are checked by the graph.
pub fn read(source: Source, claim_words: []const M31, role_words: []const u32) !QM31 {
    const value: u32 = switch (source) {
        .claim_word => |index| if (index < claim_words.len) claim_words[index].toU32() else return error.InvalidEthereumRoleBinding,
        .claim_byte => |coordinate| blk: {
            if (coordinate.word_index >= claim_words.len) return error.InvalidEthereumRoleBinding;
            const word = claim_words[coordinate.word_index].toU32();
            if (word > 65535) return error.InvalidEthereumRoleBinding;
            break :blk (word >> @as(u5, @intCast(@as(u32, coordinate.byte_index) * 8))) & 255;
        },
        .limb_bit => |coordinate| blk: {
            if (coordinate.limb >= LIMB_COUNT) return error.InvalidEthereumRoleBinding;
            const index = role.HEADER_WORD_COUNT + @as(usize, coordinate.slot) * role.TUPLE_WORD_COUNT + 4 + coordinate.limb;
            if (index >= role_words.len or role_words[index] > 65535) return error.InvalidEthereumRoleBinding;
            break :blk (role_words[index] >> coordinate.bit) & 1;
        },
        .input_carry => |slot| blk: {
            const start = claim.canonical_layout.input_start_start;
            const present = claim.canonical_layout.inputSlotPresent(slot);
            if (start >= claim_words.len or present >= claim_words.len) return error.InvalidEthereumRoleBinding;
            break :blk @intFromBool(!claim_words[present].isZero() and @as(u64, claim_words[start].toU32()) + @as(u64, slot) * 4 > 65535);
        },
        .completion_word, .completion_decoded_word, .completion_policy_word, .nonfinal_inverse, .terminal_reserved => return error.EthereumCompletionContextRequired,
    };
    return QM31.fromBase(M31.fromCanonical(value));
}

/// The independently admitted first-wrapper profile is explicitly nonfinal.
/// The span's canonical geometry bounds this nonnegative difference below
/// M31. A nonzero inverse constraint cannot be satisfied by a final segment.
pub fn requireNonfinal(builder: *Builder, job_count: Value, first_segment: Value, segment_count: Value, inverse: Value) !void {
    try equal(builder, segment_count, Value.one());
    const difference = try builder.sub(try builder.sub(job_count, first_segment), segment_count);
    try equal(builder, try builder.mul(difference, inverse), Value.one());
}

/// Exact admitted nonfinal native completion: unretired fetch and no memory clock.
pub fn constrainNonfinalCompletionPolicy(builder: *Builder, policy: [3]Value) !void {
    try equal(builder, policy[0], base(@intFromEnum(frontend.air.public_data.CompletionKind.unretired_program_fetch)));
    try zero(builder, policy[1]);
    try zero(builder, policy[2]);
}

pub fn constrainNonfinalRoleOrder(builder: *Builder, capacity: u32, sources: []const Value, selectors: []const Value) !void {
    const memory_count = try builder.add(try composeU32(builder, sources[0], sources[1]), try composeU32(builder, sources[2], sources[3]));
    var program_count = Value.zero();
    for (0..capacity) |slot| {
        const selected = selectors[slot * 5 ..][0..5];
        try zero(builder, selected[3]);
        program_count = try builder.add(program_count, selected[4]);
        try selectedEqual(builder, selected[4], base(slot), memory_count);
    }
    try equal(builder, program_count, Value.one());
}

/// The program tuple uses canonical M31 values, encoded as two u16 limbs.
/// Ban bit31 and the all-ones31 encoding of the modulus. Both checks use the
/// same constrained bit witnesses as the role stream's integer projection.
pub fn constrainCanonicalDecoded(builder: *Builder, capacity: u32, sources: []const Value, slot: usize, selected: Value) !void {
    const bits_start = HEADER_INPUT_COUNT + @as(usize, capacity) * (INPUT_SLOT_INPUT_COUNT + OUTPUT_SLOT_INPUT_COUNT);
    for (0..4) |field_index| {
        const first_bit = bits_start + (slot * LIMB_COUNT + 2 + 2 * field_index) * BIT_COUNT;
        try constrainCanonicalFieldBits(builder, sources[first_bit..][0..32].*, selected);
    }
}

/// Same canonical31-bit check for one decoded program field in a bounded
/// tuple or the streamed initial-input completion packet.
pub fn constrainCanonicalFieldBits(builder: *Builder, bits: [32]Value, selected: Value) !void {
    try zero(builder, try builder.mul(selected, bits[31]));
    var all_ones = Value.one();
    for (bits[0..31]) |bit| all_ones = try builder.mul(all_ones, bit);
    try zero(builder, try builder.mul(selected, all_ones));
}

pub fn nonfinalInverse(statement_words: []const u32) !QM31 {
    const layout = frontend.recursion.span_statement.canonical_layout;
    const job_count = try readU32(statement_words, layout.job_segment_count_start);
    const first_segment = try readU32(statement_words, layout.first_segment_start);
    const segment_count = try readU32(statement_words, layout.executed_segment_count_start);
    if (segment_count != 1 or first_segment >= job_count or first_segment + 1 >= job_count)
        return error.EthereumNonfinalWrapperRequired;
    const difference = job_count - first_segment - 1;
    if (difference >= core.fields.m31.Modulus) return error.InvalidEthereumRoleBinding;
    return field(difference).inv();
}

fn readU32(words: []const u32, at: usize) !u32 {
    if (at + 2 > words.len or words[at] > 65535 or words[at + 1] > 65535) return error.InvalidEthereumRoleBinding;
    return words[at] | (words[at + 1] << 16);
}

pub fn constrain(builder: *Builder, allocator: std.mem.Allocator, capacity: u32, sources: []const Value, role_words: []const Value, selectors: []const Value) !void {
    if (sources.len != (try budget(capacity)).input_count or role_words.len != role.HEADER_WORD_COUNT + @as(usize, capacity) * role.TUPLE_WORD_COUNT or selectors.len != @as(usize, capacity) * 5)
        return error.InvalidEthereumRoleBinding;
    const input_start: usize = HEADER_INPUT_COUNT;
    const output_start = input_start + @as(usize, capacity) * INPUT_SLOT_INPUT_COUNT;
    const bits_start = output_start + @as(usize, capacity) * OUTPUT_SLOT_INPUT_COUNT;
    const carry_start = bits_start + @as(usize, capacity) * LIMB_COUNT * BIT_COUNT;
    const input_count = try composeU32(builder, sources[0], sources[1]);
    const output_count = try composeU32(builder, sources[2], sources[3]);
    var input_total = Value.zero();
    var output_total = Value.zero();
    var previous_input = Value.one();
    var previous_output = Value.one();
    for (0..capacity) |slot| {
        const input = sources[input_start + slot * INPUT_SLOT_INPUT_COUNT ..][0..INPUT_SLOT_INPUT_COUNT];
        const output = sources[output_start + slot * OUTPUT_SLOT_INPUT_COUNT ..][0..OUTPUT_SLOT_INPUT_COUNT];
        for ([_]Value{ input[0], output[0] }) |present| try boolean(builder, present);
        try zero(builder, try builder.mul(try builder.sub(Value.one(), previous_input), input[0]));
        try zero(builder, try builder.mul(try builder.sub(Value.one(), previous_output), output[0]));
        previous_input = input[0];
        previous_output = output[0];
        input_total = try builder.add(input_total, input[0]);
        output_total = try builder.add(output_total, output[0]);
    }
    // Limb-wise counts avoid accepting count + M31 modulus as the same field.
    try equal(builder, sources[1], Value.zero());
    try equal(builder, sources[3], Value.zero());
    try equal(builder, input_count, input_total);
    try equal(builder, output_count, output_total);

    const prefix = try allocator.alloc(Value, @as(usize, capacity) + 1);
    defer allocator.free(prefix);
    const suffix = try allocator.alloc(Value, @as(usize, capacity) + 1);
    defer allocator.free(suffix);
    const weights = try allocator.alloc(Value, capacity);
    defer allocator.free(weights);
    const coefficients = try allocator.alloc(Value, capacity);
    defer allocator.free(coefficients);
    for (coefficients, 0..) |*coefficient, i| {
        var denominator = QM31.one();
        for (0..capacity) |j| if (i != j) {
            denominator = denominator.mul(field(i).sub(field(j)));
        };
        coefficient.* = Value.fromSecure(try denominator.inv());
    }
    for (0..capacity) |slot| {
        const words = role_words[role.HEADER_WORD_COUNT + slot * role.TUPLE_WORD_COUNT ..][0..role.TUPLE_WORD_COUNT];
        const selected = selectors[slot * 5 ..][0..5];
        const input = sources[input_start + slot * INPUT_SLOT_INPUT_COUNT ..][0..INPUT_SLOT_INPUT_COUNT];
        try equal(builder, selected[1], input[0]);
        const carry = sources[carry_start + slot];
        try boolean(builder, carry);
        try zero(builder, try builder.mul(try builder.sub(Value.one(), selected[1]), carry));
        try selectedEqual(builder, selected[1], try builder.add(words[6], try builder.mul(base(65536), carry)), try builder.add(sources[4], base(4 * slot)));
        try selectedEqual(builder, selected[1], words[7], try builder.add(sources[5], carry));
        try selectedEqual(builder, selected[1], words[8], Value.zero());
        try selectedEqual(builder, selected[1], words[9], Value.zero());
        for (0..4) |byte| try selectedEqual(builder, selected[1], words[10 + byte * 2], input[3 + byte]);

        // Lagrange selection over 0..capacity-1, assembled with prefix/suffix
        // products in O(capacity) operations per destination slot.
        const source_index = try builder.sub(base(slot), input_count);
        prefix[0] = Value.one();
        for (0..capacity) |i| prefix[i + 1] = try builder.mul(prefix[i], try builder.sub(source_index, base(i)));
        suffix[capacity] = Value.one();
        var reverse: usize = capacity;
        while (reverse != 0) {
            reverse -= 1;
            suffix[reverse] = try builder.mul(suffix[reverse + 1], try builder.sub(source_index, base(reverse)));
        }
        const not_input = try builder.sub(Value.one(), selected[1]);
        var output_present = Value.zero();
        for (0..capacity) |i| {
            const output = sources[output_start + i * OUTPUT_SLOT_INPUT_COUNT ..][0..OUTPUT_SLOT_INPUT_COUNT];
            weights[i] = try builder.mul(try builder.mul(try builder.mul(prefix[i], suffix[i + 1]), coefficients[i]), try builder.mul(not_input, output[0]));
            output_present = try builder.add(output_present, weights[i]);
        }
        try equal(builder, selected[2], output_present);
        for ([_]usize{ 1, 2, 5, 6, 7, 8, 9, 10 }, [_]usize{ 6, 7, 8, 9, 10, 12, 14, 16 }) |source_field, destination| {
            var expected = Value.zero();
            for (0..capacity) |i| expected = try builder.add(expected, try builder.mul(weights[i], sources[output_start + i * OUTPUT_SLOT_INPUT_COUNT + source_field]));
            try selectedEqual(builder, selected[2], words[destination], expected);
        }
        for (0..LIMB_COUNT) |limb| {
            var reconstructed = Value.zero();
            for (0..BIT_COUNT) |bit| {
                const value = sources[bits_start + (slot * LIMB_COUNT + limb) * BIT_COUNT + bit];
                try boolean(builder, value);
                reconstructed = try builder.add(reconstructed, try builder.mul(value, base(@as(u32, 1) << @as(u5, @intCast(bit)))));
            }
            try equal(builder, words[4 + limb], reconstructed);
        }
    }
}

fn field(value: usize) QM31 {
    return QM31.fromBase(M31.fromCanonical(@intCast(value)));
}
fn base(value: usize) Value {
    return Value.fromSecure(field(value));
}
fn zero(builder: *Builder, value: Value) !void {
    _ = try builder.markOutput(value);
}
fn equal(builder: *Builder, left: Value, right: Value) !void {
    try zero(builder, try builder.sub(left, right));
}
fn selectedEqual(builder: *Builder, selected: Value, left: Value, right: Value) !void {
    try zero(builder, try builder.mul(selected, try builder.sub(left, right)));
}
fn boolean(builder: *Builder, value: Value) !void {
    try zero(builder, try builder.mul(value, try builder.sub(value, Value.one())));
}
fn composeU32(builder: *Builder, low: Value, high: Value) !Value {
    return builder.add(low, try builder.mul(base(65536), high));
}

test "Ethereum role binding proves pointwise memory sources and rejects field-alias rewrites" {
    const allocator = std.testing.allocator;
    const capacity: u32 = 2;
    const source_count = (try budget(capacity)).input_count;
    const role_count = role.HEADER_WORD_COUNT + capacity * role.TUPLE_WORD_COUNT;
    const selector_count = capacity * 5;
    const input_count = role_count + selector_count + source_count;
    var builder = Builder.initDefault(allocator);
    var builder_live = true;
    defer if (builder_live) builder.deinit();
    const nodes = try allocator.alloc(Value, input_count);
    defer allocator.free(nodes);
    for (nodes, 0..) |*node, index| node.* = try builder.input(@intCast(index));
    try constrain(&builder, allocator, capacity, nodes[role_count + selector_count ..], nodes[0..role_count], nodes[role_count..][0..selector_count]);
    var circuit = try builder.finish();
    builder_live = false;
    defer circuit.deinit();
    std.debug.print("ETHEREUM_ROLE_BINDING capacity={d} inputs={d} nodes={d} constraints={d} node_estimate={d}\n", .{
        capacity, input_count, circuit.nodes().len, circuit.outputs().len, (try budget(capacity)).estimated_extra_nodes,
    });

    const shape = try claim.defaultShape();
    const claim_words = try allocator.alloc(M31, try shape.wordCount());
    defer allocator.free(claim_words);
    @memset(claim_words, M31.zero());
    setClaimU32(claim_words, claim.canonical_layout.input_word_count_start, 1);
    setClaimU32(claim_words, claim.canonical_layout.outputWordCountStart(shape), 1);
    setClaimU32(claim_words, claim.canonical_layout.input_start_start, 0xfffc);
    const input_slot = claim.canonical_layout.inputSlotPresent(0);
    claim_words[input_slot] = M31.one();
    setClaimU32(claim_words, input_slot + 1, 0xabcd1234);
    const output_slot = claim.canonical_layout.outputSlotPresent(shape, 0);
    claim_words[output_slot] = M31.one();
    setClaimU32(claim_words, output_slot + 1, 0x18000);
    setClaimU32(claim_words, output_slot + 3, 0x98767654);
    setClaimU32(claim_words, output_slot + 5, 0x10023);
    const tuples = [_]role.TupleV4{
        try role.TupleV4.init(.input_memory, &.{ 1, 0xfffc, 0, 0x34, 0x12, 0xcd, 0xab }),
        try role.TupleV4.init(.output_memory, &.{ 1, 0x18000, 0x10023, 0x54, 0x76, 0x76, 0x98 }),
    };
    const words = try role.testingCanonicalWordsAlloc(allocator, &tuples, 2);
    defer allocator.free(words);
    const inputs = try allocator.alloc(QM31, input_count);
    defer allocator.free(inputs);
    try testInputs(capacity, claim_words, words, inputs);
    var evaluated = try circuit.evaluate(allocator, inputs);
    defer evaluated.deinit();
    try std.testing.expect(try circuit.outputsAreZero(evaluated.values));
    const original_words = try allocator.dupe(u32, words);
    defer allocator.free(original_words);

    // The raw input address plus M31's modulus gives the same field element.
    // Both 16-bit limbs and their honest bit witnesses must nevertheless fail.
    const alias: u32 = 0xfffc + core.fields.m31.Modulus;
    words[role.HEADER_WORD_COUNT + 6] = alias & 65535;
    words[role.HEADER_WORD_COUNT + 7] = alias >> 16;
    try testInputs(capacity, claim_words, words, inputs);
    var changed = try circuit.evaluate(allocator, inputs);
    defer changed.deinit();
    try std.testing.expect(!try circuit.outputsAreZero(changed.values));

    for ([_]usize{ 6, 7, 8, 9, 10, 12, 14, 16 }) |field_index| {
        @memcpy(words, original_words);
        words[role.HEADER_WORD_COUNT + role.TUPLE_WORD_COUNT + field_index] ^= 1;
        try testInputs(capacity, claim_words, words, inputs);
        var mutation = try circuit.evaluate(allocator, inputs);
        defer mutation.deinit();
        try std.testing.expect(!try circuit.outputsAreZero(mutation.values));
    }
    @memcpy(words, original_words);
    // Changing the claimed input count cannot shift output routing while the
    // source slot presence remains the same.
    setClaimU32(claim_words, claim.canonical_layout.input_word_count_start, 0);
    try testInputs(capacity, claim_words, words, inputs);
    var shifted = try circuit.evaluate(allocator, inputs);
    defer shifted.deinit();
    try std.testing.expect(!try circuit.outputsAreZero(shifted.values));
    try std.testing.expectError(error.EthereumRoleBindingCapacityExceeded, budget(64));
}

test "Ethereum role binding source coordinates remain fixed across input and output counts" {
    const capacity: u32 = 2;
    const shape = try claim.defaultShape();
    try std.testing.expectEqualDeep(Source{ .claim_word = claim.canonical_layout.input_word_count_start }, try sourceAt(capacity, 0));
    try std.testing.expectEqualDeep(Source{ .claim_word = @intCast(claim.canonical_layout.outputWordCountStart(shape)) }, try sourceAt(capacity, 2));
    try std.testing.expectEqualDeep(Source{ .claim_word = @intCast(claim.canonical_layout.inputSlotPresent(1)) }, try sourceAt(capacity, HEADER_INPUT_COUNT + INPUT_SLOT_INPUT_COUNT));
    try std.testing.expectEqualDeep(Source{ .claim_byte = .{ .word_index = @intCast(claim.canonical_layout.outputSlotPresent(shape, 1) + 4), .byte_index = 1 } }, try sourceAt(capacity, HEADER_INPUT_COUNT + capacity * INPUT_SLOT_INPUT_COUNT + 2 * OUTPUT_SLOT_INPUT_COUNT - 1));
    try std.testing.expectEqualDeep(Source{ .input_carry = 1 }, try sourceAt(capacity, (try budget(capacity)).input_count - 1));
}

test "Ethereum nonfinal program profile rejects final halt missing duplicate and misplaced completion" {
    const allocator = std.testing.allocator;
    var builder = Builder.initDefault(allocator);
    var live = true;
    defer if (live) builder.deinit();
    var nodes: [21]Value = undefined;
    for (&nodes, 0..) |*node, index| node.* = try builder.input(@intCast(index));
    try requireNonfinal(&builder, nodes[0], nodes[1], nodes[2], nodes[3]);
    try constrainNonfinalRoleOrder(&builder, 2, nodes[4..8], nodes[8..18]);
    try constrainNonfinalCompletionPolicy(&builder, nodes[18..21].*);
    var circuit = try builder.finish();
    live = false;
    defer circuit.deinit();
    var inputs = [_]QM31{QM31.zero()} ** nodes.len;
    inputs[0] = field(3);
    inputs[2] = QM31.one();
    inputs[3] = try field(2).inv();
    inputs[8 + 4] = QM31.one();
    inputs[13] = QM31.one();
    inputs[18] = field(3);
    const valid = inputs;
    var evaluation = try circuit.evaluate(allocator, &inputs);
    defer evaluation.deinit();
    try std.testing.expect(try circuit.outputsAreZero(evaluation.values));
    for (0..8) |mode| {
        inputs = valid;
        switch (mode) {
            0 => inputs[1] = field(2), // Final leaf: inverse cannot help.
            1 => {
                inputs[11] = QM31.one();
                inputs[12] = QM31.zero();
            },
            2 => inputs[12] = QM31.zero(),
            3 => inputs[17] = QM31.one(),
            4 => {
                inputs[12] = QM31.zero();
                inputs[17] = QM31.one();
            },
            5 => inputs[18] = field(2),
            6 => inputs[19] = QM31.one(),
            7 => inputs[20] = QM31.one(),
            else => unreachable,
        }
        var changed = try circuit.evaluate(allocator, &inputs);
        defer changed.deinit();
        try std.testing.expect(!try circuit.outputsAreZero(changed.values));
    }
    var statement = [_]u32{0} ** frontend.recursion.span_statement.SPAN_STATEMENT_CANONICAL_WORDS;
    const layout = frontend.recursion.span_statement.canonical_layout;
    statement[layout.job_segment_count_start] = 3;
    statement[layout.executed_segment_count_start] = 1;
    statement[layout.first_segment_start] = 2;
    try std.testing.expectError(error.EthereumNonfinalWrapperRequired, nonfinalInverse(&statement));
}

fn setClaimU32(words: []M31, index: usize, value: u32) void {
    words[index] = M31.fromCanonical(value & 65535);
    words[index + 1] = M31.fromCanonical(value >> 16);
}

fn testInputs(capacity: u32, claim_words: []const M31, words: []const u32, inputs: []QM31) !void {
    const source_start = words.len + @as(usize, capacity) * 5;
    if (inputs.len != source_start + (try budget(capacity)).input_count) return error.InvalidEthereumRoleBinding;
    for (inputs[0..words.len], words) |*out, value| out.* = field(value);
    @memset(inputs[words.len..source_start], QM31.zero());
    for (0..capacity) |slot| {
        const kind = words[role.HEADER_WORD_COUNT + slot * role.TUPLE_WORD_COUNT];
        if (kind >= 5) return error.InvalidEthereumRoleBinding;
        inputs[words.len + slot * 5 + kind] = QM31.one();
    }
    for (inputs[source_start..], 0..) |*out, index| out.* = try read(try sourceAt(capacity, index), claim_words, words);
}

/// High-to-low comparison of already boolean-constrained little-endian bits.
/// Shared by native-local boundary clocks and the terminal halt clock.
pub fn lessThanBits(builder: *Builder, left: []const Value, right: []const Value) !Value {
    if (left.len != right.len) return error.InvalidEthereumRoleBinding;
    var same_prefix = Value.one();
    var less = Value.zero();
    var index = left.len;
    while (index != 0) {
        index -= 1;
        less = try builder.add(less, try builder.mul(same_prefix, try builder.mul(try builder.sub(Value.one(), left[index]), right[index])));
        const same = try builder.add(try builder.sub(try builder.sub(Value.one(), left[index]), right[index]), try builder.mul(base(2), try builder.mul(left[index], right[index])));
        same_prefix = try builder.mul(same_prefix, same);
    }
    return less;
}
