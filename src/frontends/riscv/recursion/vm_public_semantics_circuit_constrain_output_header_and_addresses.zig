//! Internal vm public semantics circuit authority shard; use vm_public_semantics_circuit.zig publicly.

const dependency_0 = @import("vm_public_semantics_circuit_contract.zig");

const ClaimAuthored = dependency_0.ClaimAuthored;
const ClaimBoundWords = dependency_0.ClaimBoundWords;
const ClaimGraphBuilder = dependency_0.ClaimGraphBuilder;
const ClaimInputSource = dependency_0.ClaimInputSource;
const ClaimPrivateSource = dependency_0.ClaimPrivateSource;
const ClaimWitness = dependency_0.ClaimWitness;
const Digest = dependency_0.Digest;
const Error = dependency_0.Error;
const M31 = dependency_0.M31;
const QM31 = dependency_0.QM31;
const SEMANTIC_DIAGNOSTIC_ENV = dependency_0.SEMANTIC_DIAGNOSTIC_ENV;
const U16_BASE = dependency_0.U16_BASE;
const U16_MAX = dependency_0.U16_MAX;
const arithmetic = dependency_0.arithmetic;
const baseValue = dependency_0.baseValue;
const claimU32Bits = dependency_0.claimU32Bits;
const claim_input = dependency_0.claim_input;
const composeClaimU32 = dependency_0.composeClaimU32;
const constrainAddConstantU32 = dependency_0.constrainAddConstantU32;
const constrainBoolean = dependency_0.constrainBoolean;
const constrainEqual = dependency_0.constrainEqual;
const constrainInputByteLength = dependency_0.constrainInputByteLength;
const constrainInputSlots = dependency_0.constrainInputSlots;
const constrainOutputSlots = dependency_0.constrainOutputSlots;
const constrainRootsAndMachineState = dependency_0.constrainRootsAndMachineState;
const copyRange = dependency_0.copyRange;
const m31 = dependency_0.m31;
const outputSlotAddressStart = dependency_0.outputSlotAddressStart;
const outputSlotValueStart = dependency_0.outputSlotValueStart;
const row15 = dependency_0.row15;
const span_statement = dependency_0.span_statement;
const std = dependency_0.std;
const vm_claim = dependency_0.vm_claim;

pub fn buildClaimGraph(
    allocator: std.mem.Allocator,
    shape: vm_claim.Shape,
) Error!ClaimAuthored {
    const claim_count = try shape.wordCount();
    try validateOutputOffsets(shape);
    var builder = ClaimGraphBuilder.init(allocator);
    errdefer builder.deinit();
    const segment = try builder.input(.segment_selector);
    try constrainBoolean(&builder, arithmetic.Value.one(), segment);

    var claim = try ClaimBoundWords.init(
        allocator,
        &builder,
        claim_count,
        .claim,
    );
    defer claim.deinit();
    var statement = try ClaimBoundWords.init(
        allocator,
        &builder,
        span_statement.SPAN_STATEMENT_CANONICAL_WORDS,
        .statement,
    );
    defer statement.deinit();
    var input_digest = try ClaimBoundWords.init(
        allocator,
        &builder,
        8,
        .input_digest,
    );
    defer input_digest.deinit();
    var output_digest = try ClaimBoundWords.init(
        allocator,
        &builder,
        8,
        .output_digest,
    );
    defer output_digest.deinit();

    try constrainRootsAndMachineState(&builder, segment, &claim, &statement);
    try constrainVectorLayout(
        &builder,
        segment,
        shape,
        &claim,
        &statement,
        &input_digest,
        &output_digest,
    );
    try constrainRelationFieldBounds(&builder, segment, shape, &claim);
    return builder.finish();
}

pub fn constrainVectorLayout(
    builder: *ClaimGraphBuilder,
    gate: arithmetic.Value,
    shape: vm_claim.Shape,
    claim: *const ClaimBoundWords,
    statement: *const ClaimBoundWords,
    input_digest: *const ClaimBoundWords,
    output_digest: *const ClaimBoundWords,
) Error!void {
    const input_flags = try constrainInputSlots(builder, gate, shape, claim);
    defer builder.allocator.free(input_flags);
    const output_flags = try constrainOutputSlots(builder, gate, shape, claim);
    defer builder.allocator.free(output_flags);

    try copyRange(
        builder,
        gate,
        claim,
        vm_claim.canonical_layout.header_output_word_count_start,
        claim,
        vm_claim.canonical_layout.outputWordCountStart(shape),
        2,
    );

    const input_present = try edgePresent(
        builder,
        gate,
        statement,
        span_statement.canonical_layout.input_edge_tag,
    );
    const input_absent = try builder.graph.sub(arithmetic.Value.one(), input_present);
    for (input_flags) |flag| try builder.constrain(
        gate,
        try builder.graph.mul(flag, input_absent),
    );
    for (0..2) |offset| try builder.constrain(
        gate,
        try builder.graph.mul(
            input_absent,
            claim.value(vm_claim.canonical_layout.input_length_start + offset),
        ),
    );
    try constrainInputByteLength(builder, gate, claim, input_flags);
    for (0..8) |limb| try builder.constrain(
        gate,
        try builder.graph.mul(
            input_present,
            try builder.graph.sub(
                input_digest.value(limb),
                statement.value(span_statement.canonical_layout.input_edge_digest_start + limb),
            ),
        ),
    );

    const output_present = try edgePresent(
        builder,
        gate,
        statement,
        span_statement.canonical_layout.output_edge_tag,
    );
    const first_output = if (output_flags.len == 0)
        arithmetic.Value.zero()
    else
        output_flags[0];
    try constrainEqual(builder, gate, first_output, output_present);
    const output_absent = try builder.graph.sub(arithmetic.Value.one(), output_present);
    for (output_flags) |flag| try builder.constrain(
        gate,
        try builder.graph.mul(flag, output_absent),
    );
    for (0..2) |offset| try builder.constrain(
        gate,
        try builder.graph.mul(
            output_absent,
            claim.value(vm_claim.canonical_layout.output_length_start + offset),
        ),
    );
    try constrainOutputHeaderAndAddresses(builder, gate, shape, claim, output_flags);
    for (0..8) |limb| try builder.constrain(
        gate,
        try builder.graph.mul(
            output_present,
            try builder.graph.sub(
                output_digest.value(limb),
                statement.value(span_statement.canonical_layout.output_edge_digest_start + limb),
            ),
        ),
    );
}

pub fn constrainOutputHeaderAndAddresses(
    builder: *ClaimGraphBuilder,
    gate: arithmetic.Value,
    shape: vm_claim.Shape,
    claim: *const ClaimBoundWords,
    flags: []const arithmetic.Value,
) Error!void {
    if (flags.len == 0) return;
    const header_bits = try claimU32Bits(
        builder,
        gate,
        claim,
        vm_claim.canonical_layout.output_length_address_start,
    );
    defer builder.allocator.free(header_bits);
    const first_address_start = outputSlotAddressStart(shape, 0);
    const first_bits = try claimU32Bits(builder, gate, claim, first_address_start);
    defer builder.allocator.free(first_bits);
    const first_gate = try builder.graph.mul(gate, flags[0]);
    try builder.constrain(first_gate, first_bits[0]);
    try builder.constrain(first_gate, first_bits[1]);
    for (2..32) |bit| try constrainEqual(
        builder,
        first_gate,
        first_bits[bit],
        header_bits[bit],
    );
    try copyRange(
        builder,
        gate,
        claim,
        vm_claim.canonical_layout.output_length_start,
        claim,
        outputSlotValueStart(shape, 0),
        2,
    );

    const data_bits = try claimU32Bits(
        builder,
        gate,
        claim,
        vm_claim.canonical_layout.output_data_address_start,
    );
    defer builder.allocator.free(data_bits);
    const offset = try builder.graph.add(
        data_bits[0],
        try builder.graph.mul(baseValue(2), data_bits[1]),
    );
    const output_count = try composeClaimU32(
        builder,
        claim,
        vm_claim.canonical_layout.outputWordCountStart(shape),
    );
    const data_count = try builder.graph.sub(output_count, arithmetic.Value.one());
    const output_length = try composeClaimU32(
        builder,
        claim,
        vm_claim.canonical_layout.output_length_start,
    );
    const has_data = if (flags.len > 1) flags[1] else arithmetic.Value.zero();
    const padding_low = try builder.private(.{ .output_padding_bit = 0 });
    const padding_high = try builder.private(.{ .output_padding_bit = 1 });
    try constrainBoolean(builder, gate, padding_low);
    try constrainBoolean(builder, gate, padding_high);
    const no_data = try builder.graph.sub(arithmetic.Value.one(), has_data);
    try builder.constrain(gate, try builder.graph.mul(no_data, padding_low));
    try builder.constrain(gate, try builder.graph.mul(no_data, padding_high));
    try builder.constrain(gate, try builder.graph.mul(no_data, output_length));
    const padding = try builder.graph.add(
        padding_low,
        try builder.graph.mul(baseValue(2), padding_high),
    );
    const length_equation = try builder.graph.add(
        try builder.graph.sub(
            try builder.graph.add(output_length, offset),
            try builder.graph.mul(baseValue(4), data_count),
        ),
        padding,
    );
    try builder.constrain(gate, try builder.graph.mul(has_data, length_equation));

    const aligned_low = try builder.graph.sub(
        try builder.graph.sub(
            claim.value(vm_claim.canonical_layout.output_data_address_start),
            data_bits[0],
        ),
        try builder.graph.mul(baseValue(2), data_bits[1]),
    );
    const aligned_high = claim.value(vm_claim.canonical_layout.output_data_address_start + 1);
    for (flags[1..], 1..) |flag, index| {
        try constrainAddConstantU32(
            builder,
            try builder.graph.mul(gate, flag),
            .{ aligned_low, aligned_high },
            @intCast((index - 1) * 4),
            .{
                claim.value(outputSlotAddressStart(shape, index)),
                claim.value(outputSlotAddressStart(shape, index) + 1),
            },
            @intCast(index),
        );
    }
}

pub fn constrainRelationFieldBounds(
    builder: *ClaimGraphBuilder,
    gate: arithmetic.Value,
    shape: vm_claim.Shape,
    claim: *const ClaimBoundWords,
) Error!void {
    for ([_]usize{
        vm_claim.canonical_layout.initial_pc_start,
        vm_claim.canonical_layout.final_pc_start,
        vm_claim.canonical_layout.clock_start,
        vm_claim.canonical_layout.input_start_start,
        vm_claim.canonical_layout.input_word_count_start,
        vm_claim.canonical_layout.output_length_address_start,
        vm_claim.canonical_layout.output_data_address_start,
        vm_claim.canonical_layout.output_length_start,
        vm_claim.canonical_layout.header_output_word_count_start,
        vm_claim.canonical_layout.outputWordCountStart(shape),
        vm_claim.canonical_layout.input_length_start,
    }) |start| {
        const bits = try constrainCanonicalM31U32(builder, gate, claim, start);
        builder.allocator.free(bits);
    }
    const clock_bits = try claimU32Bits(
        builder,
        gate,
        claim,
        vm_claim.canonical_layout.clock_start,
    );
    defer builder.allocator.free(clock_bits);
    try rejectConstantBits(builder, gate, clock_bits, m31.Modulus - 1);

    for (0..32) |register| {
        const start = vm_claim.canonical_layout.register_last_clocks_start + register * 2;
        const last_clock_bits = try constrainCanonicalM31U32(
            builder,
            gate,
            claim,
            start,
        );
        defer builder.allocator.free(last_clock_bits);
        try constrainAccessClockWithinExecution(
            builder,
            gate,
            last_clock_bits,
            clock_bits,
            true,
        );
    }
    for (0..shape.max_output_words) |raw_index| {
        const index: usize = @intCast(raw_index);
        const flag = claim.value(vm_claim.canonical_layout.outputSlotPresent(shape, index));
        const selected = try builder.graph.mul(gate, flag);
        const address_bits = try constrainCanonicalM31U32(
            builder,
            selected,
            claim,
            outputSlotAddressStart(shape, index),
        );
        defer builder.allocator.free(address_bits);
        const output_clock_bits = try constrainCanonicalM31U32(
            builder,
            selected,
            claim,
            outputSlotClockStart(shape, index),
        );
        defer builder.allocator.free(output_clock_bits);
        try constrainAccessClockWithinExecution(
            builder,
            selected,
            output_clock_bits,
            clock_bits,
            false,
        );
    }
}

/// Algebraic form of `access_clock.isWithinExecution`.  Access clocks refine
/// each instruction into the nonzero residues 1, 2, and 3 of a four-wide
/// bucket.  Their bucket index must be strictly below the instruction count;
/// register boundaries additionally admit the all-zero never-accessed value.
pub fn constrainAccessClockWithinExecution(
    builder: *ClaimGraphBuilder,
    gate: arithmetic.Value,
    access_bits: []const arithmetic.Value,
    instruction_count_bits: []const arithmetic.Value,
    allow_zero: bool,
) Error!void {
    if (access_bits.len != 32 or instruction_count_bits.len != 32)
        return error.InputLayoutMismatch;

    const low_two_are_zero = try builder.graph.mul(
        try builder.graph.sub(arithmetic.Value.one(), access_bits[0]),
        try builder.graph.sub(arithmetic.Value.one(), access_bits[1]),
    );
    if (allow_zero) {
        // Residue zero is legal only for the literal zero boundary.
        for (access_bits[2..]) |higher_bit| try builder.constrain(
            gate,
            try builder.graph.mul(low_two_are_zero, higher_bit),
        );
    } else {
        try builder.constrain(gate, low_two_are_zero);
    }

    var bucket_bits = [_]arithmetic.Value{arithmetic.Value.zero()} ** 32;
    @memcpy(bucket_bits[0..30], access_bits[2..32]);
    const bucket_is_before_end = try lessThanBits(
        builder,
        &bucket_bits,
        instruction_count_bits,
    );
    try builder.constrain(
        gate,
        try builder.graph.sub(bucket_is_before_end, arithmetic.Value.one()),
    );
}

pub fn constrainCanonicalM31U32(
    builder: *ClaimGraphBuilder,
    gate: arithmetic.Value,
    words: *const ClaimBoundWords,
    start: usize,
) Error![]arithmetic.Value {
    const bits = try claimU32Bits(builder, gate, words, start);
    errdefer builder.allocator.free(bits);
    try builder.constrain(gate, bits[31]);
    try rejectConstantBits(builder, gate, bits, m31.Modulus);
    return bits;
}

pub fn rejectConstantBits(
    builder: *ClaimGraphBuilder,
    gate: arithmetic.Value,
    bits: []const arithmetic.Value,
    constant: u32,
) Error!void {
    var equal = arithmetic.Value.one();
    for (bits, 0..) |actual, bit| {
        const selected = if (((constant >> @intCast(bit)) & 1) == 1)
            actual
        else
            try builder.graph.sub(arithmetic.Value.one(), actual);
        equal = try builder.graph.mul(equal, selected);
    }
    try builder.constrain(gate, equal);
}

pub fn lessThanBits(
    builder: *ClaimGraphBuilder,
    lhs: []const arithmetic.Value,
    rhs: []const arithmetic.Value,
) Error!arithmetic.Value {
    var equal_above = arithmetic.Value.one();
    var less = arithmetic.Value.zero();
    var index = lhs.len;
    while (index != 0) {
        index -= 1;
        const left_absent = try builder.graph.sub(arithmetic.Value.one(), lhs[index]);
        less = try builder.graph.add(
            less,
            try builder.graph.mul(
                equal_above,
                try builder.graph.mul(left_absent, rhs[index]),
            ),
        );
        const same = try builder.graph.add(
            try builder.graph.sub(
                try builder.graph.sub(arithmetic.Value.one(), lhs[index]),
                rhs[index],
            ),
            try builder.graph.mul(
                baseValue(2),
                try builder.graph.mul(lhs[index], rhs[index]),
            ),
        );
        equal_above = try builder.graph.mul(equal_above, same);
    }
    return less;
}

pub fn edgePresent(
    builder: *ClaimGraphBuilder,
    gate: arithmetic.Value,
    statement: *const ClaimBoundWords,
    tag_index: usize,
) Error!arithmetic.Value {
    const present = try builder.private(.{ .statement_edge_present = @intCast(tag_index) });
    try constrainBoolean(builder, gate, present);
    const absent_tag = baseValue(@intFromEnum(span_statement.Tag.absent_edge));
    const present_tag = baseValue(@intFromEnum(span_statement.Tag.present_edge));
    try builder.constrain(
        gate,
        try builder.graph.sub(
            try builder.graph.sub(statement.value(tag_index), absent_tag),
            try builder.graph.mul(
                present,
                try builder.graph.sub(present_tag, absent_tag),
            ),
        ),
    );
    return present;
}

pub fn claimInputValue(
    shape: vm_claim.Shape,
    source: ClaimInputSource,
    witness: ClaimWitness,
) Error!M31 {
    return switch (source) {
        .segment_selector => M31.fromCanonical(@intFromBool(witness.segment_selected)),
        .claim_word => |index| witness.claim_words[index],
        .statement_word => |index| witness.statement_words[index],
        .io_digest_word => |coordinate| M31.fromCanonical(
            if (coordinate.io_kind == 0)
                witness.input_digest[coordinate.limb]
            else
                witness.output_digest[coordinate.limb],
        ),
        .private => |private_source| M31.fromCanonical(
            try claimPrivateValue(shape, private_source, witness),
        ),
    };
}

pub fn claimPrivateValue(
    shape: vm_claim.Shape,
    source: ClaimPrivateSource,
    witness: ClaimWitness,
) Error!u32 {
    return switch (source) {
        .claim_u32_bit => |coordinate| blk: {
            const raw = try rawClaimU32(witness.claim_words, coordinate.start);
            break :blk (raw >> coordinate.bit) & 1;
        },
        .input_padding_bit => |bit| blk: {
            const count = try rawClaimU32(
                witness.claim_words,
                vm_claim.canonical_layout.input_word_count_start,
            );
            const length = try rawClaimU32(
                witness.claim_words,
                vm_claim.canonical_layout.input_length_start,
            );
            const padding = if (count == 0) 0 else count *% 4 -% length;
            break :blk (padding >> bit) & 1;
        },
        .output_padding_bit => |bit| blk: {
            const count = try rawClaimU32(
                witness.claim_words,
                vm_claim.canonical_layout.outputWordCountStart(shape),
            );
            const length = try rawClaimU32(
                witness.claim_words,
                vm_claim.canonical_layout.output_length_start,
            );
            const address = try rawClaimU32(
                witness.claim_words,
                vm_claim.canonical_layout.output_data_address_start,
            );
            const padding = if (count <= 1)
                0
            else
                (count - 1) *% 4 -% (length +% (address & 3));
            break :blk (padding >> bit) & 1;
        },
        .statement_edge_present => |index| @intFromBool(
            witness.statement_words[index].toU32() ==
                @intFromEnum(span_statement.Tag.present_edge),
        ),
        .output_address_carry => |index| blk: {
            if (index == 0) return error.InvalidPrivateInput;
            const address = try rawClaimU32(
                witness.claim_words,
                vm_claim.canonical_layout.output_data_address_start,
            );
            const aligned = address & ~@as(u32, 3);
            const addend = std.math.mul(u32, index - 1, 4) catch
                return error.OutputAddressOffsetOverflow;
            break :blk @intFromBool(
                (aligned & U16_MAX) + (addend & U16_MAX) >= U16_BASE,
            );
        },
    };
}

pub fn validateCircuitId(circuit_id: u32) Error!void {
    if (circuit_id >= m31.Modulus) return error.CircuitIdNotCanonical;
}

/// Opt-in, allocation-free graph diagnostic. Output ordinals are deterministic
/// for an authenticated circuit and identify the authored constraint without
/// weakening the production error boundary.
pub fn reportFirstNonzeroOutput(
    circuit: *const arithmetic.Circuit,
    values: []const QM31,
    comptime graph_name: []const u8,
) void {
    if (!std.process.hasEnvVarConstant(SEMANTIC_DIAGNOSTIC_ENV)) return;
    for (circuit.outputs(), 0..) |node_id, output_ordinal| {
        const value = values[node_id];
        if (value.isZero()) continue;
        const limbs = value.toM31Array();
        std.debug.print(
            "  {s} semantic output[{d}] node={d} value={d}/{d}/{d}/{d}\n",
            .{
                graph_name,
                output_ordinal,
                node_id,
                limbs[0].toU32(),
                limbs[1].toU32(),
                limbs[2].toU32(),
                limbs[3].toU32(),
            },
        );
        return;
    }
}

pub fn validateClaimWord(kind: claim_input.WordKind, value: M31) Error!void {
    const raw = value.toU32();
    switch (kind) {
        .constant => |expected| if (raw != expected) return error.InvalidClaimConstant,
        .boolean => if (raw > 1) return error.InvalidClaimBoolean,
        .u16 => if (raw > U16_MAX) return error.InvalidClaimU16,
        .field => {},
    }
}

pub fn validateDigest(value: vm_claim.Digest) Error!void {
    for (value) |word| if (word >= m31.Modulus)
        return error.DigestWordNotCanonical;
}

pub fn rawClaimU32(words: []const M31, start: usize) Error!u32 {
    if (start + 1 >= words.len) return error.InvalidPrivateInput;
    const low = words[start].toU32();
    const high = words[start + 1].toU32();
    if (low > U16_MAX or high > U16_MAX) return error.InvalidClaimU16;
    return low | (high << 16);
}

pub fn validateOutputOffsets(shape: vm_claim.Shape) Error!void {
    if (shape.max_input_words != 0) {
        _ = std.math.mul(u32, shape.max_input_words - 1, 4) catch
            return error.InputAddressOffsetOverflow;
    }
    if (shape.max_output_words != 0) {
        _ = std.math.mul(u32, shape.max_output_words - 1, 4) catch
            return error.OutputAddressOffsetOverflow;
    }
}

pub fn outputSlotClockStart(shape: vm_claim.Shape, index: usize) usize {
    return vm_claim.canonical_layout.outputSlotPresent(shape, index) + 5;
}

pub fn claimRowSource(source: ClaimInputSource) row15.Source {
    return switch (source) {
        .segment_selector => .selector,
        .claim_word => .claim,
        .statement_word => .statement,
        .io_digest_word => .io_digest,
        .private => .private,
    };
}
