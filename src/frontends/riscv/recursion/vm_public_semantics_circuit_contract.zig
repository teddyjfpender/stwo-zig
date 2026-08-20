//! Internal vm public semantics circuit authority shard; use vm_public_semantics_circuit.zig publicly.

pub const std = @import("std");
pub const stwo_core = @import("stwo_core");

pub const M31 = stwo_core.fields.m31.M31;
pub const m31 = stwo_core.fields.m31;
pub const QM31 = stwo_core.fields.qm31.QM31;

pub const SEMANTIC_DIAGNOSTIC_ENV = "STWO_RECURSION_PUBLIC_SEMANTIC_DIAGNOSTIC";

pub const arithmetic = @import("arithmetic_circuit.zig");
pub const span_statement = @import("span_statement.zig");
pub const vm_claim = @import("vm_public_claim.zig");
pub const public_data = @import("../air/public_data.zig");
pub const public_logup = @import("../air/public_logup.zig");
pub const program_decode = @import("../air/program/decode.zig");
pub const relation_challenges = @import("../air/relation_challenges.zig");
pub const claim_input = @import("air/vm_public_claim_input_witness.zig");
pub const row15 = @import("air/vm_public_claim_semantics_input_witness.zig");
pub const row16 = @import("air/vm_public_logup_input_witness.zig");
pub const row17 = @import("air/control_slice_witness.zig");
pub const verifier_schedule = @import("air/verifier_schedule.zig");

pub const Digest = [32]u8;
pub const CLAIM_GRAPH_FORMAT_VERSION: u16 = 1;
pub const LOGUP_GRAPH_FORMAT_VERSION: u16 = 1;
pub const CLAIM_GRAPH_DOMAIN =
    "stwo-zig/typed-air/recursion-vm-claim-semantics-graph/v1\x00";
pub const LOGUP_GRAPH_DOMAIN =
    "stwo-zig/typed-air/recursion-vm-public-logup-graph/v1\x00";
pub const REQUIRED_LOGUP_CHALLENGES = [_]u32{ 0, 1, 2, 3 };
pub const FIXED_PUBLIC_TERM_COUNT: u32 = 70;
pub const U16_BASE: u32 = 1 << 16;
pub const U16_MAX: u32 = std.math.maxInt(u16);

pub const Error = arithmetic.Error || claim_input.Error || row15.Error ||
    row16.Error || row17.Error || std.mem.Allocator.Error || error{
    ArithmeticOverflow,
    AuthoritySealMismatch,
    ClaimWordCountMismatch,
    CircuitIdNotCanonical,
    DigestWordNotCanonical,
    InputLayoutMismatch,
    InputValueIsNotBaseField,
    InvalidClaimBoolean,
    InvalidClaimConstant,
    InvalidClaimU16,
    InvalidPrivateInput,
    InputAddressOffsetOverflow,
    LogupClaimChallengeSchemaMismatch,
    OutputAddressOffsetOverflow,
    PublicTermCountMismatch,
    SemanticConstraintViolation,
    StatementWordCountMismatch,
};

pub const ClaimWitness = struct {
    segment_selected: bool,
    claim_words: []const M31,
    statement_words: *const span_statement.StatementWords,
    input_digest: vm_claim.Digest,
    output_digest: vm_claim.Digest,
};

pub const ClaimPrivateSource = union(enum) {
    claim_u32_bit: struct { start: u32, bit: u5 },
    input_padding_bit: u1,
    output_padding_bit: u1,
    statement_edge_present: u32,
    output_address_carry: u32,
};

pub const ClaimInputSource = union(enum) {
    segment_selector,
    claim_word: u32,
    statement_word: u32,
    io_digest_word: struct { io_kind: u1, limb: u3 },
    private: ClaimPrivateSource,
};

pub const ClaimInputBinding = struct {
    node_id: u32,
    use_count: u32,
    source: ClaimInputSource,
};

pub const ClaimAuthored = struct {
    circuit: arithmetic.Circuit,
    sources: std.ArrayList(ClaimInputSource),

    pub fn deinit(self: *ClaimAuthored) void {
        const allocator = self.circuit.allocator;
        self.sources.deinit(allocator);
        self.circuit.deinit();
        self.* = undefined;
    }
};

pub const ClaimGraphBuilder = struct {
    allocator: std.mem.Allocator,
    graph: arithmetic.Builder,
    sources: std.ArrayList(ClaimInputSource) = .empty,

    pub fn init(allocator: std.mem.Allocator) ClaimGraphBuilder {
        return .{ .allocator = allocator, .graph = arithmetic.Builder.initDefault(allocator) };
    }

    pub fn deinit(self: *ClaimGraphBuilder) void {
        self.sources.deinit(self.allocator);
        self.graph.deinit();
        self.* = undefined;
    }

    pub fn input(self: *ClaimGraphBuilder, source: ClaimInputSource) Error!arithmetic.Value {
        const input_id: u32 = @intCast(self.sources.items.len);
        try self.sources.append(self.allocator, source);
        errdefer _ = self.sources.pop();
        return self.graph.input(input_id);
    }

    pub fn private(
        self: *ClaimGraphBuilder,
        source: ClaimPrivateSource,
    ) Error!arithmetic.Value {
        return self.input(.{ .private = source });
    }

    pub fn constrain(
        self: *ClaimGraphBuilder,
        gate: arithmetic.Value,
        constraint: arithmetic.Value,
    ) Error!void {
        _ = try self.graph.markOutput(try self.graph.mul(gate, constraint));
    }

    pub fn finish(self: *ClaimGraphBuilder) Error!ClaimAuthored {
        const circuit = try self.graph.finish();
        self.graph.deinit();
        self.graph = arithmetic.Builder.initDefault(self.allocator);
        const result = ClaimAuthored{ .circuit = circuit, .sources = self.sources };
        self.sources = .empty;
        return result;
    }
};

pub const ClaimBoundWords = struct {
    allocator: std.mem.Allocator,
    values: []arithmetic.Value,

    pub fn init(
        allocator: std.mem.Allocator,
        builder: *ClaimGraphBuilder,
        count: usize,
        kind: enum { claim, statement, input_digest, output_digest },
    ) Error!ClaimBoundWords {
        const values = try allocator.alloc(arithmetic.Value, count);
        errdefer allocator.free(values);
        for (values, 0..) |*destination, index| {
            const source: ClaimInputSource = switch (kind) {
                .claim => .{ .claim_word = @intCast(index) },
                .statement => .{ .statement_word = @intCast(index) },
                .input_digest => .{ .io_digest_word = .{
                    .io_kind = 0,
                    .limb = @intCast(index),
                } },
                .output_digest => .{ .io_digest_word = .{
                    .io_kind = 1,
                    .limb = @intCast(index),
                } },
            };
            destination.* = try builder.input(source);
        }
        return .{ .allocator = allocator, .values = values };
    }

    pub fn deinit(self: *ClaimBoundWords) void {
        self.allocator.free(self.values);
        self.* = undefined;
    }

    pub fn value(self: *const ClaimBoundWords, index: usize) arithmetic.Value {
        return self.values[index];
    }
};

pub fn constrainRootsAndMachineState(
    builder: *ClaimGraphBuilder,
    gate: arithmetic.Value,
    claim: *const ClaimBoundWords,
    statement: *const ClaimBoundWords,
) Error!void {
    for ([_]usize{
        vm_claim.canonical_layout.program_root_present,
        vm_claim.canonical_layout.initial_rw_root_present,
        vm_claim.canonical_layout.final_rw_root_present,
    }) |present| try constrainEqual(builder, gate, claim.value(present), arithmetic.Value.one());

    try copyRange(
        builder,
        gate,
        claim,
        vm_claim.canonical_layout.program_root_start,
        statement,
        span_statement.canonical_layout.program_start,
        8,
    );
    try constrainMachineBoundary(
        builder,
        gate,
        claim,
        vm_claim.canonical_layout.initial_pc_start,
        vm_claim.canonical_layout.initial_registers_start,
        vm_claim.canonical_layout.initial_rw_root_start,
        statement,
        span_statement.canonical_layout.entry_state_start,
    );
    try constrainMachineBoundary(
        builder,
        gate,
        claim,
        vm_claim.canonical_layout.final_pc_start,
        vm_claim.canonical_layout.final_registers_start,
        vm_claim.canonical_layout.final_rw_root_start,
        statement,
        span_statement.canonical_layout.exit_state_start,
    );
    try copyRange(
        builder,
        gate,
        claim,
        vm_claim.canonical_layout.clock_start,
        statement,
        span_statement.canonical_layout.executed_cycle_count_start,
        2,
    );
    try builder.constrain(
        gate,
        statement.value(span_statement.canonical_layout.executed_cycle_count_start + 2),
    );
    try builder.constrain(
        gate,
        statement.value(span_statement.canonical_layout.executed_cycle_count_start + 3),
    );
}

pub fn constrainMachineBoundary(
    builder: *ClaimGraphBuilder,
    gate: arithmetic.Value,
    claim: *const ClaimBoundWords,
    pc_start: usize,
    registers_start: usize,
    root_start: usize,
    statement: *const ClaimBoundWords,
    state_start: usize,
) Error!void {
    try copyRange(
        builder,
        gate,
        claim,
        pc_start,
        statement,
        state_start + span_statement.canonical_layout.machine_state_pc_start_offset,
        2,
    );
    try copyRange(
        builder,
        gate,
        claim,
        registers_start,
        statement,
        state_start + span_statement.canonical_layout.machine_state_registers_start_offset,
        64,
    );
    try copyRange(
        builder,
        gate,
        claim,
        root_start,
        statement,
        state_start + span_statement.canonical_layout.machine_state_rw_digest_start_offset,
        8,
    );
    for (0..8) |offset| try builder.constrain(
        gate,
        statement.value(
            state_start + span_statement.canonical_layout.machine_state_io_digest_start_offset + offset,
        ),
    );
}

pub fn constrainInputSlots(
    builder: *ClaimGraphBuilder,
    gate: arithmetic.Value,
    shape: vm_claim.Shape,
    claim: *const ClaimBoundWords,
) Error![]arithmetic.Value {
    const flags = try builder.allocator.alloc(arithmetic.Value, shape.max_input_words);
    errdefer builder.allocator.free(flags);
    var previous = arithmetic.Value.one();
    var count = arithmetic.Value.zero();
    for (flags, 0..) |*destination, index| {
        const flag = claim.value(vm_claim.canonical_layout.inputSlotPresent(index));
        try constrainBoolean(builder, gate, flag);
        try builder.constrain(
            gate,
            try builder.graph.mul(
                flag,
                try builder.graph.sub(arithmetic.Value.one(), previous),
            ),
        );
        for (0..2) |offset| try builder.constrain(
            gate,
            try builder.graph.mul(
                try builder.graph.sub(arithmetic.Value.one(), flag),
                claim.value(inputSlotValueStart(index) + offset),
            ),
        );
        count = try builder.graph.add(count, flag);
        previous = flag;
        destination.* = flag;
    }
    try constrainEqual(
        builder,
        gate,
        try composeClaimU32(builder, claim, vm_claim.canonical_layout.input_word_count_start),
        count,
    );
    return flags;
}

pub fn constrainOutputSlots(
    builder: *ClaimGraphBuilder,
    gate: arithmetic.Value,
    shape: vm_claim.Shape,
    claim: *const ClaimBoundWords,
) Error![]arithmetic.Value {
    const flags = try builder.allocator.alloc(arithmetic.Value, shape.max_output_words);
    errdefer builder.allocator.free(flags);
    var previous = arithmetic.Value.one();
    var count = arithmetic.Value.zero();
    for (flags, 0..) |*destination, index| {
        const flag = claim.value(vm_claim.canonical_layout.outputSlotPresent(shape, index));
        try constrainBoolean(builder, gate, flag);
        try builder.constrain(
            gate,
            try builder.graph.mul(
                flag,
                try builder.graph.sub(arithmetic.Value.one(), previous),
            ),
        );
        for (0..6) |offset| try builder.constrain(
            gate,
            try builder.graph.mul(
                try builder.graph.sub(arithmetic.Value.one(), flag),
                claim.value(outputSlotAddressStart(shape, index) + offset),
            ),
        );
        count = try builder.graph.add(count, flag);
        previous = flag;
        destination.* = flag;
    }
    try constrainEqual(
        builder,
        gate,
        try composeClaimU32(
            builder,
            claim,
            vm_claim.canonical_layout.outputWordCountStart(shape),
        ),
        count,
    );
    return flags;
}

pub fn constrainInputByteLength(
    builder: *ClaimGraphBuilder,
    gate: arithmetic.Value,
    claim: *const ClaimBoundWords,
    flags: []const arithmetic.Value,
) Error!void {
    const count = try composeClaimU32(
        builder,
        claim,
        vm_claim.canonical_layout.input_word_count_start,
    );
    const length = try composeClaimU32(
        builder,
        claim,
        vm_claim.canonical_layout.input_length_start,
    );
    const has_words = if (flags.len == 0) arithmetic.Value.zero() else flags[0];
    const padding_low = try builder.private(.{ .input_padding_bit = 0 });
    const padding_high = try builder.private(.{ .input_padding_bit = 1 });
    try constrainBoolean(builder, gate, padding_low);
    try constrainBoolean(builder, gate, padding_high);
    const no_words = try builder.graph.sub(arithmetic.Value.one(), has_words);
    try builder.constrain(gate, try builder.graph.mul(no_words, padding_low));
    try builder.constrain(gate, try builder.graph.mul(no_words, padding_high));
    const padding = try builder.graph.add(
        padding_low,
        try builder.graph.mul(baseValue(2), padding_high),
    );
    try builder.constrain(
        gate,
        try builder.graph.add(
            try builder.graph.sub(length, try builder.graph.mul(baseValue(4), count)),
            padding,
        ),
    );
}

pub fn claimU32Bits(
    builder: *ClaimGraphBuilder,
    gate: arithmetic.Value,
    words: *const ClaimBoundWords,
    start: usize,
) Error![]arithmetic.Value {
    const bits = try builder.allocator.alloc(arithmetic.Value, 32);
    errdefer builder.allocator.free(bits);
    for (0..2) |limb| {
        var reconstructed = arithmetic.Value.zero();
        for (0..16) |bit| {
            const global_bit: u5 = @intCast(limb * 16 + bit);
            const value = try builder.private(.{ .claim_u32_bit = .{
                .start = @intCast(start),
                .bit = global_bit,
            } });
            try constrainBoolean(builder, gate, value);
            reconstructed = try builder.graph.add(
                reconstructed,
                try builder.graph.mul(baseValue(@as(u32, 1) << @intCast(bit)), value),
            );
            bits[global_bit] = value;
        }
        try constrainEqual(builder, gate, words.value(start + limb), reconstructed);
    }
    return bits;
}

pub fn constrainAddConstantU32(
    builder: *ClaimGraphBuilder,
    gate: arithmetic.Value,
    input: [2]arithmetic.Value,
    addend: u32,
    output: [2]arithmetic.Value,
    output_index: u32,
) Error!void {
    const carry = try builder.private(.{ .output_address_carry = output_index });
    try constrainBoolean(builder, gate, carry);
    try builder.constrain(
        gate,
        try builder.graph.sub(
            try builder.graph.sub(
                try builder.graph.add(input[0], baseValue(addend & U16_MAX)),
                output[0],
            ),
            try builder.graph.mul(baseValue(U16_BASE), carry),
        ),
    );
    try builder.constrain(
        gate,
        try builder.graph.sub(
            try builder.graph.add(
                try builder.graph.add(input[1], baseValue(addend >> 16)),
                carry,
            ),
            output[1],
        ),
    );
}

pub fn composeClaimU32(
    builder: *ClaimGraphBuilder,
    words: *const ClaimBoundWords,
    start: usize,
) Error!arithmetic.Value {
    return builder.graph.add(
        words.value(start),
        try builder.graph.mul(baseValue(U16_BASE), words.value(start + 1)),
    );
}

pub fn copyRange(
    builder: *ClaimGraphBuilder,
    gate: arithmetic.Value,
    source: *const ClaimBoundWords,
    source_start: usize,
    target: *const ClaimBoundWords,
    target_start: usize,
    width: usize,
) Error!void {
    for (0..width) |offset| try constrainEqual(
        builder,
        gate,
        source.value(source_start + offset),
        target.value(target_start + offset),
    );
}

pub fn constrainEqual(
    builder: *ClaimGraphBuilder,
    gate: arithmetic.Value,
    lhs: arithmetic.Value,
    rhs: arithmetic.Value,
) Error!void {
    try builder.constrain(gate, try builder.graph.sub(lhs, rhs));
}

pub fn constrainBoolean(
    builder: *ClaimGraphBuilder,
    gate: arithmetic.Value,
    value: arithmetic.Value,
) Error!void {
    try builder.constrain(
        gate,
        try builder.graph.mul(
            value,
            try builder.graph.sub(arithmetic.Value.one(), value),
        ),
    );
}

pub fn inputSlotValueStart(index: usize) usize {
    return vm_claim.canonical_layout.inputSlotPresent(index) + 1;
}

pub fn outputSlotAddressStart(shape: vm_claim.Shape, index: usize) usize {
    return vm_claim.canonical_layout.outputSlotPresent(shape, index) + 1;
}

pub fn outputSlotValueStart(shape: vm_claim.Shape, index: usize) usize {
    return vm_claim.canonical_layout.outputSlotPresent(shape, index) + 3;
}

pub fn baseValue(value: u32) arithmetic.Value {
    return arithmetic.Value.fromBase(M31.fromU64(value));
}
