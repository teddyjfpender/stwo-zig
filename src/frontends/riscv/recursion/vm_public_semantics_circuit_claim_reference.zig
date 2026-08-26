//! Internal vm public semantics circuit authority shard; use vm_public_semantics_circuit.zig publicly.

const dependency_0 = @import("vm_public_semantics_circuit_contract.zig");
const dependency_1 = @import("vm_public_semantics_circuit_constrain_output_header_and_addresses.zig");

const CLAIM_GRAPH_DOMAIN = dependency_0.CLAIM_GRAPH_DOMAIN;
const CLAIM_GRAPH_FORMAT_VERSION = dependency_0.CLAIM_GRAPH_FORMAT_VERSION;
const ClaimInputBinding = dependency_0.ClaimInputBinding;
const ClaimInputSource = dependency_0.ClaimInputSource;
const ClaimWitness = dependency_0.ClaimWitness;
const Digest = dependency_0.Digest;
const Error = dependency_0.Error;
const FIXED_PUBLIC_TERM_COUNT = dependency_0.FIXED_PUBLIC_TERM_COUNT;
const M31 = dependency_0.M31;
const QM31 = dependency_0.QM31;
const U16_BASE = dependency_0.U16_BASE;
const arithmetic = dependency_0.arithmetic;
const baseValue = dependency_0.baseValue;
const buildClaimGraph = dependency_1.buildClaimGraph;
const claimInputValue = dependency_1.claimInputValue;
const claimRowSource = dependency_1.claimRowSource;
const claim_input = dependency_0.claim_input;
const relation_challenges = dependency_0.relation_challenges;
const reportFirstNonzeroOutput = dependency_1.reportFirstNonzeroOutput;
const row15 = dependency_0.row15;
const row16 = dependency_0.row16;
const span_statement = dependency_0.span_statement;
const std = dependency_0.std;
const validateCircuitId = dependency_1.validateCircuitId;
const validateClaimWord = dependency_1.validateClaimWord;
const validateDigest = dependency_1.validateDigest;
const vm_claim = dependency_0.vm_claim;

/// Immutable graph and row-15 authority for one fixed claim capacity.
pub const ClaimReference = struct {
    allocator: std.mem.Allocator,
    shape: vm_claim.Shape,
    circuit_id: u32,
    circuit: arithmetic.Circuit,
    inputs: []ClaimInputBinding,
    row_bindings: []row15.Binding,
    claim_preprocessing: claim_input.Preprocessed,
    row_preprocessing: row15.Preprocessed,
    authority_digest: Digest,

    pub fn init(
        allocator: std.mem.Allocator,
        shape: vm_claim.Shape,
        circuit_id: u32,
    ) Error!ClaimReference {
        try validateCircuitId(circuit_id);
        var claim_preprocessing = try claim_input.Preprocessed.init(allocator, shape);
        errdefer claim_preprocessing.deinit();

        var authored = try buildClaimGraph(allocator, shape);
        errdefer authored.deinit();
        const inputs = try allocator.alloc(ClaimInputBinding, authored.sources.items.len);
        errdefer allocator.free(inputs);
        for (inputs, authored.sources.items, authored.circuit.inputNodes(), 0..) |
            *binding,
            source,
            node_id,
            input_index,
        | binding.* = .{
            .node_id = node_id,
            .use_count = try authored.circuit.inputUseCount(@intCast(input_index)),
            .source = source,
        };

        const row_bindings = try allocator.alloc(row15.Binding, inputs.len);
        errdefer allocator.free(row_bindings);
        for (row_bindings, inputs) |*destination, binding| destination.* = .{
            .source = claimRowSource(binding.source),
            .node_id = binding.node_id,
            .use_count = binding.use_count,
            .word_index = claimRowWordIndex(binding.source),
            .io_kind = claimRowIoKind(binding.source),
        };
        const row_reference = try row15.Reference.seal(circuit_id, row_bindings);
        var row_preprocessing = try row15.Preprocessed.init(allocator, row_reference);
        errdefer row_preprocessing.deinit();

        const authority_digest = claimAuthorityDigest(
            shape,
            circuit_id,
            &authored.circuit,
            inputs,
        );
        const result = ClaimReference{
            .allocator = allocator,
            .shape = shape,
            .circuit_id = circuit_id,
            .circuit = authored.circuit,
            .inputs = inputs,
            .row_bindings = row_bindings,
            .claim_preprocessing = claim_preprocessing,
            .row_preprocessing = row_preprocessing,
            .authority_digest = authority_digest,
        };
        authored.circuit = undefined;
        authored.sources.deinit(allocator);
        return result;
    }

    pub fn deinit(self: *ClaimReference) void {
        self.row_preprocessing.deinit();
        self.claim_preprocessing.deinit();
        self.allocator.free(self.row_bindings);
        self.allocator.free(self.inputs);
        self.circuit.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const ClaimReference) Error!void {
        try validateCircuitId(self.circuit_id);
        try self.circuit.validate();
        try self.claim_preprocessing.validate();
        if (self.inputs.len != self.circuit.inputNodes().len or
            self.row_bindings.len != self.inputs.len)
        {
            return error.InputLayoutMismatch;
        }
        for (self.inputs, self.circuit.inputNodes(), self.row_bindings, 0..) |
            binding,
            node_id,
            row_binding,
            input_index,
        | {
            if (binding.node_id != node_id or
                binding.use_count != try self.circuit.inputUseCount(@intCast(input_index)) or
                !std.meta.eql(row_binding, row15.Binding{
                    .source = claimRowSource(binding.source),
                    .node_id = binding.node_id,
                    .use_count = binding.use_count,
                    .word_index = claimRowWordIndex(binding.source),
                    .io_kind = claimRowIoKind(binding.source),
                }))
            {
                return error.InputLayoutMismatch;
            }
        }
        const row_reference = try row15.Reference.seal(
            self.circuit_id,
            self.row_bindings,
        );
        try self.row_preprocessing.validateAgainst(row_reference);
        const actual = claimAuthorityDigest(
            self.shape,
            self.circuit_id,
            &self.circuit,
            self.inputs,
        );
        if (!std.mem.eql(u8, &actual, &self.authority_digest))
            return error.AuthoritySealMismatch;
    }

    /// Linear instance preparation. Every private value is derived at a fixed
    /// coordinate and subsequently constrained by the graph; no host verdict
    /// substitutes for an algebraic output.
    pub fn prepare(
        self: *const ClaimReference,
        allocator: std.mem.Allocator,
        witness: ClaimWitness,
    ) Error!ClaimPrepared {
        try self.validateWitnessShape(witness);
        const input_values = try allocator.alloc(QM31, self.inputs.len);
        errdefer allocator.free(input_values);
        const row_values = try allocator.alloc(M31, self.inputs.len);
        defer allocator.free(row_values);
        for (self.inputs, input_values, row_values) |binding, *secure, *base_value| {
            base_value.* = if (witness.segment_selected)
                try claimInputValue(self.shape, binding.source, witness)
            else
                M31.zero();
            secure.* = QM31.fromBase(base_value.*);
        }
        var evaluation = try self.circuit.evaluate(allocator, input_values);
        errdefer evaluation.deinit();
        if (!try self.circuit.outputsAreZero(evaluation.values)) {
            reportFirstNonzeroOutput(&self.circuit, evaluation.values, "claim");
            return error.SemanticConstraintViolation;
        }

        const row_reference = try row15.Reference.seal(
            self.circuit_id,
            self.row_bindings,
        );
        var row_witness = try row15.MainWitness.init(
            allocator,
            &self.row_preprocessing,
            row_reference,
            row_values,
            if (witness.segment_selected) .segment_leaf else .empty_leaf,
        );
        errdefer row_witness.deinit();
        return .{
            .allocator = allocator,
            .input_values = input_values,
            .evaluation = evaluation,
            .row_witness = row_witness,
            .authority_digest = self.authority_digest,
        };
    }

    fn validateWitnessShape(
        self: *const ClaimReference,
        witness: ClaimWitness,
    ) Error!void {
        if (witness.claim_words.len != self.claim_preprocessing.rows.len)
            return error.ClaimWordCountMismatch;
        if (witness.statement_words.len != span_statement.SPAN_STATEMENT_CANONICAL_WORDS)
            return error.StatementWordCountMismatch;
        if (!witness.segment_selected) return;
        for (self.claim_preprocessing.rows, witness.claim_words) |metadata, value|
            try validateClaimWord(metadata.kind, value);
        try validateDigest(witness.input_digest);
        try validateDigest(witness.output_digest);
    }
};

pub const ClaimPrepared = struct {
    allocator: std.mem.Allocator,
    input_values: []QM31,
    evaluation: arithmetic.Evaluation,
    row_witness: row15.MainWitness,
    authority_digest: Digest,

    pub fn deinit(self: *ClaimPrepared) void {
        self.row_witness.deinit();
        self.evaluation.deinit();
        self.allocator.free(self.input_values);
        self.* = undefined;
    }

    pub fn validateAgainst(
        self: *const ClaimPrepared,
        reference: *const ClaimReference,
    ) Error!void {
        if (!std.mem.eql(u8, &self.authority_digest, &reference.authority_digest))
            return error.AuthoritySealMismatch;
        try self.row_witness.validateAgainst(&reference.row_preprocessing);
        if (!try reference.circuit.outputsAreZero(self.evaluation.values))
            return error.SemanticConstraintViolation;
    }
};

pub const LogupChallengeWords = struct {
    registers_state: [8]M31,
    memory_access: [8]M31,
    program_access: [8]M31,
    merkle: [8]M31,

    pub fn fromRelations(relations: *const relation_challenges.Relations) LogupChallengeWords {
        return .{
            .registers_state = relationWords(
                relations.registers_state.z,
                relations.registers_state.alpha,
            ),
            .memory_access = relationWords(
                relations.memory_access.z,
                relations.memory_access.alpha,
            ),
            .program_access = relationWords(
                relations.program_access.z,
                relations.program_access.alpha,
            ),
            .merkle = relationWords(relations.merkle.z, relations.merkle.alpha),
        };
    }

    pub fn words(self: LogupChallengeWords, challenge: u32) [8]M31 {
        return switch (challenge) {
            0 => self.registers_state,
            1 => self.memory_access,
            2 => self.program_access,
            3 => self.merkle,
            else => unreachable,
        };
    }
};

pub const LogupWitness = struct {
    segment_selected: bool,
    claim_words: []const M31,
    relation_words: LogupChallengeWords,
    claimed_sums: []const QM31,
};

pub const LogupInputSource = union(enum) {
    segment_selector,
    claim_word: u32,
    claim_byte: struct { word_index: u32, byte_index: u1 },
    relation_challenge_word: struct { challenge: u32, word_index: u3 },
    claimed_sum_word: struct { item_index: u32, limb_index: u2 },
};

pub const LogupInputBinding = struct {
    node_id: u32,
    use_count: u32,
    source: LogupInputSource,
};

pub const LogupPrepared = struct {
    allocator: std.mem.Allocator,
    input_values: []QM31,
    evaluation: arithmetic.Evaluation,
    proof_kind: row16.ProofKind,
    authority_digest: Digest,

    pub fn deinit(self: *LogupPrepared) void {
        self.evaluation.deinit();
        self.allocator.free(self.input_values);
        self.* = undefined;
    }
};

pub const Row16Prepared = struct {
    preprocessing: row16.Preprocessed,
    main: row16.MainWitness,

    pub fn deinit(self: *Row16Prepared) void {
        self.main.deinit();
        self.preprocessing.deinit();
        self.* = undefined;
    }
};

pub fn publicTermCount(shape: vm_claim.Shape) Error!u32 {
    return std.math.add(
        u32,
        std.math.add(u32, FIXED_PUBLIC_TERM_COUNT, shape.max_input_words) catch
            return error.ArithmeticOverflow,
        shape.max_output_words,
    ) catch return error.ArithmeticOverflow;
}

pub const LogupAuthored = struct {
    circuit: arithmetic.Circuit,
    sources: std.ArrayList(LogupInputSource),
    public_term_count: u32,

    pub fn deinit(self: *LogupAuthored) void {
        const allocator = self.circuit.allocator;
        self.sources.deinit(allocator);
        self.circuit.deinit();
        self.* = undefined;
    }
};

pub const LogupGraphBuilder = struct {
    allocator: std.mem.Allocator,
    graph: arithmetic.Builder,
    sources: std.ArrayList(LogupInputSource) = .empty,

    pub fn init(allocator: std.mem.Allocator) LogupGraphBuilder {
        return .{ .allocator = allocator, .graph = arithmetic.Builder.initDefault(allocator) };
    }

    pub fn deinit(self: *LogupGraphBuilder) void {
        self.sources.deinit(self.allocator);
        self.graph.deinit();
        self.* = undefined;
    }

    pub fn input(self: *LogupGraphBuilder, source: LogupInputSource) Error!arithmetic.Value {
        const input_id: u32 = @intCast(self.sources.items.len);
        try self.sources.append(self.allocator, source);
        errdefer _ = self.sources.pop();
        return self.graph.input(input_id);
    }

    pub fn finish(
        self: *LogupGraphBuilder,
        public_term_count: u32,
    ) Error!LogupAuthored {
        const circuit = try self.graph.finish();
        self.graph.deinit();
        self.graph = arithmetic.Builder.initDefault(self.allocator);
        const result = LogupAuthored{
            .circuit = circuit,
            .sources = self.sources,
            .public_term_count = public_term_count,
        };
        self.sources = .empty;
        return result;
    }
};

pub const LogupBoundClaim = struct {
    allocator: std.mem.Allocator,
    words: []arithmetic.Value,
    bytes: []?[2]arithmetic.Value,

    pub fn init(
        allocator: std.mem.Allocator,
        builder: *LogupGraphBuilder,
        preprocessing: *const claim_input.Preprocessed,
    ) Error!LogupBoundClaim {
        const words = try allocator.alloc(arithmetic.Value, preprocessing.rows.len);
        errdefer allocator.free(words);
        const bytes = try allocator.alloc(?[2]arithmetic.Value, preprocessing.rows.len);
        errdefer allocator.free(bytes);
        for (preprocessing.rows, words, bytes, 0..) |metadata, *word_value, *byte_pair, index| {
            word_value.* = try builder.input(.{ .claim_word = @intCast(index) });
            byte_pair.* = switch (metadata.kind) {
                .u16 => .{
                    try builder.input(.{ .claim_byte = .{
                        .word_index = @intCast(index),
                        .byte_index = 0,
                    } }),
                    try builder.input(.{ .claim_byte = .{
                        .word_index = @intCast(index),
                        .byte_index = 1,
                    } }),
                },
                else => null,
            };
        }
        return .{ .allocator = allocator, .words = words, .bytes = bytes };
    }

    pub fn deinit(self: *LogupBoundClaim) void {
        self.allocator.free(self.bytes);
        self.allocator.free(self.words);
        self.* = undefined;
    }

    pub fn word(self: *const LogupBoundClaim, index: usize) arithmetic.Value {
        return self.words[index];
    }

    pub fn u32Value(
        self: *const LogupBoundClaim,
        builder: *LogupGraphBuilder,
        start: usize,
    ) Error!arithmetic.Value {
        return builder.graph.add(
            self.word(start),
            try builder.graph.mul(baseValue(U16_BASE), self.word(start + 1)),
        );
    }

    pub fn u32Bytes(self: *const LogupBoundClaim, start: usize) Error![4]arithmetic.Value {
        const low = self.bytes[start] orelse return error.InputLayoutMismatch;
        const high = self.bytes[start + 1] orelse return error.InputLayoutMismatch;
        return .{ low[0], low[1], high[0], high[1] };
    }
};

pub const LogupBoundChallenge = struct {
    z: arithmetic.Value,
    alpha_powers: [7]arithmetic.Value,
    arity: usize,

    pub fn init(
        builder: *LogupGraphBuilder,
        challenge: u32,
        arity: usize,
    ) Error!LogupBoundChallenge {
        std.debug.assert(arity <= 7);
        var z_limbs: [4]arithmetic.Value = undefined;
        var alpha_limbs: [4]arithmetic.Value = undefined;
        for (&z_limbs, 0..) |*limb, word_index| limb.* = try builder.input(
            .{ .relation_challenge_word = .{
                .challenge = challenge,
                .word_index = @intCast(word_index),
            } },
        );
        for (&alpha_limbs, 0..) |*limb, index| limb.* = try builder.input(
            .{ .relation_challenge_word = .{
                .challenge = challenge,
                .word_index = @intCast(index + 4),
            } },
        );
        const z = try composeSecure(&builder.graph, z_limbs);
        const alpha = try composeSecure(&builder.graph, alpha_limbs);
        var powers: [7]arithmetic.Value = undefined;
        var power = arithmetic.Value.one();
        for (powers[0..arity]) |*destination| {
            destination.* = power;
            power = try builder.graph.mul(power, alpha);
        }
        for (powers[arity..]) |*destination| destination.* = arithmetic.Value.zero();
        return .{ .z = z, .alpha_powers = powers, .arity = arity };
    }

    pub fn combine(
        self: *const LogupBoundChallenge,
        builder: *LogupGraphBuilder,
        values: []const arithmetic.Value,
    ) Error!arithmetic.Value {
        if (values.len != self.arity) return error.InputLayoutMismatch;
        var result = arithmetic.Value.zero();
        for (values, self.alpha_powers[0..self.arity]) |value, power|
            result = try builder.graph.add(result, try builder.graph.mul(value, power));
        return builder.graph.sub(result, self.z);
    }
};

pub const TermSign = enum { positive, negative };

pub fn addPublicTerm(
    builder: *LogupGraphBuilder,
    total: *arithmetic.Value,
    activation: arithmetic.Value,
    denominator: arithmetic.Value,
    sign: TermSign,
    term_index: *u32,
) Error!void {
    const selected = try builder.graph.add(
        try builder.graph.mul(activation, denominator),
        try builder.graph.sub(arithmetic.Value.one(), activation),
    );
    const contribution = try builder.graph.mul(
        activation,
        try builder.graph.inverse(selected),
    );
    total.* = switch (sign) {
        .positive => try builder.graph.add(total.*, contribution),
        .negative => try builder.graph.sub(total.*, contribution),
    };
    term_index.* = std.math.add(u32, term_index.*, 1) catch
        return error.ArithmeticOverflow;
}

pub fn composeSecure(
    builder: *arithmetic.Builder,
    values: [4]arithmetic.Value,
) Error!arithmetic.Value {
    var result = values[0];
    result = try builder.add(result, try builder.mul(
        values[1],
        arithmetic.Value.fromSecure(QM31.fromU32Unchecked(0, 1, 0, 0)),
    ));
    result = try builder.add(result, try builder.mul(
        values[2],
        arithmetic.Value.fromSecure(QM31.fromU32Unchecked(0, 0, 1, 0)),
    ));
    return builder.add(result, try builder.mul(
        values[3],
        arithmetic.Value.fromSecure(QM31.fromU32Unchecked(0, 0, 0, 1)),
    ));
}

pub fn relationWords(z: QM31, alpha: QM31) [8]M31 {
    var result: [8]M31 = undefined;
    const z_limbs = z.toM31Array();
    const alpha_limbs = alpha.toM31Array();
    @memcpy(result[0..4], &z_limbs);
    @memcpy(result[4..8], &alpha_limbs);
    return result;
}

pub fn claimRowWordIndex(source: ClaimInputSource) u32 {
    return switch (source) {
        .claim_word, .statement_word => |index| index,
        .io_digest_word => |coordinate| coordinate.limb,
        .segment_selector, .private => 0,
    };
}

pub fn claimRowIoKind(source: ClaimInputSource) u32 {
    return switch (source) {
        .io_digest_word => |coordinate| coordinate.io_kind,
        else => 0,
    };
}

pub fn claimAuthorityDigest(
    shape: vm_claim.Shape,
    circuit_id: u32,
    circuit: *const arithmetic.Circuit,
    inputs: []const ClaimInputBinding,
) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(CLAIM_GRAPH_DOMAIN);
    hashInt(&hash, u16, CLAIM_GRAPH_FORMAT_VERSION);
    hashInt(&hash, u32, shape.max_input_words);
    hashInt(&hash, u32, shape.max_output_words);
    hashInt(&hash, u32, circuit_id);
    hashCircuit(&hash, circuit);
    hashInt(&hash, u32, inputs.len);
    for (inputs) |binding| {
        hashInt(&hash, u32, binding.node_id);
        hashInt(&hash, u32, binding.use_count);
        hashClaimSource(&hash, binding.source);
    }
    return hash.finalResult();
}

pub fn hashCircuit(hash: anytype, circuit: *const arithmetic.Circuit) void {
    hashInt(hash, u32, circuit.nodes().len);
    for (circuit.nodes()) |node| switch (node.op) {
        .input => hashInt(hash, u8, 0),
        .constant => |words| {
            hashInt(hash, u8, 1);
            for (words) |word| hashInt(hash, u32, word);
        },
        .add => |operands| hashBinary(hash, 2, operands),
        .sub => |operands| hashBinary(hash, 3, operands),
        .mul => |operands| hashBinary(hash, 4, operands),
        .neg => |operand| {
            hashInt(hash, u8, 5);
            hashInt(hash, u32, operand);
        },
        .inverse => |operand| {
            hashInt(hash, u8, 6);
            hashInt(hash, u32, operand);
        },
    };
    hashInt(hash, u32, circuit.outputs().len);
    for (circuit.outputs()) |output| hashInt(hash, u32, output);
    hashInt(hash, u32, circuit.useCounts().len);
    for (circuit.useCounts()) |count| hashInt(hash, u32, count);
}

pub fn hashBinary(hash: anytype, tag: u8, operands: arithmetic.BinaryOperands) void {
    hashInt(hash, u8, tag);
    hashInt(hash, u32, operands.lhs);
    hashInt(hash, u32, operands.rhs);
}

pub fn hashClaimSource(hash: anytype, source: ClaimInputSource) void {
    hashInt(hash, u8, @intFromEnum(std.meta.activeTag(source)));
    switch (source) {
        .segment_selector => {},
        .claim_word, .statement_word => |index| hashInt(hash, u32, index),
        .io_digest_word => |coordinate| {
            hashInt(hash, u8, coordinate.io_kind);
            hashInt(hash, u8, coordinate.limb);
        },
        .private => |private_source| {
            hashInt(hash, u8, @intFromEnum(std.meta.activeTag(private_source)));
            switch (private_source) {
                .claim_u32_bit => |coordinate| {
                    hashInt(hash, u32, coordinate.start);
                    hashInt(hash, u8, coordinate.bit);
                },
                .input_padding_bit, .output_padding_bit => |bit| hashInt(hash, u8, bit),
                .statement_edge_present, .output_address_carry => |index| hashInt(hash, u32, index),
            }
        },
    }
}

pub fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}
