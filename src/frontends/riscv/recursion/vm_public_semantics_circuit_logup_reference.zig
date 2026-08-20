//! Internal vm public semantics circuit authority shard; use vm_public_semantics_circuit.zig publicly.

const dependency_0 = @import("vm_public_semantics_circuit_contract.zig");
const dependency_1 = @import("vm_public_semantics_circuit_constrain_output_header_and_addresses.zig");
const dependency_2 = @import("vm_public_semantics_circuit_claim_reference.zig");

const Digest = dependency_0.Digest;
const Error = dependency_0.Error;
const LOGUP_GRAPH_DOMAIN = dependency_0.LOGUP_GRAPH_DOMAIN;
const LOGUP_GRAPH_FORMAT_VERSION = dependency_0.LOGUP_GRAPH_FORMAT_VERSION;
const LogupAuthored = dependency_2.LogupAuthored;
const LogupBoundChallenge = dependency_2.LogupBoundChallenge;
const LogupBoundClaim = dependency_2.LogupBoundClaim;
const LogupGraphBuilder = dependency_2.LogupGraphBuilder;
const LogupInputBinding = dependency_2.LogupInputBinding;
const LogupInputSource = dependency_2.LogupInputSource;
const LogupPrepared = dependency_2.LogupPrepared;
const LogupWitness = dependency_2.LogupWitness;
const M31 = dependency_0.M31;
const QM31 = dependency_0.QM31;
const REQUIRED_LOGUP_CHALLENGES = dependency_0.REQUIRED_LOGUP_CHALLENGES;
const Row16Prepared = dependency_2.Row16Prepared;
const U16_MAX = dependency_0.U16_MAX;
const addPublicTerm = dependency_2.addPublicTerm;
const arithmetic = dependency_0.arithmetic;
const baseValue = dependency_0.baseValue;
const claim_input = dependency_0.claim_input;
const composeSecure = dependency_2.composeSecure;
const hashCircuit = dependency_2.hashCircuit;
const hashInt = dependency_2.hashInt;
const inputSlotValueStart = dependency_0.inputSlotValueStart;
const outputSlotAddressStart = dependency_0.outputSlotAddressStart;
const outputSlotClockStart = dependency_1.outputSlotClockStart;
const outputSlotValueStart = dependency_0.outputSlotValueStart;
const program_decode = dependency_0.program_decode;
const publicTermCount = dependency_2.publicTermCount;
const public_data = dependency_0.public_data;
const public_logup = dependency_0.public_logup;
const relation_challenges = dependency_0.relation_challenges;
const reportFirstNonzeroOutput = dependency_1.reportFirstNonzeroOutput;
const row16 = dependency_0.row16;
const row17 = dependency_0.row17;
const span_statement = dependency_0.span_statement;
const std = dependency_0.std;
const validateCircuitId = dependency_1.validateCircuitId;
const validateClaimWord = dependency_1.validateClaimWord;
const validateOutputOffsets = dependency_1.validateOutputOffsets;
const verifier_schedule = dependency_0.verifier_schedule;
const vm_claim = dependency_0.vm_claim;

/// Immutable four-domain public-LogUp graph and row-16/17 authority metadata.
pub const LogupReference = struct {
    allocator: std.mem.Allocator,
    shape: vm_claim.Shape,
    circuit_id: u32,
    claimed_sum_count: u32,
    public_term_count: u32,
    circuit: arithmetic.Circuit,
    inputs: []LogupInputBinding,
    claim_preprocessing: claim_input.Preprocessed,
    claim_kinds: []row16.ClaimKind,
    row_bindings: []row16.Binding,
    authority_digest: Digest,

    pub fn init(
        allocator: std.mem.Allocator,
        shape: vm_claim.Shape,
        circuit_id: u32,
        claimed_sum_count: u32,
    ) Error!LogupReference {
        try validateCircuitId(circuit_id);
        const public_term_count = try publicTermCount(shape);
        var claim_preprocessing = try claim_input.Preprocessed.init(allocator, shape);
        errdefer claim_preprocessing.deinit();
        const claim_kinds = try allocator.alloc(
            row16.ClaimKind,
            claim_preprocessing.rows.len,
        );
        errdefer allocator.free(claim_kinds);
        for (claim_kinds, claim_preprocessing.rows) |*kind, metadata|
            kind.* = row16ClaimKind(metadata.kind);

        var authored = try buildLogupGraph(
            allocator,
            shape,
            &claim_preprocessing,
            claimed_sum_count,
        );
        errdefer authored.deinit();
        const inputs = try allocator.alloc(LogupInputBinding, authored.sources.items.len);
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
        const row_bindings = try allocator.alloc(row16.Binding, inputs.len);
        errdefer allocator.free(row_bindings);
        for (row_bindings, inputs) |*destination, binding| destination.* = .{
            .node_id = binding.node_id,
            .use_count = binding.use_count,
            .source = logupRowSource(binding.source),
        };
        const authority_digest = logupAuthorityDigest(
            shape,
            circuit_id,
            claimed_sum_count,
            public_term_count,
            &authored.circuit,
            inputs,
        );
        const result = LogupReference{
            .allocator = allocator,
            .shape = shape,
            .circuit_id = circuit_id,
            .claimed_sum_count = claimed_sum_count,
            .public_term_count = public_term_count,
            .circuit = authored.circuit,
            .inputs = inputs,
            .claim_preprocessing = claim_preprocessing,
            .claim_kinds = claim_kinds,
            .row_bindings = row_bindings,
            .authority_digest = authority_digest,
        };
        authored.circuit = undefined;
        authored.sources.deinit(allocator);
        return result;
    }

    pub fn deinit(self: *LogupReference) void {
        self.claim_preprocessing.deinit();
        self.allocator.free(self.row_bindings);
        self.allocator.free(self.claim_kinds);
        self.allocator.free(self.inputs);
        self.circuit.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const LogupReference) Error!void {
        try validateCircuitId(self.circuit_id);
        try self.claim_preprocessing.validate();
        try self.circuit.validate();
        if (self.public_term_count != try publicTermCount(self.shape) or
            self.inputs.len != self.circuit.inputNodes().len or
            self.row_bindings.len != self.inputs.len or
            self.claim_kinds.len != self.claim_preprocessing.rows.len)
        {
            return error.InputLayoutMismatch;
        }
        for (self.claim_kinds, self.claim_preprocessing.rows) |kind, metadata|
            if (kind != row16ClaimKind(metadata.kind)) return error.InputLayoutMismatch;
        for (self.inputs, self.circuit.inputNodes(), self.row_bindings, 0..) |
            binding,
            node_id,
            row_binding,
            input_index,
        | {
            if (binding.node_id != node_id or
                binding.use_count != try self.circuit.inputUseCount(@intCast(input_index)) or
                !std.meta.eql(row_binding, row16.Binding{
                    .node_id = binding.node_id,
                    .use_count = binding.use_count,
                    .source = logupRowSource(binding.source),
                }))
            {
                return error.InputLayoutMismatch;
            }
        }
        const actual = logupAuthorityDigest(
            self.shape,
            self.circuit_id,
            self.claimed_sum_count,
            self.public_term_count,
            &self.circuit,
            self.inputs,
        );
        if (!std.mem.eql(u8, &actual, &self.authority_digest))
            return error.AuthoritySealMismatch;
    }

    pub fn prepare(
        self: *const LogupReference,
        allocator: std.mem.Allocator,
        witness: LogupWitness,
    ) Error!LogupPrepared {
        try self.validateWitnessShape(witness);
        const input_values = try allocator.alloc(QM31, self.inputs.len);
        errdefer allocator.free(input_values);
        for (self.inputs, input_values) |binding, *destination| {
            destination.* = QM31.fromBase(if (witness.segment_selected)
                try logupInputValue(binding.source, witness)
            else
                M31.zero());
        }
        var evaluation = try self.circuit.evaluate(allocator, input_values);
        errdefer evaluation.deinit();
        if (!try self.circuit.outputsAreZero(evaluation.values)) {
            reportFirstNonzeroOutput(&self.circuit, evaluation.values, "public-logup");
            return error.SemanticConstraintViolation;
        }
        return .{
            .allocator = allocator,
            .input_values = input_values,
            .evaluation = evaluation,
            .proof_kind = if (witness.segment_selected) .segment_leaf else .empty_leaf,
            .authority_digest = self.authority_digest,
        };
    }

    /// Materializes the existing row-16 witness API. The four challenge IDs
    /// are checked explicitly so an older `{0,1,3}` API cannot silently drop
    /// the local program-access boundary term.
    pub fn prepareRow16(
        self: *const LogupReference,
        allocator: std.mem.Allocator,
        prepared: *const LogupPrepared,
    ) Error!Row16Prepared {
        if (!std.mem.eql(u32, &row16.CHALLENGES, &REQUIRED_LOGUP_CHALLENGES))
            return error.LogupClaimChallengeSchemaMismatch;
        if (!std.mem.eql(u8, &prepared.authority_digest, &self.authority_digest))
            return error.AuthoritySealMismatch;
        const reference = try row16.Reference.seal(
            self.circuit_id,
            self.claim_kinds,
            self.claimed_sum_count,
            self.row_bindings,
        );
        var preprocessing = try row16.Preprocessed.init(allocator, reference);
        errdefer preprocessing.deinit();
        const values = try allocator.alloc(M31, prepared.input_values.len);
        defer allocator.free(values);
        for (values, prepared.input_values) |*destination, value|
            destination.* = try baseLimb(value);
        var main = try row16.MainWitness.init(
            allocator,
            &preprocessing,
            reference,
            values,
            prepared.proof_kind,
        );
        errdefer main.deinit();
        return .{ .preprocessing = preprocessing, .main = main };
    }

    /// Row 17 is a verifier-owned slice: this method binds its exact term count
    /// to both authenticated plans before allowing preprocessing construction.
    pub fn prepareRow17(
        self: *const LogupReference,
        allocator: std.mem.Allocator,
        vm_plan: *const verifier_schedule.Plan,
        recursion_plan: *const verifier_schedule.Plan,
    ) Error!row17.PublicLogupPreprocessed {
        if (vm_plan.spec.public_logup_term_count != self.public_term_count or
            recursion_plan.spec.public_logup_term_count != 0)
        {
            return error.PublicTermCountMismatch;
        }
        return row17.PublicLogupPreprocessed.init(
            allocator,
            vm_plan,
            self.public_term_count,
            recursion_plan,
            0,
        );
    }

    fn validateWitnessShape(
        self: *const LogupReference,
        witness: LogupWitness,
    ) Error!void {
        if (witness.claim_words.len != self.claim_preprocessing.rows.len)
            return error.ClaimWordCountMismatch;
        if (witness.claimed_sums.len != self.claimed_sum_count)
            return error.InputLayoutMismatch;
        if (!witness.segment_selected) return;
        for (self.claim_preprocessing.rows, witness.claim_words) |metadata, value|
            try validateClaimWord(metadata.kind, value);
    }
};

/// Native differential oracle used by integration tests and profile admission.
pub fn expectedClaimedSum(
    data: *const public_data.PublicData,
    relations: *const relation_challenges.Relations,
) public_logup.Error!QM31 {
    return (try public_logup.sum(data, relations)).neg();
}

pub fn buildLogupGraph(
    allocator: std.mem.Allocator,
    shape: vm_claim.Shape,
    claim_preprocessing: *const claim_input.Preprocessed,
    claimed_sum_count: u32,
) Error!LogupAuthored {
    try validateOutputOffsets(shape);
    var builder = LogupGraphBuilder.init(allocator);
    errdefer builder.deinit();
    const segment = try builder.input(.segment_selector);
    var claim = try LogupBoundClaim.init(allocator, &builder, claim_preprocessing);
    defer claim.deinit();
    const registers = try LogupBoundChallenge.init(&builder, 0, 2);
    const memory = try LogupBoundChallenge.init(&builder, 1, 7);
    const program = try LogupBoundChallenge.init(&builder, 2, 5);
    const merkle = try LogupBoundChallenge.init(&builder, 3, 4);

    var total = arithmetic.Value.zero();
    var term_index: u32 = 0;
    try addPublicTerm(
        &builder,
        &total,
        segment,
        try registers.combine(&builder, &.{
            try claim.u32Value(&builder, vm_claim.canonical_layout.initial_pc_start),
            baseValue(1),
        }),
        .positive,
        &term_index,
    );
    try addPublicTerm(
        &builder,
        &total,
        segment,
        try registers.combine(&builder, &.{
            try claim.u32Value(&builder, vm_claim.canonical_layout.final_pc_start),
            try builder.graph.add(
                try claim.u32Value(&builder, vm_claim.canonical_layout.clock_start),
                arithmetic.Value.one(),
            ),
        }),
        .negative,
        &term_index,
    );

    for ([_]struct { present: usize, root: usize }{
        .{
            .present = vm_claim.canonical_layout.program_root_present,
            .root = vm_claim.canonical_layout.program_root_start,
        },
        .{
            .present = vm_claim.canonical_layout.initial_rw_root_present,
            .root = vm_claim.canonical_layout.initial_rw_root_start,
        },
        .{
            .present = vm_claim.canonical_layout.final_rw_root_present,
            .root = vm_claim.canonical_layout.final_rw_root_start,
        },
    }) |root| {
        const value = claim.word(root.root);
        try addPublicTerm(
            &builder,
            &total,
            try builder.graph.mul(segment, claim.word(root.present)),
            try merkle.combine(&builder, &.{
                arithmetic.Value.zero(),
                arithmetic.Value.zero(),
                value,
                value,
            }),
            .positive,
            &term_index,
        );
    }

    for (0..32) |register_index| {
        const register_address = baseValue(@intCast(register_index));
        const initial_start = vm_claim.canonical_layout.initial_registers_start +
            register_index * 2;
        const initial_bytes = try claim.u32Bytes(initial_start);
        try addPublicTerm(
            &builder,
            &total,
            segment,
            try memory.combine(&builder, &.{
                arithmetic.Value.zero(),
                register_address,
                arithmetic.Value.zero(),
                initial_bytes[0],
                initial_bytes[1],
                initial_bytes[2],
                initial_bytes[3],
            }),
            .positive,
            &term_index,
        );
        const final_start = vm_claim.canonical_layout.final_registers_start +
            register_index * 2;
        const final_bytes = try claim.u32Bytes(final_start);
        try addPublicTerm(
            &builder,
            &total,
            segment,
            try memory.combine(&builder, &.{
                arithmetic.Value.zero(),
                register_address,
                try claim.u32Value(
                    &builder,
                    vm_claim.canonical_layout.register_last_clocks_start + register_index * 2,
                ),
                final_bytes[0],
                final_bytes[1],
                final_bytes[2],
                final_bytes[3],
            }),
            .negative,
            &term_index,
        );
    }

    const input_start = try claim.u32Value(
        &builder,
        vm_claim.canonical_layout.input_start_start,
    );
    for (0..shape.max_input_words) |raw_index| {
        const index: usize = @intCast(raw_index);
        const value_bytes = try claim.u32Bytes(inputSlotValueStart(index));
        try addPublicTerm(
            &builder,
            &total,
            try builder.graph.mul(
                segment,
                claim.word(vm_claim.canonical_layout.inputSlotPresent(index)),
            ),
            try memory.combine(&builder, &.{
                arithmetic.Value.one(),
                try builder.graph.add(input_start, baseValue(@intCast(raw_index * 4))),
                arithmetic.Value.zero(),
                value_bytes[0],
                value_bytes[1],
                value_bytes[2],
                value_bytes[3],
            }),
            .positive,
            &term_index,
        );
    }

    for (0..shape.max_output_words) |raw_index| {
        const index: usize = @intCast(raw_index);
        const value_bytes = try claim.u32Bytes(outputSlotValueStart(shape, index));
        try addPublicTerm(
            &builder,
            &total,
            try builder.graph.mul(
                segment,
                claim.word(vm_claim.canonical_layout.outputSlotPresent(shape, index)),
            ),
            try memory.combine(&builder, &.{
                arithmetic.Value.one(),
                try claim.u32Value(&builder, outputSlotAddressStart(shape, index)),
                try claim.u32Value(&builder, outputSlotClockStart(shape, index)),
                value_bytes[0],
                value_bytes[1],
                value_bytes[2],
                value_bytes[3],
            }),
            .negative,
            &term_index,
        );
    }

    const self_loop = program_decode.decodeProgramWord(
        public_data.CANONICAL_SELF_LOOP_WORD,
    ) catch unreachable;
    try addPublicTerm(
        &builder,
        &total,
        segment,
        try program.combine(&builder, &.{
            try claim.u32Value(&builder, vm_claim.canonical_layout.final_pc_start),
            baseValue(self_loop[0]),
            baseValue(self_loop[1]),
            baseValue(self_loop[2]),
            baseValue(self_loop[3]),
        }),
        .negative,
        &term_index,
    );
    if (term_index != try publicTermCount(shape)) return error.PublicTermCountMismatch;

    for (0..claimed_sum_count) |item_index| {
        var limbs: [4]arithmetic.Value = undefined;
        for (&limbs, 0..) |*limb, limb_index| limb.* = try builder.input(
            .{ .claimed_sum_word = .{
                .item_index = @intCast(item_index),
                .limb_index = @intCast(limb_index),
            } },
        );
        total = try builder.graph.add(
            total,
            try builder.graph.mul(segment, try composeSecure(&builder.graph, limbs)),
        );
    }
    _ = try builder.graph.markOutput(total);
    return builder.finish(term_index);
}

pub fn logupInputValue(source: LogupInputSource, witness: LogupWitness) Error!M31 {
    return switch (source) {
        .segment_selector => M31.fromCanonical(@intFromBool(witness.segment_selected)),
        .claim_word => |index| witness.claim_words[index],
        .claim_byte => |coordinate| blk: {
            const word = witness.claim_words[coordinate.word_index].toU32();
            if (word > U16_MAX) return error.InvalidClaimU16;
            break :blk M31.fromCanonical(
                (word >> @as(u5, coordinate.byte_index) * 8) & 0xff,
            );
        },
        .relation_challenge_word => |coordinate| witness.relation_words
            .words(coordinate.challenge)[coordinate.word_index],
        .claimed_sum_word => |coordinate| witness.claimed_sums[coordinate.item_index]
            .toM31Array()[coordinate.limb_index],
    };
}

pub fn baseLimb(value: QM31) Error!M31 {
    const limbs = value.toM31Array();
    if (!limbs[1].isZero() or !limbs[2].isZero() or !limbs[3].isZero())
        return error.InputValueIsNotBaseField;
    return limbs[0];
}

pub fn row16ClaimKind(kind: claim_input.WordKind) row16.ClaimKind {
    return switch (kind) {
        .constant => .constant,
        .boolean => .boolean,
        .u16 => .u16,
        .field => .field,
    };
}

pub fn logupRowSource(source: LogupInputSource) row16.Source {
    return switch (source) {
        .segment_selector => .segment_selector,
        .claim_word => |index| .{ .claim_word = index },
        .claim_byte => |coordinate| .{ .claim_byte = .{
            .word_index = coordinate.word_index,
            .byte_index = coordinate.byte_index,
        } },
        .relation_challenge_word => |coordinate| .{ .relation_challenge_word = .{
            .challenge = coordinate.challenge,
            .word_index = coordinate.word_index,
        } },
        .claimed_sum_word => |coordinate| .{ .claimed_sum_word = .{
            .item_index = coordinate.item_index,
            .limb_index = coordinate.limb_index,
        } },
    };
}

pub fn logupAuthorityDigest(
    shape: vm_claim.Shape,
    circuit_id: u32,
    claimed_sum_count: u32,
    public_term_count: u32,
    circuit: *const arithmetic.Circuit,
    inputs: []const LogupInputBinding,
) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(LOGUP_GRAPH_DOMAIN);
    hashInt(&hash, u16, LOGUP_GRAPH_FORMAT_VERSION);
    hashInt(&hash, u32, shape.max_input_words);
    hashInt(&hash, u32, shape.max_output_words);
    hashInt(&hash, u32, circuit_id);
    hashInt(&hash, u32, claimed_sum_count);
    hashInt(&hash, u32, public_term_count);
    hashCircuit(&hash, circuit);
    hashInt(&hash, u32, inputs.len);
    for (inputs) |binding| {
        hashInt(&hash, u32, binding.node_id);
        hashInt(&hash, u32, binding.use_count);
        hashLogupSource(&hash, binding.source);
    }
    return hash.finalResult();
}

pub fn hashLogupSource(hash: anytype, source: LogupInputSource) void {
    hashInt(hash, u8, @intFromEnum(std.meta.activeTag(source)));
    switch (source) {
        .segment_selector => {},
        .claim_word => |index| hashInt(hash, u32, index),
        .claim_byte => |coordinate| {
            hashInt(hash, u32, coordinate.word_index);
            hashInt(hash, u8, coordinate.byte_index);
        },
        .relation_challenge_word => |coordinate| {
            hashInt(hash, u32, coordinate.challenge);
            hashInt(hash, u8, coordinate.word_index);
        },
        .claimed_sum_word => |coordinate| {
            hashInt(hash, u32, coordinate.item_index);
            hashInt(hash, u8, coordinate.limb_index);
        },
    }
}

comptime {
    if (span_statement.SPAN_STATEMENT_CANONICAL_WORDS != 412 or
        vm_claim.FIXED_CLAIM_WORDS != 259 or
        relation_challenges.RELATION_COUNT != 12)
    {
        @compileError("VM public recursion semantic profile drifted");
    }
}
