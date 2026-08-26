//! Internal segment public native sum authority v2 authority shard; use segment_public_native_sum_authority_v2.zig publicly.

const dependency_0 = @import("segment_public_native_sum_authority_v2_contract.zig");
const dependency_1 = @import("segment_public_native_sum_authority_v2_add_boundary_terms.zig");

const AUTHORITY_DOMAIN = dependency_0.AUTHORITY_DOMAIN;
const CHALLENGE_WORD_COUNT = dependency_0.CHALLENGE_WORD_COUNT;
const CIRCUIT_ID = dependency_0.CIRCUIT_ID;
const DESTINATION_FAILS_ATOMICALLY = dependency_0.DESTINATION_FAILS_ATOMICALLY;
const DOMAIN_COUNT = dependency_0.DOMAIN_COUNT;
const EVALUATION_DOMAIN = dependency_0.EVALUATION_DOMAIN;
const EXACT_GRAPH_AND_USE_COUNTS_SEALED = dependency_0.EXACT_GRAPH_AND_USE_COUNTS_SEALED;
const Error = dependency_0.Error;
const EvaluationBuffersV2 = dependency_0.EvaluationBuffersV2;
const FORMAT_VERSION = dependency_0.FORMAT_VERSION;
const GRAPH_OWNS_RELATION_ARITHMETIC = dependency_0.GRAPH_OWNS_RELATION_ARITHMETIC;
const HOT_HEAP_ALLOCATIONS = dependency_0.HOT_HEAP_ALLOCATIONS;
const INPUT_SUFFIX_WORD_COUNT = dependency_0.INPUT_SUFFIX_WORD_COUNT;
const InputBindingV2 = dependency_0.InputBindingV2;
const OUTPUT_COUNT = dependency_0.OUTPUT_COUNT;
const OwnedGraph = dependency_0.OwnedGraph;
const POINTER_STABLE_OWNERSHIP = dependency_0.POINTER_STABLE_OWNERSHIP;
const PUBLISHED_SUMS_ARE_NOT_AUTHORITY = dependency_0.PUBLISHED_SUMS_ARE_NOT_AUTHORITY;
const PUBLISHED_WORD_COUNT = dependency_0.PUBLISHED_WORD_COUNT;
const QM31 = dependency_0.QM31;
const ROW11_OWNS_CANONICAL_PARSING = dependency_0.ROW11_OWNS_CANONICAL_PARSING;
const SCHEMA_VERSION = dependency_0.SCHEMA_VERSION;
const TermCountsV2 = dependency_0.TermCountsV2;
const arithmetic = dependency_0.arithmetic;
const authenticatedView = dependency_1.authenticatedView;
const buildGraph = dependency_1.buildGraph;
const checkedAddU32 = dependency_1.checkedAddU32;
const countTerms = dependency_1.countTerms;
const fillInputValues = dependency_1.fillInputValues;
const hashDigest = dependency_1.hashDigest;
const hashInt = dependency_1.hashInt;
const inputSource = dependency_1.inputSource;
const lowering = dependency_0.lowering;
const nodeEql = dependency_1.nodeEql;
const overlap = dependency_1.overlap;
const public_source = dependency_0.public_source;
const std = dependency_0.std;
const wire_statement = dependency_0.wire_statement;

/// Cold, pointer-stable owner of the exact graph and its lowering authority.
/// No pointer into the caller's `PreparedV2` or canonical wire is retained.
pub const SourceV2 = struct {
    allocator: std.mem.Allocator,
    wire_word_count: u32,
    input_count: u32,
    term_counts: TermCountsV2,
    prepared_source_id: public_source.Digest,
    wire_id: public_source.Digest,
    manifest_id: public_source.Digest,
    lowering_obligation_id: public_source.Digest,
    publication_id: public_source.Digest,
    native_public_sums_id: public_source.Digest,
    relation_context_id: public_source.Digest,
    circuit: arithmetic.Circuit,
    bindings: []InputBindingV2,
    owned_graph: OwnedGraph,
    authority_digest: [32]u8,

    pub fn init(
        allocator: std.mem.Allocator,
        prepared: *const public_source.PreparedV2,
        inputs: public_source.InputsV2,
    ) Error!SourceV2 {
        try prepared.validateAgainst(inputs);
        const view = try authenticatedView(prepared, inputs);
        const wire_count = std.math.cast(u32, view.words.len) orelse
            return error.ArithmeticOverflow;
        const expected_inputs = try checkedAddU32(
            wire_count,
            INPUT_SUFFIX_WORD_COUNT,
        );
        if (prepared.lowering_obligation.input_count != expected_inputs or
            prepared.lowering_obligation.boundary_word_count != wire_count or
            prepared.lowering_obligation.zero_output_count != OUTPUT_COUNT or
            prepared.lowering_obligation.circuit_id != CIRCUIT_ID)
        {
            return error.ArithmeticAuthorityMismatch;
        }

        var authored = try buildGraph(allocator, &view);
        errdefer authored.circuit.deinit();
        if (authored.circuit.inputNodes().len != expected_inputs or
            authored.circuit.outputs().len != OUTPUT_COUNT)
        {
            return error.InputBindingMismatch;
        }

        const bindings = try allocator.alloc(
            InputBindingV2,
            authored.circuit.inputNodes().len,
        );
        errdefer allocator.free(bindings);
        for (bindings, authored.circuit.inputNodes(), 0..) |
            *binding,
            node_id,
            input_index,
        | {
            binding.* = .{
                .node_id = node_id,
                .use_count = try authored.circuit.inputUseCount(
                    @intCast(input_index),
                ),
                .source = try inputSource(wire_count, input_index),
            };
        }

        var owned_graph = try OwnedGraph.init(allocator, &authored.circuit);
        errdefer owned_graph.deinit();
        var result = SourceV2{
            .allocator = allocator,
            .wire_word_count = wire_count,
            .input_count = expected_inputs,
            .term_counts = authored.term_counts,
            .prepared_source_id = prepared.source_id,
            .wire_id = prepared.wire_id,
            .manifest_id = prepared.manifest.identity,
            .lowering_obligation_id = prepared.lowering_obligation.identity,
            .publication_id = prepared.publication_id,
            .native_public_sums_id = prepared.native_public_sums_id,
            .relation_context_id = prepared.relation_context_id,
            .circuit = authored.circuit,
            .bindings = bindings,
            .owned_graph = owned_graph,
            .authority_digest = undefined,
        };
        authored.circuit = undefined;
        result.authority_digest = authorityDigest(&result);
        try result.validateColdAgainst(prepared, inputs);
        return result;
    }

    pub fn deinit(self: *SourceV2) void {
        self.owned_graph.deinit();
        self.allocator.free(self.bindings);
        self.circuit.deinit();
        self.* = undefined;
    }

    pub fn nodeCount(self: *const SourceV2) usize {
        return self.circuit.nodes().len;
    }

    pub fn loweringLane(self: *const SourceV2) lowering.Lane {
        return .{
            .circuit_id = CIRCUIT_ID,
            .active_in = .segment,
            .circuit_identity = self.authority_digest,
            .graph = self.owned_graph.graph,
        };
    }

    pub fn loweringLanes(self: *const SourceV2) [1]lowering.Lane {
        return .{self.loweringLane()};
    }

    /// Sealed row-13--16 relay binding. Input nodes are authored first and
    /// densely, so the circuit's first `input_count` use counters are exactly
    /// the public source's node-coordinate order.
    pub fn publicBinding(
        self: *const SourceV2,
        prepared: *const public_source.PreparedV2,
    ) Error!public_source.ArithmeticGraphBindingV2 {
        if (!std.meta.eql(self.prepared_source_id, prepared.source_id) or
            !std.meta.eql(
                self.lowering_obligation_id,
                prepared.lowering_obligation.identity,
            ) or self.circuit.useCounts().len < self.input_count)
        {
            return error.ArithmeticAuthorityMismatch;
        }
        return public_source.sealArithmeticGraphBinding(
            prepared,
            self.owned_graph.graph.identity_digest,
            self.authority_digest,
            self.circuit.useCounts()[0..@intCast(self.input_count)],
        );
    }

    /// Allocation-free production handoff from the authenticated graph to
    /// rows 13--16. The graph and all public inputs are revalidated before the
    /// row source sees the sealed multiplicity view.
    pub fn writePublicRowsInto(
        self: *const SourceV2,
        prepared: *const public_source.PreparedV2,
        destinations: public_source.DestinationsV2,
        inputs: public_source.InputsV2,
        use_count_scratch: []u32,
    ) Error!void {
        try self.validateInto(prepared, inputs, use_count_scratch);
        const binding = try self.publicBinding(prepared);
        try public_source.writeIntoBound(
            prepared,
            destinations,
            inputs,
            binding,
        );
    }

    pub fn inputUseCount(
        self: *const SourceV2,
        input_index: usize,
    ) Error!u32 {
        if (input_index >= self.bindings.len)
            return error.InputBindingMismatch;
        return self.bindings[input_index].use_count;
    }

    /// Cold audit.  This form may allocate the circuit's temporary use-count
    /// validation array; hot paths use `validateInto` below.
    pub fn validateColdAgainst(
        self: *const SourceV2,
        prepared: *const public_source.PreparedV2,
        inputs: public_source.InputsV2,
    ) Error!void {
        try prepared.validateAgainst(inputs);
        const view = try authenticatedView(prepared, inputs);
        try self.validateIdentityAndShape(prepared, &view);
        try self.circuit.validate();
        try self.validateGraphAndBindings();
    }

    /// Allocation-free authority audit using caller-owned scratch.
    pub fn validateInto(
        self: *const SourceV2,
        prepared: *const public_source.PreparedV2,
        inputs: public_source.InputsV2,
        use_count_scratch: []u32,
    ) Error!void {
        if (use_count_scratch.len != self.circuit.nodes().len)
            return error.BufferLengthMismatch;
        try prepared.validateAgainst(inputs);
        const view = try authenticatedView(prepared, inputs);
        try self.validateIdentityAndShape(prepared, &view);
        try self.circuit.validateInto(use_count_scratch);
        try self.validateGraphAndBindings();
    }

    /// Zero-allocation and fail-atomic hot evaluation. Scratch buffers are
    /// disposable on failure; `destination_values` is byte-for-byte unchanged
    /// unless the complete graph replays and all five outputs are zero.
    pub fn evaluateInto(
        self: *const SourceV2,
        prepared: *const public_source.PreparedV2,
        inputs: public_source.InputsV2,
        buffers: EvaluationBuffersV2,
    ) Error!lowering.Evaluation {
        try validateBufferGeometry(self, buffers);
        try rejectBufferAliases(self, prepared, inputs, buffers);
        try self.validateInto(
            prepared,
            inputs,
            buffers.use_count_scratch,
        );
        fillInputValues(prepared, inputs, buffers.scratch_inputs);
        try self.circuit.evaluateIntoAssumeValid(
            buffers.scratch_inputs,
            buffers.scratch_values,
        );
        if (!try self.circuit.outputsAreZero(buffers.scratch_values))
            return error.PublishedSumMismatch;
        @memcpy(buffers.destination_values, buffers.scratch_values);
        return .{
            .circuit_identity = self.authority_digest,
            .values = buffers.destination_values,
        };
    }

    fn validateIdentityAndShape(
        self: *const SourceV2,
        prepared: *const public_source.PreparedV2,
        view: *const wire_statement.CanonicalWireViewV2,
    ) Error!void {
        const wire_count = std.math.cast(u32, view.words.len) orelse
            return error.ArithmeticOverflow;
        const expected_inputs = try checkedAddU32(
            wire_count,
            INPUT_SUFFIX_WORD_COUNT,
        );
        if (self.wire_word_count != wire_count or
            self.input_count != expected_inputs or
            self.bindings.len != expected_inputs or
            self.circuit.inputNodes().len != expected_inputs or
            self.circuit.outputs().len != OUTPUT_COUNT or
            !std.meta.eql(self.term_counts, try countTerms(view)) or
            !std.meta.eql(self.prepared_source_id, prepared.source_id) or
            !std.meta.eql(self.wire_id, prepared.wire_id) or
            !std.meta.eql(self.manifest_id, prepared.manifest.identity) or
            !std.meta.eql(
                self.lowering_obligation_id,
                prepared.lowering_obligation.identity,
            ) or
            !std.meta.eql(self.publication_id, prepared.publication_id) or
            !std.meta.eql(
                self.native_public_sums_id,
                prepared.native_public_sums_id,
            ) or
            !std.meta.eql(
                self.relation_context_id,
                prepared.relation_context_id,
            ) or
            !std.mem.eql(u8, &self.authority_digest, &authorityDigest(self)))
        {
            return error.ArithmeticAuthorityMismatch;
        }
    }

    fn validateGraphAndBindings(self: *const SourceV2) Error!void {
        try self.owned_graph.validate();
        if (self.owned_graph.nodes.len != self.circuit.nodes().len or
            self.owned_graph.outputs.len != self.circuit.outputs().len or
            !std.mem.eql(u32, self.owned_graph.outputs, self.circuit.outputs()))
        {
            return error.GraphMirrorMismatch;
        }
        for (self.owned_graph.nodes, self.circuit.nodes()) |graph, circuit| {
            if (!nodeEql(graph, circuit)) return error.GraphMirrorMismatch;
        }
        for (self.bindings, self.circuit.inputNodes(), 0..) |
            binding,
            node_id,
            input_index,
        | {
            if (binding.node_id != node_id or
                binding.use_count != try self.circuit.inputUseCount(
                    @intCast(input_index),
                ) or
                !std.meta.eql(
                    binding.source,
                    try inputSource(self.wire_word_count, input_index),
                ))
            {
                return error.InputBindingMismatch;
            }
        }
        for (self.circuit.inputNodes(), 0..) |node_id, input_index| {
            if (node_id != @as(u32, @intCast(input_index)))
                return error.InputBindingMismatch;
        }
    }
};

/// Compact owning handoff from the public native-sum graph to the shared
/// verifier-arithmetic lowering rows. Construction is cold and independently
/// evaluates the complete authenticated graph. Only the committed node values
/// survive construction; the three temporary replay buffers are released
/// immediately, so retaining this lane does not multiply the graph's resident
/// storage.
///
/// The returned `lowering.Evaluation` always borrows `values`. The allocation,
/// rather than this movable wrapper's address, is therefore pointer-stable.
pub const OwnedEvaluationV2 = struct {
    allocator: std.mem.Allocator,
    source_authority_digest: [32]u8,
    values: []QM31,
    identity: [32]u8,

    pub fn init(
        allocator: std.mem.Allocator,
        source: *const SourceV2,
        prepared: *const public_source.PreparedV2,
        inputs: public_source.InputsV2,
    ) Error!OwnedEvaluationV2 {
        const values = try allocator.alloc(QM31, source.nodeCount());
        errdefer allocator.free(values);
        const scratch_inputs = try allocator.alloc(QM31, source.input_count);
        defer allocator.free(scratch_inputs);
        const scratch_values = try allocator.alloc(QM31, source.nodeCount());
        defer allocator.free(scratch_values);
        const use_count_scratch = try allocator.alloc(u32, source.nodeCount());
        defer allocator.free(use_count_scratch);

        const evaluation = try source.evaluateInto(prepared, inputs, .{
            .destination_values = values,
            .scratch_inputs = scratch_inputs,
            .scratch_values = scratch_values,
            .use_count_scratch = use_count_scratch,
        });
        var result = OwnedEvaluationV2{
            .allocator = allocator,
            .source_authority_digest = evaluation.circuit_identity,
            .values = values,
            .identity = undefined,
        };
        result.identity = ownedEvaluationIdentity(&result);
        try result.validateAgainst(source);
        return result;
    }

    pub fn deinit(self: *OwnedEvaluationV2) void {
        self.allocator.free(self.values);
        self.* = undefined;
    }

    pub fn validateAgainst(
        self: *const OwnedEvaluationV2,
        source: *const SourceV2,
    ) Error!void {
        if (self.values.len != source.nodeCount() or
            !std.mem.eql(
                u8,
                &self.source_authority_digest,
                &source.authority_digest,
            ) or !std.mem.eql(u8, &self.identity, &ownedEvaluationIdentity(self)) or
            !try source.circuit.outputsAreZero(self.values))
        {
            return error.ArithmeticAuthorityMismatch;
        }
    }

    pub fn loweringEvaluation(
        self: *const OwnedEvaluationV2,
        source: *const SourceV2,
    ) Error!lowering.Evaluation {
        try self.validateAgainst(source);
        return .{
            .circuit_identity = self.source_authority_digest,
            .values = self.values,
        };
    }
};

pub fn validateBufferGeometry(
    source: *const SourceV2,
    buffers: EvaluationBuffersV2,
) Error!void {
    if (buffers.destination_values.len != source.circuit.nodes().len or
        buffers.scratch_inputs.len != source.input_count or
        buffers.scratch_values.len != source.circuit.nodes().len or
        buffers.use_count_scratch.len != source.circuit.nodes().len)
    {
        return error.BufferLengthMismatch;
    }
}

pub fn rejectBufferAliases(
    source: *const SourceV2,
    prepared: *const public_source.PreparedV2,
    inputs: public_source.InputsV2,
    buffers: EvaluationBuffersV2,
) Error!void {
    const outputs = [_][]u8{
        std.mem.sliceAsBytes(buffers.destination_values),
        std.mem.sliceAsBytes(buffers.scratch_inputs),
        std.mem.sliceAsBytes(buffers.scratch_values),
        std.mem.sliceAsBytes(buffers.use_count_scratch),
    };
    const sources = [_][]const u8{
        std.mem.asBytes(source),
        std.mem.sliceAsBytes(source.circuit.nodes()),
        std.mem.sliceAsBytes(source.circuit.inputNodes()),
        std.mem.sliceAsBytes(source.circuit.outputs()),
        std.mem.sliceAsBytes(source.circuit.useCounts()),
        std.mem.sliceAsBytes(source.bindings),
        std.mem.sliceAsBytes(source.owned_graph.nodes),
        std.mem.sliceAsBytes(source.owned_graph.outputs),
        std.mem.asBytes(prepared),
        std.mem.asBytes(inputs.statement_source),
        std.mem.asBytes(inputs.owned_public_data),
        std.mem.sliceAsBytes(inputs.owned_public_data.canonical_words),
        std.mem.asBytes(inputs.publication),
        std.mem.asBytes(inputs.native_public_sums),
        std.mem.asBytes(inputs.verified_receipt),
        std.mem.asBytes(inputs.relations),
        std.mem.sliceAsBytes(inputs.component_descs),
        std.mem.sliceAsBytes(inputs.infra_descs),
    };
    for (outputs, 0..) |left, index| {
        for (outputs[index + 1 ..]) |right| if (overlap(left, right))
            return error.AliasedBuffer;
        for (sources) |right| if (overlap(left, right))
            return error.AliasedBuffer;
    }
}

pub fn authorityDigest(source: *const SourceV2) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(AUTHORITY_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, SCHEMA_VERSION);
    hashInt(&hash, u32, CIRCUIT_ID);
    hashInt(&hash, u32, source.wire_word_count);
    hashInt(&hash, u32, source.input_count);
    hashInt(&hash, u32, source.term_counts.registers_state);
    hashInt(&hash, u32, source.term_counts.memory_access);
    hashInt(&hash, u32, source.term_counts.program_access);
    hashInt(&hash, u32, source.term_counts.merkle);
    hashDigest(&hash, source.prepared_source_id);
    hashDigest(&hash, source.wire_id);
    hashDigest(&hash, source.manifest_id);
    hashDigest(&hash, source.lowering_obligation_id);
    hashDigest(&hash, source.publication_id);
    hashDigest(&hash, source.native_public_sums_id);
    hashDigest(&hash, source.relation_context_id);
    hash.update(&source.owned_graph.graph.identity_digest);
    hashInt(&hash, u32, @as(u32, @intCast(source.circuit.nodes().len)));
    hashInt(&hash, u32, @as(u32, @intCast(source.circuit.outputs().len)));
    for (source.circuit.useCounts()) |count| hashInt(&hash, u32, count);
    hashInt(&hash, u32, @as(u32, @intCast(source.bindings.len)));
    for (source.bindings) |binding| {
        hashInt(&hash, u32, binding.node_id);
        hashInt(&hash, u32, binding.use_count);
        const tag = std.meta.activeTag(binding.source);
        hashInt(&hash, u8, @intFromEnum(tag));
        switch (binding.source) {
            .wire_word => |index| hashInt(&hash, u32, index),
            .published_sum_word => |coordinate| {
                hashInt(&hash, u8, @intFromEnum(coordinate.domain));
                hashInt(&hash, u8, coordinate.limb);
                hashInt(&hash, u8, coordinate.publication_index);
            },
            .published_total_word => |coordinate| {
                hashInt(&hash, u8, coordinate.limb);
                hashInt(&hash, u8, coordinate.publication_index);
            },
            .native_challenge_word => |coordinate| {
                hashInt(&hash, u8, @intFromEnum(coordinate.relation));
                hashInt(&hash, u8, coordinate.limb);
            },
        }
    }
    return hash.finalResult();
}

pub fn ownedEvaluationIdentity(evaluation: *const OwnedEvaluationV2) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(EVALUATION_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, SCHEMA_VERSION);
    hash.update(&evaluation.source_authority_digest);
    hashInt(&hash, u32, @as(u32, @intCast(evaluation.values.len)));
    for (evaluation.values) |value| for (value.toM31Array()) |word|
        hashInt(&hash, u32, word.toU32());
    return hash.finalResult();
}

comptime {
    if (CIRCUIT_ID != 42 or DOMAIN_COUNT != 4 or
        PUBLISHED_WORD_COUNT != 20 or CHALLENGE_WORD_COUNT != 32 or
        OUTPUT_COUNT != 5 or HOT_HEAP_ALLOCATIONS != 0 or
        !DESTINATION_FAILS_ATOMICALLY or !POINTER_STABLE_OWNERSHIP or
        !EXACT_GRAPH_AND_USE_COUNTS_SEALED or
        !ROW11_OWNS_CANONICAL_PARSING or
        !GRAPH_OWNS_RELATION_ARITHMETIC or
        !PUBLISHED_SUMS_ARE_NOT_AUTHORITY)
    {
        @compileError("SegmentV2 native-sum arithmetic authority ABI drifted");
    }
}
