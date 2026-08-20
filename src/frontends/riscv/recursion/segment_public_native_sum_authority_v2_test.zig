//! Focused parity, custody, mutation and hot-path tests for the SegmentV2
//! native-public-sum arithmetic authority.

const std = @import("std");
const stwo_core = @import("stwo_core");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const public_data_v2 = @import("../air/public_data_v2.zig");
const public_data_support = @import("../air/public_data_v2_test_support.zig");
const native_relations = @import("../air/relation_challenges.zig");
const statement_v1 = @import("../air/statement.zig");
const native_statement = @import("../air/statement_v2.zig");
const leaf_source = @import("segment_leaf_authority_v2.zig");
const public_source = @import("segment_public_outer_source_v2.zig");
const subject = @import("segment_public_native_sum_authority_v2.zig");
const fixture_support = @import("segment_public_outer_test_support.zig");

const Fixture = fixture_support.Fixture;

test "SegmentV2 native-sum graph exactly replays all four domains and total" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const prepared = try public_source.preflight(fixture.inputs());
    var source = try subject.SourceV2.init(
        std.testing.allocator,
        &prepared,
        fixture.inputs(),
    );
    defer source.deinit();

    var owned = try OwnedEvaluation.init(std.testing.allocator, &source);
    defer owned.deinit();
    const evaluation = try source.evaluateInto(
        &prepared,
        fixture.inputs(),
        owned.buffers(),
    );
    try std.testing.expectEqual(source.nodeCount(), evaluation.values.len);
    try std.testing.expectEqualDeep(source.authority_digest, evaluation.circuit_identity);
    try std.testing.expect(try source.circuit.outputsAreZero(evaluation.values));
    for (source.circuit.outputs()) |output|
        try std.testing.expect(evaluation.values[output].isZero());

    const native_counts = try native_statement.nativePublicTermCounts(
        &fixture.owned_public.data,
    );
    try std.testing.expectEqual(@as(u32, 2), source.term_counts.registers_state);
    try std.testing.expectEqual(native_counts.memory, source.term_counts.memory_access);
    try std.testing.expectEqual(native_counts.merkle, source.term_counts.merkle);
    try std.testing.expect(source.term_counts.total() > 0);

    const lane = source.loweringLane();
    try std.testing.expectEqual(subject.CIRCUIT_ID, lane.circuit_id);
    try std.testing.expectEqualDeep(source.authority_digest, lane.circuit_identity);
    try std.testing.expectEqual(source.owned_graph.nodes.ptr, lane.graph.nodes.ptr);
    try lane.graph.validate();
}

test "SegmentV2 native-sum graph pins dense input and circuit-44 bridge order" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const prepared = try public_source.preflight(fixture.inputs());
    var source = try subject.SourceV2.init(
        std.testing.allocator,
        &prepared,
        fixture.inputs(),
    );
    defer source.deinit();

    const wire_count = fixture.owned_public.data.words().len;
    try std.testing.expectEqual(
        wire_count + subject.PUBLISHED_WORD_COUNT +
            subject.CHALLENGE_WORD_COUNT,
        source.bindings.len,
    );
    for (source.bindings, 0..) |binding, index| {
        try std.testing.expectEqual(@as(u32, @intCast(index)), binding.node_id);
        try std.testing.expectEqual(
            try source.circuit.inputUseCount(@intCast(index)),
            binding.use_count,
        );
        if (index < wire_count) {
            try std.testing.expectEqual(
                @as(u32, @intCast(index)),
                binding.source.wire_word,
            );
            continue;
        }
        const suffix = index - wire_count;
        if (suffix < 16) {
            const coordinate = binding.source.published_sum_word;
            try std.testing.expectEqual(
                @as(u8, @intCast(public_source.PUBLICATION_SUM_START + suffix)),
                coordinate.publication_index,
            );
        } else if (suffix < 20) {
            const coordinate = binding.source.published_total_word;
            try std.testing.expectEqual(
                @as(u8, @intCast(
                    public_source.PUBLICATION_SEAL_START + suffix - 16,
                )),
                coordinate.publication_index,
            );
        } else {
            const coordinate = binding.source.native_challenge_word;
            const challenge_index = suffix - subject.PUBLISHED_WORD_COUNT;
            try std.testing.expectEqual(
                @as(u8, @intCast(challenge_index / 8)),
                @intFromEnum(coordinate.relation),
            );
            try std.testing.expectEqual(
                @as(u3, @intCast(challenge_index % 8)),
                coordinate.limb,
            );
        }
    }
}

test "SegmentV2 native-sum owned evaluation is a compact lowering handoff" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const prepared = try public_source.preflight(fixture.inputs());
    var source = try subject.SourceV2.init(
        std.testing.allocator,
        &prepared,
        fixture.inputs(),
    );
    defer source.deinit();

    var owned = try subject.OwnedEvaluationV2.init(
        std.testing.allocator,
        &source,
        &prepared,
        fixture.inputs(),
    );
    const values_pointer = owned.values.ptr;
    var moved = owned;
    owned = undefined;
    defer moved.deinit();
    try std.testing.expectEqual(values_pointer, moved.values.ptr);

    const evaluation = try moved.loweringEvaluation(&source);
    try std.testing.expectEqual(source.nodeCount(), evaluation.values.len);
    try std.testing.expectEqualDeep(
        source.authority_digest,
        evaluation.circuit_identity,
    );
    try std.testing.expect(try source.circuit.outputsAreZero(evaluation.values));

    const output = source.circuit.outputs()[0];
    moved.values[output] = QM31.one();
    try std.testing.expectError(
        error.ArithmeticAuthorityMismatch,
        moved.loweringEvaluation(&source),
    );
}

test "SegmentV2 native-sum hot evaluation is destination-fail-atomic" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const prepared = try public_source.preflight(fixture.inputs());
    var source = try subject.SourceV2.init(
        std.testing.allocator,
        &prepared,
        fixture.inputs(),
    );
    defer source.deinit();
    var owned = try OwnedEvaluation.init(std.testing.allocator, &source);
    defer owned.deinit();
    owned.fillDestinationSentinel();
    const before = owned.destinationDigest();

    var bad_prepared = prepared;
    bad_prepared.public_sums.merkle = bad_prepared.public_sums.merkle.add(QM31.one());
    try expectEvaluationFailure(
        &source,
        &bad_prepared,
        fixture.inputs(),
        owned.buffers(),
    );
    try std.testing.expectEqual(before, owned.destinationDigest());

    const saved_relations = fixture.relations;
    fixture.relations.memory_access.alpha =
        fixture.relations.memory_access.alpha.add(QM31.one());
    try expectEvaluationFailure(
        &source,
        &prepared,
        fixture.inputs(),
        owned.buffers(),
    );
    fixture.relations = saved_relations;
    try std.testing.expectEqual(before, owned.destinationDigest());

    const last = fixture.owned_public.canonical_words.len - 1;
    const saved_word = fixture.owned_public.canonical_words[last];
    fixture.owned_public.canonical_words[last] = saved_word.add(M31.one());
    try expectEvaluationFailure(
        &source,
        &prepared,
        fixture.inputs(),
        owned.buffers(),
    );
    fixture.owned_public.canonical_words[last] = saved_word;
    try std.testing.expectEqual(before, owned.destinationDigest());

    var aliased = owned.buffers();
    aliased.scratch_values = aliased.destination_values;
    try std.testing.expectError(
        error.AliasedBuffer,
        source.evaluateInto(&prepared, fixture.inputs(), aliased),
    );
    try std.testing.expectEqual(before, owned.destinationDigest());

    var short = owned.buffers();
    short.destination_values = short.destination_values[0 .. short.destination_values.len - 1];
    try std.testing.expectError(
        error.BufferLengthMismatch,
        source.evaluateInto(&prepared, fixture.inputs(), short),
    );
    try std.testing.expectEqual(before, owned.destinationDigest());
}

test "SegmentV2 native-sum graph ownership survives moves and detects mutations" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const prepared = try public_source.preflight(fixture.inputs());
    var source = try subject.SourceV2.init(
        std.testing.allocator,
        &prepared,
        fixture.inputs(),
    );
    const graph_pointer = source.owned_graph.nodes.ptr;
    var moved = source;
    source = undefined;
    defer moved.deinit();
    try std.testing.expectEqual(graph_pointer, moved.owned_graph.graph.nodes.ptr);

    const scratch = try std.testing.allocator.alloc(u32, moved.nodeCount());
    defer std.testing.allocator.free(scratch);
    try moved.validateInto(&prepared, fixture.inputs(), scratch);

    moved.owned_graph.outputs[0] ^= 1;
    if (moved.validateInto(&prepared, fixture.inputs(), scratch)) |_| {
        return error.TestExpectedError;
    } else |_| {}
}

test "SegmentV2 native-sum graph applies empty continuation-root compensation" {
    var fixture = try EmptyFixture.init(std.testing.allocator);
    defer fixture.deinit();
    const prepared = try public_source.preflight(fixture.inputs());
    var source = try subject.SourceV2.init(
        std.testing.allocator,
        &prepared,
        fixture.inputs(),
    );
    defer source.deinit();
    try std.testing.expectEqual(@as(u32, 64), source.term_counts.memory_access);
    try std.testing.expectEqual(@as(u32, 5), source.term_counts.merkle);
    try std.testing.expectEqual(@as(u32, 1), source.term_counts.program_access);

    var owned = try OwnedEvaluation.init(std.testing.allocator, &source);
    defer owned.deinit();
    const evaluation = try source.evaluateInto(
        &prepared,
        fixture.inputs(),
        owned.buffers(),
    );
    try std.testing.expect(try source.circuit.outputsAreZero(evaluation.values));
}

test "SegmentV2 native-sum performance and custody flags remain fail closed" {
    try std.testing.expectEqual(@as(usize, 0), subject.HOT_HEAP_ALLOCATIONS);
    try std.testing.expect(subject.DESTINATION_FAILS_ATOMICALLY);
    try std.testing.expect(subject.POINTER_STABLE_OWNERSHIP);
    try std.testing.expect(subject.EXACT_GRAPH_AND_USE_COUNTS_SEALED);
    try std.testing.expect(subject.ROW11_OWNS_CANONICAL_PARSING);
    try std.testing.expect(subject.GRAPH_OWNS_RELATION_ARITHMETIC);
    try std.testing.expect(subject.PUBLISHED_SUMS_ARE_NOT_AUTHORITY);
}

const OwnedEvaluation = struct {
    allocator: std.mem.Allocator,
    destination: []QM31,
    scratch_inputs: []QM31,
    scratch_values: []QM31,
    use_count_scratch: []u32,

    fn init(
        allocator: std.mem.Allocator,
        source: *const subject.SourceV2,
    ) !OwnedEvaluation {
        const destination = try allocator.alloc(QM31, source.nodeCount());
        errdefer allocator.free(destination);
        const scratch_inputs = try allocator.alloc(QM31, source.input_count);
        errdefer allocator.free(scratch_inputs);
        const scratch_values = try allocator.alloc(QM31, source.nodeCount());
        errdefer allocator.free(scratch_values);
        const use_count_scratch = try allocator.alloc(u32, source.nodeCount());
        errdefer allocator.free(use_count_scratch);
        return .{
            .allocator = allocator,
            .destination = destination,
            .scratch_inputs = scratch_inputs,
            .scratch_values = scratch_values,
            .use_count_scratch = use_count_scratch,
        };
    }

    fn deinit(self: *OwnedEvaluation) void {
        self.allocator.free(self.use_count_scratch);
        self.allocator.free(self.scratch_values);
        self.allocator.free(self.scratch_inputs);
        self.allocator.free(self.destination);
        self.* = undefined;
    }

    fn buffers(self: *OwnedEvaluation) subject.EvaluationBuffersV2 {
        return .{
            .destination_values = self.destination,
            .scratch_inputs = self.scratch_inputs,
            .scratch_values = self.scratch_values,
            .use_count_scratch = self.use_count_scratch,
        };
    }

    fn fillDestinationSentinel(self: *OwnedEvaluation) void {
        for (self.destination, 0..) |*value, index| {
            value.* = QM31.fromU32Unchecked(
                @intCast(index + 1),
                17,
                23,
                41,
            );
        }
    }

    fn destinationDigest(self: *const OwnedEvaluation) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        for (self.destination) |value| {
            for (value.toM31Array()) |word| {
                var bytes: [4]u8 = undefined;
                std.mem.writeInt(u32, &bytes, word.toU32(), .little);
                hash.update(&bytes);
            }
        }
        return hash.finalResult();
    }
};

const EmptyFixture = struct {
    allocator: std.mem.Allocator,
    owned_public: native_statement.OwnedPublicDataV2,
    keys: leaf_source.VerifierKeyAuthorityV2,
    source_trace: OwnedSourceTrace,
    source_prepared: leaf_source.PreparedV2,
    relations: native_relations.Relations,
    native_sums: native_statement.NativePublicSums,
    receipt: native_statement.VerifiedReceipt,
    publication: leaf_source.VerifiedNativePublicLogUpPublicationV2,

    fn init(allocator: std.mem.Allocator) !EmptyFixture {
        const support = try public_data_support.Fixture.init();
        var segment = support.rightSource();
        segment.memory_words = &.{};
        segment.entry_memory_clocks = &.{};
        segment.exit_memory_clocks = &.{};
        const words = try public_data_support.encode(allocator, &segment);
        defer allocator.free(words);
        const borrowed = try public_data_v2.PublicDataV2.authenticate(words);
        var owned_public = try native_statement.OwnedPublicDataV2.initVerified(
            allocator,
            &borrowed,
        );
        errdefer owned_public.deinit();
        const keys = try leaf_source.VerifierKeyAuthorityV2.init(
            public_data_support.id("native-sum-empty-leaf-vk"),
            public_data_support.id("native-sum-empty-parent-vk"),
        );
        const shape = try leaf_source.preflight(&owned_public.data, &keys);
        var source_trace = try OwnedSourceTrace.init(
            allocator,
            shape.manifest.trace_row_count,
        );
        errdefer source_trace.deinit();
        var source_prepared: leaf_source.PreparedV2 = undefined;
        try leaf_source.prepareInto(
            &source_prepared,
            source_trace.columns(),
            &owned_public.data,
            &keys,
        );
        const relations = native_relations.Relations.dummy();
        const native_sums = try native_statement.NativePublicSums.init(
            &owned_public.data,
            &relations,
        );
        const receipt = try emptyVerifiedReceipt(&owned_public.data);
        var publication: leaf_source.VerifiedNativePublicLogUpPublicationV2 =
            undefined;
        try leaf_source.prepareVerifiedNativePublicLogUpInto(
            &publication,
            &source_prepared,
            &owned_public.data,
            &relations,
            &native_sums,
            &receipt,
            &fixture_support.component_descs,
            &fixture_support.infra_descs,
        );
        return .{
            .allocator = allocator,
            .owned_public = owned_public,
            .keys = keys,
            .source_trace = source_trace,
            .source_prepared = source_prepared,
            .relations = relations,
            .native_sums = native_sums,
            .receipt = receipt,
            .publication = publication,
        };
    }

    fn deinit(self: *EmptyFixture) void {
        self.source_trace.deinit();
        self.owned_public.deinit();
        self.* = undefined;
    }

    fn inputs(self: *const EmptyFixture) public_source.InputsV2 {
        return .{
            .statement_source = &self.source_prepared,
            .owned_public_data = &self.owned_public,
            .publication = &self.publication,
            .native_public_sums = &self.native_sums,
            .verified_receipt = &self.receipt,
            .relations = &self.relations,
            .component_descs = &fixture_support.component_descs,
            .infra_descs = &fixture_support.infra_descs,
        };
    }
};

const OwnedSourceTrace = struct {
    allocator: std.mem.Allocator,
    active: []M31,
    scope: []M31,
    index: []M31,
    value: []M31,

    fn init(allocator: std.mem.Allocator, rows: usize) !OwnedSourceTrace {
        const active = try allocator.alloc(M31, rows);
        errdefer allocator.free(active);
        const scope = try allocator.alloc(M31, rows);
        errdefer allocator.free(scope);
        const index = try allocator.alloc(M31, rows);
        errdefer allocator.free(index);
        const value = try allocator.alloc(M31, rows);
        errdefer allocator.free(value);
        return .{
            .allocator = allocator,
            .active = active,
            .scope = scope,
            .index = index,
            .value = value,
        };
    }

    fn deinit(self: *OwnedSourceTrace) void {
        self.allocator.free(self.value);
        self.allocator.free(self.index);
        self.allocator.free(self.scope);
        self.allocator.free(self.active);
        self.* = undefined;
    }

    fn columns(self: *OwnedSourceTrace) leaf_source.TraceColumnsV2 {
        return .{
            .active = self.active,
            .scope = self.scope,
            .index = self.index,
            .value = self.value,
        };
    }
};

fn emptyVerifiedReceipt(
    data: *const public_data_v2.PublicDataV2,
) !native_statement.VerifiedReceipt {
    var components: [statement_v1.MAX_COMPONENTS]statement_v1.FamilyComponentDesc =
        undefined;
    components[0] = fixture_support.component_descs[0];
    var infra: [statement_v1.MAX_INFRA_COMPONENTS]statement_v1.InfraComponentDesc =
        undefined;
    infra[0] = fixture_support.infra_descs[0];
    const core_public = try native_statement.canonicalCorePublicData(data);
    const core = statement_v1.RiscVStatement{
        .n_components = 1,
        .component_descs = components,
        .initial_pc = core_public.initial_pc,
        .final_pc = core_public.final_pc,
        .total_steps = core_public.clock,
        .public_data = core_public,
        .n_infra = 1,
        .infra_descs = infra,
    };
    const statement = try native_statement.RiscVStatementV2.init(core, data.*);
    return statement.verifiedReceipt();
}

fn expectEvaluationFailure(
    source: *const subject.SourceV2,
    prepared: *const public_source.PreparedV2,
    inputs: public_source.InputsV2,
    buffers: subject.EvaluationBuffersV2,
) !void {
    if (source.evaluateInto(prepared, inputs, buffers)) |_| {
        return error.TestExpectedError;
    } else |_| {}
}
