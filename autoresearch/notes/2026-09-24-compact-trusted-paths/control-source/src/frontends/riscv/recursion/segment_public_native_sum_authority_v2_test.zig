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
const fixed_profile = @import("fixed_profile.zig");
const protocol = @import("protocol.zig");
const channel = @import("poseidon2_channel.zig");
const schedule = @import("air/verifier_schedule.zig");
const register_bytes = @import("segment_register_byte_layout_v1.zig");
const lowering = @import("air/verifier_arithmetic_lowering.zig");

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
    const canonical = try fixture.owned_public.data.authenticatedView();
    const memory = try register_bytes.MemoryLayout.init(&canonical);
    var zero_bytes: u32 = 0;
    for (register_bytes.BYTE_COUNT..memory.byteCount()) |index|
        zero_bytes += @intFromBool(memory.value(canonical.words, index).isZero());
    // Graph inventory schedules zero-byte terms too; their exact selectors
    // make their contribution zero. The native oracle counts active terms.
    try std.testing.expectEqual(native_counts.merkle + zero_bytes, source.term_counts.merkle);
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
    const memory = try register_bytes.MemoryLayout.init(&try fixture.owned_public.data.authenticatedView());
    try std.testing.expectEqual(
        wire_count + subject.PUBLISHED_WORD_COUNT +
            subject.CHALLENGE_WORD_COUNT + memory.totalBridgeWords(),
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
        } else if (suffix < subject.PUBLISHED_WORD_COUNT + subject.CHALLENGE_WORD_COUNT) {
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
        } else {
            const byte = suffix - subject.PUBLISHED_WORD_COUNT - subject.CHALLENGE_WORD_COUNT;
            if (byte < register_bytes.BYTE_COUNT) {
                try std.testing.expectEqual(@as(u8, @intCast(byte)), binding.source.register_byte);
            } else if (byte < memory.byteCount()) {
                try std.testing.expectEqual(@as(u32, @intCast(byte - register_bytes.BYTE_COUNT)), binding.source.memory_byte);
            } else {
                try std.testing.expectEqual(@as(u32, @intCast(byte - memory.byteCount())), binding.source.memory_selector);
            }
        }
    }
}

test "SegmentV2 native-sum register inputs preserve graph and preprocessing across canonical statements" {
    const allocator = std.testing.allocator;
    var first = try Fixture.initWithRegister7(allocator, 0x01020304);
    defer first.deinit();
    var second = try Fixture.initWithRegister7(allocator, 0x05060708);
    defer second.deinit();
    const first_prepared = try public_source.preflight(first.inputs());
    const second_prepared = try public_source.preflight(second.inputs());
    var first_source = try subject.SourceV2.init(allocator, &first_prepared, first.inputs());
    defer first_source.deinit();
    var second_source = try subject.SourceV2.init(allocator, &second_prepared, second.inputs());
    defer second_source.deinit();
    try std.testing.expect(!std.meta.eql(first_source.wire_id, second_source.wire_id));
    try std.testing.expectEqualDeep(first_prepared.manifest.log_sizes, second_prepared.manifest.log_sizes);
    try std.testing.expectEqualSlices(@import("air/composition_circuit.zig").Node, first_source.owned_graph.nodes, second_source.owned_graph.nodes);
    try std.testing.expectEqualSlices(u32, first_source.owned_graph.outputs, second_source.owned_graph.outputs);
    try std.testing.expectEqualDeep(first_source.owned_graph.graph.identity_digest, second_source.owned_graph.graph.identity_digest);
    try std.testing.expectEqualDeep(first_source.bindings, second_source.bindings);

    // The shared lowering owner requires both proof modes. Keep one identical
    // companion lane in both plans; only the segment lane varies in this test.
    var companion = first_source.loweringLane();
    companion.active_in = .binary;
    companion.circuit_id += 1;
    const first_lanes = [_]lowering.Lane{ first_source.loweringLane(), companion };
    const second_lanes = [_]lowering.Lane{ second_source.loweringLane(), companion };
    var first_plan = try lowering.Plan.init(allocator, try lowering.Reference.seal(&first_lanes));
    defer first_plan.deinit();
    var second_plan = try lowering.Plan.init(allocator, try lowering.Reference.seal(&second_lanes));
    defer second_plan.deinit();
    try std.testing.expectEqualDeep(first_plan.multiply_rows, second_plan.multiply_rows);
    try std.testing.expectEqualDeep(first_plan.inverse_rows, second_plan.inverse_rows);
    try std.testing.expectEqualDeep(first_plan.linear_rows, second_plan.linear_rows);
    try std.testing.expectEqualDeep(first_plan.public_terms, second_plan.public_terms);

    var first_values = try OwnedEvaluation.init(allocator, &first_source);
    defer first_values.deinit();
    var second_values = try OwnedEvaluation.init(allocator, &second_source);
    defer second_values.deinit();
    _ = try first_source.evaluateInto(&first_prepared, first.inputs(), first_values.buffers());
    _ = try second_source.evaluateInto(&second_prepared, second.inputs(), second_values.buffers());
    try std.testing.expect(!std.meta.eql(first_values.destinationDigest(), second_values.destinationDigest()));
    const byte_index = register_bytes.byteIndex(.entry, 7, 0);
    const existing_inputs = first.owned_public.data.words().len + subject.PUBLISHED_WORD_COUNT + subject.CHALLENGE_WORD_COUNT;
    const input_index = register_bytes.inputIndex(existing_inputs, byte_index);
    try std.testing.expect(first_source.bindings[input_index].use_count > 0);
    try std.testing.expectEqual(@as(u32, 4), first_values.scratch_inputs[input_index].toM31Array()[0].toU32());
    try std.testing.expectEqual(@as(u32, 8), second_values.scratch_inputs[input_index].toM31Array()[0].toU32());
    // Even a canonical byte cannot be substituted while preserving the native
    // public sums. Row11/15 relation tests separately prove the byte's source.
    first_values.scratch_inputs[input_index] = QM31.fromBase(M31.fromCanonical(5));
    try first_source.circuit.evaluateIntoAssumeValid(first_values.scratch_inputs, first_values.scratch_values);
    try std.testing.expect(!try first_source.circuit.outputsAreZero(first_values.scratch_values));
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
    @constCast(fixture.owned_public.canonical_words)[last] =
        saved_word.add(M31.one());
    try expectEvaluationFailure(
        &source,
        &prepared,
        fixture.inputs(),
        owned.buffers(),
    );
    @constCast(fixture.owned_public.canonical_words)[last] = saved_word;
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
    vm_plan: schedule.Plan,

    fn init(allocator: std.mem.Allocator) !EmptyFixture {
        const support = try public_data_support.Fixture.init();
        var segment = support.rightSource();
        segment.memory_words = &.{};
        segment.entry_memory_clocks = &.{};
        segment.exit_memory_clocks = &.{};
        const empty_snapshot = @import("segment_statement_v2.zig").snapshotDigest(&.{}, .initial_word).id;
        segment.base_statement.job.complete.initial_state.rw_memory = empty_snapshot;
        segment.base_statement.job.complete.final_state.rw_memory = empty_snapshot;
        segment.base_statement.body.executed.entry.rw_memory = empty_snapshot;
        segment.base_statement.body.executed.exit.rw_memory = empty_snapshot;
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
        var vm_plan = try schedule.Plan.initShape(
            allocator,
            schedule.VM_PROGRAM_SPEC_V1,
            .{
                .protocol_id = channel.hashBytes("native-sum-v2-protocol", 0x4e53_5632),
                .shape_id = channel.hashBytes("native-sum-v2-shape", 0x4e53_5653),
                .interaction_pow_bits = 0,
                .pcs_pow_bits = protocol.PCS_POW_BITS,
                .query_count = 1,
                .table_count = 4,
                .claimed_sum_count = 4,
                .sampled_value_count = 8,
                .tree_heights = .{ 9, 9, 9, 9 },
                .fri = try fixed_profile.FriSchedule.init(
                    8,
                    protocol.PCS_CONFIG.fri_config,
                ),
            },
        );
        errdefer vm_plan.deinit();
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
            .vm_plan = vm_plan,
        };
    }

    fn deinit(self: *EmptyFixture) void {
        self.vm_plan.deinit();
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
            .vm_plan = &self.vm_plan,
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

test "SegmentV2 native-sum graph independently binds every Span snapshot digest limb" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit();
    const prepared = try public_source.preflight(fixture.inputs());
    var source = try subject.SourceV2.init(allocator, &prepared, fixture.inputs());
    defer source.deinit();
    var owned = try OwnedEvaluation.init(allocator, &source);
    defer owned.deinit();
    _ = try source.evaluateInto(&prepared, fixture.inputs(), owned.buffers());
    const wire = @import("segment_statement_v2.zig");
    const span = @import("span_statement.zig");
    const relation_output_count = subject.DOMAIN_COUNT + 1;
    try std.testing.expectEqual(relation_output_count + 16, source.circuit.outputs().len);
    inline for (.{
        .{ span.canonical_layout.entry_state_start, wire.fixed_layout.entry_snapshot_id },
        .{ span.canonical_layout.exit_state_start, wire.fixed_layout.exit_snapshot_id },
    }, 0..) |side, side_index| {
        const state_start = wire.fixed_layout.base_statement + side[0] + span.canonical_layout.machine_state_rw_digest_start_offset;
        for (0..8) |limb| {
            // Exercise both directions without a host admission call masking
            // the AIR relation: only one independent equality may fail.
            for ([_]usize{ state_start + limb, side[1] + limb }) |input_index| {
                const original = owned.scratch_inputs[input_index];
                defer owned.scratch_inputs[input_index] = original;
                owned.scratch_inputs[input_index] = original.add(QM31.one());
                try source.circuit.evaluateIntoAssumeValid(owned.scratch_inputs, owned.scratch_values);
                try std.testing.expect(!try source.circuit.outputsAreZero(owned.scratch_values));
                for (source.circuit.outputs(), 0..) |output, output_index| {
                    try std.testing.expectEqual(
                        output_index != relation_output_count + side_index * 8 + limb,
                        owned.scratch_values[output].isZero(),
                    );
                }
            }
        }
    }
    try source.circuit.evaluateIntoAssumeValid(owned.scratch_inputs, owned.scratch_values);
    try std.testing.expect(try source.circuit.outputsAreZero(owned.scratch_values));
}

const sparseValueCanonicalWords = public_data_support.sparseValueCanonicalWords;

test "SegmentV2 native-sum sparse values preserve fixed graph under identical address topology" {
    const allocator = std.testing.allocator;
    const segment = @import("segment_statement_v2.zig");
    const graph_contract = @import("segment_public_native_sum_authority_v2_contract.zig");
    const graph_builder = @import("segment_public_native_sum_authority_v2_add_boundary_terms.zig");
    const values = [_]u32{ 13, 14, 269 };
    var graphs: [values.len]graph_contract.OwnedGraph = undefined;
    var initialized: usize = 0;
    defer for (graphs[0..initialized]) |*graph| graph.deinit();
    var counts: [values.len]graph_contract.TermCountsV2 = undefined;
    var native_totals: [values.len]QM31 = undefined;
    var first_words: ?[]M31 = null;
    defer if (first_words) |words| allocator.free(words);
    for (values, 0..) |value, index| {
        const words = try sparseValueCanonicalWords(allocator, value);
        defer if (index != 0) allocator.free(words);
        if (index == 0) first_words = words;
        const view = try segment.authenticateCanonicalWire(words);
        const baseline = try segment.authenticateCanonicalWire(first_words.?);
        try std.testing.expectEqual(baseline.words.len, view.words.len);
        inline for (.{ "entry_snapshot", "exit_snapshot", "entry_memory_clocks", "exit_memory_clocks" }) |field| {
            const before = @field(baseline, field);
            const after = @field(view, field);
            try std.testing.expectEqual(before.count, after.count);
            for (0..before.count) |row| {
                // All retained sections begin each row with canonical address
                // limbs; counts and membership are the admitted topology here.
                const before_address = baseline.words[before.payload_start + row * segment.RETAINED_ENTRY_WORDS ..][0..2];
                const after_address = view.words[after.payload_start + row * segment.RETAINED_ENTRY_WORDS ..][0..2];
                try std.testing.expectEqualSlices(M31, before_address, after_address);
            }
        }
        var authored = try graph_builder.buildGraph(allocator, &view);
        defer authored.circuit.deinit();
        graphs[index] = try graph_contract.OwnedGraph.init(allocator, &authored.circuit);
        initialized += 1;
        counts[index] = authored.term_counts;
        native_totals[index] = try evaluateSparseCanonicalGraph(allocator, &authored.circuit, words);
    }
    var plans: [values.len]lowering.Plan = undefined;
    var plan_count: usize = 0;
    defer for (plans[0..plan_count]) |*plan| plan.deinit();
    const companion = lowering.Lane{ .circuit_id = subject.CIRCUIT_ID + 1, .active_in = .binary, .circuit_identity = graphs[0].graph.identity_digest, .graph = graphs[0].graph };
    for (&graphs, 0..) |*graph, index| {
        const lanes = [_]lowering.Lane{ .{ .circuit_id = subject.CIRCUIT_ID, .active_in = .segment, .circuit_identity = graph.graph.identity_digest, .graph = graph.graph }, companion };
        plans[index] = try lowering.Plan.init(allocator, try lowering.Reference.seal(&lanes));
        plan_count += 1;
        std.debug.print("SEGMENT_V2_SPARSE_SPECIALIZATION value={d} nodes={d} merkle_terms={d} public_terms={d} graph_sha256={s} native_proof_created=false\n", .{
            values[index],                                           graph.nodes.len, counts[index].merkle, plans[index].public_terms.len,
            std.fmt.bytesToHex(graph.graph.identity_digest, .lower),
        });
    }
    // The retained 13/14/269 regression previously changed graph constants
    // and, when a second byte became nonzero, the operation schedule. All
    // three now use one graph and fixed lowering anchors. Native sums and
    // witness evaluation must still respond to the actual values.
    for (1..values.len) |index| {
        try std.testing.expectEqualDeep(graphs[0].graph.identity_digest, graphs[index].graph.identity_digest);
        try std.testing.expectEqualDeep(graphs[0].nodes, graphs[index].nodes);
        try std.testing.expect(sparseSpecializationTermsEqual(plans[0].public_terms, plans[index].public_terms));
        try std.testing.expectEqualDeep(plans[0].multiply_rows, plans[index].multiply_rows);
        try std.testing.expectEqualDeep(plans[0].inverse_rows, plans[index].inverse_rows);
        try std.testing.expectEqualDeep(plans[0].linear_rows, plans[index].linear_rows);
        try std.testing.expectEqualDeep(counts[0], counts[index]);
        try std.testing.expect(!native_totals[0].eql(native_totals[index]));
    }
}

fn sparseSpecializationTermsEqual(left: []const lowering.PublicWireTerm, right: []const lowering.PublicWireTerm) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b| if (!std.meta.eql(a, b)) return false;
    return true;
}

// Independent input construction for the production graph, using its shared
// typed coordinates and the native public-sum oracle. No native verification
// receipt is fabricated just to exercise an arithmetic compiler regression.
fn evaluateSparseCanonicalGraph(allocator: std.mem.Allocator, circuit: *const @import("arithmetic_circuit.zig").Circuit, words: []const M31) !QM31 {
    const build = @import("segment_public_native_sum_authority_v2_add_boundary_terms.zig");
    const data = try public_data_v2.PublicDataV2.authenticate(words);
    const view = try data.authenticatedView();
    const memory = try register_bytes.MemoryLayout.init(&view);
    const relations = native_relations.Relations.dummy();
    const sums = try native_statement.NativePublicSums.init(&data, &relations);
    const domain_sums = [_]QM31{ sums.sums.registers_state, sums.sums.memory_access, sums.sums.program_access, sums.sums.merkle };
    const challenges = [_][2]QM31{
        .{ relations.registers_state.z, relations.registers_state.alpha },
        .{ relations.memory_access.z, relations.memory_access.alpha },
        .{ relations.program_access.z, relations.program_access.alpha },
        .{ relations.merkle.z, relations.merkle.alpha },
    };
    const inputs = try allocator.alloc(QM31, circuit.inputNodes().len);
    defer allocator.free(inputs);
    for (inputs, 0..) |*input, index| {
        const coordinate = try build.inputSource(@intCast(words.len), @intCast(memory.memoryByteCount()), index);
        const word = switch (coordinate) {
            .wire_word => |i| words[i],
            .published_sum_word => |c| domain_sums[@intFromEnum(c.domain)].toM31Array()[c.limb],
            .published_total_word => |c| sums.total.toM31Array()[c.limb],
            .native_challenge_word => |c| challenges[@intFromEnum(c.relation)][c.limb / 4].toM31Array()[c.limb % 4],
            .register_byte => |i| register_bytes.value(words, i),
            .memory_byte => |i| memory.value(words, register_bytes.BYTE_COUNT + i),
            .memory_selector => |i| M31.fromCanonical(@intFromBool(!memory.value(words, register_bytes.BYTE_COUNT + i).isZero())),
        };
        input.* = QM31.fromBase(word);
    }
    var evaluation = try circuit.evaluate(allocator, inputs);
    defer evaluation.deinit();
    try std.testing.expect(try circuit.outputsAreZero(evaluation.values));
    var byte_input: ?usize = null;
    var selector_input: ?usize = null;
    for (inputs, 0..) |_, index| {
        switch (try build.inputSource(@intCast(words.len), @intCast(memory.memoryByteCount()), index)) {
            .memory_byte => |i| if (i == 0) {
                byte_input = index;
            },
            .memory_selector => |i| if (i == 0) {
                selector_input = index;
            },
            else => {},
        }
    }
    for ([_]usize{ byte_input.?, selector_input.? }) |index| {
        const saved = inputs[index];
        defer inputs[index] = saved;
        inputs[index] = if (index == selector_input.?) QM31.zero() else saved.add(QM31.one());
        var changed = try circuit.evaluate(allocator, inputs);
        defer changed.deinit();
        try std.testing.expect(!try circuit.outputsAreZero(changed.values));
    }
    return sums.total;
}
