//! Canonical two-leaf Span fold, recorded from the existing statement circuit.
//! Child words have only boundary-graph provenance; parent words must be bound
//! to the independently published parent statement. This is an AIR preparation
//! owner, not a proof receipt. V2 lineage/hash and provider closure remain the
//! surrounding parent profile's obligations.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const recursion = frontend.recursion;
const span = recursion.span_statement;
const semantics = recursion.statement_semantics_circuit;
const statement_input = recursion.air.statement_input;
const recorder = recursion.air.composition_graph_recorder;
const boundary = @import("recursive_segment_v2_detached_boundary.zig");
const S = recorder.Scalar;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Words = span.StatementWords;
const WORD_COUNT = span.SPAN_STATEMENT_CANONICAL_WORDS;
pub const InputSource = union(enum) {
    child: struct { child: u1, boundary_node: u32, word: u32, projection: enum { span, raw } = .span },
    parent_word: u16,
    hint: struct { instance: u2, semantic_input: u32 },
    word_bit: struct { statement: u2, word: u16, bit: u4 },
};
pub const InputBinding = struct { node_id: u32, source: InputSource };

pub const OwnedV1 = opaque {
    const Storage = struct {
        allocator: std.mem.Allocator,
        semantics: semantics.Circuit,
        circuit: recorder.Circuit,
        inputs: []QM31,
        bindings: []InputBinding,
        values: []QM31,
        words: [3]Words,
        boundary_graphs: [2][32]u8,
    };
    fn storage(self: *const OwnedV1) *const Storage {
        return @ptrCast(@alignCast(self));
    }
    pub fn init(allocator: std.mem.Allocator, left: *const boundary.OwnedV1, right: *const boundary.OwnedV1) !*OwnedV1 {
        const children = [_]*const boundary.OwnedV1{ left, right };
        var words: [3]Words = undefined;
        for (children, 0..) |child, index| for (&words[index], child.spanNodes()) |*word, node| {
            if (node >= child.evaluatedValues().len) return error.InvalidParentProjection;
            word.* = try child.evaluatedValues()[node].tryIntoM31();
        };
        const left_span = try span.SpanStatement.fromCanonicalWords(&words[0]);
        const right_span = try span.SpanStatement.fromCanonicalWords(&words[1]);
        const parent = try span.SpanStatement.fold(left_span, right_span);
        _ = try span.RootStatement.init(parent);
        words[2] = try parent.canonicalWords();
        var semantic = try semantics.build(allocator);
        errdefer semantic.deinit();
        var builder = recorder.Builder.init(allocator);
        defer builder.deinit();
        var inputs: std.ArrayList(QM31) = .empty;
        defer inputs.deinit(allocator);
        var bindings: std.ArrayList(InputBinding) = .empty;
        defer bindings.deinit(allocator);
        const Range = struct { value: S, bits: [16]S };
        var ranges: std.ArrayList(Range) = .empty;
        defer ranges.deinit(allocator);
        var word_nodes: [3][WORD_COUNT]S = undefined;
        for (&word_nodes, words, 0..) |*nodes, values, index| for (nodes, values, 0..) |*node, value, word| {
            const input = try builder.input();
            node.* = input.value;
            try inputs.append(allocator, QM31.fromBase(value));
            try bindings.append(allocator, .{ .node_id = input.node_id, .source = if (index < 2)
                .{ .child = .{ .child = @intCast(index), .boundary_node = children[index].spanNodes()[word], .word = @intCast(word) } }
            else
                .{ .parent_word = @intCast(word) } });
        };
        // Complete the native V2 adjacency predicate outside the412-word
        // Span: session/job, exact sparse state and clocks, and lineage.
        // Position, cycle and machine-state adjacency use the shared Span AIR.
        var adjacency_pairs: std.ArrayList([2]S) = .empty;
        defer adjacency_pairs.deinit(allocator);
        const fixed = recursion.segment_statement_v2.fixed_layout;
        const left_clocks = left.retainedSections()[3];
        const right_clocks = right.retainedSections()[2];
        const left_snapshot = left.retainedSections()[1];
        const right_snapshot = right.retainedSections()[0];
        if (left_clocks.count != right_clocks.count) return error.InvalidParentClockProfile;
        if (left_snapshot.count != right_snapshot.count) return error.InvalidParentMemoryProfile;
        const regions = [_]struct { left: usize, right: usize, count: usize }{
            .{ .left = fixed.session_id, .right = fixed.session_id, .count = 8 },
            .{ .left = fixed.job_id, .right = fixed.job_id, .count = 8 },
            .{ .left = fixed.exit_lineage_id, .right = fixed.entry_lineage_id, .count = 8 },
            .{ .left = left_snapshot.payload_start, .right = right_snapshot.payload_start, .count = left_snapshot.payloadWords() },
            .{ .left = fixed.exit_register_clocks, .right = fixed.entry_register_clocks, .count = 64 },
            .{ .left = fixed.exit_memory_clock_id, .right = fixed.entry_memory_clock_id, .count = 10 },
            .{ .left = left_clocks.payload_start, .right = right_clocks.payload_start, .count = left_clocks.payloadWords() },
        };
        for (regions) |region| for (0..region.count) |word| {
            var pair: [2]S = undefined;
            for (children, [_]usize{ region.left + word, region.right + word }, &pair, 0..) |child, raw_word, *symbol, index| {
                const boundary_node = try child.rawWireNode(raw_word);
                const input = try builder.input();
                symbol.* = input.value;
                try inputs.append(allocator, child.evaluatedValues()[boundary_node]);
                try bindings.append(allocator, .{ .node_id = input.node_id, .source = .{ .child = .{
                    .child = @intCast(index),
                    .boundary_node = boundary_node,
                    .word = @intCast(raw_word),
                    .projection = .raw,
                } } });
            }
            try adjacency_pairs.append(allocator, pair);
        };
        // Close the shared typed statement-input u16 contract for each unique
        // child/parent word, without relying on external child admission.
        for (words, word_nodes, 0..) |word_values, nodes, instance| for (word_values, nodes, 0..) |value, node, word| {
            if (!span.isIntegerWord(word)) continue;
            var range: Range = .{ .value = node, .bits = undefined };
            for (&range.bits, 0..) |*bit, shift| {
                const input = try builder.input();
                bit.* = input.value;
                try inputs.append(allocator, QM31.fromBase(M31.fromCanonical((value.toU32() >> @as(u5, @intCast(shift))) & 1)));
                try bindings.append(allocator, .{ .node_id = input.node_id, .source = .{ .word_bit = .{ .statement = @intCast(instance), .word = @intCast(word), .bit = @intCast(shift) } } });
            }
            try ranges.append(allocator, range);
        };
        var instance_inputs: [3][semantics.INPUT_COUNT]S = undefined;
        var prepared: [semantics.INPUT_COUNT]QM31 = undefined;
        for (&instance_inputs, 0..) |*symbols, instance| {
            try semantic.prepareInputsInto(witness(&words, instance), &prepared);
            for (symbols, semantic.inputBindings(), prepared, 0..) |*symbol, binding, value, index| {
                symbol.* = switch (binding.source) {
                    .selector => S.fromSecure(value),
                    .statement => |coordinate| blk: {
                        if (!coordinate.active_kinds.contains(kind(instance))) break :blk S.zero();
                        const projected = try projectedScope(instance, coordinate.scope);
                        break :blk word_nodes[projected][coordinate.index];
                    },
                    .private => |active| blk: {
                        if (!active.contains(kind(instance))) break :blk S.zero();
                        const input = try builder.input();
                        try inputs.append(allocator, value);
                        try bindings.append(allocator, .{ .node_id = input.node_id, .source = .{ .hint = .{ .instance = @intCast(instance), .semantic_input = @intCast(index) } } });
                        break :blk input.value;
                    },
                };
            }
        }
        const values_by_node = try allocator.alloc(S, semantic.nodeCount());
        defer allocator.free(values_by_node);
        try builder.activate();
        for (adjacency_pairs.items) |pair| try builder.constrainZero(pair[0].sub(pair[1]));
        for (ranges.items) |range| {
            var reconstructed = S.zero();
            for (range.bits, 0..) |bit, shift| {
                try builder.constrainZero(bit.mul(bit.sub(S.one())));
                reconstructed = reconstructed.add(bit.mul(S.fromBase(M31.fromCanonical(@as(u32, 1) << @as(u5, @intCast(shift))))));
            }
            try builder.constrainZero(range.value.sub(reconstructed));
        }
        for (&instance_inputs) |symbols| {
            var input_at: usize = 0;
            for (semantic.graph().nodes(), values_by_node) |node, *value| {
                value.* = switch (node.op) {
                    .input => blk: {
                        const result = symbols[input_at];
                        input_at += 1;
                        break :blk result;
                    },
                    .constant => |limbs| S.fromSecure(QM31.fromU32Unchecked(limbs[0], limbs[1], limbs[2], limbs[3])),
                    .add => |op| values_by_node[op.lhs].add(values_by_node[op.rhs]),
                    .sub => |op| values_by_node[op.lhs].sub(values_by_node[op.rhs]),
                    .mul => |op| values_by_node[op.lhs].mul(values_by_node[op.rhs]),
                    .neg => |operand| values_by_node[operand].neg(),
                    .inverse => |operand| values_by_node[operand].inverse(),
                };
            }
            for (semantic.graph().outputs()) |output| try builder.constrainZero(values_by_node[output]);
        }
        var root_checks = RootChecks{ .builder = &builder };
        try span.RootStatement.emitCanonicalChecks(word_nodes[2], &root_checks);
        builder.deactivate();
        var circuit = try builder.finish();
        errdefer circuit.deinit();
        const values = try allocator.alloc(QM31, circuit.nodes.len);
        errdefer allocator.free(values);
        try circuit.evaluateInto(inputs.items, values);
        const result = try allocator.create(Storage);
        errdefer allocator.destroy(result);
        const owned_inputs = try inputs.toOwnedSlice(allocator);
        errdefer allocator.free(owned_inputs);
        const owned_bindings = try bindings.toOwnedSlice(allocator);
        errdefer allocator.free(owned_bindings);
        result.* = .{ .allocator = allocator, .semantics = semantic, .circuit = circuit, .inputs = owned_inputs, .bindings = owned_bindings, .values = values, .words = words, .boundary_graphs = .{ left.graph().identity_digest, right.graph().identity_digest } };
        return @ptrCast(result);
    }
    pub fn deinit(self: *OwnedV1) void {
        const value: *Storage = @ptrCast(@alignCast(self));
        const allocator = value.allocator;
        value.semantics.deinit();
        value.circuit.deinit();
        allocator.free(value.inputs);
        allocator.free(value.bindings);
        allocator.free(value.values);
        allocator.destroy(value);
    }
    pub fn graph(self: *const OwnedV1) recursion.air.composition_circuit.CircuitGraph {
        return self.storage().circuit.graph();
    }
    pub fn inputBindings(self: *const OwnedV1) []const InputBinding {
        return self.storage().bindings;
    }
    pub fn inputValues(self: *const OwnedV1) []const QM31 {
        return self.storage().inputs;
    }
    pub fn evaluatedValues(self: *const OwnedV1) []const QM31 {
        return self.storage().values;
    }
    pub fn boundaryGraphIdentities(self: *const OwnedV1) [2][32]u8 {
        return self.storage().boundary_graphs;
    }
    pub fn parentWords(self: *const OwnedV1) Words {
        return self.storage().words[2];
    }
};

fn kind(instance: usize) semantics.ProofKind {
    return if (instance < 2) .segment_leaf else .binary_node;
}
fn witness(words: *const [3]Words, instance: usize) semantics.Witness {
    return if (instance < 2) semantics.Witness.forSegment(&words[instance]) else semantics.Witness.forBinary(&words[0], &words[1], &words[2]);
}
fn projectedScope(instance: usize, scope: u32) !usize {
    if (instance < 2) {
        if (scope != statement_input.SEGMENT_STATEMENT_SCOPE and scope != statement_input.PARENT_STATEMENT_SCOPE) return error.InvalidParentProjection;
        return instance;
    }
    return switch (scope) {
        statement_input.LEFT_STATEMENT_SCOPE => 0,
        statement_input.RIGHT_STATEMENT_SCOPE => 1,
        statement_input.PARENT_STATEMENT_SCOPE => 2,
        else => error.InvalidParentProjection,
    };
}
const RootChecks = struct {
    builder: *recorder.Builder,
    pub fn equal(self: *RootChecks, left: anytype, right: @TypeOf(left), _: anyerror) !void {
        for (left, right) |a, b| try self.builder.constrainZero(a.sub(b));
    }
    pub fn constant(self: *RootChecks, values: anytype, expected: u32, _: anyerror) !void {
        for (values) |value| try self.builder.constrainZero(value.sub(S.fromBase(M31.fromCanonical(expected))));
    }
};

// Mutation inputs retain the same graph and refresh the existing circuit's
// private hints. Rejection must come from arithmetic, not a stale hint vector or
// the host Span decoder/fold invoked during honest construction.
fn expectArithmeticRejection(owner: *const OwnedV1, words: *const [3]Words) !void {
    const value = owner.storage();
    const inputs = try value.allocator.alloc(QM31, value.inputs.len);
    defer value.allocator.free(inputs);
    const values = try value.allocator.alloc(QM31, value.values.len);
    defer value.allocator.free(values);
    var prepared: [3][semantics.INPUT_COUNT]QM31 = undefined;
    for (&prepared, 0..) |*destination, instance|
        try value.semantics.prepareInputsInto(witness(words, instance), destination);
    for (value.bindings, inputs, 0..) |binding, *input, index| input.* = switch (binding.source) {
        .child => |source| if (source.projection == .span) QM31.fromBase(words[source.child][source.word]) else value.inputs[index],
        .parent_word => |word| QM31.fromBase(words[2][word]),
        .hint => |source| prepared[source.instance][source.semantic_input],
        .word_bit => |source| QM31.fromBase(M31.fromCanonical((words[source.statement][source.word].toU32() >> @as(u5, source.bit)) & 1)),
    };
    try std.testing.expectError(error.UnsatisfiedCircuit, value.circuit.evaluateInto(inputs, values));
}

pub fn testFromExpectedFiles(allocator: std.mem.Allocator, left_path: []const u8, right_path: []const u8) !void {
    const command = @import("recursive_segment_v2_detached_command.zig");
    const left_json = try std.fs.cwd().readFileAlloc(allocator, left_path, 16 * 1024 * 1024);
    defer allocator.free(left_json);
    const right_json = try std.fs.cwd().readFileAlloc(allocator, right_path, 16 * 1024 * 1024);
    defer allocator.free(right_json);
    var left_data = try command.OwnedExpectedV1.decode(allocator, left_json);
    defer left_data.deinit();
    var right_data = try command.OwnedExpectedV1.decode(allocator, right_json);
    defer right_data.deinit();
    const left = try boundary.testing.fromExpected(allocator, &left_data.data);
    const right = boundary.testing.fromExpected(allocator, &right_data.data) catch |err| {
        left.deinit();
        return err;
    };
    const owner = OwnedV1.init(allocator, left, right) catch |err| {
        left.deinit();
        right.deinit();
        return err;
    };
    defer owner.deinit();
    // The composed owner retains scalar copies and graph-node provenance only.
    // Destroy both boundary graph producers before further evaluation.
    left.deinit();
    right.deinit();
    const saved = owner.storage();
    const scratch = try allocator.alloc(QM31, saved.values.len);
    defer allocator.free(scratch);
    try saved.circuit.evaluateInto(owner.inputValues(), scratch);
    try std.testing.expectEqualDeep(owner.evaluatedValues(), scratch);
    var projected_words: [2]usize = .{ 0, 0 };
    var published_words: usize = 0;
    var raw_boundary_words: [2]usize = .{ 0, 0 };
    for (owner.inputBindings()) |binding| switch (binding.source) {
        .child => |source| if (source.projection == .span) {
            projected_words[source.child] += 1;
        } else {
            raw_boundary_words[source.child] += 1;
        },
        .parent_word => published_words += 1,
        .hint => {},
        .word_bit => {},
    };
    try std.testing.expectEqual([2]usize{ WORD_COUNT, WORD_COUNT }, projected_words);
    try std.testing.expectEqual(WORD_COUNT, published_words);
    try std.testing.expectEqual(raw_boundary_words[0], raw_boundary_words[1]);
    try std.testing.expect(raw_boundary_words[0] >= 74);
    try testRawBoundaryRejections(owner);
    const layout = span.canonical_layout;
    const Mutation = struct { statement: usize, word: usize };
    const mutations = [_]Mutation{
        .{ .statement = 1, .word = layout.slot_node_index_start },
        .{ .statement = 1, .word = layout.first_segment_start },
        .{ .statement = 1, .word = layout.executed_segment_count_start },
        .{ .statement = 1, .word = layout.first_cycle_start },
        .{ .statement = 1, .word = layout.executed_cycle_count_start },
        .{ .statement = 1, .word = layout.entry_state_start + layout.machine_state_rw_digest_start_offset },
        .{ .statement = 0, .word = layout.exit_state_start + layout.machine_state_registers_start_offset + 14 },
        .{ .statement = 2, .word = layout.slot_node_index_start },
        .{ .statement = 2, .word = layout.slot_height },
        .{ .statement = 2, .word = layout.first_segment_start },
        .{ .statement = 2, .word = layout.executed_segment_count_start },
        .{ .statement = 2, .word = layout.first_cycle_start },
        .{ .statement = 2, .word = layout.executed_cycle_count_start },
        .{ .statement = 2, .word = layout.initial_state_start },
        .{ .statement = 2, .word = layout.final_state_start },
        .{ .statement = 2, .word = layout.public_input_start },
        .{ .statement = 2, .word = layout.public_output_start },
    };
    for (mutations) |mutation| {
        var changed = saved.words;
        changed[mutation.statement][mutation.word] = changed[mutation.statement][mutation.word].add(M31.one());
        try expectArithmeticRejection(owner, &changed);
    }
    var swapped = saved.words;
    std.mem.swap(Words, &swapped[0], &swapped[1]);
    try expectArithmeticRejection(owner, &swapped);
    var duplicated = saved.words;
    duplicated[1] = duplicated[0];
    try expectArithmeticRejection(owner, &duplicated);
    // A valid binary prefix must still fail complete-job root coverage: the
    // same extended job is supplied to both children and parent.
    var incomplete = saved.words;
    for (&incomplete) |*words| words[layout.total_cycles_start] = words[layout.total_cycles_start].add(M31.one());
    try expectArithmeticRejection(owner, &incomplete);
    // Equality alone could accept a non-u16 register limb shared by the job,
    // both children and parent. The authoritative integer ranges must reject it.
    var non_u16 = saved.words;
    for (&non_u16) |*words| for ([_]usize{ layout.initial_state_start, layout.final_state_start, layout.entry_state_start, layout.exit_state_start }) |start| {
        words[start + layout.machine_state_registers_start_offset + 14] = M31.fromCanonical(65536);
    };
    try expectArithmeticRejection(owner, &non_u16);
    std.debug.print("detached-parent-statement child_words={d}/{d} published_words={d} nodes={d} outputs={d} arithmetic_mutations={d} boundary_producers_destroyed=true proof_verified=false\n", .{ projected_words[0], projected_words[1], published_words, saved.circuit.nodes.len, saved.circuit.outputs.len, mutations.len + 4 });
}

test "SegmentV2 detached parent folds actual child projections and constrains complete root" {
    const allocator = std.testing.allocator;
    const left = std.process.getEnvVarOwned(allocator, "STWO_SEGMENT_V2_PARENT_LEFT_EXPECTED_WIRE") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return error.SkipZigTest,
        else => return err,
    };
    defer allocator.free(left);
    const right = try std.process.getEnvVarOwned(allocator, "STWO_SEGMENT_V2_PARENT_RIGHT_EXPECTED_WIRE");
    defer allocator.free(right);
    try testFromExpectedFiles(allocator, left, right);
}

fn testRawBoundaryRejections(owner: *const OwnedV1) !void {
    const saved = owner.storage();
    const inputs = try saved.allocator.dupe(QM31, saved.inputs);
    defer saved.allocator.free(inputs);
    const values = try saved.allocator.alloc(QM31, saved.values.len);
    defer saved.allocator.free(values);
    var count: usize = 0;
    var first_left: ?usize = null;
    var distinct_left: ?usize = null;
    var regressed: bool = false;
    for (saved.bindings, 0..) |binding, index| {
        const source = switch (binding.source) {
            .child => |source| source,
            else => continue,
        };
        if (source.projection != .raw) continue;
        inputs[index] = saved.inputs[index].add(QM31.one());
        try std.testing.expectError(error.UnsatisfiedCircuit, saved.circuit.evaluateInto(inputs, values));
        inputs[index] = saved.inputs[index];
        count += 1;
        if (source.child == 0) {
            if (first_left) |first| {
                if (!saved.inputs[first].eql(saved.inputs[index])) distinct_left = index;
            } else first_left = index;
            if (!regressed and !saved.inputs[index].isZero()) {
                inputs[index] = saved.inputs[index].sub(QM31.one());
                try std.testing.expectError(error.UnsatisfiedCircuit, saved.circuit.evaluateInto(inputs, values));
                inputs[index] = saved.inputs[index];
                regressed = true;
            }
        }
    }
    if (first_left != null and distinct_left != null) {
        std.mem.swap(QM31, &inputs[first_left.?], &inputs[distinct_left.?]);
        try std.testing.expectError(error.UnsatisfiedCircuit, saved.circuit.evaluateInto(inputs, values));
        std.mem.swap(QM31, &inputs[first_left.?], &inputs[distinct_left.?]);
    }
    try std.testing.expect(count >= 148);
    try saved.circuit.evaluateInto(inputs, values);
    std.debug.print("detached-parent-v2-adjacency raw_word_mutations={d} unequal_word_swap={any} decrement={any} host_admission_bypassed=true\n", .{ count, distinct_left != null, regressed });
}
