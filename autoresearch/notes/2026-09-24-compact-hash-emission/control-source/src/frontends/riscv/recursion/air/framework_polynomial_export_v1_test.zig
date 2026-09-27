const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const backend = @import("stwo_prover_engine").air.component_prover;
const exporter = @import("framework_polynomial_export_v1.zig");
const direct = @import("direct_constraint_program.zig");
const bindings = @import("universal_relation_binding.zig");
const universal = @import("universal_challenges.zig");
const lang = @import("../../air/lang/mod.zig");
const allocator = std.testing.allocator;
const tree_counts = [_]usize{ 4096, 4096, 4096 };

test "framework backend export matches authenticated direct and relation plans" {
    inline for (.{ @import("qm31_mul_add_v1.zig"), @import("detached_opening_accumulate4_v1.zig"), @import("linear_ops.zig"), @import("detached_graph_input_v1.zig"), @import("detached_poseidon_graph_v1.zig"), @import("fri_merkle_node.zig") }) |Air| {
        var definition = if (@typeInfo(@TypeOf(Air.build)).@"fn".params.len == 2) try Air.build(allocator, .generated) else try Air.build(allocator);
        defer definition.deinit();
        try exercise(Air, &definition);
    }
}

fn exercise(comptime Air: type, definition: *const Air.Definition) !void {
    const compiled = try direct.authenticate(&definition.arena, Air.SEMANTIC_DIGEST, Air.LOGICAL_INPUT_COUNT);
    const plan = try bindings.Binding(Air).authenticate(definition);
    const parameter_count = Air.LOGICAL_INPUT_COUNT - Air.PHYSICAL_MAIN_COLUMN_COUNT - Air.PREPROCESSED_COLUMN_COUNT;
    var inputs: [Air.LOGICAL_INPUT_COUNT]backend.TypedPolynomialInputV1 = undefined;
    for (&inputs, 0..) |*input, index| input.* = if (index < inputs.len - parameter_count)
        .{ .trace_column = .{ .tree_index = @intCast(index % 3), .column_index = @intCast(index * 3 + 7) } }
    else
        .{ .profile_parameter = @intCast(index - (inputs.len - parameter_count)) };
    var columns: [Air.INTERACTION_COLUMN_COUNT]backend.TypedPolynomialColumnV1 = undefined;
    for (&columns, 0..) |*column, index| column.* = .{ .tree_index = 2, .column_index = @intCast(index * 2 + 1000) };
    var program = try exporter.exportPrepared(Air, allocator, &compiled, &plan, &inputs, &columns, parameter_count, &tree_counts);
    defer program.deinit();
    const relations = universal.UniversalRelations.dummy();
    const parameters = try exporter.exportRelationParameters(allocator, &plan, &relations);
    defer allocator.free(parameters);
    var profile_values: [parameter_count]M31 = undefined;
    const identity = program.identity;
    for (0..4) |sample| {
        for (&profile_values, 0..) |*value, index| value.* = M31.fromU64((sample + 1) * (index + 2));
        const invocation = backend.FrameworkPolynomialParametersV1{ .profile_values = &profile_values, .relation_values = parameters, .trace_log_size = 8, .claimed_sum = QM31.fromU32Unchecked(7, 11, 13, 17) };
        try invocation.validate(&program);
        var invalid = invocation;
        invalid.trace_log_size = 0;
        try std.testing.expectError(error.InvalidFrameworkPolynomialParameters, invalid.validate(&program));
        invalid = invocation;
        invalid.relation_values = parameters[1..];
        try std.testing.expectError(error.InvalidFrameworkPolynomialParameters, invalid.validate(&program));
        if (comptime parameter_count != 0) {
            const saved_parameter = profile_values[0];
            profile_values[0] = .{ .v = core.fields.m31.Modulus };
            try std.testing.expectError(error.InvalidFrameworkPolynomialParameters, invocation.validate(&program));
            profile_values[0] = saved_parameter;
        }
        try std.testing.expect((try invocation.claimedSumShift()).mulM31(M31.fromCanonical(256)).eql(invocation.claimed_sum));
        var base: [Air.LOGICAL_INPUT_COUNT]M31 = undefined;
        var secure: [Air.LOGICAL_INPUT_COUNT]QM31 = undefined;
        for (inputs, &base, &secure) |input, *value, *extension| switch (input) {
            .trace_column => |column| {
                value.* = M31.fromU64((column.tree_index + @as(usize, 1)) * (column.column_index + 19) * (sample + 11));
                extension.* = QM31.fromM31(value.*, M31.fromU64(column.column_index + 2), M31.fromU64(sample + 3), M31.fromU64(column.tree_index + 5));
            },
            .profile_parameter => |index| {
                if (comptime parameter_count == 0) unreachable;
                value.* = profile_values[index];
                extension.* = QM31.fromBase(value.*);
            },
        };
        const actual_base = try evaluate(M31, program.direct.nodes, &base);
        defer allocator.free(actual_base);
        const actual_secure = try evaluate(QM31, program.direct.nodes, &secure);
        defer allocator.free(actual_secure);
        var scratch_base: [direct.MAX_NODES]M31 = undefined;
        var scratch_secure: [direct.MAX_NODES]QM31 = undefined;
        var expected_base: [Air.DIRECT_CONSTRAINT_COUNT]M31 = undefined;
        var expected_secure: [Air.DIRECT_CONSTRAINT_COUNT]QM31 = undefined;
        try compiled.evaluateBaseInto(&base, &scratch_base, &expected_base);
        try compiled.evaluateSecureInto(&secure, &scratch_secure, &expected_secure);
        for (program.direct.roots, expected_base, expected_secure) |root, expected, expected_ext| {
            try std.testing.expect(actual_base[root].eql(expected));
            try std.testing.expect(actual_secure[root].eql(expected_ext));
        }
        const actual_entries = try evaluate(M31, program.lookup_nodes, &base);
        defer allocator.free(actual_entries);
        const expected_entries = plan.preparedEntries(base);
        for (program.entries, expected_entries) |entry, expected| {
            try std.testing.expectEqual(@intFromEnum(expected.domain), entry.domain);
            try std.testing.expectEqual(expected.schema_version, entry.schema_version);
            try std.testing.expect(QM31.fromBase(actual_entries[entry.numerator]).eql(expected.numerator));
            for (entry.values[0..entry.arity], expected.values[0..entry.arity]) |node, value| try std.testing.expect(QM31.fromBase(actual_entries[node]).eql(value));
        }
        const actual_lookup_secure = try evaluate(QM31, program.lookup_nodes, &secure);
        defer allocator.free(actual_lookup_secure);
        const expected_pairs = try plan.preparedSecureRowPairs(secure, &relations);
        var parameter_cursor: usize = 0;
        for (program.batches, expected_pairs) |batch, expected| {
            for (0..batch.entry_count) |offset| {
                const entry = program.entries[batch.first_entry + offset];
                var denominator = parameters[parameter_cursor].neg();
                parameter_cursor += 1;
                for (entry.values[0..entry.arity]) |node| {
                    denominator = denominator.add(parameters[parameter_cursor].mul(actual_lookup_secure[node]));
                    parameter_cursor += 1;
                }
                try std.testing.expect(denominator.eql(if (offset == 0) expected.d1 else expected.d2));
                try std.testing.expect(actual_lookup_secure[entry.numerator].eql(if (offset == 0) expected.n1 else expected.n2));
            }
        }
        try std.testing.expectEqualSlices(u8, &identity, &program.identityDigest());
    }
    // Admission rejects binding, batching and identity drift. Input values can
    // change without recompiling the graph, but coordinates cannot silently do so.
    const saved = program.inputs[0];
    program.inputs[0] = .{ .trace_column = .{ .tree_index = 3, .column_index = 0 } };
    try std.testing.expectError(error.InvalidFrameworkPolynomialInput, program.validate(&tree_counts));
    program.inputs[0] = .{ .trace_column = .{ .tree_index = 0, .column_index = 2 } };
    try std.testing.expectError(error.InvalidFrameworkPolynomialIdentity, program.validate(&tree_counts));
    program.inputs[0] = saved;
    const batch = program.batches[0];
    program.batches[0].first_entry = 1;
    try std.testing.expectError(error.InvalidFrameworkPolynomialBatch, program.validate(&tree_counts));
    program.batches[0] = batch;
    var bad_direct = compiled;
    bad_direct.semantic_digest[0] ^= 1;
    try std.testing.expectError(error.InvalidPreparedFrameworkProgram, exporter.exportPrepared(Air, allocator, &bad_direct, &plan, &inputs, &columns, parameter_count, &tree_counts));
}

fn evaluate(comptime F: type, nodes: []const backend.BasePolynomialNode, inputs: []const F) ![]F {
    const values = try allocator.alloc(F, nodes.len);
    errdefer allocator.free(values);
    for (nodes, values) |node, *value| value.* = switch (node.op) {
        .constant => if (F == M31) M31.fromCanonical(node.value) else QM31.fromBase(M31.fromCanonical(node.value)),
        .column => inputs[node.value],
        .add => values[node.lhs].add(values[node.rhs]),
        .sub => values[node.lhs].sub(values[node.rhs]),
        .mul => values[node.lhs].mul(values[node.rhs]),
        .neg => values[node.lhs].neg(),
    };
    return values;
}

const GatedFixture = struct {
    pub const PHYSICAL_MAIN_COLUMN_COUNT = 4;
    pub const PREPROCESSED_COLUMN_COUNT = 1;
    pub const LOGICAL_INPUT_COUNT = 6;
    pub const DIRECT_CONSTRAINT_COUNT = 2;
    pub const RELATION_EVENT_COUNT = 3;
    pub const LOOKUP_BATCH_SIZE = 2;
    pub const INTERACTION_BATCH_COUNT = 2;
    pub const INTERACTION_COLUMN_COUNT = 8;
    pub const SEMANTIC_DIGEST: [32]u8 = .{ 0x14, 0xd8, 0x35, 0xa4, 0x2f, 0xbd, 0x2c, 0xbe, 0x9b, 0x24, 0xd4, 0xa8, 0x5f, 0xe5, 0x60, 0xd0, 0xe7, 0xb7, 0x22, 0xd4, 0xe2, 0x9f, 0xfe, 0x7a, 0x0e, 0x96, 0xcc, 0x12, 0x81, 0x8e, 0xff, 0xb8 };
    pub const Definition = struct {
        arena: lang.ir.Arena,
        events: [3]lang.types.EffectId,
        pub fn deinit(self: *@This()) void {
            self.arena.deinit();
        }
        pub fn validate(self: *const @This()) !void {
            try lang.validate.validate(&self.arena);
            const actual = (try lang.digest.computeIdentity(&self.arena)).bytes;
            if (!std.mem.eql(u8, &actual, &SEMANTIC_DIGEST)) {
                std.debug.print("FRAMEWORK_GATED_FIXTURE_DIGEST={s}\n", .{std.fmt.bytesToHex(actual, .lower)});
                return error.InvalidFixtureIdentity;
            }
        }
    };
    fn build() !Definition {
        var arena = lang.ir.Arena.init(allocator);
        errdefer arena.deinit();
        const span = lang.source.SourceSpan.generated();
        const x = try arena.input("x", .felt, span);
        const gate = try arena.input("gate", .selector, span);
        const low = try arena.input("low", .byte, span);
        const high = try arena.input("high", .byte, span);
        const p = try arena.input("preprocessed", .felt, span);
        const y = try arena.input("parameter", .felt, span);
        const product = try arena.mul(x, p, span);
        const selection = try arena.select(gate, product, y, span);
        const root = try arena.neg(selection, span);
        _ = try arena.assertZero("gated", root, gate, .semantic, span);
        _ = try arena.assertZero("ordered_second", try arena.sub(x, y, span), null, .semantic, span);
        const events = try @import("relation_effect.zig").appendGroup(3, &arena, .{
            .{ .domain = .recursion_statement_word, .role = .emit, .values = &.{ x, y, selection }, .weight = gate },
            .{ .domain = .recursion_statement_word, .role = .consume, .values = &.{ x, y, selection }, .weight = x },
            .{ .domain = .range_check_8_8, .role = .request, .values = &.{ low, high }, .weight = gate },
        }, span);
        return .{ .arena = arena, .events = events };
    }
};

test "framework export preserves gated root order selection and request signs" {
    var fixture = try GatedFixture.build();
    defer fixture.deinit();
    try fixture.validate();
    try exercise(GatedFixture, &fixture);
}

test "framework exporter allocation failure cleans every partial owned program" {
    const Air = @import("qm31_mul_add_v1.zig");
    var definition = try Air.build(allocator);
    defer definition.deinit();
    const compiled = try direct.authenticate(&definition.arena, Air.SEMANTIC_DIGEST, Air.LOGICAL_INPUT_COUNT);
    const plan = try bindings.Binding(Air).authenticate(&definition);
    var inputs: [Air.LOGICAL_INPUT_COUNT]backend.TypedPolynomialInputV1 = undefined;
    for (&inputs, 0..) |*input, index| input.* = .{ .trace_column = .{ .tree_index = 0, .column_index = @intCast(index) } };
    var columns: [Air.INTERACTION_COLUMN_COUNT]backend.TypedPolynomialColumnV1 = undefined;
    for (&columns, 0..) |*column, index| column.* = .{ .tree_index = 2, .column_index = @intCast(index) };
    try std.testing.checkAllAllocationFailures(allocator, allocationRun, .{ &compiled, &plan, &inputs, &columns });
}
fn allocationRun(a: std.mem.Allocator, compiled: *const direct.Program, plan: *const bindings.Binding(@import("qm31_mul_add_v1.zig")).Plan, inputs: *const [@import("qm31_mul_add_v1.zig").LOGICAL_INPUT_COUNT]backend.TypedPolynomialInputV1, columns: *const [@import("qm31_mul_add_v1.zig").INTERACTION_COLUMN_COUNT]backend.TypedPolynomialColumnV1) !void {
    var program = try exporter.exportPrepared(@import("qm31_mul_add_v1.zig"), a, compiled, plan, inputs, columns, 0, &tree_counts);
    defer program.deinit();
}

test "framework component projection retains admitted parameter and tree ownership" {
    const Air = @import("linear_ops.zig");
    var definition = try Air.build(allocator, .generated);
    defer definition.deinit();
    const parameter_count = Air.LOGICAL_INPUT_COUNT - Air.PHYSICAL_MAIN_COLUMN_COUNT - Air.PREPROCESSED_COLUMN_COUNT;
    const relations = universal.UniversalRelations.dummy();
    var component = .{
        .log_size = @as(u32, 8),
        .claimed_sum = QM31.fromU32Unchecked(3, 5, 7, 11),
        .relations = &relations,
        .direct = try direct.authenticate(&definition.arena, Air.SEMANTIC_DIGEST, Air.LOGICAL_INPUT_COUNT),
        .relation_plan = try bindings.Binding(Air).authenticate(&definition),
        .parameters = [_]M31{M31.one()} ** parameter_count,
        .placement = .{ .main_offset = @as(u32, 19), .preprocessed_offset = @as(u32, 43), .interaction_offset = @as(u32, 107) },
    };
    const capability = exporter.capability(Air, @TypeOf(component), component.log_size);
    var program = try capability.export_program(&component, allocator, &tree_counts);
    var parameters = try capability.export_parameters(&component, allocator);
    defer parameters.deinit();
    try parameters.values.validate(&program);
    try std.testing.expectEqual(capability.trace_log_size, parameters.values.trace_log_size);
    component.parameters[0] = M31.zero();
    try std.testing.expect(parameters.values.profile_values[0].eql(M31.one()));
    try std.testing.checkAllAllocationFailures(allocator, allocationParameters, .{ capability, @as(*const anyopaque, &component) });
    defer program.deinit();
    for (program.inputs[0..Air.PHYSICAL_MAIN_COLUMN_COUNT], 0..) |input, index| {
        try std.testing.expectEqual(@as(u8, 1), input.trace_column.tree_index);
        try std.testing.expectEqual(19 + index, input.trace_column.column_index);
    }
    const parameter_start = Air.PHYSICAL_MAIN_COLUMN_COUNT + Air.PREPROCESSED_COLUMN_COUNT;
    for (program.inputs[Air.PHYSICAL_MAIN_COLUMN_COUNT..parameter_start], 0..) |input, index| {
        try std.testing.expectEqual(@as(u8, 0), input.trace_column.tree_index);
        try std.testing.expectEqual(43 + index, input.trace_column.column_index);
    }
    for (program.inputs[parameter_start..], 0..) |input, index| try std.testing.expectEqual(index, input.profile_parameter);
    for (program.interaction_columns, 0..) |column, index| {
        try std.testing.expectEqual(@as(u8, 2), column.tree_index);
        try std.testing.expectEqual(107 + index, column.column_index);
    }
}

fn allocationParameters(a: std.mem.Allocator, capability: backend.FrameworkPolynomialCapabilityV1, ctx: *const anyopaque) !void {
    var parameters = try capability.export_parameters(ctx, a);
    defer parameters.deinit();
}
