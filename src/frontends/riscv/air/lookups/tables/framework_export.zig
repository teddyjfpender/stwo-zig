//! Native fixed-table projection into the backend's independent LogUp layout.
//! Equations come from interaction.tableEntryGeneric; invocation challenges and
//! claims are owned separately and never enter the generated program identity.
const std = @import("std");
const core = @import("stwo_core");
const QM31 = core.fields.qm31.QM31;
const backend = @import("stwo_prover_engine").air.component_prover;
const Component = @import("component.zig").LookupTableComponent;
const schema = @import("schema.zig");
const interaction = @import("interaction.zig");
const entry = @import("../entry.zig");
const symbolic = @import("../../extract/symbolic.zig");
const runtime = @import("../../extract/runtime_program.zig");

pub fn capability(kind: schema.Kind) backend.FrameworkPolynomialCapabilityV1 {
    const Callbacks = struct {
        fn program(ctx: *const anyopaque, allocator: std.mem.Allocator, counts: []const usize) !backend.OwnedFrameworkPolynomialProgramV1 {
            return exportProgram(allocator, @ptrCast(@alignCast(ctx)), counts);
        }
        fn parameters(ctx: *const anyopaque, allocator: std.mem.Allocator) !backend.OwnedFrameworkPolynomialParametersV1 {
            return exportParameters(allocator, @ptrCast(@alignCast(ctx)));
        }
    };
    return .{ .trace_log_size = schema.logSize(kind), .export_program = Callbacks.program, .export_parameters = Callbacks.parameters };
}

pub fn exportProgram(allocator: std.mem.Allocator, component: *const Component, counts: []const usize) !backend.OwnedFrameworkPolynomialProgramV1 {
    try validateComponent(component);
    const arity = schema.arity(component.kind);
    const input_count = arity + 2;
    // At most five source columns and one negation. Keep the symbolic recorder
    // local; only the final immutable export uses the caller's allocator.
    var recording_storage: [4096]u8 = undefined;
    var recording = std.heap.FixedBufferAllocator.init(&recording_storage);
    var arena = symbolic.Arena.init(recording.allocator());
    defer arena.deinit();
    symbolic.begin(&arena);
    defer symbolic.end();
    const multiplicity = arena.column("main");
    var tuple: [schema.MAX_ARITY]symbolic.Scalar = undefined;
    for (tuple[0..arity]) |*word| word.* = arena.column("tuple");
    const relation = interaction.tableEntryGeneric(symbolic.Scalar, component.kind, tuple[0..arity], multiplicity);
    var list = entry.Builder(symbolic.Scalar).List{};
    list.entries[0] = relation;
    list.len = 1;
    const lookup = try runtime.ownLookupProgram(allocator, &arena, &list, input_count);
    defer allocator.free(lookup.entries);
    errdefer allocator.free(lookup.nodes);
    const inputs = try allocator.alloc(backend.TypedPolynomialInputV1, input_count);
    errdefer allocator.free(inputs);
    inputs[0] = .{ .trace_column = .{ .tree_index = 1, .column_index = try column(component.main_col_offset) } };
    for (component.tuple_col_indices[0..arity], inputs[1..][0..arity]) |source, *target|
        target.* = .{ .trace_column = .{ .tree_index = 0, .column_index = try column(source) } };
    inputs[input_count - 1] = .{ .trace_column = .{ .tree_index = 0, .column_index = try column(component.is_first_col_idx) } };
    const columns = try allocator.alloc(backend.TypedPolynomialColumnV1, interaction.N_COLUMNS);
    errdefer allocator.free(columns);
    for (columns, 0..) |*target, index| target.* = .{ .tree_index = 2, .column_index = try column(try std.math.add(usize, component.interaction_col_offset, index)) };
    const entries = try allocator.alloc(backend.FrameworkLookupEntryV1, 1);
    errdefer allocator.free(entries);
    entries[0] = .{ .domain = @intFromEnum(relation.domain), .schema_version = 1, .numerator = lookup.entries[0].numerator, .arity = relation.arity };
    @memcpy(entries[0].values[0..arity], lookup.entries[0].values[0..arity]);
    const batches = try allocator.alloc(backend.FrameworkLookupBatchV1, 1);
    errdefer allocator.free(batches);
    batches[0] = .{ .first_entry = 0, .entry_count = 1, .interaction_column_start = 0 };
    var result = backend.OwnedFrameworkPolynomialProgramV1{
        .allocator = allocator,
        .semantic_digest = sourceDigest(@embedFile("interaction.zig")),
        .registry_order_digest = sourceDigest(@embedFile("../entry.zig")),
        .direct = .{ .allocator = allocator, .nodes = &.{}, .roots = &.{}, .column_count = input_count },
        .lookup_nodes = lookup.nodes,
        .entries = entries,
        .batches = batches,
        .inputs = inputs,
        .interaction_columns = columns,
        .profile_parameter_count = 0,
        .layout = .independent_prefix_v1,
        .is_first_input = @intCast(input_count - 1),
        .identity = @splat(0),
    };
    result.identity = result.identityDigest();
    try result.validate(counts);
    return result;
}

pub fn exportParameters(allocator: std.mem.Allocator, component: *const Component) !backend.OwnedFrameworkPolynomialParametersV1 {
    try validateComponent(component);
    try canonical(component.claim);
    switch (component.kind) {
        inline else => |kind| try validateRelation(@field(component.relations, @tagName(kind))),
    }
    var values: std.ArrayList(QM31) = .empty;
    defer values.deinit(allocator);
    try entry.appendRelationParameters(&values, allocator, component.relations, schema.domain(component.kind));
    const relations = try values.toOwnedSlice(allocator);
    errdefer allocator.free(relations);
    const claims = try allocator.dupe(QM31, &.{component.claim});
    return .{ .allocator = allocator, .values = .{
        .profile_values = &.{},
        .relation_values = relations,
        .trace_log_size = schema.logSize(component.kind),
        .claimed_sum = QM31.zero(),
        .batch_claims = claims,
    } };
}

fn validateComponent(component: *const Component) !void {
    const arity = schema.arity(component.kind);
    for (component.tuple_col_indices[0..arity], 0..) |selected, index| {
        if (selected == component.is_first_col_idx) return error.InvalidNativeTableBinding;
        for (component.tuple_col_indices[0..index]) |prior| if (selected == prior) return error.InvalidNativeTableBinding;
    }
    for (component.tuple_col_indices[arity..]) |unused| if (unused != 0) return error.InvalidNativeTableBinding;
}

fn validateRelation(relation: anytype) !void {
    try canonical(relation.z);
    try canonical(relation.alpha);
    for (relation.alpha_powers) |power| try canonical(power);
    var expected = QM31.one();
    for (relation.alpha_powers) |power| {
        if (!power.eql(expected)) return error.InvalidNativeTableChallenges;
        expected = expected.mul(relation.alpha);
    }
}

fn canonical(value: QM31) !void {
    for (value.toM31Array()) |word| if (word.toU32() >= core.fields.m31.Modulus) return error.InvalidNativeTableChallenges;
}

fn column(index: usize) !u32 {
    return std.math.cast(u32, index) orelse error.InvalidNativeTableBinding;
}

fn sourceDigest(source: []const u8) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo/native-fixed-table-framework/v1\x00");
    hash.update(source);
    return hash.finalResult();
}

const testing = std.testing;
const Relations = @import("../../relation_challenges.zig").Relations;

fn fixture(kind: schema.Kind, relations: *const Relations) !Component {
    const columns = [_]usize{ 5, 2, 9, 4 };
    return Component.initProver(kind, 7, columns[0..schema.arity(kind)], 3, 5, relations, QM31.fromU32Unchecked(31, 17, 23, 9));
}

fn replay(program: *const backend.OwnedFrameworkPolynomialProgramV1, parameters: backend.FrameworkPolynomialParametersV1, inputs: []const QM31, current: QM31, previous: QM31) !QM31 {
    var values: [32]QM31 = undefined;
    try testing.expect(program.lookup_nodes.len <= values.len);
    for (program.lookup_nodes, 0..) |node, index| values[index] = switch (node.op) {
        .constant => QM31.fromBase(core.fields.m31.M31.fromCanonical(node.value)),
        .column => inputs[node.value],
        .add => values[node.lhs].add(values[node.rhs]),
        .sub => values[node.lhs].sub(values[node.rhs]),
        .mul => values[node.lhs].mul(values[node.rhs]),
        .neg => values[node.lhs].neg(),
    };
    const relation = program.entries[0];
    var denominator = parameters.relation_values[0].neg();
    for (relation.values[0..relation.arity], 0..) |node, index|
        denominator = denominator.add(values[node].mul(parameters.relation_values[index + 1]));
    return current.sub(previous).add(inputs[program.is_first_input.?].mul(parameters.batch_claims[0])).mul(denominator).sub(values[relation.numerator]);
}

test "native table framework export matches all six native AIRs at base and secure points" {
    const relations = Relations.dummy();
    var random_state = std.Random.DefaultPrng.init(0x7461626c65);
    const random = random_state.random();
    inline for (std.meta.tags(schema.Kind)) |kind| {
        const component = try fixture(kind, &relations);
        const handle = component.asProverComponent();
        const selected = handle.backend_composition_capability.?.framework_polynomial_v1;
        try testing.expectEqual(schema.logSize(kind), selected.trace_log_size);
        var program = try selected.export_program(handle.ctx, testing.allocator, &.{ 12, 7, 10 });
        defer program.deinit();
        var parameters = try selected.export_parameters(handle.ctx, testing.allocator);
        defer parameters.deinit();
        try parameters.values.validate(&program);
        try testing.expectEqual(@as(usize, 0), program.direct.roots.len);
        try testing.expectEqual(backend.FrameworkLookupLayoutV1.independent_prefix_v1, program.layout);
        try testing.expectEqual(@as(u32, 3), program.inputs[0].trace_column.column_index);
        for (component.tuple_col_indices[0..schema.arity(kind)], program.inputs[1..][0..schema.arity(kind)]) |expected, input|
            try testing.expectEqual(expected, input.trace_column.column_index);
        for (0..64) |case| {
            var inputs: [schema.MAX_ARITY + 2]QM31 = undefined;
            for (inputs[0..program.inputs.len]) |*value| value.* = if (case < 32)
                QM31.fromU32Unchecked(random.int(u16), 0, 0, 0)
            else
                QM31.fromU32Unchecked(random.int(u16), random.int(u16), random.int(u16), random.int(u16));
            const current = QM31.fromU32Unchecked(random.int(u16), 17, 9, 1);
            const previous = QM31.fromU32Unchecked(random.int(u16), 11, 3, 7);
            const actual = try replay(&program, parameters.values, inputs[0..program.inputs.len], current, previous);
            const expected = try interaction.evaluateGeneric(QM31, kind, inputs[1..][0..schema.arity(kind)], inputs[0], current, previous, inputs[program.is_first_input.?], component.claim, &relations);
            try testing.expect(actual.eql(expected));
        }
    }
}

test "native table framework identity excludes invocation challenges and binds placement" {
    var relations = Relations.dummy();
    var component = try fixture(.range_check_8_8, &relations);
    var before = try exportProgram(testing.allocator, &component, &.{ 12, 7, 10 });
    defer before.deinit();
    component.claim = component.claim.add(QM31.one());
    relations.range_check_8_8 = @TypeOf(relations.range_check_8_8).init(QM31.one(), QM31.fromU32Unchecked(9, 7, 5, 3));
    var after = try exportProgram(testing.allocator, &component, &.{ 12, 7, 10 });
    defer after.deinit();
    try testing.expectEqualSlices(u8, &before.identity, &after.identity);
    component.main_col_offset += 1;
    var moved = try exportProgram(testing.allocator, &component, &.{ 12, 7, 10 });
    defer moved.deinit();
    try testing.expect(!std.mem.eql(u8, &before.identity, &moved.identity));
}

test "native table framework rejects corrupted bindings and challenges before use" {
    var relations = Relations.dummy();
    var component = try fixture(.range_check_8_8, &relations);
    try testing.expectError(error.InvalidFrameworkPolynomialInput, exportProgram(testing.allocator, &component, &.{ 5, 7, 10 }));
    component.tuple_col_indices[1] = component.tuple_col_indices[0];
    try testing.expectError(error.InvalidNativeTableBinding, exportProgram(testing.allocator, &component, &.{ 12, 7, 10 }));
    component = try fixture(.range_check_8_8, &relations);
    relations.range_check_8_8.alpha_powers[1] = QM31.zero();
    try testing.expectError(error.InvalidNativeTableChallenges, exportParameters(testing.allocator, &component));
    relations = Relations.dummy();
    relations.range_check_8_8.alpha = QM31.zero();
    relations.range_check_8_8.alpha.c0.a.v = core.fields.m31.Modulus;
    try testing.expectError(error.InvalidNativeTableChallenges, exportParameters(testing.allocator, &component));
    relations = Relations.dummy();
    component.claim = QM31.zero();
    component.claim.c0.b.v = core.fields.m31.Modulus;
    try testing.expectError(error.InvalidNativeTableChallenges, exportParameters(testing.allocator, &component));
}

fn allocationCase(allocator: std.mem.Allocator) !void {
    const relations = Relations.dummy();
    const component = try fixture(.bitwise, &relations);
    var program = try exportProgram(allocator, &component, &.{ 12, 7, 10 });
    defer program.deinit();
    var parameters = try exportParameters(allocator, &component);
    defer parameters.deinit();
    try parameters.values.validate(&program);
}

test "native table framework cleans up every failed export allocation" {
    try testing.checkAllAllocationFailures(testing.allocator, allocationCase, .{});
}
