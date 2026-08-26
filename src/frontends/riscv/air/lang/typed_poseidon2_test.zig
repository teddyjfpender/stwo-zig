const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const m31 = @import("stwo_core").fields.m31;
const degree = @import("degree.zig");
const digest = @import("digest.zig");
const functions = @import("functions.zig");
const ir = @import("ir.zig");
const permutation = @import("../memory_commitment/poseidon2.zig");
const poseidon = @import("typed_poseidon2.zig");
const source = @import("source.zig");
const types = @import("types.zig");
const validate = @import("validate.zig");

test "typed Poseidon2 has a static width and an explicit unmaterialized degree" {
    comptime {
        if (poseidon.State.len != poseidon.WIDTH)
            @compileError("typed Poseidon2 state lost its static width");
        if (poseidon.State.element_tag != .felt)
            @compileError("typed Poseidon2 state must remain M31-valued");
    }
    try std.testing.expectEqual(@as(usize, 16), poseidon.WIDTH);
    try std.testing.expectEqual(@as(usize, 8), poseidon.N_EXTERNAL_ROUNDS);
    try std.testing.expectEqual(@as(usize, 14), poseidon.N_INTERNAL_ROUNDS);
    try std.testing.expectEqual(@as(usize, 22), poseidon.N_NONLINEAR_ROUNDS);
    try std.testing.expectEqual(
        @as(u64, 2_384_185_791_015_625),
        poseidon.UNMATERIALIZED_OUTPUT_DEGREE,
    );
    try std.testing.expect(std.meta.eql(
        types.Type{ .array = .{ .element = .felt, .len = 16 } },
        try poseidon.State.semanticType(),
    ));
}

test "typed Poseidon2 independently evaluates pinned full-state vectors" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();

    const cases = [_]struct {
        input: [poseidon.WIDTH]u32,
        expected: [poseidon.WIDTH]u32,
    }{
        .{
            .input = .{ 1, 2 } ++ .{0} ** 14,
            .expected = .{
                1_975_699_496, 659_439_428,   1_311_250_656, 1_131_371_218,
                387_468_254,   249_454_591,   289_085_402,   659_581_845,
                382_139_612,   1_366_230_544, 1_674_587_697, 995_729_863,
                1_412_916_101, 1_893_437_899, 23_371_529,    369_091_567,
            },
        },
        .{
            .input = .{0} ** poseidon.WIDTH,
            .expected = .{
                1_183_174_448, 1_175_856_650, 1_867_564_627, 1_119_649_365,
                1_934_733_286, 1_626_743_204, 679_580_665,   363_794_656,
                1_242_285_733, 1_681_575_677, 777_545_328,   931_445_469,
                485_467_387,   704_712_606,   1_913_388_221, 1_290_687_798,
            },
        },
        .{
            .input = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
            .expected = .{
                1_348_310_665, 996_460_804,   2_044_919_169, 1_269_301_599,
                615_961_333,   595_876_573,   1_377_780_500, 1_776_267_289,
                715_842_585,   1_823_756_332, 1_870_636_634, 1_979_645_732,
                311_256_455,   1_364_752_356, 58_674_647,    323_699_327,
            },
        },
    };

    for (cases) |case| {
        const input = fromCanonical(case.input);
        const actual = try evaluate(
            std.testing.allocator,
            &fixture.arena,
            fixture.definition,
            input,
        );
        const pinned = fromCanonical(case.expected);
        try expectStateEqual(pinned, actual);

        var scalar = input;
        permutation.permute(&scalar);
        try expectStateEqual(pinned, scalar);
    }
}

test "typed Poseidon2 matches the production scalar permutation on random states" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var prng = std.Random.DefaultPrng.init(0x74797065642d7032);
    const random = prng.random();

    for (0..128) |_| {
        var input: permutation.State = undefined;
        for (&input) |*value| {
            value.* = M31.fromCanonical(random.int(u32) % m31.Modulus);
        }
        const actual = try evaluate(
            std.testing.allocator,
            &fixture.arena,
            fixture.definition,
            input,
        );
        var expected = input;
        permutation.permute(&expected);
        try expectStateEqual(expected, actual);
    }
}

test "typed Poseidon2 is a validated pure function graph" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    try validate.validate(&fixture.arena);
    // 16 inputs plus the canonical, structurally interned round expansion.
    // Pinning this catches a missing round or an accidental dynamic traversal
    // before H-003 gives materialization its own versioned identity.
    try std.testing.expectEqual(@as(usize, 2_171), fixture.arena.nodeCount());

    try std.testing.expectEqual(@as(usize, 1), functions.view(&fixture.arena).len);
    try std.testing.expectEqual(@as(usize, 0), functions.calls(&fixture.arena).len);
    try std.testing.expectEqual(@as(usize, 0), fixture.arena.constraintsView().len);
    try std.testing.expectEqual(@as(usize, 0), fixture.arena.effectsView().len);
    try std.testing.expectEqual(@as(usize, 0), fixture.arena.hints.items.len);

    const declaration = functions.get(
        &fixture.arena,
        fixture.definition.function,
    ).?;
    try std.testing.expect(declaration.complete);
    try std.testing.expectEqualStrings(
        poseidon.function_name,
        fixture.arena.name(declaration.name).?,
    );
    const input_values = poseidon.values(fixture.definition.inputs);
    const output_values = poseidon.values(fixture.definition.outputs);
    try std.testing.expectEqualSlices(
        types.ValueId,
        &input_values,
        functions.inputs(&fixture.arena, fixture.definition.function).?,
    );
    try std.testing.expectEqualSlices(
        types.ValueId,
        &output_values,
        functions.outputs(&fixture.arena, fixture.definition.function).?,
    );
    for (fixture.definition.inputs.items, poseidon.input_names) |item, name| {
        const node = fixture.arena.node(item.value).?;
        try std.testing.expectEqual(types.Type.felt, node.key.ty);
        try std.testing.expectEqualStrings(
            name,
            fixture.arena.name(node.key.op.input).?,
        );
    }
    for (fixture.definition.outputs.items) |item| {
        try std.testing.expectEqual(
            types.Type.felt,
            fixture.arena.node(item.value).?.key.ty,
        );
    }
}

test "typed Poseidon2 graph has the exact round-derived semantic degree" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();

    const degrees = try analyzeWideDegrees(std.testing.allocator, &fixture.arena);
    defer std.testing.allocator.free(degrees);
    for (fixture.definition.outputs.items) |output| {
        try std.testing.expectEqual(
            poseidon.UNMATERIALIZED_OUTPUT_DEGREE,
            degrees[types.idIndex(output.value)],
        );
    }

    // The v0 analyzer deliberately fails closed at u32 overflow. H-003 must
    // materialize this graph before applying the degree-three protocol budget.
    try std.testing.expectError(
        error.DegreeOverflow,
        degree.analyze(std.testing.allocator, &fixture.arena),
    );
}

test "typed Poseidon2 expansion is deterministic across clean arenas" {
    var first = try Fixture.init(std.testing.allocator);
    defer first.deinit();
    var second = try Fixture.init(std.testing.allocator);
    defer second.deinit();

    try std.testing.expectEqual(first.arena.nodeCount(), second.arena.nodeCount());
    for (first.arena.nodesView(), second.arena.nodesView()) |lhs, rhs| {
        try std.testing.expect(std.meta.eql(lhs.key, rhs.key));
        try std.testing.expect(std.meta.eql(lhs.primary_source, rhs.primary_source));
    }
    const first_digest = try digest.compute(&first.arena);
    const second_digest = try digest.compute(&second.arena);
    try std.testing.expectEqual(first_digest, second_digest);
}

test "typed Poseidon2 retains stage and lane source provenance" {
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const source_id = try arena.addSource("air/components/poseidon2_m31.zig");
    const spans = try distinctSpans(source_id);
    const definition = try poseidon.define(&arena, spans);
    try validate.validate(&arena);

    for (definition.inputs.items, spans.inputs) |item, expected| {
        try std.testing.expect(std.meta.eql(expected, item.source_span));
        try std.testing.expect(std.meta.eql(
            expected,
            arena.node(item.value).?.primary_source,
        ));
    }
    const final_span = spans.body.external_rounds[
        poseidon.N_EXTERNAL_ROUNDS - 1
    ].linear;
    for (definition.outputs.items) |item| {
        try std.testing.expect(std.meta.eql(final_span, item.source_span));
        try std.testing.expect(std.meta.eql(
            final_span,
            arena.node(item.value).?.primary_source,
        ));
    }
    try std.testing.expect(std.meta.eql(
        spans.declaration,
        functions.get(&arena, definition.function).?.source_span,
    ));
}

test "typed Poseidon2 preflights every span before expansion" {
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const generated = source.SourceSpan.generated();
    const input = try arena.input("shared", .felt, generated);
    const state = try poseidon.State.fromValues(
        &arena,
        &([_]types.ValueId{input} ** poseidon.WIDTH),
    );
    var spans = poseidon.BodySpans.uniform(generated);
    spans.external_rounds[poseidon.N_EXTERNAL_ROUNDS - 1].linear = .{
        .source = try types.idFromIndex(types.SourceId, 99),
        .start = .{ .byte_offset = 0, .line = 1, .column = 1 },
        .end = .{ .byte_offset = 1, .line = 1, .column = 2 },
    };
    const before = arena.nodeCount();
    try std.testing.expectError(
        error.UnknownSource,
        poseidon.permute(&arena, state, spans),
    );
    try std.testing.expectEqual(before, arena.nodeCount());
    try std.testing.expectEqual(arena.nodeCount(), arena.interned_nodes.count());
    try validate.validate(&arena);
}

test "typed Poseidon2 construction releases every partial allocation" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

const Fixture = struct {
    arena: ir.Arena,
    definition: poseidon.Definition,

    fn init(allocator: std.mem.Allocator) !Fixture {
        var arena = ir.Arena.init(allocator);
        errdefer arena.deinit();
        const definition = try poseidon.define(
            &arena,
            poseidon.DefinitionSpans.uniform(source.SourceSpan.generated()),
        );
        return .{ .arena = arena, .definition = definition };
    }

    fn deinit(self: *Fixture) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit();
    try validate.validate(&fixture.arena);
}

fn evaluate(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
    definition: poseidon.Definition,
    input: permutation.State,
) !permutation.State {
    const node_values = try allocator.alloc(M31, arena.nodeCount());
    defer allocator.free(node_values);
    const input_ids = poseidon.values(definition.inputs);

    for (arena.nodesView(), 0..) |node, index| {
        node_values[index] = switch (node.key.op) {
            .constant => |constant| switch (constant) {
                .field => |value| M31.fromCanonical(value),
                .unsigned => |value| M31.fromU64(value),
            },
            .input => input[
                inputIndex(&input_ids, @enumFromInt(index)) orelse
                    return error.UnknownPoseidonInput
            ],
            .add => |binary| node_values[types.idIndex(binary.lhs)].add(
                node_values[types.idIndex(binary.rhs)],
            ),
            .sub => |binary| node_values[types.idIndex(binary.lhs)].sub(
                node_values[types.idIndex(binary.rhs)],
            ),
            .mul => |binary| node_values[types.idIndex(binary.lhs)].mul(
                node_values[types.idIndex(binary.rhs)],
            ),
            .neg => |value| node_values[types.idIndex(value)].neg(),
            .select => |selection| if (!node_values[
                types.idIndex(selection.selector)
            ].isZero())
                node_values[types.idIndex(selection.when_true)]
            else
                node_values[types.idIndex(selection.when_false)],
            .hint_output, .call_output, .machine_derived => return error.UnsupportedPoseidonNode,
        };
    }

    var output: permutation.State = undefined;
    for (&output, definition.outputs.items) |*value, item| {
        value.* = node_values[types.idIndex(item.value)];
    }
    return output;
}

fn inputIndex(
    inputs: *const [poseidon.WIDTH]types.ValueId,
    target: types.ValueId,
) ?usize {
    for (inputs, 0..) |input, index| {
        if (input == target) return index;
    }
    return null;
}

fn analyzeWideDegrees(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
) ![]u64 {
    try validate.validate(arena);
    const result = try allocator.alloc(u64, arena.nodeCount());
    errdefer allocator.free(result);
    for (arena.nodesView(), 0..) |node, index| {
        result[index] = switch (node.key.op) {
            .constant => 0,
            .input, .hint_output, .call_output => 1,
            .add, .sub => |binary| @max(
                result[types.idIndex(binary.lhs)],
                result[types.idIndex(binary.rhs)],
            ),
            .mul => |binary| try std.math.add(
                u64,
                result[types.idIndex(binary.lhs)],
                result[types.idIndex(binary.rhs)],
            ),
            .neg => |value| result[types.idIndex(value)],
            .select => |selection| try std.math.add(
                u64,
                result[types.idIndex(selection.selector)],
                @max(
                    result[types.idIndex(selection.when_true)],
                    result[types.idIndex(selection.when_false)],
                ),
            ),
            .machine_derived => |derived| switch (derived) {
                .register_address => |address| result[types.idIndex(address.index)],
                .aligned_word_address => |address| result[types.idIndex(address.word_index)],
                .access_clock => |clock| result[types.idIndex(clock.instruction_clock)],
                .strict_clock_gap => |gap| @max(
                    result[types.idIndex(gap.current_clock)],
                    result[types.idIndex(gap.previous_clock)],
                ),
                .instruction_next_pc => |next| result[types.idIndex(next.current)],
                .instruction_next_clock => |next| result[types.idIndex(next.current)],
            },
        };
    }
    return result;
}

fn fromCanonical(values: [poseidon.WIDTH]u32) permutation.State {
    var result: permutation.State = undefined;
    for (&result, values) |*output, value| {
        output.* = M31.fromCanonical(value);
    }
    return result;
}

fn expectStateEqual(expected: permutation.State, actual: permutation.State) !void {
    for (expected, actual, 0..) |expected_value, actual_value, lane| {
        errdefer std.debug.print("Poseidon2 lane {d}\n", .{lane});
        try std.testing.expectEqual(expected_value, actual_value);
    }
}

fn distinctSpans(source_id: types.SourceId) !poseidon.DefinitionSpans {
    var next_line: u32 = 1;
    const declaration = try spanAt(source_id, next_line);
    next_line += 1;
    var inputs: [poseidon.WIDTH]source.SourceSpan = undefined;
    for (&inputs) |*span| {
        span.* = try spanAt(source_id, next_line);
        next_line += 1;
    }
    const initial_linear = try spanAt(source_id, next_line);
    next_line += 1;
    var external: [poseidon.N_EXTERNAL_ROUNDS]poseidon.ExternalRoundSpans = undefined;
    for (&external) |*round| {
        round.* = .{
            .constants = try spanAt(source_id, next_line),
            .sbox = try spanAt(source_id, next_line + 1),
            .linear = try spanAt(source_id, next_line + 2),
        };
        next_line += 3;
    }
    var internal: [poseidon.N_INTERNAL_ROUNDS]poseidon.InternalRoundSpans = undefined;
    for (&internal) |*round| {
        round.* = .{
            .constant = try spanAt(source_id, next_line),
            .sbox = try spanAt(source_id, next_line + 1),
            .linear = try spanAt(source_id, next_line + 2),
        };
        next_line += 3;
    }
    return .{
        .declaration = declaration,
        .inputs = inputs,
        .body = .{
            .initial_linear = initial_linear,
            .external_rounds = external,
            .internal_rounds = internal,
        },
    };
}

fn spanAt(source_id: types.SourceId, line: u32) !source.SourceSpan {
    return source.SourceSpan.init(
        source_id,
        .{ .byte_offset = 8 * line, .line = line, .column = 1 },
        .{ .byte_offset = 8 * line + 1, .line = line, .column = 2 },
    );
}
