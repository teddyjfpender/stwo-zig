const std = @import("std");
const compat_layout = @import("compat_layout.zig");
const degree = @import("degree.zig");
const digest = @import("digest.zig");
const expr = @import("expr.zig");
const lower_effects = @import("lower_effects.zig");
const program = @import("program.zig");
const shadow_program = @import("shadow_program.zig");
const source = @import("source.zig");
const typed = @import("typed_base_alu_reg.zig");
const types = @import("types.zig");
const witness_layout = @import("../../witness_layout.zig");

const Fingerprint = [32]u8;
const Binding = struct { value: types.ValueId, column: u32 };

test "typed BASE_ALU_REG is compatibility-exact for every constraint and effect" {
    var authored = try typed.build(std.testing.allocator, .generated);
    defer authored.deinit();
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .base_alu_reg,
        source.SourceSpan.generated(),
    );
    defer imported.deinit();
    const layout = try compat_layout.build(&imported);

    try authored.validate();
    var degrees = try degree.analyze(std.testing.allocator, &authored.arena);
    defer degrees.deinit();
    try std.testing.expectEqual(
        @as(degree.Degree, 3),
        degrees.maximumConstraintDegree(),
    );
    try std.testing.expectEqual(typed.MAIN_COLUMN_COUNT, layout.main().len);
    try std.testing.expectEqual(typed.RELATION_BATCH_SIZE, imported.batch_size);
    const physical = authored.columns.physical();
    for (physical, witness_layout.columnNames(.base_alu_reg)) |value, expected_name| {
        const node = authored.arena.node(value).?;
        const name = switch (node.key.op) {
            .input => |name_id| authored.arena.name(name_id).?,
            else => return error.ExpectedPhysicalInput,
        };
        try std.testing.expectEqualStrings(expected_name, name);
    }

    const authored_bindings = typedBindings(&authored);
    var production_bindings: [typed.MAIN_COLUMN_COUNT + 1]Binding = undefined;
    for (layout.main(), production_bindings[0..typed.MAIN_COLUMN_COUNT]) |
        column,
        *binding,
    | binding.* = .{ .value = column.value, .column = column.reference.local_index };
    production_bindings[typed.MAIN_COLUMN_COUNT] = .{
        .value = imported.selector,
        .column = typed.MAIN_COLUMN_COUNT,
    };
    const actual_fingerprints = try fingerprintProgram(
        std.testing.allocator,
        &authored.arena,
        &authored_bindings,
    );
    defer std.testing.allocator.free(actual_fingerprints);
    const expected_fingerprints = try fingerprintProgram(
        std.testing.allocator,
        &imported.imported.arena,
        &production_bindings,
    );
    defer std.testing.allocator.free(expected_fingerprints);

    try std.testing.expectEqual(
        typed.DIRECT_CONSTRAINT_COUNT,
        imported.direct_constraints.len,
    );
    for (authored.constraints, imported.direct_constraints) |actual_id, expected_id| {
        const actual = authored.arena.constraint(actual_id).?;
        const expected = imported.imported.arena.constraint(expected_id).?;
        try std.testing.expectEqual(
            expected_fingerprints[types.idIndex(expected.root)],
            actual_fingerprints[types.idIndex(actual.root)],
        );
    }

    const expected_kinds = [_]program.EffectKind{
        .program_fetch,
        .state_consume,
        .state_produce,
        .register_read,
        .register_read,
        .register_read,
        .register_read,
        .register_read,
        .register_read,
        .bitwise_request,
        .bitwise_request,
        .bitwise_request,
        .bitwise_request,
        .range_request,
        .range_request,
        .register_write,
        .register_write,
        .register_write,
    };
    const typed_events = try lower_effects.ValidatedProgram.init(&authored.arena);
    try std.testing.expectEqual(typed.RELATION_EVENT_COUNT, imported.lookups.len);
    for (imported.lookups, expected_kinds, 0..) |expected, expected_kind, index| {
        const id = try types.idFromIndex(types.EffectId, index);
        const actual = typed_events.event(id).?;
        try std.testing.expectEqual(expected_kind, actual.kind);
        try std.testing.expectEqual(expected.schema, actual.schema);
        try std.testing.expectEqual(expected.role, actual.role);
        try std.testing.expectEqual(expected.access_ordinal, actual.access_ordinal);
        const expected_values = imported.lookupFields(index).?;
        try std.testing.expectEqual(expected_values.len, actual.values.len);
        for (expected_values, actual.values, 0..) |expected_value, actual_value, field| {
            if (!std.mem.eql(
                u8,
                &expected_fingerprints[types.idIndex(expected_value)],
                &actual_fingerprints[types.idIndex(actual_value)],
            )) std.debug.print("BASE_ALU_REG effect mismatch event={d} field={d}\n", .{
                index,
                field,
            });
            try std.testing.expectEqual(
                expected_fingerprints[types.idIndex(expected_value)],
                actual_fingerprints[types.idIndex(actual_value)],
            );
        }
        const signed_liveness = switch (expected.role) {
            .emit => actual_fingerprints[types.idIndex(actual.liveness)],
            .request, .consume => unaryFingerprint(
                5,
                actual_fingerprints[types.idIndex(actual.liveness)],
            ),
        };
        try std.testing.expectEqual(
            expected_fingerprints[types.idIndex(expected.numerator)],
            signed_liveness,
        );
    }
}

test "typed BASE_ALU_REG identity is source-independent and allocation-atomic" {
    var generated = try typed.build(std.testing.allocator, .generated);
    defer generated.deinit();
    var first = try typed.build(std.testing.allocator, fileLocation("base_reg.air", 7));
    defer first.deinit();
    var moved = try typed.build(std.testing.allocator, fileLocation("moved/base_reg.air", 91));
    defer moved.deinit();
    try std.testing.expectEqual(
        try digest.computeIdentity(&generated.arena),
        try digest.computeIdentity(&first.arena),
    );
    try std.testing.expectEqual(
        try digest.computeIdentity(&generated.arena),
        try digest.computeIdentity(&moved.arena),
    );
    try std.testing.expectEqual(
        typed.SEMANTIC_DIGEST,
        try digest.computeV6(&generated.arena),
    );
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    var definition = try typed.build(allocator, .generated);
    defer definition.deinit();
}

fn fileLocation(path: []const u8, line: u32) typed.Location {
    return .{ .file = .{
        .path = path,
        .start = .{ .byte_offset = line * 8, .line = line, .column = 1 },
        .end = .{ .byte_offset = line * 8 + 7, .line = line, .column = 8 },
    } };
}

fn typedBindings(authored: *const typed.Definition) [36]Binding {
    var bindings: [36]Binding = undefined;
    for (authored.columns.physical(), bindings[0..35], 0..) |value, *binding, column|
        binding.* = .{ .value = value, .column = @intCast(column) };
    bindings[35] = .{ .value = authored.is_active, .column = 35 };
    return bindings;
}

fn fingerprintProgram(
    allocator: std.mem.Allocator,
    arena: *const @import("ir.zig").Arena,
    bindings: []const Binding,
) ![]Fingerprint {
    const fingerprints = try allocator.alloc(Fingerprint, arena.nodeCount());
    errdefer allocator.free(fingerprints);
    for (arena.nodesView(), 0..) |node, index| {
        const id = try types.idFromIndex(types.ValueId, index);
        fingerprints[index] = if (columnFor(bindings, id)) |column|
            scalarFingerprint(0, @intCast(column))
        else switch (node.key.op) {
            .constant => |constant| scalarFingerprint(1, switch (constant) {
                .field, .unsigned => |value| value,
            }),
            .add => |binary| binaryFingerprint(
                2,
                fingerprintAt(fingerprints, binary.lhs),
                fingerprintAt(fingerprints, binary.rhs),
                true,
            ),
            .sub => |binary| binaryFingerprint(
                3,
                fingerprintAt(fingerprints, binary.lhs),
                fingerprintAt(fingerprints, binary.rhs),
                false,
            ),
            .mul => |binary| binaryFingerprint(
                4,
                fingerprintAt(fingerprints, binary.lhs),
                fingerprintAt(fingerprints, binary.rhs),
                true,
            ),
            .neg => |value| unaryFingerprint(5, fingerprintAt(fingerprints, value)),
            .select => |selection| selectFingerprint(fingerprints, selection),
            .machine_derived => |derived| derivedFingerprint(fingerprints, derived),
            .input => return error.UnmappedInput,
            .hint_output, .call_output => return error.UnsupportedNode,
        };
    }
    return fingerprints;
}

fn derivedFingerprint(values: []const Fingerprint, derived: expr.MachineDerived) Fingerprint {
    const one = scalarFingerprint(1, 1);
    const four = scalarFingerprint(1, 4);
    return switch (derived) {
        .register_address => |address| fingerprintAt(values, address.index),
        .aligned_word_address => |address| binaryFingerprint(
            4,
            fingerprintAt(values, address.word_index),
            four,
            true,
        ),
        .access_clock => |clock| binaryFingerprint(
            2,
            binaryFingerprint(
                4,
                binaryFingerprint(
                    3,
                    fingerprintAt(values, clock.instruction_clock),
                    one,
                    false,
                ),
                four,
                true,
            ),
            scalarFingerprint(1, @intFromEnum(clock.phase)),
            true,
        ),
        .strict_clock_gap => |gap| binaryFingerprint(
            3,
            binaryFingerprint(
                3,
                fingerprintAt(values, gap.current_clock),
                fingerprintAt(values, gap.previous_clock),
                false,
            ),
            one,
            false,
        ),
        .instruction_next_pc => |next| binaryFingerprint(
            2,
            fingerprintAt(values, next.current),
            four,
            true,
        ),
        .instruction_next_clock => |next| binaryFingerprint(
            2,
            fingerprintAt(values, next.current),
            one,
            true,
        ),
    };
}

fn selectFingerprint(values: []const Fingerprint, selection: expr.Selection) Fingerprint {
    const difference = binaryFingerprint(
        3,
        fingerprintAt(values, selection.when_true),
        fingerprintAt(values, selection.when_false),
        false,
    );
    return binaryFingerprint(
        2,
        fingerprintAt(values, selection.when_false),
        binaryFingerprint(
            4,
            fingerprintAt(values, selection.selector),
            difference,
            true,
        ),
        true,
    );
}

fn fingerprintAt(values: []const Fingerprint, id: types.ValueId) Fingerprint {
    return values[types.idIndex(id)];
}

fn scalarFingerprint(tag: u8, value: u32) Fingerprint {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(&.{tag});
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, value, .little);
    hash.update(&bytes);
    return hash.finalResult();
}

fn unaryFingerprint(tag: u8, value: Fingerprint) Fingerprint {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(&.{tag});
    hash.update(&value);
    return hash.finalResult();
}

fn binaryFingerprint(
    tag: u8,
    first_unordered: Fingerprint,
    second_unordered: Fingerprint,
    commutative: bool,
) Fingerprint {
    var first = first_unordered;
    var second = second_unordered;
    if (commutative and std.mem.order(u8, &first, &second) == .gt)
        std.mem.swap(Fingerprint, &first, &second);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(&.{tag});
    hash.update(&first);
    hash.update(&second);
    return hash.finalResult();
}

fn columnFor(bindings: []const Binding, value: types.ValueId) ?usize {
    for (bindings) |binding| if (binding.value == value) return binding.column;
    return null;
}
