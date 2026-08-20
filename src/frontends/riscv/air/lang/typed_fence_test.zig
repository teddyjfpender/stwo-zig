const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const compat_layout = @import("compat_layout.zig");
const degree = @import("degree.zig");
const digest = @import("digest.zig");
const expr = @import("expr.zig");
const ir = @import("ir.zig");
const lower_effects = @import("lower_effects.zig");
const manifest = @import("manifest.zig");
const program = @import("program.zig");
const shadow_program = @import("shadow_program.zig");
const source = @import("source.zig");
const typed_fence = @import("typed_fence.zig");
const types = @import("types.zig");
const witness_layout = @import("../../witness_layout.zig");

const Fingerprint = [32]u8;
const Binding = struct { value: types.ValueId, column: u32 };

test "typed FENCE has exact six columns two roots and three ordered effects" {
    var authored = try typed_fence.build(std.testing.allocator, .generated);
    defer authored.deinit();
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .fence,
        source.SourceSpan.generated(),
    );
    defer imported.deinit();
    const layout = try compat_layout.build(&imported);

    try authored.validate();
    var degrees = try degree.analyze(std.testing.allocator, &authored.arena);
    defer degrees.deinit();
    try std.testing.expectEqual(@as(degree.Degree, 2), degrees.maximumConstraintDegree());
    var derived_count: usize = 0;
    for (authored.arena.nodesView()) |node| switch (node.key.op) {
        .machine_derived => derived_count += 1,
        else => {},
    };
    try std.testing.expectEqual(@as(usize, 2), derived_count);
    try std.testing.expectEqual(typed_fence.MAIN_COLUMN_COUNT, layout.main().len);
    for (authored.columns.physical(), witness_layout.columnNames(.fence)) |
        value,
        expected_name,
    | {
        const node = authored.arena.node(value).?;
        const name = switch (node.key.op) {
            .input => |name_id| authored.arena.name(name_id).?,
            else => return error.ExpectedPhysicalInput,
        };
        try std.testing.expectEqualStrings(expected_name, name);
    }

    const authored_bindings = typedBindings(&authored);
    var production_bindings: [typed_fence.MAIN_COLUMN_COUNT + 1]Binding = undefined;
    for (layout.main(), production_bindings[0..typed_fence.MAIN_COLUMN_COUNT]) |
        column,
        *binding,
    | binding.* = .{ .value = column.value, .column = column.reference.local_index };
    production_bindings[typed_fence.MAIN_COLUMN_COUNT] = .{
        .value = imported.selector,
        .column = typed_fence.MAIN_COLUMN_COUNT,
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
        typed_fence.DIRECT_CONSTRAINT_COUNT,
        imported.direct_constraints.len,
    );
    for (authored.model.constraints, imported.direct_constraints) |actual_id, expected_id| {
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
    };
    const typed_events = try lower_effects.ValidatedProgram.init(&authored.arena);
    try std.testing.expectEqual(typed_fence.LOOKUP_COUNT, imported.lookups.len);
    for (imported.lookups, expected_kinds, 0..) |expected, expected_kind, index| {
        const actual = typed_events.event(try types.idFromIndex(types.EffectId, index)).?;
        try std.testing.expectEqual(expected_kind, actual.kind);
        try std.testing.expectEqual(expected.schema, actual.schema);
        try std.testing.expectEqual(expected.role, actual.role);
        try std.testing.expectEqual(expected.access_ordinal, actual.access_ordinal);
        try std.testing.expectEqual(authored.columns.enabler, actual.liveness);
        const expected_values = imported.lookupFields(index).?;
        try std.testing.expectEqual(expected_values.len, actual.values.len);
        for (expected_values, actual.values) |expected_value, actual_value| {
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
        const batch = index / imported.batch_size;
        const batch_column = layout.interactions()[batch * 4];
        try std.testing.expectEqual(batch, @as(usize, batch_column.batch));
        try std.testing.expectEqual(batch * imported.batch_size, batch_column.first_lookup);
        try std.testing.expectEqual(
            @min(@as(usize, imported.batch_size), imported.lookups.len - batch * imported.batch_size),
            batch_column.entry_count,
        );
    }
}

test "typed FENCE identity is source-independent and requires v7 manifest" {
    var generated = try typed_fence.build(std.testing.allocator, .generated);
    defer generated.deinit();
    var first = try typed_fence.build(
        std.testing.allocator,
        fileLocation("guest/fence.air", 11, 3),
    );
    defer first.deinit();
    var second = try typed_fence.build(
        std.testing.allocator,
        fileLocation("moved/fence.air", 87, 17),
    );
    defer second.deinit();
    const generated_identity = try digest.computeIdentity(&generated.arena);
    try std.testing.expectEqual(generated_identity, try digest.computeIdentity(&first.arena));
    try std.testing.expectEqual(generated_identity, try digest.computeIdentity(&second.arena));
    try std.testing.expectEqual(
        digest.sequential_retirement_format_version,
        generated_identity.format_version,
    );
    try std.testing.expectEqual(generated_identity.bytes, try digest.computeV5(&generated.arena));
    try std.testing.expectEqual(typed_fence.SEMANTIC_DIGEST, generated_identity.bytes);
    try std.testing.expectError(
        error.SequentialRetirementRequiresManifestV7,
        manifest.serializeAllocV6(std.testing.allocator, &generated.arena),
    );
    const v7 = try manifest.serializeAllocV7(std.testing.allocator, &generated.arena);
    defer std.testing.allocator.free(v7);
    const current = try manifest.serializeAllocCurrent(std.testing.allocator, &generated.arena);
    defer std.testing.allocator.free(current);
    try std.testing.expectEqualSlices(u8, v7, current);
}

test "typed FENCE boundary encoding rows and forgeries match production" {
    var authored = try typed_fence.build(std.testing.allocator, .generated);
    defer authored.deinit();
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .fence,
        source.SourceSpan.generated(),
    );
    defer imported.deinit();
    const bindings = typedBindings(&authored);
    const corpus = [_][7]M31{
        honestRow(0, 0, 0, 0),
        honestRow(31, 31, 0x3fffffff, 0x7ff),
        honestRow(17, 9, 0x1000, 0x800),
        honestRow(7, 13, 0x00ffffff, 0xf53),
    };
    for (corpus) |row|
        try expectProgramParityAndZero(&authored, &imported, &bindings, row);

    var forged = honestRow(7, 13, 0x1000, 0xf53);
    forged[0] = M31.fromCanonical(2);
    forged[6] = forged[0];
    try expectConstraintNonZero(&authored, &bindings, forged, 0);
    forged = honestRow(7, 13, 0x1000, 0xf53);
    forged[6] = M31.zero();
    try expectConstraintNonZero(&authored, &bindings, forged, 1);
}

fn fileLocation(path: []const u8, line: u32, column: u32) typed_fence.Location {
    return .{ .file = .{
        .path = path,
        .start = .{ .byte_offset = line * 8, .line = line, .column = column },
        .end = .{ .byte_offset = line * 8 + 5, .line = line, .column = column + 5 },
    } };
}

fn typedBindings(authored: *const typed_fence.Definition) [7]Binding {
    var bindings: [7]Binding = undefined;
    for (authored.columns.physical(), bindings[0..6], 0..) |value, *binding, column|
        binding.* = .{ .value = value, .column = @intCast(column) };
    bindings[6] = .{ .value = authored.is_active, .column = 6 };
    return bindings;
}

fn honestRow(rd: u32, rs1: u32, pc: u32, immediate: u32) [7]M31 {
    return .{
        M31.one(),
        M31.fromCanonical(37),
        M31.fromCanonical(pc),
        M31.fromCanonical(rd),
        M31.fromCanonical(rs1),
        M31.fromCanonical(immediate),
        M31.one(),
    };
}

fn expectProgramParityAndZero(
    authored: *const typed_fence.Definition,
    imported: *const shadow_program.ImportedProgram,
    bindings: []const Binding,
    row: [7]M31,
) !void {
    const actual_values = try evaluate(std.testing.allocator, &authored.arena, bindings, &row);
    defer std.testing.allocator.free(actual_values);
    const expected_values = try std.testing.allocator.alloc(
        M31,
        imported.imported.arena.nodeCount(),
    );
    defer std.testing.allocator.free(expected_values);
    try imported.imported.replay(&row, expected_values);
    for (authored.model.constraints, imported.direct_constraints) |actual_id, expected_id| {
        const actual = valueAt(actual_values, authored.arena.constraint(actual_id).?.root);
        const expected = valueAt(
            expected_values,
            imported.imported.arena.constraint(expected_id).?.root,
        );
        try std.testing.expectEqual(expected.toU32(), actual.toU32());
        try std.testing.expect(actual.isZero());
    }
    const typed_events = try lower_effects.ValidatedProgram.init(&authored.arena);
    for (imported.lookups, 0..) |expected, index| {
        const actual = typed_events.event(try types.idFromIndex(types.EffectId, index)).?;
        const actual_liveness = valueAt(actual_values, actual.liveness);
        const signed_liveness = switch (expected.role) {
            .emit => actual_liveness,
            .request, .consume => actual_liveness.neg(),
        };
        try std.testing.expectEqual(
            valueAt(expected_values, expected.numerator).toU32(),
            signed_liveness.toU32(),
        );
        for (imported.lookupFields(index).?, actual.values) |expected_value, actual_value| {
            try std.testing.expectEqual(
                valueAt(expected_values, expected_value).toU32(),
                valueAt(actual_values, actual_value).toU32(),
            );
        }
    }
}

fn expectConstraintNonZero(
    authored: *const typed_fence.Definition,
    bindings: []const Binding,
    row: [7]M31,
    index: usize,
) !void {
    const values = try evaluate(std.testing.allocator, &authored.arena, bindings, &row);
    defer std.testing.allocator.free(values);
    const root = authored.arena.constraint(authored.model.constraints[index]).?.root;
    try std.testing.expect(!valueAt(values, root).isZero());
}

fn evaluate(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
    bindings: []const Binding,
    columns: []const M31,
) ![]M31 {
    const values = try allocator.alloc(M31, arena.nodeCount());
    errdefer allocator.free(values);
    for (arena.nodesView(), 0..) |node, index| {
        const id = try types.idFromIndex(types.ValueId, index);
        values[index] = if (columnFor(bindings, id)) |column|
            columns[column]
        else switch (node.key.op) {
            .constant => |constant| switch (constant) {
                .field, .unsigned => |value| M31.fromU64(value),
            },
            .add => |binary| valueAt(values, binary.lhs).add(valueAt(values, binary.rhs)),
            .sub => |binary| valueAt(values, binary.lhs).sub(valueAt(values, binary.rhs)),
            .mul => |binary| valueAt(values, binary.lhs).mul(valueAt(values, binary.rhs)),
            .neg => |value| valueAt(values, value).neg(),
            .select => |selection| if (valueAt(values, selection.selector).isZero())
                valueAt(values, selection.when_false)
            else
                valueAt(values, selection.when_true),
            .machine_derived => |derived| evaluateDerived(values, derived),
            .input => return error.UnmappedInput,
            .hint_output, .call_output => return error.UnsupportedNode,
        };
    }
    return values;
}

fn evaluateDerived(values: []const M31, derived: expr.MachineDerived) M31 {
    return switch (derived) {
        .register_address => |address| valueAt(values, address.index),
        .aligned_word_address => |address| valueAt(values, address.word_index)
            .mul(M31.fromCanonical(4)),
        .access_clock => |clock| valueAt(values, clock.instruction_clock)
            .sub(M31.one()).mul(M31.fromCanonical(4))
            .add(M31.fromCanonical(@intFromEnum(clock.phase))),
        .strict_clock_gap => |gap| valueAt(values, gap.current_clock)
            .sub(valueAt(values, gap.previous_clock)).sub(M31.one()),
        .instruction_next_pc => |next| valueAt(values, next.current)
            .add(M31.fromCanonical(4)),
        .instruction_next_clock => |next| valueAt(values, next.current).add(M31.one()),
    };
}

fn fingerprintProgram(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
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

fn valueAt(values: []const M31, id: types.ValueId) M31 {
    return values[types.idIndex(id)];
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
