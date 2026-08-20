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
const typed_auipc = @import("typed_auipc.zig");
const authority = @import("typed_auipc_authority.zig");
const types = @import("types.zig");
const witness_layout = @import("../../witness_layout.zig");

const Fingerprint = [32]u8;
const Binding = struct { value: types.ValueId, column: u32 };

test "typed AUIPC fixed authority binding digest is pinned" {
    var authored = try typed_auipc.build(std.testing.allocator, .generated);
    defer authored.deinit();
    const binding = try authority.Binding.canonical(&authored);
    const admitted = try authority.Authority.init(&authored, &binding);
    try std.testing.expectEqual(
        authority.AUTHORITY_BINDING_DIGEST,
        admitted.identityDigest(),
    );
    try std.testing.expectEqual(authority.CANONICAL_BINDING, binding);
    try std.testing.expectEqual(
        authority.CANONICAL_BINDING,
        authority.Authority.pinned().identitySnapshot(),
    );
}

test "typed AUIPC has exact 29 columns 17 roots and 12 ordered effects" {
    var authored = try typed_auipc.build(std.testing.allocator, .generated);
    defer authored.deinit();
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .auipc,
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
    try std.testing.expectEqual(@as(usize, 5), derived_count);
    try std.testing.expectEqual(typed_auipc.MAIN_COLUMN_COUNT, layout.main().len);
    const physical = authored.columns.physical();
    const physical_names = witness_layout.columnNames(.auipc);
    for (physical, physical_names) |value, expected_name| {
        const node = authored.arena.node(value).?;
        const name = switch (node.key.op) {
            .input => |name_id| authored.arena.name(name_id).?,
            else => return error.ExpectedPhysicalInput,
        };
        try std.testing.expectEqualStrings(expected_name, name);
    }

    const authored_bindings = typedBindings(&authored);
    var production_bindings: [typed_auipc.MAIN_COLUMN_COUNT + 1]Binding = undefined;
    for (layout.main(), production_bindings[0..typed_auipc.MAIN_COLUMN_COUNT]) |
        column,
        *binding,
    | binding.* = .{ .value = column.value, .column = column.reference.local_index };
    production_bindings[typed_auipc.MAIN_COLUMN_COUNT] = .{
        .value = imported.selector,
        .column = typed_auipc.MAIN_COLUMN_COUNT,
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
        typed_auipc.DIRECT_CONSTRAINT_COUNT,
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
        .range_request,
        .range_request,
        .range_request,
        .range_request,
        .range_request,
        .range_request,
        .register_write,
        .register_write,
        .register_write,
    };
    const typed_events = try lower_effects.ValidatedProgram.init(&authored.arena);
    try std.testing.expectEqual(typed_auipc.LOOKUP_COUNT, imported.lookups.len);
    for (imported.lookups, expected_kinds, 0..) |expected, expected_kind, index| {
        const event_id = try types.idFromIndex(types.EffectId, index);
        const actual = typed_events.event(event_id).?;
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

test "typed AUIPC identity is source-independent and requires v9 manifest" {
    var generated = try typed_auipc.build(std.testing.allocator, .generated);
    defer generated.deinit();
    var first = try typed_auipc.build(
        std.testing.allocator,
        fileLocation("guest/auipc.air", 17, 4),
    );
    defer first.deinit();
    var second = try typed_auipc.build(
        std.testing.allocator,
        fileLocation("moved/auipc.air", 91, 12),
    );
    defer second.deinit();

    const generated_identity = try digest.computeIdentity(&generated.arena);
    const first_identity = try digest.computeIdentity(&first.arena);
    const second_identity = try digest.computeIdentity(&second.arena);
    try std.testing.expectEqual(
        digest.range_refinement_format_version,
        generated_identity.format_version,
    );
    try std.testing.expectEqual(generated_identity, first_identity);
    try std.testing.expectEqual(generated_identity, second_identity);
    try std.testing.expectEqual(generated_identity.bytes, try digest.computeV7(&generated.arena));
    try std.testing.expectEqual(typed_auipc.SEMANTIC_DIGEST, generated_identity.bytes);
    try std.testing.expectError(error.InvalidEffect, digest.computeV6(&generated.arena));
    try std.testing.expectError(
        error.RangeRefinementRequiresManifestV9,
        manifest.serializeAllocV8(std.testing.allocator, &generated.arena),
    );
    const v9 = try manifest.serializeAllocV9(std.testing.allocator, &generated.arena);
    defer std.testing.allocator.free(v9);
    const current = try manifest.serializeAllocCurrent(std.testing.allocator, &generated.arena);
    defer std.testing.allocator.free(current);
    try std.testing.expectEqualSlices(u8, v9, current);
}

test "typed AUIPC honest boundaries and forged roots match production semantics" {
    var authored = try typed_auipc.build(std.testing.allocator, .generated);
    defer authored.deinit();
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .auipc,
        source.SourceSpan.generated(),
    );
    defer imported.deinit();
    const bindings = typedBindings(&authored);
    const corpus = [_][30]M31{
        honestRow(0, 0, 0),
        honestRow(7, 0xff, 0x1000),
        honestRow(31, 0xffff, 0x7fff_f000),
        honestRow(3, (@as(u32, 1) << 30) - 4, @bitCast(@as(u32, 0x8000_0000))),
        honestRow(9, 0x00ff_ffff, @bitCast(@as(u32, 0xffff_f000))),
    };
    for (corpus) |row|
        try expectProgramParityAndZero(&authored, &imported, &bindings, row);

    var forged = honestRow(7, 0x1000, 0x1000);
    forged[20] = forged[20].add(M31.one());
    try expectConstraintNonZero(&authored, &bindings, forged, 1);
    forged = honestRow(7, 0x1000, 0x1000);
    forged[24] = M31.one();
    try expectConstraintNonZero(&authored, &bindings, forged, 4);
    forged = honestRow(7, 0xff, 0x1000);
    forged[14] = forged[14].add(M31.one());
    try expectAnyConstraintNonZero(&authored, &bindings, forged, 5, 9);
    forged = honestRow(0, 0x1000, 0);
    forged[9] = M31.one();
    try expectConstraintNonZero(&authored, &bindings, forged, 12);
    forged = honestRow(7, 0x1000, 0);
    forged[0] = M31.fromCanonical(2);
    forged[29] = forged[0];
    try expectConstraintNonZero(&authored, &bindings, forged, 0);
    forged = honestRow(7, 0x1000, 0);
    forged[29] = M31.zero();
    try expectConstraintNonZero(&authored, &bindings, forged, 16);
}

fn fileLocation(path: []const u8, line: u32, column: u32) typed_auipc.Location {
    return .{ .file = .{
        .path = path,
        .start = .{ .byte_offset = line * 8, .line = line, .column = column },
        .end = .{ .byte_offset = line * 8 + 5, .line = line, .column = column + 5 },
    } };
}

fn typedBindings(authored: *const typed_auipc.Definition) [31]Binding {
    var bindings: [31]Binding = undefined;
    for (authored.columns.physical(), bindings[0..29], 0..) |value, *binding, column|
        binding.* = .{ .value = value, .column = @intCast(column) };
    bindings[29] = .{ .value = authored.is_active, .column = 29 };
    bindings[30] = .{ .value = authored.pc_polynomial, .column = 2 };
    return bindings;
}

fn honestRow(rd: u32, pc: u32, immediate: i32) [30]M31 {
    const immediate_bits: u32 = @bitCast(immediate);
    std.debug.assert(immediate_bits & 0xfff == 0);
    std.debug.assert(pc < (@as(u32, 1) << 30));
    const result = pc +% immediate_bits;
    var row = [_]M31{M31.zero()} ** 30;
    row[0] = M31.one();
    row[1] = M31.fromCanonical(37);
    row[2] = M31.fromCanonical(pc);
    row[3] = M31.fromCanonical(rd);
    if (rd != 0) {
        putWord(&row, 4, 0x4433_2211);
        row[8] = M31.fromCanonical(3);
        putWord(&row, 9, result);
        row[18] = M31.one();
        row[19] = M31.fromCanonical(rd).inv() catch unreachable;
    }
    row[13] = signed(immediate);
    putWord(&row, 14, result);
    putWord(&row, 20, pc);
    putWord(&row, 24, immediate_bits);
    row[28] = if (immediate < 0) M31.one() else M31.zero();
    row[29] = M31.one();
    return row;
}

fn putWord(row: *[30]M31, offset: usize, word: u32) void {
    inline for (0..4) |limb| row[offset + limb] = M31.fromCanonical(
        (word >> @intCast(limb * 8)) & 0xff,
    );
}

fn signed(value: i32) M31 {
    if (value >= 0) return M31.fromU64(@intCast(value));
    return M31.zero().sub(M31.fromU64(@intCast(-@as(i64, value))));
}

fn expectProgramParityAndZero(
    authored: *const typed_auipc.Definition,
    imported: *const shadow_program.ImportedProgram,
    bindings: []const Binding,
    row: [30]M31,
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
        const actual_root = authored.arena.constraint(actual_id).?.root;
        const expected_root = imported.imported.arena.constraint(expected_id).?.root;
        const actual = valueAt(actual_values, actual_root);
        const expected = valueAt(expected_values, expected_root);
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
    authored: *const typed_auipc.Definition,
    bindings: []const Binding,
    row: [30]M31,
    constraint_index: usize,
) !void {
    const values = try evaluate(std.testing.allocator, &authored.arena, bindings, &row);
    defer std.testing.allocator.free(values);
    const root = authored.arena.constraint(authored.model.constraints[constraint_index]).?.root;
    try std.testing.expect(!valueAt(values, root).isZero());
}

fn expectAnyConstraintNonZero(
    authored: *const typed_auipc.Definition,
    bindings: []const Binding,
    row: [30]M31,
    first: usize,
    end: usize,
) !void {
    const values = try evaluate(std.testing.allocator, &authored.arena, bindings, &row);
    defer std.testing.allocator.free(values);
    for (authored.model.constraints[first..end]) |id| {
        const root = authored.arena.constraint(id).?.root;
        if (!valueAt(values, root).isZero()) return;
    }
    return error.ExpectedNonZeroConstraint;
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

test "AUIPC authority contract suite" {
    _ = @import("typed_auipc_authority_test.zig");
}
