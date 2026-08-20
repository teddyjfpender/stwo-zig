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
const typed_addi = @import("typed_addi.zig");
const typed_lui = @import("typed_lui.zig");
const types = @import("types.zig");
const witness_layout = @import("../../witness_layout.zig");

const Fingerprint = [32]u8;
const Binding = struct { value: types.ValueId, column: u32 };

test "typed ADDI has exact 35 columns 22 roots and 16 ordered events" {
    var authored = try typed_addi.build(std.testing.allocator, .generated);
    defer authored.deinit();
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .base_alu_imm,
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
    var derived_count: usize = 0;
    for (authored.arena.nodesView()) |node| switch (node.key.op) {
        .machine_derived => derived_count += 1,
        else => {},
    };
    try std.testing.expectEqual(@as(usize, 8), derived_count);
    try std.testing.expectEqual(typed_addi.MAIN_COLUMN_COUNT, layout.main().len);
    try std.testing.expectEqual(
        typed_addi.RELATION_BATCH_SIZE,
        imported.batch_size,
    );
    const physical = authored.columns.physical();
    const physical_names = witness_layout.columnNames(.base_alu_imm);
    for (physical, physical_names) |value, expected_name| {
        const node = authored.arena.node(value).?;
        const name = switch (node.key.op) {
            .input => |name_id| authored.arena.name(name_id).?,
            else => return error.ExpectedPhysicalInput,
        };
        try std.testing.expectEqualStrings(expected_name, name);
    }

    const authored_bindings = typedBindings(&authored);
    var production_bindings: [typed_addi.MAIN_COLUMN_COUNT + 1]Binding = undefined;
    for (layout.main(), production_bindings[0..typed_addi.MAIN_COLUMN_COUNT]) |
        column,
        *binding,
    | binding.* = .{ .value = column.value, .column = column.reference.local_index };
    production_bindings[typed_addi.MAIN_COLUMN_COUNT] = .{
        .value = imported.selector,
        .column = typed_addi.MAIN_COLUMN_COUNT,
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
        typed_addi.DIRECT_CONSTRAINT_COUNT,
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
        .range_request,
        .state_consume,
        .state_produce,
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
    try std.testing.expectEqual(typed_addi.RELATION_EVENT_COUNT, imported.lookups.len);
    for (imported.lookups, expected_kinds, 0..) |expected, expected_kind, index| {
        const id = try types.idFromIndex(types.EffectId, index);
        const actual = typed_events.event(id).?;
        try std.testing.expectEqual(expected_kind, actual.kind);
        try std.testing.expectEqual(expected.schema, actual.schema);
        try std.testing.expectEqual(expected.role, actual.role);
        try std.testing.expectEqual(expected.access_ordinal, actual.access_ordinal);
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
        try std.testing.expectEqual(
            batch * imported.batch_size,
            batch_column.first_lookup,
        );
        try std.testing.expectEqual(
            @min(
                @as(usize, imported.batch_size),
                imported.lookups.len - batch * imported.batch_size,
            ),
            batch_column.entry_count,
        );
    }
}

test "typed ADDI identity is source-independent v8 v6 and leaves LUI v7 v5" {
    var generated = try typed_addi.build(std.testing.allocator, .generated);
    defer generated.deinit();
    var first = try typed_addi.build(
        std.testing.allocator,
        fileLocation("guest/addi.air", 11, 7),
    );
    defer first.deinit();
    var second = try typed_addi.build(
        std.testing.allocator,
        fileLocation("moved/addi.air", 83, 19),
    );
    defer second.deinit();

    const generated_identity = try digest.computeIdentity(&generated.arena);
    const first_identity = try digest.computeIdentity(&first.arena);
    const second_identity = try digest.computeIdentity(&second.arena);
    try std.testing.expectEqual(
        digest.typed_lookup_request_format_version,
        generated_identity.format_version,
    );
    try std.testing.expectEqual(generated_identity, first_identity);
    try std.testing.expectEqual(generated_identity, second_identity);
    try std.testing.expectEqual(
        generated_identity.bytes,
        try digest.computeV6(&generated.arena),
    );
    const identity_hex = std.fmt.bytesToHex(generated_identity.bytes, .lower);
    try std.testing.expectEqualStrings(
        typed_addi.SEMANTIC_DIGEST_HEX,
        &identity_hex,
    );

    try std.testing.expectError(error.InvalidEffect, digest.computeV5(&generated.arena));
    try std.testing.expectError(
        error.TypedLookupRequestRequiresManifestV8,
        manifest.serializeAllocV7(std.testing.allocator, &generated.arena),
    );
    const exact = try manifest.serializeAllocV8(
        std.testing.allocator,
        &generated.arena,
    );
    defer std.testing.allocator.free(exact);
    const current = try manifest.serializeAllocCurrent(
        std.testing.allocator,
        &generated.arena,
    );
    defer std.testing.allocator.free(current);
    try std.testing.expectEqualSlices(u8, exact, current);
    try std.testing.expectEqual(
        manifest.typed_lookup_request_format_version,
        std.mem.readInt(u16, exact[8..10], .little),
    );
    try std.testing.expectEqual(
        manifest.typed_lookup_request_logical_schema_version,
        std.mem.readInt(u16, exact[10..12], .little),
    );
    var manifest_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(exact, &manifest_hash, .{});
    const rendered_manifest = std.fmt.bytesToHex(manifest_hash, .lower);
    try std.testing.expectEqualStrings(
        "d938e9efdc3efbdda5eeb53876c7af1fefefad4d6b8a682e64c50d50d081f2b5",
        &rendered_manifest,
    );
    try std.testing.expectEqual(@as(usize, 3333), exact.len);

    var lui = try typed_lui.build(std.testing.allocator, .generated);
    defer lui.deinit();
    const lui_identity = try digest.computeIdentity(&lui.arena);
    try std.testing.expectEqual(
        digest.sequential_retirement_format_version,
        lui_identity.format_version,
    );
    try std.testing.expectEqual(typed_lui.SEMANTIC_DIGEST, lui_identity.bytes);
    const lui_manifest = try manifest.serializeAllocCurrent(
        std.testing.allocator,
        &lui.arena,
    );
    defer std.testing.allocator.free(lui_manifest);
    var lui_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(lui_manifest, &lui_hash, .{});
    try std.testing.expectEqualStrings(
        "7c1d8fd99b8b2b14b3626591abd242b6fc4218c9f7a7be00d7d31f2478d2d9f9",
        &std.fmt.bytesToHex(lui_hash, .lower),
    );
}

test "typed ADDI honest boundary alias carry and overflow rows match production" {
    var authored = try typed_addi.build(std.testing.allocator, .generated);
    defer authored.deinit();
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .base_alu_imm,
        source.SourceSpan.generated(),
    );
    defer imported.deinit();
    const bindings = typedBindings(&authored);

    const corpus = [_][36]M31{
        honestAddiRow(0, 0, 0, 1),
        honestAddiRow(7, 7, 41, 1),
        honestAddiRow(3, 5, 0, -2048),
        honestAddiRow(3, 5, 0, 2047),
        honestAddiRow(9, 4, 0x0000_00ff, 1),
        honestAddiRow(9, 4, 0x00ff_ffff, 1),
        honestAddiRow(9, 4, 0xffff_ffff, 1),
        honestAddiRow(9, 4, 0x8000_0000, -1),
    };
    for (corpus) |row| try expectProgramParityAndZero(
        &authored,
        &imported,
        &bindings,
        row,
    );
}

test "typed ADDI rejects carry read-only placement and M31 alias forgeries" {
    var authored = try typed_addi.build(std.testing.allocator, .generated);
    defer authored.deinit();
    const bindings = typedBindings(&authored);

    var forged = honestAddiRow(3, 5, 0xff, 1);
    forged[29] = M31.fromCanonical(1);
    forged[8] = forged[29];
    try expectAnyConstraintNonZero(&authored, &bindings, forged, 6, 10);

    forged = honestAddiRow(3, 5, 41, 1);
    forged[13] = M31.fromCanonical(42);
    try expectConstraintNonZero(&authored, &bindings, forged, 17);

    forged = honestAddiRow(3, 5, 0, 0);
    forged[29] = M31.fromCanonical(255);
    forged[30] = M31.fromCanonical(255);
    forged[31] = M31.fromCanonical(255);
    forged[32] = M31.fromCanonical(127);
    forged[8] = forged[29];
    forged[9] = forged[30];
    forged[10] = forged[31];
    forged[11] = forged[32];
    try expectAnyConstraintNonZero(&authored, &bindings, forged, 6, 10);

    forged = honestAddiRow(3, 5, 0, 1);
    forged[35] = M31.zero();
    try expectConstraintNonZero(&authored, &bindings, forged, 21);

    forged = honestAddiRow(3, 5, 0, 1);
    forged[25] = M31.fromCanonical(2);
    forged[35] = M31.fromCanonical(2);
    try expectConstraintNonZero(&authored, &bindings, forged, 0);
}

fn fileLocation(path: []const u8, line: u32, column: u32) typed_addi.Location {
    return .{ .file = .{
        .path = path,
        .start = .{ .byte_offset = line * 8, .line = line, .column = column },
        .end = .{ .byte_offset = line * 8 + 5, .line = line, .column = column + 5 },
    } };
}

fn typedBindings(authored: *const typed_addi.Definition) [36]Binding {
    var bindings: [36]Binding = undefined;
    for (authored.columns.physical(), bindings[0..35], 0..) |value, *binding, column|
        binding.* = .{ .value = value, .column = @intCast(column) };
    bindings[35] = .{ .value = authored.is_active, .column = 35 };
    return bindings;
}

fn honestAddiRow(rd: u32, rs1: u32, source_word: u32, immediate: i32) [36]M31 {
    std.debug.assert(immediate >= -2048 and immediate <= 2047);
    var row = [_]M31{M31.zero()} ** 36;
    row[0] = M31.fromCanonical(37);
    row[1] = M31.fromCanonical(0x1040);
    row[2] = M31.fromCanonical(rd);
    putWord(&row, 3, source_word);
    row[7] = M31.fromCanonical(5);
    const immediate_word: u32 = @bitCast(immediate);
    const result = source_word +% immediate_word;
    if (rd != 0) putWord(&row, 8, result);
    row[12] = M31.fromCanonical(rs1);
    putWord(&row, 13, source_word);
    row[17] = M31.fromCanonical(3);
    putWord(&row, 18, source_word);
    const immediate_bits = immediate_word & 0xfff;
    row[22] = M31.fromCanonical(immediate_bits & 0xff);
    row[23] = M31.fromCanonical((immediate_bits >> 8) & 0x7);
    row[24] = M31.fromCanonical(immediate_bits >> 11);
    row[25] = M31.one();
    putWord(&row, 29, result);
    if (rd != 0) {
        row[33] = M31.one();
        row[34] = M31.fromCanonical(rd).inv() catch unreachable;
    }
    row[35] = M31.one();
    return row;
}

fn putWord(row: *[36]M31, offset: usize, word: u32) void {
    inline for (0..4) |limb| row[offset + limb] = M31.fromCanonical(
        (word >> @intCast(limb * 8)) & 0xff,
    );
}

fn expectProgramParityAndZero(
    authored: *const typed_addi.Definition,
    imported: *const shadow_program.ImportedProgram,
    bindings: []const Binding,
    row: [36]M31,
) !void {
    const actual_values = try evaluate(
        std.testing.allocator,
        &authored.arena,
        bindings,
        &row,
    );
    defer std.testing.allocator.free(actual_values);
    const expected_values = try std.testing.allocator.alloc(
        M31,
        imported.imported.arena.nodeCount(),
    );
    defer std.testing.allocator.free(expected_values);
    try imported.imported.replay(&row, expected_values);
    for (authored.constraints, imported.direct_constraints) |actual_id, expected_id| {
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
        const signed = switch (expected.role) {
            .emit => actual_liveness,
            .request, .consume => actual_liveness.neg(),
        };
        try std.testing.expectEqual(
            valueAt(expected_values, expected.numerator).toU32(),
            signed.toU32(),
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
    authored: *const typed_addi.Definition,
    bindings: []const Binding,
    row: [36]M31,
    constraint_index: usize,
) !void {
    const values = try evaluate(std.testing.allocator, &authored.arena, bindings, &row);
    defer std.testing.allocator.free(values);
    const root = authored.arena.constraint(authored.constraints[constraint_index]).?.root;
    try std.testing.expect(!valueAt(values, root).isZero());
}

fn expectAnyConstraintNonZero(
    authored: *const typed_addi.Definition,
    bindings: []const Binding,
    row: [36]M31,
    first: usize,
    end: usize,
) !void {
    const values = try evaluate(std.testing.allocator, &authored.arena, bindings, &row);
    defer std.testing.allocator.free(values);
    for (authored.constraints[first..end]) |id| {
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
