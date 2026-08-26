//! Exact semantic, layout, identity, and boundary tests for native typed JAL.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const compat = @import("typed_air_compatibility_test_support.zig");
const compat_layout = @import("compat_layout.zig");
const degree = @import("degree.zig");
const digest = @import("digest.zig");
const expr = @import("expr.zig");
const ir = @import("ir.zig");
const manifest = @import("manifest.zig");
const shadow_program = @import("shadow_program.zig");
const source = @import("source.zig");
const typed_jal = @import("typed_jal.zig");
const types = @import("types.zig");
const witness_layout = @import("../../witness_layout.zig");
const legacy_writer = @import("../../runner/witness/jal_legacy_test_oracle.zig").writeRow;

const ROW_WIDTH = typed_jal.MAIN_COLUMN_COUNT + 1;
const AUTHORED_BINDING_COUNT = typed_jal.MAIN_COLUMN_COUNT + 2;
const Binding = compat.Binding;

test "typed JAL has exact 20 columns 10 roots and 8 native ordered lookups" {
    var authored = try typed_jal.build(std.testing.allocator, .generated);
    defer authored.deinit();
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .jal,
        source.SourceSpan.generated(),
    );
    defer imported.deinit();
    const layout = try compat_layout.build(&imported);

    try authored.validate();
    try std.testing.expectEqual(typed_jal.MAIN_COLUMN_COUNT, layout.main().len);
    try std.testing.expectEqual(typed_jal.LOOKUP_COUNT, imported.lookups.len);
    try std.testing.expectEqual(typed_jal.LOOKUP_BATCH_SIZE, imported.batch_size);
    var authored_degrees = try degree.analyze(std.testing.allocator, &authored.arena);
    defer authored_degrees.deinit();
    var production_degrees = try degree.analyze(
        std.testing.allocator,
        &imported.imported.arena,
    );
    defer production_degrees.deinit();
    try std.testing.expectEqual(
        production_degrees.maximumConstraintDegree(),
        authored_degrees.maximumConstraintDegree(),
    );
    try std.testing.expectEqual(
        @as(degree.Degree, 2),
        authored_degrees.maximumConstraintDegree(),
    );

    for (authored.columns.physical(), witness_layout.columnNames(.jal)) |
        value,
        expected_name,
    | {
        const node = authored.arena.node(value).?;
        const actual_name = switch (node.key.op) {
            .input => |name| authored.arena.name(name).?,
            else => return error.ExpectedPhysicalInput,
        };
        try std.testing.expectEqualStrings(expected_name, actual_name);
    }

    const authored_bindings = typedBindings(&authored);
    var production_bindings: [ROW_WIDTH]Binding = undefined;
    for (layout.main(), production_bindings[0..typed_jal.MAIN_COLUMN_COUNT]) |
        column,
        *binding,
    | binding.* = .{ .value = column.value, .column = column.reference.local_index };
    production_bindings[typed_jal.MAIN_COLUMN_COUNT] = .{
        .value = imported.selector,
        .column = typed_jal.MAIN_COLUMN_COUNT,
    };
    const actual = try compat.fingerprintProgram(
        std.testing.allocator,
        &authored.arena,
        &authored_bindings,
    );
    defer std.testing.allocator.free(actual);
    const expected = try compat.fingerprintProgram(
        std.testing.allocator,
        &imported.imported.arena,
        &production_bindings,
    );
    defer std.testing.allocator.free(expected);

    try std.testing.expectEqual(
        typed_jal.DIRECT_CONSTRAINT_COUNT,
        imported.direct_constraints.len,
    );
    for (authored.model.constraints, imported.direct_constraints, 0..) |
        actual_id,
        expected_id,
        index,
    | {
        const actual_root = authored.arena.constraint(actual_id).?.root;
        const expected_root = imported.imported.arena.constraint(expected_id).?.root;
        if (!std.mem.eql(
            u8,
            &compat.at(actual, actual_root),
            &compat.at(expected, expected_root),
        )) {
            std.log.err("JAL direct fingerprint mismatch at {d}", .{index});
            return error.DirectFingerprintMismatch;
        }
    }

    for (authored.arena.effectsView(), imported.lookups, 0..) |
        actual_effect,
        expected_lookup,
        index,
    | {
        const binding = actual_effect.binding.?;
        try std.testing.expectEqual(expected_lookup.schema, binding.schema);
        try std.testing.expectEqual(expected_lookup.role, binding.role);
        try std.testing.expectEqual(
            expected_lookup.access_ordinal,
            actual_effect.access_ordinal,
        );
        const signed_liveness = switch (expected_lookup.role) {
            .emit => compat.at(actual, actual_effect.liveness.?),
            .request, .consume => compat.unary(
                5,
                compat.at(actual, actual_effect.liveness.?),
            ),
        };
        try std.testing.expectEqual(
            compat.at(expected, expected_lookup.numerator),
            signed_liveness,
        );
        const effect_id = try types.idFromIndex(types.EffectId, index);
        const actual_fields = authored.arena.effectValues(effect_id).?;
        const expected_fields = imported.lookupFields(index).?;
        try std.testing.expectEqual(expected_fields.len, actual_fields.len);
        for (actual_fields, expected_fields, 0..) |
            actual_field,
            expected_field,
            field_index,
        | if (!std.mem.eql(
            u8,
            &compat.at(actual, actual_field),
            &compat.at(expected, expected_field),
        )) {
            std.log.err("JAL lookup fingerprint mismatch at {d}:{d}", .{
                index,
                field_index,
            });
            return error.LookupFingerprintMismatch;
        };

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

test "typed JAL identity is source-independent and requires manifest v11" {
    var generated = try typed_jal.build(std.testing.allocator, .generated);
    defer generated.deinit();
    var moved = try typed_jal.build(std.testing.allocator, .{ .file = .{
        .path = "moved/control/jal.air",
        .start = .{ .byte_offset = 71, .line = 9, .column = 3 },
        .end = .{ .byte_offset = 99, .line = 9, .column = 31 },
    } });
    defer moved.deinit();
    const generated_identity = try digest.computeIdentity(&generated.arena);
    try std.testing.expectEqual(
        digest.program_control_target_format_version,
        generated_identity.format_version,
    );
    try std.testing.expectEqual(generated_identity, try digest.computeIdentity(&moved.arena));
    try std.testing.expectEqual(generated_identity.bytes, try digest.computeV9(&generated.arena));
    try std.testing.expectEqual(typed_jal.SEMANTIC_DIGEST, generated_identity.bytes);
    try std.testing.expectError(error.InvalidEffect, digest.computeV8(&generated.arena));
    try std.testing.expectError(
        error.ProgramControlTargetRequiresManifestV11,
        manifest.serializeAllocV10(std.testing.allocator, &generated.arena),
    );
    const v11 = try manifest.serializeAllocV11(std.testing.allocator, &generated.arena);
    defer std.testing.allocator.free(v11);
    const current = try manifest.serializeAllocCurrent(std.testing.allocator, &generated.arena);
    defer std.testing.allocator.free(current);
    try std.testing.expectEqualSlices(u8, v11, current);
}

test "typed JAL signed offsets destination boundaries and padding match production" {
    var authored = try typed_jal.build(std.testing.allocator, .generated);
    defer authored.deinit();
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .jal,
        source.SourceSpan.generated(),
    );
    defer imported.deinit();
    const bindings = typedBindings(&authored);
    const actual_values = try std.testing.allocator.alloc(M31, authored.arena.nodeCount());
    defer std.testing.allocator.free(actual_values);
    const expected_values = try std.testing.allocator.alloc(
        M31,
        imported.imported.arena.nodeCount(),
    );
    defer std.testing.allocator.free(expected_values);

    const offsets = [_]i32{
        -1_048_576,
        -4096,
        -2,
        0,
        2,
        4094,
        1_048_574,
    };
    const pcs = [_]u32{ 0, 4, 0x1000, 0x3fff_fffc, 0x7fff_fffa };
    var visited: usize = 0;
    for (offsets) |offset| for (pcs) |pc| {
        const rd: u5 = if (visited % 3 == 0) 0 else if (visited % 3 == 1) 1 else 31;
        const row = honestRow(.{
            .pc = pc,
            .offset = offset,
            .rd = rd,
            .clock = @intCast(17 + visited),
        });
        try compareAcceptedRow(
            &authored,
            &imported,
            &bindings,
            &row,
            actual_values,
            expected_values,
        );
        visited += 1;
    };
    const padding = [_]M31{M31.zero()} ** ROW_WIDTH;
    try compareAcceptedRow(
        &authored,
        &imported,
        &bindings,
        &padding,
        actual_values,
        expected_values,
    );
    try std.testing.expectEqual(@as(usize, offsets.len * pcs.len), visited);
}

test "typed JAL definition rejects coordinated control-proof mutations" {
    {
        var authored = try typed_jal.build(std.testing.allocator, .generated);
        defer authored.deinit();
        authored.arena.range_refinements.items[0]
            .premise.program_control_target.offset = authored.columns.rd.addr;
        try std.testing.expectError(error.InvalidNodeShape, authored.validate());
    }
    {
        var authored = try typed_jal.build(std.testing.allocator, .generated);
        defer authored.deinit();
        authored.arena.range_refinements.items[0]
            .premise.program_control_target.kind = .{ .branch = .{
            .condition = authored.columns.enabler,
            .condition_constraint = authored.model.constraints[0],
        } };
        try std.testing.expectError(error.InvalidNodeShape, authored.validate());
    }
    {
        var authored = try typed_jal.build(std.testing.allocator, .generated);
        defer authored.deinit();
        const produce = authored.events.retirement.events.produce;
        const range = authored.arena.effects.items[types.idIndex(produce)].values;
        authored.arena.effect_values.items[range.start] = authored.columns.pc;
        try std.testing.expectError(error.InvalidEffect, authored.validate());
    }
}

test "typed JAL construction releases every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    var authored = try typed_jal.build(allocator, .generated);
    defer authored.deinit();
    try authored.validate();
}

fn typedBindings(authored: *const typed_jal.Definition) [AUTHORED_BINDING_COUNT]Binding {
    var bindings: [AUTHORED_BINDING_COUNT]Binding = undefined;
    for (authored.columns.physical(), bindings[0..typed_jal.MAIN_COLUMN_COUNT], 0..) |
        value,
        *binding,
        column,
    | binding.* = .{ .value = value, .column = @intCast(column) };
    bindings[typed_jal.MAIN_COLUMN_COUNT] = .{
        .value = authored.is_active,
        .column = typed_jal.MAIN_COLUMN_COUNT,
    };
    bindings[typed_jal.MAIN_COLUMN_COUNT + 1] = .{
        .value = authored.pc_polynomial,
        .column = 2,
    };
    return bindings;
}

const RowConfig = struct {
    pc: u32,
    offset: i32,
    rd: u5,
    clock: u32,
    previous: u32 = 0x1122_3344,
    previous_clock: u32 = 3,
};

const WriterRow = struct {
    clk: u32,
    pc: u32,
    rd: u5,
    rd_prev_val: u32,
    rd_prev_clk: u32,
    rd_val: u32,
    imm: i32,
};

fn honestRow(config: RowConfig) [ROW_WIDTH]M31 {
    const link = config.pc +% 4;
    const writer_row = WriterRow{
        .clk = config.clock,
        .pc = config.pc,
        .rd = config.rd,
        .rd_prev_val = if (config.rd == 0) 0 else config.previous,
        .rd_prev_clk = if (config.rd == 0) 0 else config.previous_clock,
        .rd_val = if (config.rd == 0) 0 else link,
        .imm = config.offset,
    };
    var storage: [typed_jal.MAIN_COLUMN_COUNT][1]M31 =
        .{.{M31.zero()}} ** typed_jal.MAIN_COLUMN_COUNT;
    var columns: [typed_jal.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&columns, &storage) |*column, *slot| column.* = slot;
    legacy_writer(&columns, 0, writer_row);
    var row: [ROW_WIDTH]M31 = undefined;
    for (storage, row[0..typed_jal.MAIN_COLUMN_COUNT]) |slot, *value|
        value.* = slot[0];
    row[typed_jal.MAIN_COLUMN_COUNT] = M31.one();
    return row;
}

fn compareAcceptedRow(
    authored: *const typed_jal.Definition,
    imported: *const shadow_program.ImportedProgram,
    bindings: []const Binding,
    row: []const M31,
    actual_values: []M31,
    expected_values: []M31,
) !void {
    try evaluateInto(&authored.arena, bindings, row, actual_values);
    try imported.imported.replay(row, expected_values);
    for (authored.model.constraints, imported.direct_constraints) |
        actual_id,
        expected_id,
    | {
        const actual = at(actual_values, authored.arena.constraint(actual_id).?.root);
        const expected = at(
            expected_values,
            imported.imported.arena.constraint(expected_id).?.root,
        );
        try std.testing.expectEqual(expected.toU32(), actual.toU32());
        try std.testing.expect(actual.isZero());
    }
    for (authored.arena.effectsView(), imported.lookups, 0..) |
        actual_effect,
        expected_lookup,
        lookup_index,
    | {
        const signed = switch (expected_lookup.role) {
            .emit => at(actual_values, actual_effect.liveness.?),
            .request, .consume => at(actual_values, actual_effect.liveness.?).neg(),
        };
        try std.testing.expectEqual(
            at(expected_values, expected_lookup.numerator).toU32(),
            signed.toU32(),
        );
        const actual_id = try types.idFromIndex(types.EffectId, lookup_index);
        for (authored.arena.effectValues(actual_id).?, imported.lookupFields(lookup_index).?) |
            actual_field,
            expected_field,
        | try std.testing.expectEqual(
            at(expected_values, expected_field).toU32(),
            at(actual_values, actual_field).toU32(),
        );
    }
}

fn evaluateInto(
    arena: *const ir.Arena,
    bindings: []const Binding,
    columns: []const M31,
    values: []M31,
) !void {
    if (values.len != arena.nodeCount()) return error.InvalidScratchShape;
    for (arena.nodesView(), 0..) |node, index| {
        const id = try types.idFromIndex(types.ValueId, index);
        values[index] = if (columnFor(bindings, id)) |column|
            columns[column]
        else switch (node.key.op) {
            .constant => |constant| switch (constant) {
                .field, .unsigned => |value| M31.fromU64(value),
            },
            .add => |binary| at(values, binary.lhs).add(at(values, binary.rhs)),
            .sub => |binary| at(values, binary.lhs).sub(at(values, binary.rhs)),
            .mul => |binary| at(values, binary.lhs).mul(at(values, binary.rhs)),
            .neg => |value| at(values, value).neg(),
            .select => |selection| if (at(values, selection.selector).isZero())
                at(values, selection.when_false)
            else
                at(values, selection.when_true),
            .machine_derived => |derived| evaluateDerived(values, derived),
            .input => return error.UnmappedInput,
            .hint_output, .call_output => return error.UnsupportedNode,
        };
    }
}

fn evaluateDerived(values: []const M31, derived: expr.MachineDerived) M31 {
    return switch (derived) {
        .register_address => |address| at(values, address.index),
        .aligned_word_address => |address| at(values, address.word_index)
            .mul(M31.fromCanonical(4)),
        .access_clock => |clock| at(values, clock.instruction_clock)
            .sub(M31.one()).mul(M31.fromCanonical(4))
            .add(M31.fromCanonical(@intFromEnum(clock.phase))),
        .strict_clock_gap => |gap| at(values, gap.current_clock)
            .sub(at(values, gap.previous_clock)).sub(M31.one()),
        .instruction_next_pc => |next| at(values, next.current)
            .add(M31.fromCanonical(4)),
        .instruction_next_clock => |next| at(values, next.current).add(M31.one()),
    };
}

fn at(values: []const M31, id: types.ValueId) M31 {
    return values[types.idIndex(id)];
}

fn columnFor(bindings: []const Binding, value: types.ValueId) ?usize {
    for (bindings) |binding| if (binding.value == value) return binding.column;
    return null;
}
