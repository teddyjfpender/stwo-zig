const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const digest = @import("digest.zig");
const effects = @import("effects.zig");
const ir = @import("ir.zig");
const lower_effects = @import("lower_effects.zig");
const manifest = @import("manifest.zig");
const program = @import("program.zig");
const relation = @import("relation.zig");
const shadow_program = @import("shadow_program.zig");
const source = @import("source.zig");
const types = @import("types.zig");
const validate = @import("validate.zig");

test "typed program and retirement effects reproduce the LUI relation prefix" {
    var fixture = try Fixture.init(std.testing.allocator, false, true);
    defer fixture.deinit();
    try validate.validate(&fixture.arena);

    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .lui,
        source.SourceSpan.generated(),
    );
    defer imported.deinit();
    try std.testing.expectEqual(@as(usize, 7), imported.lookups.len);
    try std.testing.expectEqual(@as(u8, 2), imported.batch_size);

    const validated = try lower_effects.ValidatedProgram.init(&fixture.arena);
    const expected_arities = [_]usize{ 5, 2, 2 };
    for (0..3) |index| {
        const id = try types.idFromIndex(types.EffectId, index);
        const event = validated.event(id).?;
        const production = imported.lookups[index];
        try std.testing.expectEqual(production.schema, event.schema);
        try std.testing.expectEqual(production.role, event.role);
        try std.testing.expectEqual(production.access_ordinal, event.access_ordinal);
        try std.testing.expectEqual(
            relation.getById(production.schema).?.version,
            event.schema_version,
        );
        try std.testing.expectEqual(expected_arities[index], event.values.len);
        try std.testing.expectEqual(fixture.active, event.liveness);
    }

    // The authored IDs and the production DAG are independent graphs. Assign
    // each authored semantic input by identity, replay the shipped LUI graph,
    // then compare the three ordered tuples in field space. Distinct tuple
    // coordinates make a ProgramTuple.values() reorder observable instead of
    // comparing that helper with an array produced by the same helper.
    const assignments = [_]LuiAssignment{
        .{ .active = 0, .clock = 13, .pc = 0x1000, .rd = 7, .imm_0 = 0xc, .imm_1 = 0xab, .imm_2 = 0xde },
        .{ .active = 1, .clock = 29, .pc = 0x2340, .rd = 19, .imm_0 = 3, .imm_1 = 0x51, .imm_2 = 0xa7 },
        .{ .active = 1, .clock = 0x103, .pc = 0x4560, .rd = 23, .imm_0 = 0xf, .imm_1 = 0x82, .imm_2 = 0x39 },
        .{ .active = 0, .clock = 0x211, .pc = 0x7890, .rd = 31, .imm_0 = 5, .imm_1 = 0xe4, .imm_2 = 0x62 },
    };
    try std.testing.expectEqual(@as(usize, 18), imported.main_column_count);
    try std.testing.expectEqual(@as(usize, 19), imported.imported.columns.len);
    const production_columns = try std.testing.allocator.alloc(
        M31,
        imported.imported.columns.len,
    );
    defer std.testing.allocator.free(production_columns);
    const production_values = try std.testing.allocator.alloc(
        M31,
        imported.imported.arena.nodeCount(),
    );
    defer std.testing.allocator.free(production_values);
    const typed_values = try std.testing.allocator.alloc(
        M31,
        fixture.arena.nodeCount(),
    );
    defer std.testing.allocator.free(typed_values);

    for (assignments, 0..) |assignment, sample_index| {
        for (production_columns, 0..) |*value, column| {
            value.* = M31.fromU64(0x10_000 + sample_index * 0x100 + column);
        }
        production_columns[0] = M31.fromU64(assignment.active);
        production_columns[1] = M31.fromU64(assignment.clock);
        production_columns[2] = M31.fromU64(assignment.pc);
        production_columns[3] = M31.fromU64(assignment.rd);
        production_columns[13] = M31.fromU64(assignment.imm_0);
        production_columns[14] = M31.fromU64(assignment.imm_1);
        production_columns[15] = M31.fromU64(assignment.imm_2);
        production_columns[18] = production_columns[0];
        try imported.imported.replay(production_columns, production_values);

        for (typed_values, 0..) |*value, index| {
            value.* = M31.fromU64(0x20_000 + sample_index * 0x100 + index);
        }
        const immediate = production_columns[13]
            .add(production_columns[14].mul(M31.fromCanonical(1 << 4)))
            .add(production_columns[15].mul(M31.fromCanonical(1 << 12)));
        setValue(typed_values, fixture.pc, production_columns[2]);
        setValue(
            typed_values,
            fixture.next_pc,
            production_columns[2].add(M31.fromCanonical(4)),
        );
        setValue(typed_values, fixture.clock, production_columns[1]);
        setValue(
            typed_values,
            fixture.next_clock,
            production_columns[1].add(M31.one()),
        );
        setValue(typed_values, fixture.opcode_id, M31.fromCanonical(35));
        setValue(typed_values, fixture.rd, production_columns[3]);
        setValue(typed_values, fixture.immediate, immediate);
        setValue(typed_values, fixture.operand, M31.zero());
        setValue(typed_values, fixture.active, production_columns[0]);

        for (0..3) |event_index| {
            const event_id = try types.idFromIndex(types.EffectId, event_index);
            const event = validated.event(event_id).?;
            const production = imported.lookups[event_index];
            const production_fields = imported.lookupFields(event_index).?;
            try std.testing.expectEqual(production_fields.len, event.values.len);
            for (production_fields, event.values) |production_id, typed_id| {
                try expectFieldEqual(
                    production_values[types.idIndex(production_id)],
                    typed_values[types.idIndex(typed_id)],
                );
            }

            const signed_liveness = production_values[types.idIndex(production.numerator)];
            const normalized_liveness = switch (production.role) {
                .request, .consume => signed_liveness.neg(),
                .emit => signed_liveness,
            };
            try expectFieldEqual(
                production_values[types.idIndex(imported.active_row)],
                normalized_liveness,
            );
            try expectFieldEqual(
                normalized_liveness,
                typed_values[types.idIndex(event.liveness)],
            );
        }
    }
    try std.testing.expectEqual(program.EffectKind.program_fetch, fixture.arena.effects.items[0].kind);
    try std.testing.expectEqual(program.EffectKind.state_consume, fixture.arena.effects.items[1].kind);
    try std.testing.expectEqual(program.EffectKind.state_produce, fixture.arena.effects.items[2].kind);
}

test "typed effect constructors reject semantic type errors before mutation" {
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const generated = source.SourceSpan.generated();
    const felt = try arena.input("felt", .felt, generated);
    const pc = try arena.input("pc", .pc, generated);
    const clock = try arena.input("clock", .clock, generated);
    const active = try arena.input("active", .bit, generated);

    try std.testing.expectError(
        error.InvalidFieldType,
        effects.programFetch(
            &arena,
            .{ .pc = felt, .opcode_id = felt, .rd = felt, .rs1 = felt, .operand = felt },
            active,
            generated,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), arena.effects.items.len);
    try std.testing.expectEqual(@as(usize, 0), arena.effect_values.items.len);

    try std.testing.expectError(
        error.InvalidFieldType,
        effects.retire(
            &arena,
            .{ .pc = pc, .clock = clock },
            .{ .pc = pc, .clock = felt },
            active,
            generated,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), arena.effects.items.len);
    try std.testing.expectEqual(@as(usize, 0), arena.effect_values.items.len);

    try std.testing.expectError(
        error.InvalidEffectLiveness,
        effects.stateConsume(
            &arena,
            .{ .pc = pc, .clock = clock },
            felt,
            generated,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), arena.effects.items.len);
}

test "whole-program validation rejects forged relation bindings and liveness" {
    var fixture = try Fixture.init(std.testing.allocator, false, true);
    defer fixture.deinit();

    const saved_program_binding = fixture.arena.effects.items[0].binding;
    fixture.arena.effects.items[0].binding = null;
    try std.testing.expectError(error.InvalidEffect, validate.validate(&fixture.arena));
    fixture.arena.effects.items[0].binding = saved_program_binding;

    fixture.arena.effects.items[0].binding.?.schema = relation.id(.registers_state);
    try std.testing.expectError(error.InvalidEffect, validate.validate(&fixture.arena));
    fixture.arena.effects.items[0].binding = saved_program_binding;

    fixture.arena.effects.items[0].binding.?.role = .emit;
    try std.testing.expectError(error.InvalidEffect, validate.validate(&fixture.arena));
    fixture.arena.effects.items[0].binding = saved_program_binding;

    fixture.arena.effects.items[0].binding.?.schema_version += 1;
    try std.testing.expectError(error.InvalidEffect, validate.validate(&fixture.arena));
    fixture.arena.effects.items[0].binding = saved_program_binding;

    const saved_liveness = fixture.arena.effects.items[0].liveness;
    fixture.arena.effects.items[0].liveness = null;
    try std.testing.expectError(error.InvalidEffect, validate.validate(&fixture.arena));
    fixture.arena.effects.items[0].liveness = saved_liveness;
    try validate.validate(&fixture.arena);
}

test "state retirement pairing rejects reversal splitting and activation drift" {
    var fixture = try Fixture.init(std.testing.allocator, false, true);
    defer fixture.deinit();
    std.mem.swap(
        program.EffectKind,
        &fixture.arena.effects.items[1].kind,
        &fixture.arena.effects.items[2].kind,
    );
    std.mem.swap(
        ?program.RelationBinding,
        &fixture.arena.effects.items[1].binding,
        &fixture.arena.effects.items[2].binding,
    );
    try std.testing.expectError(error.InvalidEffect, validate.validate(&fixture.arena));

    var split = ir.Arena.init(std.testing.allocator);
    defer split.deinit();
    const generated = source.SourceSpan.generated();
    const pc = try split.input("pc", .pc, generated);
    const clock = try split.input("clock", .clock, generated);
    const active = try split.input("active", .bit, generated);
    const state = effects.MachineState{ .pc = pc, .clock = clock };
    _ = try effects.stateConsume(&split, state, active, generated);
    _ = try split.addEffect(.public_consume, &.{pc}, active, null, generated);
    _ = try effects.stateProduce(&split, state, active, generated);
    try std.testing.expectError(error.InvalidEffect, validate.validate(&split));

    var drift = try Fixture.init(std.testing.allocator, false, true);
    defer drift.deinit();
    const other_active = try drift.arena.input("other_active", .bit, generated);
    drift.arena.effects.items[2].liveness = other_active;
    try std.testing.expectError(error.InvalidEffect, validate.validate(&drift.arena));
}

test "typed relation iterator is numeric allocation-free and declaration ordered" {
    var fixture = try Fixture.init(std.testing.allocator, false, true);
    defer fixture.deinit();
    const validated = try lower_effects.ValidatedProgram.init(&fixture.arena);

    const before_capacity = fixture.arena.effect_values.capacity;
    var events = validated.iterator();
    var count: usize = 0;
    while (events.next()) |event| {
        try std.testing.expectEqual(count, types.idIndex(event.effect));
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 3), count);
    try std.testing.expectEqual(before_capacity, fixture.arena.effect_values.capacity);
}

test "validated effect capability rejects malformed records and unknown IDs" {
    var fixture = try Fixture.init(std.testing.allocator, false, true);
    defer fixture.deinit();
    const first = try types.idFromIndex(types.EffectId, 0);
    const validated = try lower_effects.ValidatedProgram.init(&fixture.arena);
    try std.testing.expect(validated.event(first) != null);

    const saved_binding = fixture.arena.effects.items[0].binding;
    fixture.arena.effects.items[0].binding = null;
    try std.testing.expectError(
        error.InvalidEffect,
        lower_effects.ValidatedProgram.init(&fixture.arena),
    );
    fixture.arena.effects.items[0].binding = saved_binding;

    const saved_liveness = fixture.arena.effects.items[0].liveness;
    fixture.arena.effects.items[0].liveness = null;
    try std.testing.expectError(
        error.InvalidEffect,
        lower_effects.ValidatedProgram.init(&fixture.arena),
    );
    fixture.arena.effects.items[0].liveness = saved_liveness;

    const saved_values = fixture.arena.effects.items[0].values;
    fixture.arena.effects.items[0].values = .{
        .start = std.math.maxInt(u32),
        .len = 1,
    };
    try std.testing.expectError(
        error.InvalidRange,
        lower_effects.ValidatedProgram.init(&fixture.arena),
    );
    fixture.arena.effects.items[0].values = saved_values;

    const unknown: types.EffectId = @enumFromInt(std.math.maxInt(u32));
    const restored = try lower_effects.ValidatedProgram.init(&fixture.arena);
    try std.testing.expect(restored.event(unknown) == null);
    try validate.validate(&fixture.arena);
}

test "typed effects use explicit manifest v4 and semantic digest v2 identities" {
    var canonical = try Fixture.init(std.testing.allocator, false, true);
    defer canonical.deinit();
    var perturbed = try Fixture.init(std.testing.allocator, true, true);
    defer perturbed.deinit();
    var reordered = try Fixture.init(std.testing.allocator, false, false);
    defer reordered.deinit();

    try std.testing.expectError(
        error.RelationBindingsRequireManifestV4,
        manifest.serializeAlloc(std.testing.allocator, &canonical.arena),
    );
    try std.testing.expectError(error.InvalidEffect, digest.compute(&canonical.arena));

    const canonical_manifest = try manifest.serializeAllocV4(
        std.testing.allocator,
        &canonical.arena,
    );
    defer std.testing.allocator.free(canonical_manifest);
    const perturbed_manifest = try manifest.serializeAllocV4(
        std.testing.allocator,
        &perturbed.arena,
    );
    defer std.testing.allocator.free(perturbed_manifest);
    const reordered_manifest = try manifest.serializeAllocV4(
        std.testing.allocator,
        &reordered.arena,
    );
    defer std.testing.allocator.free(reordered_manifest);
    try std.testing.expectEqual(
        manifest.typed_effect_format_version,
        std.mem.readInt(u16, canonical_manifest[8..10], .little),
    );
    try std.testing.expectEqual(
        manifest.typed_effect_logical_schema_version,
        std.mem.readInt(u16, canonical_manifest[10..12], .little),
    );
    try std.testing.expectEqualSlices(u8, canonical_manifest, perturbed_manifest);
    try std.testing.expect(!std.mem.eql(u8, canonical_manifest, reordered_manifest));

    const canonical_digest = try digest.computeV2(&canonical.arena);
    const perturbed_digest = try digest.computeV2(&perturbed.arena);
    const reordered_digest = try digest.computeV2(&reordered.arena);
    try std.testing.expectEqual(canonical_digest, perturbed_digest);
    try std.testing.expect(!std.mem.eql(u8, &canonical_digest, &reordered_digest));
    const identity = try digest.computeIdentity(&canonical.arena);
    try std.testing.expectEqual(digest.typed_effect_format_version, identity.format_version);
    try std.testing.expectEqual(canonical_digest, identity.bytes);

    var manifest_digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(canonical_manifest, &manifest_digest, .{});
    const rendered_program = std.fmt.bytesToHex(canonical_digest, .lower);
    const rendered_manifest = std.fmt.bytesToHex(manifest_digest, .lower);
    try std.testing.expectEqualStrings(
        "51e283d422f098286fd6b84482ffd7566cbc417231372f076ea57579085c04f3",
        &rendered_program,
    );
    try std.testing.expectEqual(@as(usize, 246), canonical_manifest.len);
    try std.testing.expectEqualStrings(
        "cc8d20c16b738ad52ad17657aa5daf79d53508dba9fa4ee784724ae47712cecb",
        &rendered_manifest,
    );
}

test "retirement rolls back both event pools when its second append cannot grow" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const allocator = failing.allocator();
    {
        var arena = ir.Arena.init(allocator);
        defer arena.deinit();
        const generated = source.SourceSpan.generated();
        const pc = try arena.input("pc", .pc, generated);
        const next_pc = try arena.input("next_pc", .pc, generated);
        const clock = try arena.input("clock", .clock, generated);
        const next_clock = try arena.input("next_clock", .clock, generated);
        const active = try arena.input("active", .bit, generated);

        try arena.effect_values.ensureTotalCapacityPrecise(allocator, 2);
        try arena.effects.ensureTotalCapacityPrecise(allocator, 1);
        failing.fail_index = failing.alloc_index;
        failing.resize_fail_index = failing.resize_index;
        try std.testing.expectError(
            error.OutOfMemory,
            effects.retire(
                &arena,
                .{ .pc = pc, .clock = clock },
                .{ .pc = next_pc, .clock = next_clock },
                active,
                generated,
            ),
        );
        try std.testing.expectEqual(@as(usize, 0), arena.effects.items.len);
        try std.testing.expectEqual(@as(usize, 0), arena.effect_values.items.len);
        try validate.validate(&arena);
    }
    try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
}

test "retirement preserves an existing prefix when second value growth fails" {
    try exerciseRetirementGrowthFailure(.second_value_pool);
}

test "retirement preserves an existing prefix when second effect growth fails" {
    try exerciseRetirementGrowthFailure(.second_effect_pool);
}

test "typed effect construction releases every partial allocation" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

const Fixture = struct {
    arena: ir.Arena,
    pc: types.ValueId,
    next_pc: types.ValueId,
    clock: types.ValueId,
    next_clock: types.ValueId,
    opcode_id: types.ValueId,
    rd: types.ValueId,
    immediate: types.ValueId,
    operand: types.ValueId,
    active: types.ValueId,

    fn init(
        allocator: std.mem.Allocator,
        perturbed: bool,
        fetch_first: bool,
    ) !Fixture {
        var arena = ir.Arena.init(allocator);
        errdefer arena.deinit();
        const generated = source.SourceSpan.generated();
        if (perturbed) {
            const names = [_][]const u8{
                "active",     "operand", "immediate", "rd", "opcode_id",
                "next_clock", "clock",   "next_pc",   "pc",
            };
            for (names) |name| _ = try arena.internName(name);
        }
        const pc = try arena.input("pc", .pc, generated);
        const next_pc = try arena.input("next_pc", .pc, generated);
        const clock = try arena.input("clock", .clock, generated);
        const next_clock = try arena.input("next_clock", .clock, generated);
        const opcode_id = try arena.input("opcode_id", .felt, generated);
        const rd = try arena.input("rd", .register_index, generated);
        const immediate = try arena.input("immediate", .uint20, generated);
        const operand = try arena.input("operand", .felt, generated);
        const active = try arena.input("active", .bit, generated);
        const program_tuple = effects.ProgramTuple{
            .pc = pc,
            .opcode_id = opcode_id,
            .rd = rd,
            .rs1 = immediate,
            .operand = operand,
        };
        const before = effects.MachineState{ .pc = pc, .clock = clock };
        const after = effects.MachineState{ .pc = next_pc, .clock = next_clock };
        if (fetch_first) {
            _ = try effects.programFetch(&arena, program_tuple, active, generated);
            _ = try effects.retire(&arena, before, after, active, generated);
        } else {
            _ = try effects.retire(&arena, before, after, active, generated);
            _ = try effects.programFetch(&arena, program_tuple, active, generated);
        }
        try validate.validate(&arena);
        return .{
            .arena = arena,
            .pc = pc,
            .next_pc = next_pc,
            .clock = clock,
            .next_clock = next_clock,
            .opcode_id = opcode_id,
            .rd = rd,
            .immediate = immediate,
            .operand = operand,
            .active = active,
        };
    }

    fn deinit(self: *Fixture) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

const LuiAssignment = struct {
    active: u32,
    clock: u32,
    pc: u32,
    rd: u32,
    imm_0: u32,
    imm_1: u32,
    imm_2: u32,
};

const RetirementGrowthFailure = enum {
    second_value_pool,
    second_effect_pool,
};

fn setValue(values: []M31, id: types.ValueId, value: M31) void {
    values[types.idIndex(id)] = value;
}

fn expectFieldEqual(expected: M31, actual: M31) !void {
    try std.testing.expectEqual(expected.toU32(), actual.toU32());
}

fn exerciseRetirementGrowthFailure(target: RetirementGrowthFailure) !void {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const allocator = failing.allocator();
    {
        var arena = ir.Arena.init(allocator);
        defer arena.deinit();
        const generated = source.SourceSpan.generated();
        const pc = try arena.input("pc", .pc, generated);
        const next_pc = try arena.input("next_pc", .pc, generated);
        const clock = try arena.input("clock", .clock, generated);
        const next_clock = try arena.input("next_clock", .clock, generated);
        const active = try arena.input("active", .bit, generated);

        // One public event is the pre-existing committed prefix. Capacity is
        // selected so the requested second append must grow exactly the pool
        // named by `target`; the other pool can complete both appends.
        const values_capacity: usize = switch (target) {
            .second_value_pool => 3,
            .second_effect_pool => 5,
        };
        const effects_capacity: usize = switch (target) {
            .second_value_pool => 3,
            .second_effect_pool => 2,
        };
        try arena.effect_values.ensureTotalCapacityPrecise(
            allocator,
            values_capacity,
        );
        try arena.effects.ensureTotalCapacityPrecise(
            allocator,
            effects_capacity,
        );
        _ = try arena.addEffect(
            .public_consume,
            &.{pc},
            active,
            null,
            generated,
        );
        try validate.validate(&arena);

        const prefix_effect = arena.effects.items[0];
        const prefix_value = arena.effect_values.items[0];
        const effects_len = arena.effects.items.len;
        const values_len = arena.effect_values.items.len;
        const effects_capacity_before = arena.effects.capacity;
        const values_capacity_before = arena.effect_values.capacity;
        try std.testing.expectEqual(effects_capacity, effects_capacity_before);
        try std.testing.expectEqual(values_capacity, values_capacity_before);

        failing.fail_index = failing.alloc_index;
        failing.resize_fail_index = failing.resize_index;
        try std.testing.expectError(
            error.OutOfMemory,
            effects.retire(
                &arena,
                .{ .pc = pc, .clock = clock },
                .{ .pc = next_pc, .clock = next_clock },
                active,
                generated,
            ),
        );
        try std.testing.expect(failing.has_induced_failure);

        try std.testing.expectEqual(effects_len, arena.effects.items.len);
        try std.testing.expectEqual(values_len, arena.effect_values.items.len);
        try std.testing.expectEqual(effects_capacity_before, arena.effects.capacity);
        try std.testing.expectEqual(values_capacity_before, arena.effect_values.capacity);
        try std.testing.expectEqual(prefix_effect, arena.effects.items[0]);
        try std.testing.expectEqual(prefix_value, arena.effect_values.items[0]);
        try validate.validate(&arena);
    }
    try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
}

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    var fixture = try Fixture.init(allocator, false, true);
    defer fixture.deinit();
    const bytes = try manifest.serializeAllocV4(allocator, &fixture.arena);
    defer allocator.free(bytes);
}
