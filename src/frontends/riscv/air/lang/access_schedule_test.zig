const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const production_clock = @import("../../access_clock.zig");
const digest = @import("digest.zig");
const effects = @import("effects.zig");
const expr = @import("expr.zig");
const ir = @import("ir.zig");
const lower_effects = @import("lower_effects.zig");
const manifest = @import("manifest.zig");
const program = @import("program.zig");
const relation = @import("relation.zig");
const source = @import("source.zig");
const types = @import("types.zig");
const validate = @import("validate.zig");

test "access ordinals use pinned one-based wire values" {
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(types.AccessOrdinal.first));
    try std.testing.expectEqual(@as(u8, 2), @intFromEnum(types.AccessOrdinal.second));
    try std.testing.expectEqual(@as(u8, 3), @intFromEnum(types.AccessOrdinal.third));
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(types.AccessPhase.first));
    try std.testing.expectEqual(@as(u8, 2), @intFromEnum(types.AccessPhase.second));
    try std.testing.expectEqual(@as(u8, 3), @intFromEnum(types.AccessPhase.third));
    try std.testing.expectEqual(@as(u2, 0), @intFromEnum(production_clock.Ordinal.first));
    try std.testing.expectEqual(@as(u2, 1), @intFromEnum(production_clock.Ordinal.second));
    try std.testing.expectEqual(@as(u2, 2), @intFromEnum(production_clock.Ordinal.third));
}

test "access schedule emits exact atomic read and write triples" {
    var fixture = try Fixture.init(std.testing.allocator, 2);
    defer fixture.deinit();

    try validate.validate(&fixture.arena);
    try std.testing.expectEqual(@as(usize, 6), fixture.arena.effectsView().len);
    try std.testing.expectEqual(@as(usize, 30), fixture.arena.effectValuesView().len);
    try std.testing.expectEqual(@as(usize, 0), fixture.arena.constraintsView().len);

    const validated = try lower_effects.ValidatedProgram.init(&fixture.arena);
    var iterator = validated.iterator();
    for (0..6) |event_index| {
        const event = iterator.next().?;
        try std.testing.expectEqual(event_index, types.idIndex(event.effect));
        const group_index = event_index / 3;
        const position = event_index % 3;
        try std.testing.expectEqual(@as(u8, @intCast(group_index + 1)), event.access_ordinal.?);
        try std.testing.expectEqual(fixture.active, event.liveness);
        try std.testing.expectEqual(
            if (group_index == 0)
                program.EffectKind.register_read
            else
                program.EffectKind.register_write,
            event.kind,
        );
        try std.testing.expectEqual(
            if (position == 2)
                relation.id(.range_check_20)
            else
                relation.id(.memory_access),
            event.schema,
        );
        try std.testing.expectEqual(
            switch (position) {
                0 => types.RelationRole.consume,
                1 => types.RelationRole.emit,
                2 => types.RelationRole.request,
                else => unreachable,
            },
            event.role,
        );
    }
    try std.testing.expect(iterator.next() == null);

    const read_consume = fixture.values(0);
    const read_emit = fixture.values(1);
    try std.testing.expectEqual(read_consume[0], read_emit[0]);
    try std.testing.expectEqual(read_consume[1], read_emit[1]);
    try std.testing.expectEqualSlices(types.ValueId, read_consume[3..7], read_emit[3..7]);
    const write_consume = fixture.values(3);
    const write_emit = fixture.values(4);
    try std.testing.expectEqual(write_consume[0], write_emit[0]);
    try std.testing.expectEqual(write_consume[1], write_emit[1]);
    try std.testing.expect(!std.mem.eql(
        types.ValueId,
        write_consume[3..7],
        write_emit[3..7],
    ));
}

test "machine-derived access clocks and strict gaps replay production formula" {
    var fixture = try Fixture.init(std.testing.allocator, 3);
    defer fixture.deinit();
    try validate.validate(&fixture.arena);

    const assignments = [_]struct { clock: u32, previous: [3]u32 }{
        .{ .clock = 9, .previous = .{ 2, 7, 11 } },
        .{ .clock = 41, .previous = .{ 31, 89, 101 } },
        .{ .clock = 257, .previous = .{ 13, 511, 777 } },
        .{ .clock = 1024, .previous = .{ 100, 2000, 3000 } },
    };
    const ordinals = [_]production_clock.Ordinal{ .first, .second, .third };
    const values = try std.testing.allocator.alloc(M31, fixture.arena.nodeCount());
    defer std.testing.allocator.free(values);
    for (assignments) |assignment| {
        @memset(values, M31.zero());
        values[types.idIndex(fixture.instruction_clock)] = M31.fromU64(assignment.clock);
        values[types.idIndex(fixture.active)] = M31.one();
        for (fixture.previous_clocks, assignment.previous) |id, previous|
            values[types.idIndex(id)] = M31.fromU64(previous);
        try replayMachineNodes(&fixture.arena, values);

        for (ordinals, 0..) |ordinal, group_index| {
            const emit = fixture.values(group_index * 3 + 1);
            const gap = fixture.values(group_index * 3 + 2);
            const expected_clock = production_clock.encode(assignment.clock, ordinal);
            try std.testing.expectEqual(
                expected_clock,
                values[types.idIndex(emit[2])].toU32(),
            );
            const expected_gap = M31.fromU64(expected_clock)
                .sub(M31.fromU64(assignment.previous[group_index]))
                .sub(M31.one());
            try std.testing.expectEqual(
                expected_gap.toU32(),
                values[types.idIndex(gap[0])].toU32(),
            );
        }
    }
}

test "access schedule permits dynamic register aliases but never resets ordinals" {
    var fixture = try Fixture.init(std.testing.allocator, 3);
    defer fixture.deinit();
    try validate.validate(&fixture.arena);

    for (0..3) |group_index| {
        const consume = fixture.values(group_index * 3);
        const address = machine(fixture.arena.node(consume[1]).?);
        try std.testing.expectEqual(
            fixture.register_index,
            address.register_address.index,
        );
    }

    var schedule = try effects.AccessSchedule.begin(
        &fixture.arena,
        fixture.instruction_clock,
        fixture.active,
        source.SourceSpan.generated(),
    );
    for (0..3) |index| {
        _ = try schedule.registerRead(
            fixture.readInput(index),
            source.SourceSpan.generated(),
        );
    }
    try std.testing.expectError(
        error.AccessScheduleExhausted,
        schedule.registerRead(fixture.readInput(0), source.SourceSpan.generated()),
    );
}

test "register group construction rejects bad semantic inputs before mutation" {
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const generated = source.SourceSpan.generated();
    const clock = try arena.input("clock", .clock, generated);
    const active = try arena.input("active", .bit, generated);
    const index = try arena.input("index", .register_index, generated);
    const felt = try arena.input("felt", .felt, generated);
    const bytes = try byteInputs(&arena, "byte", generated);
    var schedule = try effects.AccessSchedule.begin(&arena, clock, active, generated);

    try std.testing.expectError(
        error.InvalidFieldType,
        schedule.registerRead(.{
            .index = felt,
            .previous_clock = clock,
            .value = bytes,
        }, generated),
    );
    var bad_bytes = bytes;
    bad_bytes[2] = felt;
    try std.testing.expectError(
        error.InvalidFieldType,
        schedule.registerWrite(.{
            .index = index,
            .previous_clock = clock,
            .previous = bytes,
            .next = bad_bytes,
        }, generated),
    );
    try std.testing.expectEqual(@as(usize, 0), arena.effectsView().len);
    try std.testing.expectEqual(@as(usize, 0), arena.effectValuesView().len);
    try std.testing.expectEqual(@as(u8, 1), schedule.next_ordinal);
}

test "whole-program validation rejects malformed register triples" {
    try expectMutationRejected(mutateReadLimb);
    try expectMutationRejected(mutateOrdinalHole);
    try expectMutationRejected(mutateWrongRole);
    try expectMutationRejected(mutateWrongSchemaVersion);
    try expectMutationRejected(mutateLiveness);
    try expectMutationRejected(mutateNonzeroAddressSpace);
    try expectMutationRejected(mutateRawRegisterAddress);
    try expectMutationRejected(mutateArbitraryAddress);
    try expectMutationRejected(mutateWitnessCurrentClock);
    try expectMutationRejected(mutateWitnessGap);
    try expectMutationRejected(mutateSplitTriple);
}

test "machine-derived values reject orphaning and generic consumers" {
    var orphan = ir.Arena.init(std.testing.allocator);
    defer orphan.deinit();
    const generated = source.SourceSpan.generated();
    const clock = try orphan.input("clock", .clock, generated);
    _ = try orphan.accessClock(clock, .first, generated);
    try std.testing.expectError(error.InvalidEffect, validate.validate(&orphan));

    var fixture = try Fixture.init(std.testing.allocator, 1);
    defer fixture.deinit();
    const current = fixture.values(1)[2];
    _ = try fixture.arena.assertZero(
        "forbidden-derived-consumer",
        current,
        null,
        .semantic,
        generated,
    );
    try std.testing.expectError(error.InvalidEffect, validate.validate(&fixture.arena));
}

test "register access group rollback is leak-free under every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

test "failed access append preserves an existing group and schedule ordinal" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const allocator = failing.allocator();
    {
        var arena = ir.Arena.init(allocator);
        defer arena.deinit();
        const generated = source.SourceSpan.generated();
        const clock = try arena.input("clock", .clock, generated);
        const active = try arena.input("active", .bit, generated);
        const index = try arena.input("index", .register_index, generated);
        const previous_1 = try arena.input("previous_1", .clock, generated);
        const previous_2 = try arena.input("previous_2", .clock, generated);
        const value = try byteInputs(&arena, "value", generated);
        var schedule = try effects.AccessSchedule.begin(&arena, clock, active, generated);
        _ = try schedule.registerRead(.{
            .index = index,
            .previous_clock = previous_1,
            .value = value,
        }, generated);
        try validate.validate(&arena);

        const effects_before = arena.effects.items[0..3].*;
        const values_before = arena.effect_values.items[0..15].*;
        const nodes_before = arena.nodes.items.len;
        arena.nodes.shrinkAndFree(allocator, arena.nodes.items.len);
        failing.fail_index = failing.alloc_index;
        failing.resize_fail_index = failing.resize_index;
        try std.testing.expectError(
            error.OutOfMemory,
            schedule.registerWrite(.{
                .index = index,
                .previous_clock = previous_2,
                .previous = value,
                .next = value,
            }, generated),
        );
        try std.testing.expectEqual(@as(u8, 2), schedule.next_ordinal);
        try std.testing.expectEqual(nodes_before, arena.nodes.items.len);
        try std.testing.expectEqualSlices(program.Effect, &effects_before, arena.effects.items);
        try std.testing.expectEqualSlices(
            types.ValueId,
            &values_before,
            arena.effect_values.items,
        );
        try validate.validate(&arena);
    }
    try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
}

test "register groups use manifest v5 and semantic digest v3" {
    var fixture = try Fixture.init(std.testing.allocator, 2);
    defer fixture.deinit();
    var perturbed = try Fixture.initConfigured(std.testing.allocator, 2, true, false);
    defer perturbed.deinit();
    var reordered = try Fixture.initConfigured(std.testing.allocator, 2, false, true);
    defer reordered.deinit();
    try std.testing.expectError(
        error.MachineDerivedRequiresManifestV5,
        manifest.serializeAllocV4(std.testing.allocator, &fixture.arena),
    );
    try std.testing.expectError(error.InvalidEffect, digest.computeV2(&fixture.arena));

    const encoded = try manifest.serializeAllocV5(std.testing.allocator, &fixture.arena);
    defer std.testing.allocator.free(encoded);
    const perturbed_encoded = try manifest.serializeAllocV5(
        std.testing.allocator,
        &perturbed.arena,
    );
    defer std.testing.allocator.free(perturbed_encoded);
    const reordered_encoded = try manifest.serializeAllocV5(
        std.testing.allocator,
        &reordered.arena,
    );
    defer std.testing.allocator.free(reordered_encoded);
    try std.testing.expectEqualSlices(u8, encoded, perturbed_encoded);
    try std.testing.expect(!std.mem.eql(u8, encoded, reordered_encoded));
    try std.testing.expectEqual(
        manifest.register_group_format_version,
        std.mem.readInt(u16, encoded[8..10], .little),
    );
    try std.testing.expectEqual(
        manifest.register_group_logical_schema_version,
        std.mem.readInt(u16, encoded[10..12], .little),
    );
    const semantic = try digest.computeV3(&fixture.arena);
    const perturbed_semantic = try digest.computeV3(&perturbed.arena);
    const reordered_semantic = try digest.computeV3(&reordered.arena);
    try std.testing.expectEqual(semantic, perturbed_semantic);
    try std.testing.expect(!std.mem.eql(u8, &semantic, &reordered_semantic));
    const identity = try digest.computeIdentity(&fixture.arena);
    try std.testing.expectEqual(digest.register_group_format_version, identity.format_version);
    try std.testing.expectEqual(semantic, identity.bytes);

    var manifest_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(encoded, &manifest_hash, .{});
    const rendered_digest = std.fmt.bytesToHex(semantic, .lower);
    const rendered_manifest = std.fmt.bytesToHex(manifest_hash, .lower);
    try std.testing.expectEqualStrings(
        "bdb39bebbecf6123bc05695e42a577f658d33b1d2f6edcfaa67aaec6aee20f9e",
        &rendered_digest,
    );
    try std.testing.expectEqual(@as(usize, 572), encoded.len);
    try std.testing.expectEqualStrings(
        "20e612cf044220395c6fe52ffc846f92665d228fbbd89a340feb25f48e727ae5",
        &rendered_manifest,
    );
}

const Fixture = struct {
    arena: ir.Arena,
    instruction_clock: types.ValueId,
    active: types.ValueId,
    register_index: types.ValueId,
    previous_clocks: [3]types.ValueId,
    read_value: [4]types.ValueId,
    write_value: [4]types.ValueId,

    fn init(allocator: std.mem.Allocator, group_count: u8) !Fixture {
        return initConfigured(allocator, group_count, false, false);
    }

    fn initConfigured(
        allocator: std.mem.Allocator,
        group_count: u8,
        perturb_names: bool,
        write_first: bool,
    ) !Fixture {
        var arena = ir.Arena.init(allocator);
        errdefer arena.deinit();
        const generated = source.SourceSpan.generated();
        if (perturb_names) {
            const names = [_][]const u8{
                "write_3",
                "write_2",
                "write_1",
                "write_0",
                "read_3",
                "read_2",
                "read_1",
                "read_0",
                "previous_clock_3",
                "previous_clock_2",
                "previous_clock_1",
                "register_index",
                "active",
                "instruction_clock",
            };
            for (names) |name| _ = try arena.internName(name);
        }
        const instruction_clock = try arena.input("instruction_clock", .clock, generated);
        const active = try arena.input("active", .bit, generated);
        const register_index = try arena.input("register_index", .register_index, generated);
        const previous_clocks = [3]types.ValueId{
            try arena.input("previous_clock_1", .clock, generated),
            try arena.input("previous_clock_2", .clock, generated),
            try arena.input("previous_clock_3", .clock, generated),
        };
        const read_value = try byteInputs(&arena, "read", generated);
        const write_value = try byteInputs(&arena, "write", generated);
        var schedule = try effects.AccessSchedule.begin(
            &arena,
            instruction_clock,
            active,
            generated,
        );
        if (group_count >= 1) {
            if (write_first) {
                _ = try schedule.registerWrite(.{
                    .index = register_index,
                    .previous_clock = previous_clocks[0],
                    .previous = read_value,
                    .next = write_value,
                }, generated);
            } else {
                _ = try schedule.registerRead(.{
                    .index = register_index,
                    .previous_clock = previous_clocks[0],
                    .value = read_value,
                }, generated);
            }
        }
        if (group_count >= 2) {
            if (write_first) {
                _ = try schedule.registerRead(.{
                    .index = register_index,
                    .previous_clock = previous_clocks[1],
                    .value = write_value,
                }, generated);
            } else {
                _ = try schedule.registerWrite(.{
                    .index = register_index,
                    .previous_clock = previous_clocks[1],
                    .previous = read_value,
                    .next = write_value,
                }, generated);
            }
        }
        if (group_count >= 3)
            _ = try schedule.registerRead(.{
                .index = register_index,
                .previous_clock = previous_clocks[2],
                .value = write_value,
            }, generated);
        try validate.validate(&arena);
        return .{
            .arena = arena,
            .instruction_clock = instruction_clock,
            .active = active,
            .register_index = register_index,
            .previous_clocks = previous_clocks,
            .read_value = read_value,
            .write_value = write_value,
        };
    }

    fn deinit(self: *Fixture) void {
        self.arena.deinit();
        self.* = undefined;
    }

    fn values(self: *const Fixture, effect_index: usize) []const types.ValueId {
        const id = types.idFromIndex(types.EffectId, effect_index) catch unreachable;
        return self.arena.effectValues(id).?;
    }

    fn readInput(self: *const Fixture, index: usize) effects.RegisterReadInput {
        return .{
            .index = self.register_index,
            .previous_clock = self.previous_clocks[index],
            .value = self.read_value,
        };
    }
};

fn byteInputs(
    arena: *ir.Arena,
    comptime prefix: []const u8,
    span: source.SourceSpan,
) ![4]types.ValueId {
    var result: [4]types.ValueId = undefined;
    inline for (&result, 0..) |*value, index| {
        value.* = try arena.input(
            std.fmt.comptimePrint("{s}_{d}", .{ prefix, index }),
            .byte,
            span,
        );
    }
    return result;
}

fn machine(node: expr.Node) expr.MachineDerived {
    return switch (node.key.op) {
        .machine_derived => |derived| derived,
        else => unreachable,
    };
}

fn replayMachineNodes(arena: *const ir.Arena, values: []M31) !void {
    if (values.len != arena.nodeCount()) return error.InvalidReplayBuffer;
    for (arena.nodesView(), 0..) |node, index| {
        values[index] = switch (node.key.op) {
            .constant => |constant| switch (constant) {
                .field, .unsigned => |value| M31.fromU64(value),
            },
            .input => values[index],
            .machine_derived => |derived| switch (derived) {
                .register_address => |address| values[types.idIndex(address.index)],
                .aligned_word_address => |address| values[types.idIndex(address.word_index)]
                    .mul(M31.fromCanonical(4)),
                .access_clock => |clock| values[types.idIndex(clock.instruction_clock)]
                    .sub(M31.one())
                    .mul(M31.fromCanonical(4))
                    .add(M31.fromCanonical(@intFromEnum(clock.phase))),
                .strict_clock_gap => |gap| values[types.idIndex(gap.current_clock)]
                    .sub(values[types.idIndex(gap.previous_clock)])
                    .sub(M31.one()),
                .instruction_next_pc => |next| values[types.idIndex(next.current)]
                    .add(M31.fromCanonical(4)),
                .instruction_next_clock => |next| values[types.idIndex(next.current)]
                    .add(M31.one()),
            },
            else => return error.UnsupportedReplayNode,
        };
    }
}

fn expectMutationRejected(comptime mutate: fn (*Fixture) void) !void {
    var fixture = try Fixture.init(std.testing.allocator, 2);
    defer fixture.deinit();
    mutate(&fixture);
    try std.testing.expectError(error.InvalidEffect, validate.validate(&fixture.arena));
}

fn mutateReadLimb(fixture: *Fixture) void {
    const emit = fixture.arena.effects.items[1].values;
    fixture.arena.effect_values.items[@as(usize, emit.start) + 3] = fixture.write_value[0];
}

fn mutateOrdinalHole(fixture: *Fixture) void {
    for (fixture.arena.effects.items[3..6]) |*effect| effect.access_ordinal = 3;
}

fn mutateWrongRole(fixture: *Fixture) void {
    fixture.arena.effects.items[1].binding.?.role = .consume;
}

fn mutateWrongSchemaVersion(fixture: *Fixture) void {
    fixture.arena.effects.items[2].binding.?.schema_version += 1;
}

fn mutateLiveness(fixture: *Fixture) void {
    fixture.arena.effects.items[2].liveness = fixture.instruction_clock;
}

fn mutateNonzeroAddressSpace(fixture: *Fixture) void {
    const one = fixture.arena.constantField(1, source.SourceSpan.generated()) catch unreachable;
    for (0..2) |event_index| {
        const range = fixture.arena.effects.items[event_index].values;
        fixture.arena.effect_values.items[range.start] = one;
    }
}

fn mutateRawRegisterAddress(fixture: *Fixture) void {
    for (0..2) |event_index| {
        const range = fixture.arena.effects.items[event_index].values;
        fixture.arena.effect_values.items[@as(usize, range.start) + 1] = fixture.register_index;
    }
}

fn mutateArbitraryAddress(fixture: *Fixture) void {
    const address = fixture.arena.input(
        "forged_address",
        .address,
        source.SourceSpan.generated(),
    ) catch unreachable;
    for (0..2) |event_index| {
        const range = fixture.arena.effects.items[event_index].values;
        fixture.arena.effect_values.items[@as(usize, range.start) + 1] = address;
    }
}

fn mutateWitnessCurrentClock(fixture: *Fixture) void {
    const range = fixture.arena.effects.items[1].values;
    fixture.arena.effect_values.items[@as(usize, range.start) + 2] = fixture.previous_clocks[0];
}

fn mutateWitnessGap(fixture: *Fixture) void {
    const forged = fixture.arena.input(
        "forged_gap",
        .uint20,
        source.SourceSpan.generated(),
    ) catch unreachable;
    const range = fixture.arena.effects.items[2].values;
    fixture.arena.effect_values.items[range.start] = forged;
}

fn mutateSplitTriple(fixture: *Fixture) void {
    fixture.arena.effects.items[1].kind = .public_consume;
}

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    var arena = ir.Arena.init(allocator);
    defer arena.deinit();
    const generated = source.SourceSpan.generated();
    const clock = try arena.input("clock", .clock, generated);
    const active = try arena.input("active", .bit, generated);
    const index = try arena.input("index", .register_index, generated);
    const previous = try arena.input("previous", .clock, generated);
    const value = try byteInputs(&arena, "value", generated);
    var schedule = try effects.AccessSchedule.begin(&arena, clock, active, generated);
    _ = try schedule.registerRead(.{
        .index = index,
        .previous_clock = previous,
        .value = value,
    }, generated);
    try validate.validate(&arena);
}
